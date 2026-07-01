# Windows 11 Notepad — `OleControls.dll` ImageBlock: Static Analysis Notes

> **Status: research notes, not a confirmed vulnerability.**
> This is a static reverse-engineering analysis of code shipped inside the
> `Microsoft.WindowsNotepad` package. The image feature these code paths belong to
> is present in the binary but not yet functionally enabled in public Insider
> (Canary/Dev) builds at the time of writing. Nothing here has been confirmed
> dynamically. Where a conclusion is an inference from disassembly rather than an
> observed fact, it is called out as such. The remote-fetch behaviour described
> below should be read as a well-supported hypothesis, not as an established,
> exploitable bug.

## Summary

Windows 11 Notepad's upcoming inline-image feature is implemented as an OLE
embeddable object, internally called the "ImageBlock", living in
`OleControls.dll`. Static analysis shows a code path in which an image that a
document references by URL is fetched over HTTP by a WinRT `HttpClient`. Along
that path the URL's scheme is only classified, never security-validated, and no
application-level host allow-list or user consent prompt was found before the
request goes out.

Tracing the other half of the story inside `Notepad.exe` — the container that
hosts the object — shows that this URL is read, and the remote image source is
built, automatically while the document's content is being deserialized, with no
user interaction anywhere along the path. The single sub-step that static
analysis cannot pin down is whether the HTTP request fires at load time or is
deferred to the first render of the image; both are non-interactive, and only a
dynamic test can establish the exact instant.

## Scope and environment

The target is `OleControls.dll` from the `Microsoft.WindowsNotepad` package,
version `11.2604.5.0`, x64. All work was done in Ghidra. Microsoft does not
publish a public PDB for this DLL, so the analysis was carried out without
symbols, helped by the RTTI strings the compiler left in the binary. The method
was the usual one: map the attack surface, find where untrusted input enters,
trace it towards dangerous operations, and identify the object's COM interfaces to
understand how the container drives it. No dynamic testing was possible because
the feature is not activatable in shipping builds.

## Why this DLL is the interesting surface

The package manifest (`AppxManifest.xml`) registers a COM server for
`Notepad.OleControls.ImageBlock`, marked `InsertableObject="true"`, backed by
`OleControls.dll`. That single line is what turns a formerly text-only editor into
something that embeds and renders rich objects, which is exactly the kind of new
surface worth looking at.

![ImageBlock COM server registration](images/01-manifest-imageblock.png)

The manifest also registers the `ms-notepad` protocol handler, a system-wide entry
point that any process — including a web page via the browser — can trigger.

![ms-notepad protocol registration](images/02-manifest-protocol.png)

On top of that it declares a broad set of file associations, including an
`anyfile` catch-all mapped to `*`, so Notepad offers to open essentially anything.
The content of a file you open is therefore fully attacker-controlled input, and
the ImageBlock is the component that processes the image parts of that content.

The DLL's import table tells us how images are handled and how the network is
touched. Rendering goes through GDI+: the imports include
`GdipCreateBitmapFromScan0` and `GdipBitmapLockBits`, which work on raw pixel
buffers, and notably there is no `Gdip*FromStream`, so no compressed-format decode
is delegated to GDI+ inside this DLL.

![GDIPLUS imports](images/03-imports-gdiplus.png)

From `urlmon.dll` only `CreateUri` is imported, which is URI parsing, not
downloading. The actual network fetch happens through the WinRT
`Windows.Web.Http` stack instead, which we reach later in the chain.

![URLMON imports — only CreateUri](images/04-imports-urlmon.png)

## The chain inside `OleControls.dll`

### The URL comes from the document

`FUN_180003630` is the routine that deserializes an ImageBlock from the OLE streams
stored inside a document. It reads a stream called `ImgMetadataStream` into object
fields at offsets `+0x50` and `+0x70`, reads a second stream called
`ImgRuntimeDependencyStream` for the image dimensions at `+0xb0` and `+0xb4`, and
crucially runs the URL through a scheme classifier whose result it stores in a
type discriminant at offset `+0xbc`.

![ImageBlock deserialization](images/05-deserialize-180003630.png)

The relevant line is:

```c
uVar1 = FUN_180001620((LPCWSTR)(param_1 + 0x50));   // classify URL scheme
*(int *)(param_1 + 0xbc) = (int)CONCAT71(...,uVar1); // source-type discriminant
```

In other words, the value at `+0xbc` — which later decides whether to perform an
HTTP fetch — is derived directly from the scheme of a URL that came straight out
of the document. An attacker who crafts the document controls that URL, controls
its scheme, and therefore controls this discriminant.

### The scheme classifier is not a security check

`FUN_180001620` is the classifier. It builds an `IUri` from the string via
`CreateUri`, pulls out the scheme name with `GetSchemeName`, and maps it to a small
integer.

![URL scheme classifier](images/06-classify-scheme-180001620.png)

The mapping is simple: the scheme `notepad-image` returns 2, the scheme `file`
returns 0 or 1 depending on a further comparison, and everything else — `http`,
`https`, or any other scheme whatsoever — falls into the `else` branch and returns
1. There is no allow-list, no host inspection, no rejection of unexpected schemes,
   and no prompt. This is a type-sorting routine, not a validation routine, and its
   default outcome for anything that is not a local file or the custom
   `notepad-image` scheme is "treat as a remote source".

### Source type 1 drives an HTTP fetch, with no application-level check on the way

`FUN_18001c540` is a state machine driven by a `switch` on `param_1[8]`, and the
type-1 path is the one that goes to the network. It is entered when
`*(int *)(lVar26 + 0xbc) == 1`, i.e. when the source was classified as a remote
URL. Case 4 builds a `Windows.Web.Http.HttpClient`, sets a request User-Agent
header, and assembles the request from the document's URL:

```c
if (*(int *)(lVar26 + 0xbc) == 1) {                  // remote-URL source type
    // build-path strings present in this branch:
    //   ...\src\OleControls\...\winrt\Windows.Web.Http.h
    //   ...\src\OleControls\...\winrt\Windows.Web.Http.Headers.h
    *(wchar_t **)(param_1 + 0x3e) = L"Notepad (Windows NT 10.0)";  // User-Agent
    // ... request assembled from the document URL, then sent ...
}
```

Case 6 creates the request object and calls `SendRequestAsync` through vtable
offset `+0xa0` on the `Windows.Web.Http` object, and case 8 reads the HTTP response
into a stream and hands it to GDI+ (`GdipCreateBitmapFromScan0`,
`GdipBitmapLockBits`) for decoding.

The client itself is instantiated by `FUN_180014d50`, recognisable from the
runtime-class string it activates:

```c
local_58 = L"Windows.Web.Http.HttpClient";
// build path: ...\src\OleControls\...\winrt\base.h
FUN_1800149c0(local_78, (longlong *)&local_70,
              &DAT_1800469a8, (longlong *)&local_38);   // activate runtime class
```

Across cases 4, 6 and 8 there is no host comparison, no `http`/`https` allow-list,
no loopback or intranet check, and no user-consent prompt. The only string-shape
test anywhere near this path is one that distinguishes local `C:\`-style paths (a
letter followed by `:` and a slash), which is local-path normalization for the
file branch, not remote-URL validation.

One honest caveat belongs here. `Windows.Web.Http.HttpClient` is a system WinRT
runtime, so this analysis only demonstrates the absence of application-level checks
inside `OleControls.dll`. It does not rule out policy that the system runtime might
enforce a layer below what is visible here.

### The object is an OLE embeddable, renderable through IViewObject

The ImageBlock's `QueryInterface` (`FUN_180001e40`) walks an ATL interface map at
`DAT_180046d40`. Decoding the IIDs in that table shows that, alongside several
custom Notepad-internal interfaces, the object implements `IViewObject` (IID
`0000010D-0000-0000-C000-000000000046`, the rendering interface) and `IOleObject`
(IID `00000112-0000-0000-C000-000000000046`, the embedding interface). RTTI
confirms the class as `ATL::CComObject<...Image...>`. The `IUnknown` branch of the
QI is the standard ATL pattern:

```c
// IUnknown IID = {00000000-0000-0000-C000-000000000046}
else if ((*param_2 == 0) && (param_2[1] == 0) &&
         (param_2[2] == 0xc0) && (param_2[3] == 0x46000000)) {
    (**(code **)(*param_1 + 8))();   // AddRef
    *param_3 = param_1;              // return self
}
else {
    plVar3 = &DAT_180046d50;         // iterate the ATL interface map
    do { /* compare requested IID against each entry */ } while (*plVar3 != 0);
}
```

The presence of `IViewObject` matters because it means the container paints the
image by calling `Draw`, which happens when the image needs to be shown — typically
on open or view — rather than requiring an explicit activation like
`IOleObject::DoVerb`.

### The fetch is launched by a class method reached only through a vtable

The state machine is started by `FUN_180002a20`, which allocates the state object,
installs the state-machine function, records the source object, sets the initial
state and kicks it off:

```c
piVar6 = FUN_18001b8fc(0x840);                 // allocate state object
*(code **)(piVar6 + 2) = FUN_18001c530;
*(code **)piVar6       = FUN_18001c540;        // install state machine
*(longlong *)(piVar6 + 6) = param_1 + -0x18;   // source object
piVar6[8] = 0x10002;                           // initial state = 2
FUN_18001c540(piVar6, uVar7, piVar8);          // start
```

This function has no direct callers. Ghidra shows it referenced only as data: it
sits at index 8 of two ATL vtables (`1800463a0` and `180046640`), it appears in the
CFG guard table, and it has a `.pdata` entry. It is therefore invoked purely as
method 8 of the class vtable, dispatched by whatever code hosts the object.

The factory that builds the object, `FUN_180005290`, allocates 200 bytes,
zero-initializes the fields (including the `+0xbc` discriminant), and installs one
sub-vtable per COM interface the object exposes:

```c
plVar2 = FUN_18001b938(200);                        // allocate object
// ... zero-init fields ...
*(undefined4 *)((longlong)plVar2 + 0xbc) = 0;       // source-type discriminant = 0
*plVar2   = (longlong)ATL::CComObject<>::vftable;    // 7 interface sub-vtables
plVar2[1] = (longlong)ATL::CComObject<>::vftable;
// ... plVar2[2] .. plVar2[6], one per interface ...
```

## The chain inside the container (`Notepad.exe`)

The object that `OleControls.dll` implements has to be created and driven by
something, and that something is `Notepad.exe` itself. This is clear from the
symbols in that binary (`PageSetupDialog`, `NotepadTextBox`, `TabState`) and from
the fact that the ImageBlock CLSID `95b90fa7-3125-40d3-b9ff-1e807810a5f7` sits in
its data section right next to the `ImgMetadataStream`, `ImgRuntimeDependencyStream`
and `notepad-image` strings. So `Notepad.exe` is not a thin launcher; it is the OLE
container.

Following the deserialization path from the document end shows that the
ImageBlock's URL is read as an ordinary part of parsing the document's content,
with nobody clicking anything. When a document is opened, or a tab is restored, a
content-deserialization loop walks the serialized elements one by one and hands
each to a document-element dispatcher, `FUN_1401567d0`. That dispatcher is a large
switch over element tags — text, formatting, tables, and so on — and when it meets
tag `0x14` it calls the ImageBlock deserializer:

```c
case 0x14:
    uVar8 = FUN_140153890(param_2 + 0x1e);   // deserialize an ImageBlock element
    return uVar8;
```

There is no "user clicked" case here; this is sequential consumption of document
bytes, which is exactly what you would expect from a routine that turns a saved
file back into an in-memory document.

Inside the ImageBlock deserializer, `FUN_140156f10` first confirms that the
serialized object really is a `Notepad.OleControls.ImageBlock`, using a 30-byte
`memcmp` against that class name and throwing the serialization-subsystem error
GUID `1e626e63-28b3-4ae5-a02b-8bdb44df8ef6` if it is not, and then reads the
object's data. The metadata parsing itself is done by `FUN_1401517e0`, which
reconstructs a small C++ input stream over the raw bytes and decodes two
length-prefixed UTF-16 strings from it — one of which is the image URL. The length
prefix is a LEB128-style varint (read one byte at a time, seven bits of length per
byte, continue while the high bit is set), followed by that many wide characters.
This is worth recording precisely, because it documents the on-disk metadata
format that a hand-crafted proof-of-concept document would need to reproduce.

The lowest-level step, `FUN_140128b20`, is a small helper from `Common\OleUtils.cpp`
that actually pulls the bytes off disk: it opens the `ImgMetadataStream` via
`IStorage::OpenStream` (vtable offset `+0x20`) and then loops on `IStream::Read`
(offset `+0x18`) until the stream is exhausted. After the read loop, back up in
`FUN_140153890`, the parsed strings are used to build the image "source" object —
recognisable from the tagged pointers with the high bits set to `0xC000...` — and
that source is registered via `FUN_140151f70`. This is the moment the URL taken
from the document becomes a live image source inside the container.

Putting the two halves together, opening a document that contains an ImageBlock
causes Notepad to deserialize it during content parsing and to extract the URL and
build the remote image source automatically, without any user interaction.
Combined with the `OleControls.dll` chain, where a URL of type 1 leads to an HTTP
fetch with no application-level check, the entire setup of the remote request is
automatic on open.

## What is not established

Three things remain genuinely open, and it is important to be precise about them.

The first is the exact instant the request fires. The end-to-end static trace shows
that the URL is read and the remote source is built automatically when the document
is opened. What it does not pin down is whether the HTTP request goes out
immediately during load or is deferred to the first render or layout pass over the
image. Both possibilities are non-interactive, so the "no click required" character
of the behaviour does not depend on the answer, but only dynamic observation can
say exactly when the packet leaves. This point is strongly supported as automatic;
the precise timing is unconfirmed.

The second is whether the system runtime imposes any policy of its own. The
`Windows.Web.Http` stack lives below the application, and this analysis only
covers the application code. It is possible, though not visible here, that the
runtime applies some host or scheme policy.

The third is simply that none of this has been observed at runtime, because the
feature cannot be activated in shipping builds.

## Why it would matter if confirmed

If the trigger is automatic and no runtime check exists, opening a crafted document
would cause Notepad to issue an HTTP request to a host of the attacker's choosing,
carrying the distinctive `Notepad (Windows NT 10.0)` User-Agent. The impact would
sit in the SSRF, information-leak and silent read-receipt family — the moral
equivalent of a tracking pixel hidden inside what looks like a text file — and it
would additionally deliver attacker-controlled bytes to the GDI+ decoder. This is
the same class of risk that commentators raised publicly when the feature was
announced, and it rhymes with the earlier Markdown-link issue (CVE-2026-20841),
which Microsoft hardened by adding URI checks and user prompts.

## Responsible next steps

This should not be treated as a live vulnerability. The code path is not
user-reachable in shipping builds, and Microsoft may well add prompts or validation
before general release, exactly as they did for CVE-2026-20841; the code visible
today may not be the code that ships.

Because the on-disk metadata format is now understood — element tag `0x14`, the
class string `Notepad.OleControls.ImageBlock`, and an `ImgMetadataStream` holding
varint-length-prefixed UTF-16 strings including the URL — a test document could in
principle be built by hand rather than relying on the currently inert UI button.
The verification itself is simple and low-impact: point the URL at a local
listener, open the document, and watch whether and when a request arrives.

If that reproduces, the right destination is MSRC (https://msrc.microsoft.com),
and an observational proof-of-concept — a captured request landing on your own
listener — is entirely sufficient. No memory-corruption exploit is needed or
appropriate.

## Key functions and offsets

The following table collects the functions referenced above for quick lookup.

| Item | Binary / source | Role |
|---|---|---|
| `FUN_180003630` | OleControls (ImageBlock) | Deserialize from OLE streams; sets `+0xbc` |
| `FUN_180001620` | OleControls (StringUtils) | URL scheme to source-type (no security check) |
| `FUN_180001e40` | OleControls | `QueryInterface`; interface map at `DAT_180046d40` |
| `FUN_18001c540` | OleControls (ImageBlock) | State machine; HTTP fetch on cases 4/6/8 |
| `FUN_180014d50` | OleControls | Instantiates `Windows.Web.Http.HttpClient` |
| `FUN_180002a20` | OleControls | Starts state machine; class vtable method 8 |
| `FUN_180005290` | OleControls | Factory/constructor; installs 7 sub-vtables |
| `FUN_1401567d0` | Notepad.exe | Document-element dispatcher; case `0x14` is ImageBlock |
| `FUN_140153890` | Notepad.exe | ImageBlock deserialization loop |
| `FUN_140156f10` | Notepad.exe | Validates class name; reads metadata |
| `FUN_1401517e0` | Notepad.exe | Parse metadata (varint + UTF-16 strings; URL) |
| `FUN_140128b20` | Notepad.exe (OleUtils) | Reads `ImgMetadataStream` (OpenStream then Read) |
| ImageBlock CLSID | Notepad.exe | `95b90fa7-3125-40d3-b9ff-1e807810a5f7` |
| `+0xbc` | object field | Source-type discriminant (1 means remote URL) |
| User-Agent | OleControls case 4 | `Notepad (Windows NT 10.0)` |
| `IViewObject` IID | `180046e50` | `0000010D-...-46` (rendering) |
| `IOleObject` IID | `180046e60` | `00000112-...-46` (embedding) |

---
*Static analysis notes, no dynamic confirmation. Shared for research documentation;
verify before drawing conclusions.*
