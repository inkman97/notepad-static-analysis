# Notepad ImageBlock — static analysis

This repo collects my notes from reverse-engineering a piece of Windows 11
Notepad that isn't switched on yet: the upcoming inline-image feature. The image
button has been showing up in Notepad's "What's new" dialog in Insider builds for
a while now, but it doesn't actually do anything when you click it — the code
ships in the binary, but the UI that would drive it hasn't been wired up in any
public build I could get my hands on. That gap is exactly what made it
interesting to look at. The feature that will one day let you drop pictures into a
note is already sitting there in disassembly, so you can read what it's going to
do before it's live.

The short version of what I found: the component that handles embedded images
(Microsoft calls it the "ImageBlock", and it lives in `OleControls.dll`) can
reference an image by URL, and when it does, it fetches that image over HTTP using
a WinRT `HttpClient`. Following the code, the URL comes straight out of the
document, its scheme gets classified but never actually security-checked, and I
couldn't find any host allow-list or "do you want to load remote content?" prompt
in front of the request. On the other side, over in `Notepad.exe`, the URL is read
and the remote source is set up automatically while the document is being parsed —
nobody has to click anything. If that holds up once the feature is live, opening a
booby-trapped document could quietly make Notepad phone home to a server the
attacker picked, which is the kind of thing you really don't expect a text editor
to do.

I want to be upfront about what this is and isn't. It's a **static** analysis —
I read the code, I didn't run it, because I couldn't turn the feature on. So the
whole chain is traced through disassembly, not observed live. Most of it I'm
confident about: the URL genuinely comes from the document, there genuinely isn't
an app-level check, and the deserialization that pulls out the URL genuinely
happens on open without interaction. The one thing I can't pin down from static
analysis alone is the exact moment the network request goes out — whether it's the
instant the document loads or the first time the image gets painted on screen.
Both of those are "no click required", so it doesn't change the shape of the
problem, but only actually running it would tell you precisely when the packet
leaves. Until someone can do that, treat the remote-fetch behaviour as a
well-supported hypothesis, not a proven bug.

The full write-up, with the function-by-function trace across both binaries and
the Ghidra screenshots, is in
[`notepad-imageblock-analysis.md`](notepad-imageblock-analysis.md). One useful
byproduct that's in there: I worked out the on-disk format of the image metadata
(how the URL is stored inside the document), which is the piece you'd need to
build a test document by hand and finally confirm the behaviour dynamically —
possibly even before the UI button starts working.

If any of this turns out to be real once the feature is live, the right thing to
do is report it to Microsoft through MSRC (https://msrc.microsoft.com), and a
simple captured request landing on a local listener is all the proof-of-concept
that would need. Nothing here is meant as a weaponized exploit; it's documentation
of a code path, shared so it can be verified properly when the time comes.

---

*Static analysis of unreleased code. Not dynamically confirmed. Provided for
research and documentation purposes.*
