# Producing the README demo recording

The README embeds `docs/media/demo.gif`, a ~12 second recording of
`make demo` producing 20 findings and the cross-source identity graph.
The recording is generated from `demo.tape` (root of the repo) using
[VHS](https://github.com/charmbracelet/vhs).

## One-time setup

```bash
brew install vhs        # ffmpeg comes along for the ride
```

VHS uses headless Chrome under the hood, so the first run downloads a
~100MB Chromium. Subsequent runs reuse it.

## Re-record

After any change to the demo's output (new finding, new collector, new
formatting):

```bash
vhs demo.tape
# regenerates docs/media/demo.gif and docs/media/demo.mp4
git add docs/media/demo.gif docs/media/demo.mp4
git commit -m "Refresh demo recording"
```

The tape is deterministic: same demo + same tape produce a
byte-similar GIF. Useful for diffing what changed visually.

## What the tape does

`demo.tape` is roughly:

```
Output docs/media/demo.gif
Output docs/media/demo.mp4
Set Width 1200, Height 720, FontSize 13, Theme "Catppuccin Mocha"
Type "make demo"
Enter
Sleep 12s
```

The `Sleep 12s` after Enter gives the demo (~5-8 seconds) plus a few
seconds for the viewer to read the final findings + identity graph
frames.

## Tweaking the recording

- **Faster typing**: lower `Set TypingSpeed`.
- **Shorter dwell**: lower the trailing `Sleep`.
- **Different theme**: VHS ships about a dozen built-in themes; see
  `vhs themes`. Catppuccin Mocha is the dark default the README uses.
- **Pause on a specific frame**: insert `Wait+Screen` to wait for a
  pattern to appear, then `Sleep 1.5s` to dwell.

## Asciinema alternative

If you want an interactive recording (viewers can select+copy text)
instead of a video:

```bash
brew install asciinema agg
asciinema rec demo.cast
make demo
exit
agg demo.cast docs/media/demo.gif       # convert to GIF for the README
```

Asciinema casts can be uploaded to asciinema.org and embedded, but for
a GitHub README the in-repo GIF is the lowest-friction path.
