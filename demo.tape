# VHS tape for the Afterlife README demo recording.
# Run with: vhs demo.tape  (after `brew install vhs`)
# Produces docs/media/demo.gif and docs/media/demo.mp4.

Output docs/media/demo.gif
Output docs/media/demo.mp4

Set Shell zsh
Set FontSize 13
Set FontFamily "JetBrainsMono Nerd Font, Menlo, monospace"
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms

# Make sure the demo's prior state doesn't leak into the screen.
Hide
Type "clear"
Enter
Sleep 200ms
Show

# The shot.
Type "make demo"
Sleep 600ms
Enter

# `make demo` runs in ~5-8 seconds end to end. Give the viewer time to
# scan the findings table + identity graph in the final frames.
Sleep 12s
