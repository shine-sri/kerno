# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# vhs tape — records a kerno doctor demo GIF for the README.
#
# Run with:
#   sudo -v && vhs demo.tape
#
# `sudo -v` caches the user's password so the recorded shell doesn't
# block waiting for input. `bin/kerno` is referenced as a relative
# path so the binary doesn't need to be on $PATH inside the recorded
# tty.
#
# Output:    demo.gif (~5 MB target after gifsicle)
# Required:  vhs (https://github.com/charmbracelet/vhs), ttyd, ffmpeg.

Output demo.gif

# ── visual config ──
Set Shell      "bash"
Set FontSize   14
Set Width      1100
Set Height     720
Set Theme      "Dracula"
Set TypingSpeed 30ms
Set Padding    20

# ── intro ──
Type "# Kerno doctor — eBPF-based incident diagnosis"
Sleep 1s
Enter
Type "# Step 1: induce a synthetic disk-fsync bottleneck in the background"
Sleep 800ms
Enter
Type "./bin/kerno chaos --induce disk-sat --duration 25s --intensity high --yes &"
Enter
Sleep 2s

# ── doctor run ──
Type "# Step 2: ask kerno to diagnose the system"
Sleep 600ms
Enter
Type "sudo ./bin/kerno --config scripts/verify-config.yaml doctor --duration 12s"
Enter

# Doctor takes ~12s + a couple seconds to render. Wait for the box-drawn
# report to finish painting before fading out.
Sleep 16s

# ── outro ──
Type "# Done — root cause identified, fix steps printed."
Sleep 2s
Enter
Type "# Same flow runs in CI via 'make verify' (62 checks across 13 phases)."
Sleep 3s
