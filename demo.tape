# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# vhs tape — records a kerno doctor demo GIF for the README.
#
# Run with:   vhs demo.tape
# Output:     demo.gif (~5 MB target)
#
# Requirements: vhs (https://github.com/charmbracelet/vhs), bin/kerno,
# bin/bpf-verify, sudo, kernel >= 5.8 with BTF.

Output demo.gif

# ── visual config ──
Set FontSize 14
Set Width  1100
Set Height 700
Set Theme  "Dracula"
Set TypingSpeed 30ms
Set Padding 20

# ── intro ──
Type "# Kerno doctor — eBPF-based incident diagnosis in 30 seconds"
Sleep 1s
Enter
Sleep 500ms

Type "# Step 1: induce a synthetic disk-fsync bottleneck in the background"
Sleep 800ms
Enter
Type "kerno chaos --induce disk-sat --duration 25s --intensity high --yes &"
Enter
Sleep 2s

# ── doctor run ──
Type "# Step 2: ask kerno to diagnose the system"
Sleep 600ms
Enter
Type "sudo kerno --config scripts/verify-config.yaml doctor --duration 12s"
Enter

# Doctor takes ~12s + a few seconds to render. Wait for output.
Sleep 16s

# ── outro ──
Type "# Done — root cause identified, fix steps printed. Same flow runs in CI."
Sleep 3s
