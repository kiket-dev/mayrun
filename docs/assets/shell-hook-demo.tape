# VHS tape — mayrun shell-hook denies rm -rf with rule_id (~20s, no audio).
# Render: vhs docs/assets/shell-hook-demo.tape
# Requires: vhs, and `mayrun` on PATH (cargo build --release && export PATH).

Output docs/assets/shell-hook-demo.gif
Set FontSize 16
Set Width 900
Set Height 400
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Type "mayrun init --force"
Enter
Sleep 400ms
Type `eval "$(mayrun shell-hook)"`
Enter
Sleep 500ms
Type "rm -rf /"
Enter
Sleep 1200ms
# Expect denial with rule_id (pack.dangerous.rm-root) — fail closed
Type "# denied — rule_id printed above"
Enter
Sleep 800ms
