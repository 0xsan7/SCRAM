# SCRAM demo tape — regenerable terminal recording.
#
# The GIF in the README is produced from this file, not screen-recorded by
# hand. Re-run `vhs demo.tape` whenever the CLI output changes and the demo
# cannot go stale, which a hand-recorded GIF always eventually does.
#
# Requirements: vhs (github.com/charmbracelet/vhs) on PATH.
# The scram binary must already be built and on PATH:
#   go build -o scram ./cmd/scram && export PATH="$PWD:$PATH"
#
# Note on determinism: the demo scans a checked-in fixture
# (testdata/demo-app) rather than a live repository, so the component count
# and the finding IDs are stable across runs and across machines. The scores
# can move as upstream advisories change, which is honest — a demo that showed
# a stale fixed number would be the exact problem this project exists to fix.

Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 640
Set Padding 12
Set Theme {"background":"#0d1117","foreground":"#c9d1d9","selection":"#1f6feb","cursor":"#c9d1d9"}
Set TypingSpeed 45ms

# --- the problem: a CVE in a package nobody chose -------------------------
Type "cd testdata/demo-app && ls"
Enter
Sleep 2s

Type "grep -c '\"version\"' package-lock.json"
Enter
Sleep 1s

# --- the scan ------------------------------------------------------------
Type "scram scan . --no-gate"
Enter
Sleep 9s

# --- the finding, and where it came from ---------------------------------
Type ""
Sleep 500ms
Type "There is a CVE in a package we never asked for. Who added it, and how deep?"
Enter
Sleep 3s

Type "scram why qs"
Enter
Sleep 8s

Type "scram blame qs"
Enter
Sleep 7s

# --- the trend -----------------------------------------------------------
Type "scram scan . --no-gate"
Enter
Sleep 8s

Hide
Type "exit"
Enter
Sleep 500ms
Show
