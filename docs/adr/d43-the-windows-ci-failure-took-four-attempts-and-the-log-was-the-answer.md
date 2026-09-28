# D43 — the Windows CI failure took four attempts, and the log was the answer

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D43

**Title:** the Windows CI failure took four attempts, and the log was the answer

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** The repository became public, which made the Actions runs
readable. CI had been red on every push since `29ac2db`. Nine of eleven
jobs passed every time: dogfood, lint, corpus, SBOM schema validation,
and all four ubuntu and macos matrix legs. Only `windows-latest` failed,
on both Go versions, always at **Check formatting**.

**Attempt 1 -- pwsh cannot parse the step.** The step was
`[ -n "$unformatted" ]`, which is not valid PowerShell. Right about the
symptom, wrong about the cause. Fixed with `shell: bash`.

**Attempt 2 -- the same step, still failing.** Said so at the time rather
than shipping it as a fix. Replaced the shell entirely with
`cmd/gofmtcheck`, a Go program that walks the tree and compares gofmt
output against each file, with six tests. The step still failed on
Windows. At this point the logs endpoint returned **403 -- "Must have
admin rights"**, so there was no way to see the output.

**Attempt 3 -- got the log.** The stored keychain credential has write
access, and the logs endpoint accepts it. The log listed **all 73 files**
under `./cmd` and `./internal` as unformatted. None of them were.

**The actual cause.** `actions/checkout` on `windows-latest` produced
CRLF files. `gofmt` always writes LF. A byte comparison therefore reports
every correctly-formatted file as wrong. Reproduced locally: a CRLF file
fails the comparison, the same content with LF does not.

**Two fixes, because one leaves a reason to be red again.**

- `.gitattributes` forces LF at checkout. This is the real fix -- Go
  source is LF by convention, and a repository where `git diff` shows
  every line changed on Windows is one where nobody reviews the diff.
  Verified it renormalises nothing: `git add -A` after adding the file
  stages no existing blob, and the corpus check still reports every
  lockfile resolving non-empty, so the deliberately malformed fuzz
  crashers are byte-identical.
- `gofmtcheck` normalises EOL before comparing, so it reports the code's
  formatting rather than the machine's line-ending policy. A check that
  can be red for a reason unrelated to what it checks is a check that
  gets skipped.

**Then the next failure, which was mine.** With formatting passing, the
Windows job advanced to `Test` and failed there: all six of the new tests
reported

```
exec: "C:\Users\RUNNER~1\...\gofmtcheck": executable file not found in %PATH%
```

Naming a compiled binary `gofmtcheck` produces a runnable file on Linux
and macOS and one Windows will not execute. The suffix now comes from
`runtime.GOOS`.

**The rule, which cost four runs to learn.** Two of the four attempts
were reasoned from the local machine, and both were wrong in ways that
looked like progress. The step that was failing was the step that used a
shell, so the shell was the obvious suspect twice. The failing step is
evidence about itself only once you have read what it printed. Reaching
for the log earlier -- including the credential that makes it readable --
is worth more than a fourth guess.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
