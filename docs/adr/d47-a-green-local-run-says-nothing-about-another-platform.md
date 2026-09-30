# D47 — a green local run says nothing about another platform

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D47

**Title:** a green local run says nothing about another platform

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** The four tests added in D46 drive `scripts/diff_vulns.py` through
a Python subprocess. They passed on macOS. Both Windows CI jobs failed, twice,
on the `Test` step.

**First fix: wrong.** The change before last concluded that `python3` was not
on PATH on `windows-latest` and resolved the interpreter per platform. Both
jobs then failed **identically**, which proved the theory wrong. That commit's
message asserted a cause it had not checked — the same failure this project
has been logging all session, committed in a hurry because the fix felt
obviously right.

**The actual cause, from the runner log:**

```
OSError: [Errno 22] Invalid argument:
'D:\a\SCRAM\SCRAM\\SCRAM\SCRAM\scripts\diff_vulns.py'
```

The absolute path was interpolated into the `python -c` program text and
arrived mangled — repo segment repeated, stray control byte. `GOOS=windows go
vet` was clean throughout, and would have stayed clean: it compiles, it does
not execute. No local signal could ever have shown this.

**Decision.**

1. **The script path goes on stdin as JSON**, never in program text. The
   interpreter receives exactly the bytes Go resolved, and nothing has to
   survive being embedded in a program.
2. **`runPython` asserts the program text contains no path.** The specific
   reintroduction now fails in a local test rather than on a runner six
   minutes later.
3. **Three near-duplicate inline-Python harnesses collapse into one**
   `runPython` plus `canonicalClasses`.

**The rule, which is not really about Windows.** When a check fails only on a
platform you are not running, read that platform's actual output before
changing anything. A confident wrong fix costs a full push-and-wait cycle and
produces documentation that lies. The same commit is in TESTING.md alongside
the guard-phrasing rule, because both are the same shape: a check that
appeared to cover something and covered only the case in front of me.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
