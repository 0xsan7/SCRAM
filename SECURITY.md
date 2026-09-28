# Security policy

## Reporting a vulnerability

SCRAM is a security tool, so a vulnerability report is worth more here
than in most projects: a false all-clear in a dependency scanner is worse
than no scanner, because it is trusted.

**Email is not monitored.** Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/0xsan7/SCRAM>).

Please include:

- what you ran, and on which lockfile or repository
- what SCRAM reported, verbatim, including the exit code
- what you expected instead
- the commit SHA (`scram --version` prints it for release builds)

### What is most useful

A report that demonstrates a **false negative** — SCRAM reporting CLEAN,
or exiting 0, when a known-vulnerable component is present — is the
highest-value report this project accepts. The project's whole design
rests on failing closed, so each one is a defect in the central claim
rather than in a feature.

Concretely, the cases the codebase already tries to prevent, and where
you would expect a new one to look like:

- a lockfile that declares dependencies and resolves to zero
  (`ErrSilentZero`, D26)
- a filename the detector claims to support but the resolver cannot read
  (D37, which is how `requirements-dev.txt` was silently ignored)
- an ecosystem added to the resolver but not to the OSV matcher's
  supported set, so components are catalogued and never checked
- a range where an exact pin was required for the vulnerability to match

## Response

| severity | acknowledgement | target |
|---|---|---|
| critical (false all-clear, RCE, data loss) | 48 hours | 7 days |
| high | 3 days | 30 days |
| medium / low | 7 days | next release |

These are targets, not guarantees. There is one maintainer.

Disclosure is coordinated with the reporter. Credit is given unless you
prefer otherwise.

## Supported versions

SCRAM has no release yet, so there is no version table to keep honest.
Once `v1` exists, security fixes land on the newest minor and the
previous one.

## What "verified" means here

Claims about this project are backed by something runnable, and you can
run it too:

```bash
go test ./...                                    # unit + integration
python3 scripts/test_fetch_corpus.py             # fetcher regressions
python3 scripts/mutation_audit.py                # re-breaks each fix, expects red
go test -run 'Fuzz' ./internal/resolve/          # replays the committed fuzz corpus
go run ./cmd/corpus-check                        # every real lockfile resolves non-empty
```

The mutation audit is the interesting one: it reverses each historical
bug fix and fails if the test suite does not notice. A fix that no test
protects will show up there as a surviving mutant.

## Scope

In scope: the scanner's behaviour, the parsers, the CI configuration in
this repository, and the release pipeline.

Out of scope: vulnerabilities in upstream dependencies of SCRAM itself
(those go to the upstream project, though you are welcome to say so in
an issue), and findings from running SCRAM against a target you are not
authorised to scan.
