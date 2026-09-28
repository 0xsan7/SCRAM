# Support

## This project has no support commitment

One maintainer, built in spare time. Nothing here is a promise of a
response time, because an unkept promise is worse than an honest absence
of one.

## Getting help

1. **Check [LIMITATIONS.md](LIMITATIONS.md).** If the behaviour you are
   seeing is documented there, it is working as intended.
2. **Reproduce it.** A report with the lockfile, the exact command, the
   output, and the exit code is answerable. One without is guesswork.
3. **Open an issue.** Not a support forum, and not a discussion board.

## Questions this project answers well

- "What does this lockfile resolve to?" — `scram sbom generate`
- "What did this PR change?" — `scram scan` against a baseline
- "Where did this dependency come from?" — `scram why`, `scram blame`
- "Why is this component scored 41?" — `scram scan --explain`

## Questions it does not

- "Why did CI fail on a runner I do not have?" — the workflows are the
  answer, and the failure output is the documentation.
- "Which vulnerability is real in my specific context?" — reachability
  analysis is not implemented. See the roadmap note in
  [docs/STATUS.md](docs/STATUS.md).

## Reporting a vulnerability

Not here. Use [SECURITY.md](SECURITY.md).
