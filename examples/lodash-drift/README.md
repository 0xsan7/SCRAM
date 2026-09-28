# lodash drift demo

Reproduces the output at the top of the main README.

```bash
./run.sh
```

It builds a real npm project, a real git repository, a real baseline, and a
real bump, then scans both sides. Nothing in the README's opening block is
transcribed: the numbers come from whatever OSV says at the time you run
it. The findings move as advisories are published or withdrawn, and the
component and finding counts are stable.

Needs Go 1.23+ and network access for OSV/EPSS. Takes about ten seconds and
does not need a Node toolchain -- the lockfile is written directly, with the
integrity hashes npm actually publishes.

Scratch directory: `$TMPDIR/scram-lodash-drift`. Override with
`SCRAM_DRIFT_DEMO_DIR`, or pass `--keep` to leave it in place.
