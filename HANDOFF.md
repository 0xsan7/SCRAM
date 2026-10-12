# HANDOFF — SCRAM v0.2.0 released 2026-10-12

The authorized release is complete.

- Stable release: [v0.2.0](https://github.com/0xsan7/SCRAM/releases/tag/v0.2.0), source `7a76788583ec43091e0397a39a5fbf4d1b017e25`. GitHub marks it non-prerelease and latest.
- Candidate retained: [v0.2.0-rc1](https://github.com/0xsan7/SCRAM/releases/tag/v0.2.0-rc1), source `aeefc1d28bb27352e190103c16744f93e8b58a24`.
- Five binaries verified by checksum, exact keyless workflow/tag identity, certificate source SHA, and Go build metadata; both SBOMs verified. All five platforms exercised on real runners.
- Action checked on push and both PR cases against the stable tag: unchanged dependencies pass; genuinely new minimist advisories fail. Both PR comments render /65 and update existing comments. Fixture PRs closed without merging.
- Source CI, coverage, race detection, full-history secret scans, 22 fuzz targets, and 40/40 mutation cases passed.

Evidence, immutable run links, and stable checksums: [docs/releases/v0.2.0.md](docs/releases/v0.2.0.md).

Two issues found while resuming were fixed before stable publication: malformed
Go module paths accepted by the fallback resolver (D48), and PR comments
skipped after policy failure (D49). The published notes lead with the JSON
schema 2.0.0 / 65-point score migration warning.

Main includes the release source plus follow-up validation documentation.
Use `git rev-parse HEAD origin/main` and the current remote checks to inspect
its current state rather than relying on a self-referential hash here.

No further release tag is authorized by this completed v0.2.0 release task.
All previous releases, tags, and branches remain intact. Continue to avoid
force-pushing, rewriting history, or deleting branches/releases.

Longer-term work remains in ROADMAP.md: SLSA build attestations, reachability,
data for a truthful 100-point score, more ecosystems, npm v1 dependency-type
fidelity, and wider CLI/mutation coverage. Abandonment prediction remains
unimplemented. A documentation site remains declined. These are roadmap
items, not unfinished v0.2.0 release steps.
