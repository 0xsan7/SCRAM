# Roadmap

Ordered by what is missing, with the evidence for each. Every "not
implemented" below is a real limitation with a test or a measurement
behind it, not a placeholder.

## Not started

**SLSA provenance.** cosign signs the release blobs keyless; there is no
attestation for the build itself, so a verifier learns the artifact was
signed by this workflow but not what it was built from. `.goreleaser.yml`
and `ci.yml` are the inputs a `slsa-github-generator` workflow would
need.

**Reachability analysis.** SCRAM reports a vulnerable component whether or
not the vulnerable function is called. On a 1,478-component repository
like `nestjs/nest` that is most of the noise. This is the single largest
gap between what the tool reports and what is exploitable, and it needs
call-graph data this project does not collect.

**More ecosystems.** Cargo, Maven, and RubyGems are absent, and the README
says so. The resolver interface and the registry dispatch are what a new
one needs; the walkthrough in the README is verified end to end against
the current registry.

**Published release, and therefore a real `@v1` action tag.** No tag has
been cut. `uses: 0xsan7/SCRAM@v1` in the README is marked pending for
this reason, and the Action currently downloads from
`releases/latest/download/`, which 404s until a release exists.

**Abandonment prediction.** Named in the original scope, deliberately not
built. It is a prediction about maintainer behaviour, and a scanner's
output should not contain a guess of that kind without evidence it can be
calibrated against. Recorded here so the omission is visible rather than
a gap nobody noticed.

## Partial

**`cli` coverage, 24.5%.** The weakest package by a wide margin, and the
one that decides exit codes. Overall coverage is 67.0% with a per-package
median of 83.3%; the number is in
[docs/STATUS.md](docs/STATUS.md) rather than in a badge, because no
coverage service is configured.

**npm v1 fidelity.** Six real v1 fixtures, all resolving. What is lost is
the dev/optional/peer distinction that v1 records but the resolver does
not read, so a v1 project's dependency *shape* is under-reported even
when the inventory is complete. Documented in
[LIMITATIONS.md](LIMITATIONS.md).

**`why` and `trend`.** Both run against a real corpus repository. Neither
has been audited for edge cases the way the resolvers have.

## Done, and verified

Named here so the list above is read as a remaining-work list rather than
a verdict. The evidence for each is in [docs/STATUS.md](docs/STATUS.md).

Real-world corpus (86 lockfiles, every one resolving non-empty), mutation
audit (16 mutants, all killed), fuzzing (607 promoted inputs), differential
comparison against syft and grype
([REPRODUCIBILITY.md](REPRODUCIBILITY.md)), benchmarks
([BENCHMARKS.md](BENCHMARKS.md)), release automation verified by snapshot
build, and SBOM output validated against the official CycloneDX 1.5 and
SPDX 2.3 schemas in CI.

## Unverified

CI had never run until the repository became public. It has now, and the
first run was red on `windows-latest` for a reason unrelated to the code.
Anything still marked unverified in [docs/BLOCKED.md](docs/BLOCKED.md)
has not run, and that list is the honest one.
