# Roadmap

Ordered by what is missing, with the evidence for each. Every "not
implemented" below is a real limitation with a test or a measurement
behind it, not a placeholder.

**mkdocs documentation site.** Decided against, on 2026-09-29, after
the decision was first claimed to be recorded here when it was not.

The argument for skipping it: the documentation is 43 markdown files
that GitHub already renders, every relative link resolves, and 28 of them
are ADRs behind a generated index. A site generator adds a build system, a
deployment, a second place for content to go stale, and a dependency
chain to maintain — in a repository whose entire premise is not shipping
unaudited dependencies.

The argument for building it is real, and this is a judgement call
rather than a technical fact: a docs site is the difference between
"read the source" and "use the tool" for anyone arriving from the
Marketplace listing, and the CLI reference in particular cannot be
generated from Cobra without one.

What settles it either way is that GitHub renders the same markdown
natively and `docs/adr/` now has a generated index, so the marginal
value is lower than it was. **If the project gains a second maintainer
or a docs-heavy feature, revisit this** — the two conditions that would
change the answer.

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

**More ecosystems.** Tracked, not in this pass:

- **Maven** — `pom.xml` and Gradle lockfiles. Not started. The reason is
  that Maven is the one ecosystem here where a correct inventory is not
  derivable from the file alone. `pom.xml` declares *ranges* plus parent
  and BOM imports, and the resolved set only exists after an effective-POM
  computation, so anything short of running Maven's own resolver risks
  reporting versions the build would never select. Given this project's
  rule that an inventory may be under- or over-stated but must never be
  silently wrong, the honest sequence is: get an effective-pom (via
  `mvn help:effective-pom`, or `mvn dependency:tree -DoutputType=json`)
  and pin that output as the corpus, then write the resolver against it.
  It is tracked rather than dropped because the walkthrough in the README
  covers everything except this, and this is the part that is not a
  parser.
- **RubyGems** — `Gemfile.lock`. Genuinely missing. The format is a
  simple indented lockfile, closer to npm v2 than to pnpm, and would be
  the cheapest of the outstanding ecosystems.
- **.NET** — `packages.lock.json`. Also missing, and it has the same
  transitive-resolution problem Maven does, for the same reason.

`yarn.lock` (classic and Berry), `pnpm-lock.yaml` and `Cargo.lock` were
added in this pass, each with a real fixture corpus. The resolver
interface, the registry dispatch, and the README walkthrough are what a
new one needs, and the walkthrough is verified end to end against the
current registry.

**A moving `@v1` action tag.** Resolved. `v0.1.0` is published, and the
Action resolves its release from the ref it is invoked at, so
`uses: 0xsan7/SCRAM@v0.1.0` installs exactly that build with a verified
checksum. What does not exist is a *moving* `@v1` tag: pinning to one is
the correct default here precisely because the Action executes a
downloaded binary, and a floating tag would make a review gate
non-reproducible. A user who wants to track HEAD can pass the branch ref
and accept that the action refuses it, by design.

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
