# Roadmap

Ordered by what is missing, with the evidence for each. Every "not
implemented" below is a real limitation with a test or a measurement
behind it, not a placeholder.

## Next release candidate

Finish the existing scanner and browser viewer before expanding the feature
set. The [release-readiness checklist](docs/release-readiness.md) separates
locally verified behavior from browser, hosted-runner and release-artifact
checks that are still outstanding. v0.2.0 remains the published stable release;
the viewer and post-release correctness fixes need a new reviewed release.

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

**A score that can be out of 100.** The presented scale is 0-65, because
that is what the tool can currently measure: severity, plus exploitability
when EPSS is reachable. The formula still computes 0-100 internally, and
the gap is data, not arithmetic. Restoring a 100-point claim needs the
missing terms to actually produce values:

- **Latest-version data for freshness** (15 points). Freshness is
  structurally 0 today because nothing collects a component's latest
  release. This needs a version-source per ecosystem (npm registry,
  PyPI, crates.io, proxy.golang.org), which is a fetch and a cache
  problem rather than a resolver one. Until it exists, freshness cannot
  distinguish "one patch release behind" from "abandoned since 2019".
- **Reliable EPSS coverage** (25 points). Exploitability works and is
  tested; it returns 0 when FIRST.org is unreachable, which is common
  offline and in air-gapped CI. A cached or vendored EPSS feed would make
  the term dependable rather than opportunistic.

Neither is hard; both are new subsystems. The choice made for now was to
present the 65 points the tool can earn rather than the 100 it was
promised, because a denominator that overstates the evidence makes every
score look worse than the measurement justifies.

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

**Version-pinned Action installation.** Resolved. `v0.2.0` is published, and the
Action resolves its release from the ref it is invoked at, so
`uses: 0xsan7/SCRAM@v0.2.0` installs exactly that build with a verified
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

**CLI and scan orchestration coverage.** Measured on preview source `c6c50fe`
on 2026-11-20: CLI 44.9%, scan 60.1%, overall 71.4%, with race detection.
These replace the older 24.5% / 67.0% snapshot as the current local evidence;
they do not establish platform parity. Prioritize real exit-code, baseline,
configuration, outage and output-failure scenarios. See
[release-readiness evidence](docs/release-readiness.md#local-evidence).

**Dependency-type fidelity.** Six real npm v1 fixtures resolve successfully.
The earlier assertion that v1 records no dependency flags was incorrect;
the reliability pass corrected it. The public component model currently
exposes direct/transitive classification, not development, optional or peer
scope. Treat those as separate facts; direct does not mean production-only.
The current format limitations are in [LIMITATIONS.md](LIMITATIONS.md).

**`why` and `trend`.** Both run against a real corpus repository. Neither
has been audited for edge cases the way the resolvers have.

## Done, and verified

Named here so the list above is read as a remaining-work list rather than
a verdict. The evidence for each is in [docs/STATUS.md](docs/STATUS.md).

The real-world corpus, mutation audit, fuzzing, differential comparison
against syft and grype ([REPRODUCIBILITY.md](REPRODUCIBILITY.md)), benchmarks
([BENCHMARKS.md](BENCHMARKS.md)), release snapshot build and official SBOM
schema checks have recorded evidence. Counts are dated measurements, not a
fixed feature of the project: the [post-release audit](docs/audits/2026-10-12.md)
records 69/69 selected mutations killed and 23 fuzz targets. Those expensive
checks have not been rerun on the viewer candidate by the local check below.

## Unverified

The old sections of [docs/STATUS.md](docs/STATUS.md) and
[docs/BLOCKED.md](docs/BLOCKED.md) preserve historical observations. For the
next release, use the explicit gates in [docs/release-readiness.md](docs/release-readiness.md).
Local success and a Cloudflare preview build do not establish that the same
candidate passed all hosted CI jobs or that newly published binaries work.
