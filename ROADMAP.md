# Roadmap

## Product direction

**The decision SCRAM should earn a place in:** a maintainer reviews a pull request,
identifies the dependency finding that changed, and explains the merge or fix
decision to a teammate. The first audience is teams with supported lockfiles,
GitHub Actions and an existing advisory backlog. The CLI and local viewer also
let a reviewer work with the same report outside GitHub.

### Implementation and release order

The first audience is maintainers of GitHub repositories with npm, Python, Go
or Cargo dependencies and an existing advisory backlog. Their first job is to
tell a teammate why a dependency PR should merge, wait for a fix, or be rerun
because evidence is missing. The pilot is the test of demand.

| Priority | What ships | Acceptance evidence |
| --- | --- | --- |
| 0 · Make the review trustworthy | OSV continuation through the last page, retention of successful batches, and checked/partial/unchecked counts in terminal, JSON, PR comments and viewer. Advisory mode preserves a failed verdict while keeping the pilot check nonblocking for policy decisions. | Implementation in this revision. Fixtures cover successful and failed continuation, later batches, cancellation, degraded policy, old reports and the Action’s exit codes and comment. |
| 1 · Qualify a release candidate | Validate a fresh install, v0.2.0 upgrade, version-pinned Action, artifact access and signature verification. Run passing, blocking, advisory and operational-failure jobs on GitHub. Cover same-repository and fork PRs with the documented permission model. Verify the packaged viewer independently of the hosted deployment. | Record exact artifact digests and run links in the release checklist. A reviewer can retrieve the failed gate’s report and open it locally. Record Firefox, Safari and keyboard results. Keep the published stable version available for rollback. |
| 2 · Run a one-week pilot | Invite three maintainers, one repo each. Start with a version-pinned advisory check, then review false positives, coverage warnings and ignored comments with each team before proposing a required check. | Target two maintainers choosing to keep the check enabled. Target four of five observed reviews correctly explaining the verdict, affected component and any evidence gap in under two minutes. If either target is missed, fix the recurring problem before widening scope. |
| 3 · Close evidence gaps from the pilot | Record resolution skips, starting with skipped Python ranges and VCS references. Show affected scopes and incomplete inventory separately from OSV matching. Track advisory-detail and EPSS freshness, add a dated EPSS cache, and evaluate retry latency on real repositories. | Fixture tests distinguish skipped inputs, incomplete matching, missing metadata and stale enrichment. Reviewers can identify which evidence to refresh before merging. |
| 4 · Improve prioritization and distribution | Pilot Go reachability with distinct called, uncalled and unknown outcomes. Add build provenance verification to releases. Consider RubyGems, resolved Maven input or .NET only after pilot demand identifies the next ecosystem. | Validate reachability against fixtures and real projects, verify an artifact’s source and builder, and compare a new inventory with its native package manager before enabling the resolver. |

**How to measure adoption.** Ask participating teams for time to first review,
how often someone changes a merge decision, and which comments they ignore.
Collect those observations by consent. Report files can remain local. If teams
cannot identify a decision the product improved, revisit the review experience
before expanding ecosystem coverage.

**Operational ownership.** The maintainer owns release verification, schema
compatibility and issue triage. Pilot repository owners choose their baseline,
severity threshold and required-check settings. Use the [release checklist](docs/release-readiness.md)
for handoff and the [current limits](LIMITATIONS.md) when evaluating fit.

## Technical backlog

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

**CLI and scan orchestration coverage.** The [November audit](docs/audits/2026-11-21.md)
records a full shuffled race run with 73.1% statement coverage. Continue with
outage, baseline, report export and installed-binary tests.

**Dependency-type fidelity.** Six real npm v1 fixtures resolve successfully.
The earlier assertion that v1 records no dependency flags was incorrect;
the reliability pass corrected it. The public component model currently
exposes direct/transitive classification, not development, optional or peer
scope. Treat those as separate facts; direct does not mean production-only.
The current format limitations are in [LIMITATIONS.md](LIMITATIONS.md).

**`why` and `trend`.** Both run against a real corpus repository. The November audit added mutation checks for directness, unknown paths and trend delta direction.

## Done, and verified

Named here so the list above is read as a remaining-work list rather than
a verdict. The evidence for each is in [docs/STATUS.md](docs/STATUS.md).

The real-world corpus, mutation audit, fuzzing, differential comparison
against syft and grype ([REPRODUCIBILITY.md](REPRODUCIBILITY.md)), benchmarks
([BENCHMARKS.md](BENCHMARKS.md)), release snapshot build and official SBOM
schema checks have recorded evidence. Counts are dated measurements, not a
fixed feature of the project: the [post-release audit](docs/audits/2026-10-12.md)
records 69/69 selected mutations killed and 23 fuzz targets. The November candidate audit records a subsequent 78/78 mutations killed and 23 completed fuzz targets.

## Unverified

The old sections of [docs/STATUS.md](docs/STATUS.md) and
[docs/BLOCKED.md](docs/BLOCKED.md) preserve historical observations. For the
next release, use the explicit gates in [docs/release-readiness.md](docs/release-readiness.md).
Local success and a Cloudflare preview build do not establish that the same
candidate passed all hosted CI jobs or that newly published binaries work.
