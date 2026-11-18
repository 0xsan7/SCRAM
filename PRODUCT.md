# SCRAM

<!-- impeccable:product-schema 1 -->

## Platform

web

The browser report viewer complements the existing Go command-line scanner.

## Stack

Existing scanner: Go. Implementation choice for the approved browser-local
viewer: static HTML, CSS and JavaScript modules, with Node's standard library
for checks/packaging. No frontend framework or runtime dependency is needed.

## Users

Maintainers reviewing dependency changes and portfolio visitors evaluating
SCRAM's behavior. They need to distinguish a policy outcome from the evidence
and limitations behind it.

## Product Purpose

Open a bundled example or local SCRAM JSON report; inspect the policy result,
warnings, dependency inventory and new/resolved findings without installing
the scanner or sending the report to a server.

## Capabilities and Constraints

- Consume the existing versioned JSON format and preserve scanner semantics.
- A passed policy can contain existing vulnerabilities. Zero known findings
  cannot establish completeness or safety.
- Warnings/failure reasons remain prominent. Missing evidence stays unknown.
- No upload endpoint, public scan service, account, live model call or
  automatic advisory request. File-picker and drop imports stay in the browser;
  the optional CLI viewer serves an explicitly selected file on loopback only.
- Prepare responsive keyboard-usable layouts, native file selection, clear
  errors and safe text rendering for untrusted report strings.
- The user authorizes pushing ready, verified commits to GitHub. Merging,
  public deployment and DNS changes remain separate review decisions.
- Future proposed subdomain: scram.0xsan7.in. The root portfolio stays unchanged.

## Brand Commitments

The user selected a dark interface matching the portfolio. Keep the SCRAM
name and an evidence-focused voice. Use existing portfolio font assets with
their license notices where available. Detailed composition is an
implementation choice within this approved direction.

## Evidence on Hand

Four synthetic reports in examples/report-viewer/fixtures are generated and
checked against the production score, drift, policy and JSON writer. They
demonstrate an existing finding that passes policy, a newly disclosed finding
that fails policy and incomplete data with zero known findings. These are
synthetic demonstrations, not live observations. The fourth supports a full
review of six dependencies across four ecosystems. The implementation brief is
examples/report-viewer/README.md.

## Product Principles

- Explain the result before presenting a score.
- Keep report contents and provenance distinguishable.
- Never turn missing data into a successful assessment.
- Preserve the scanner's semantics and minimize dependencies.
