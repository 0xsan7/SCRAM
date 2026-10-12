# HANDOFF — SCRAM release resumed 2026-10-12

The user authorized fully releasing the project on 2026-10-12, including
rc1 validation and stable v0.2.0 publication. The former pause and rc1-only
restriction are superseded by that authorization.

Release validation is in progress. On resuming, remote main was `078a48f`.
Its original push CI was green, but scheduled fuzzing had since exposed the
malformed Go module path issue recorded in D48. That issue is fixed with a
regression seed and mutation check. No v0.2 tag existed when work resumed.

Next: confirm CI on the release preparation commit, cut v0.2.0-rc1, verify
all five binaries and keyless signing identities, test the Action on push
and unchanged/new-finding PRs with the /65 comment, then publish and verify
stable v0.2.0. Update this handoff with the final evidence and status.

Keep all existing releases and branches. Never force-push or rewrite
history. Run gitleaks v8.30.1 with
`detect --source=. --log-opts=--all --redact` before each push; the planted
positive control was confirmed to fail on resuming.

SLSA build attestations and the other ROADMAP.md items remain future work.
The current signature verification proves the workflow/tag identity and
Rekor inclusion; it must not be described as a SLSA build attestation.

The grype alias question is closed in D46; remaining differences are
OSV-confirmed advisories absent from grype's database. See TESTING.md for
the standing test requirements and known limits.
