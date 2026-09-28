# D37 — syft found a bug SCRAM's own corpus could not

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D37

**Title:** syft found a bug SCRAM's own corpus could not

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Section 4 of the plan: validate against the tools already trusted in
production. Installed syft 1.52.0, grype 0.119.0 and osv-scanner 2.6.0
(darwin/arm64; osv-scanner's SHA256 verified against the release's
`osv-scanner_SHA256SUMS`), and ran SCRAM's SBOM generator against syft's
cataloger over 15 real corpus repos spanning every npm lockfileVersion and
all three ecosystems.

**syft reported 0 components for `psf/requests`. SCRAM agreed: 0, CLEAN,
exit 0.**

requests' only Python file is a `requirements-dev.txt` declaring five
packages. It had been invisible to SCRAM since the beginning.

### Three layers, three lists, two of them wrong

The filename existed in three places, and they disagreed:

| layer | claimed | actually read |
|---|---|---|
| `detect.candidates` | `requirements.txt` only | `requirements.txt` |
| `pypiResolver.Handles` | 15 names | — (dispatch only) |
| `pypiResolver.Resolve` | 3 names | 3 names |

`GetFor` correctly routed `requirements-dev.txt` to the pypi resolver, which
then rejected it with `ErrUnsupported`. And because the DETECTOR never
listed it, no resolver call happened at all — which is why **the D26
silent-zero invariant could not catch it.** There was no resolver to return
zero from. A guard that fires on the wrong layer is not a guard.

**The worst part:** the file is in SCRAM's own corpus. 86 real lockfiles,
run through a property test asserting "manifest detected → non-zero
components" — and it passed, because the file was never detected. Every
test asserted a property of a file the code had already decided did not
exist.

After the fix: **6 components, 3 real vulnerability findings, score 30/100
LOW**, where it had reported CLEAN with exit 0.

### Three changes, because one would leave it half-fixed

1. `detect.candidates` lists all fifteen requirements filenames, most
   specific first (only the first hit per ecosystem per directory is used,
   so this is a fallback chain — a lockfile still wins).
2. `pypiResolver.Resolve` no longer switches on its own hardcoded list; it
   branches on `Handles`, so there is no fourth list to drift.
3. `TestDetectorAndResolverAgreeOnFilenames` compares the two lists in both
   directions and fails if either claims something the other does not.

**The new test immediately failed**, catching `requirements-prod.dev.txt` —
a name the resolver claimed and nobody had listed. Fixing the detector by
hand would have missed it; the cross-check found it in one run.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
