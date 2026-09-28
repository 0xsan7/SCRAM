# D30 — npm v1: documented, then the documentation turned out to be wrong

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D30

**Title:** npm v1: documented, then the documentation turned out to be wrong

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

The plan was to document a limitation: SCRAM parses npm lockfileVersion 1 but
has no real npm 6 lockfile in its corpus, so the v1 path has no real-world
coverage. The instruction was explicit about how to handle this -- do not
synthesise a fixture to claim coverage, warn at runtime instead, and log it in
LIMITATIONS.md.

**The warning was written first, claiming no coverage existed.** Then the
instruction's own "grab one opportunistically, but don't block on it" was
tried, and six real v1 lockfiles turned up: mocha 6.2.0/8.0.0/9.0.0,
marked 0.6.0/0.8.0, less 3.13.0, totalling 2.8 MB, all resolving non-empty
(829 to 2,492 components). The limitation as written was no longer true.

**Two ways the search nearly produced a false negative.** The first run
reported 0/20 and looked authoritative. Probing `axios/axios/0.19.0/package.json`
-- a file certain to exist at that tag -- also 404'd, which proved the
network was fine and the URLs were wrong: raw.githubusercontent.com requires
the `v` prefix on tags. With that fixed, 2/20 real hits appeared immediately.
The second: probing tags from before May 2017 returned nothing at all,
because `package-lock.json` did not exist until npm 5. Both are recorded in
`fetch_corpus.py` and asserted by a test, because a search that returns zero
is indistinguishable from a search pointed at the wrong place.

The warning was rewritten to state the real limitation. v1 records no
dependency flags -- v2/v3 carry `dev`, `optional` and `peer` in the `packages`
map, v1 carries nothing -- so SCRAM **cannot distinguish a production
dependency from a development-only one** in a v1 lockfile. The warning says
exactly that, and states its own corpus count, computed at runtime from the
fixtures rather than hardcoded, so the sentence cannot drift into a claim the
corpus does not support.

### A WARNER, because a warning is not a failure

There was no channel for a resolver to say "I read this, but read it with less
confidence" -- `Resolve` returns components or an error, and nothing between
those two states existed. Widening `Resolve` would have given every resolver
a second return value for something only one ever says, so `Warner` is a
separate optional interface.

The distinction that matters: the silent-zero invariant (D26) hard-fails,
because a file SCRAM could not read must not report CLEAN. A coverage warning
never fails a scan -- the components are correct, the caller just deserves to
know how much to trust them. Conflating the two would mean refusing to scan
every legacy repo, which is a much worse product decision than flagging one.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
