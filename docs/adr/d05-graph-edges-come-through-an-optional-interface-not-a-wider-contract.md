# D05 — Graph edges come through an optional interface, not a wider contract

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D05

**Title:** Graph edges come through an optional interface, not a wider contract

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

`scram why` needs parentage, but widening `resolve.Resolver` would force every
ecosystem to supply edges it cannot. Instead the npm resolver implements an
optional `graph.EdgeProvider`; the graph builder type-asserts for it.

A new ecosystem therefore gets `why` and `blame` for free if it implements the
interface, and is silently treated as a flat tree if it does not — which is
honest, since most lockfile formats genuinely do not record parentage.

Edge endpoints are resolved against the component list and dropped when they
do not match, so the graph can never name a component the SBOM omitted.

---

### Established testing standard for this project

Carried over from previous work and enforced here without exception:

- An acceptance criterion is not satisfied until it has been executed end to
  end with real inputs. A tool appearing in a list, a handler existing, or a
  test that never calls the thing it names does not count.
- A test that does not call the thing it is named for is not a test of it. A
  test that cannot fail is worse than no test, because it is counted.
- Before trusting a new guard, break the code it guards and confirm it goes
  red.

Every bug in D01 and D02 was found by running the feature against real data,
not by reading the code. All of them would have passed a suite that only
checked the tool was registered.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
