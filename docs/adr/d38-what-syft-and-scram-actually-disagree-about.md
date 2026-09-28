# D38 — What syft and SCRAM actually disagree about

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D38

**Title:** What syft and SCRAM actually disagree about

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

The remaining differences are scope, and each was measured rather than
argued. Comparing counts directly would compare two different questions.

### npm: syft reports production only, SCRAM reports everything

nestjs/nest, the largest fixture:

| | components |
|---|---|
| syft | 190 |
| SCRAM (full) | 1,478 |
| SCRAM, non-dev only | 180 |

1,479 of the 1,676 lockfile entries are marked `dev`. syft's
`javascript-lock-cataloger` excludes them by default; SCRAM includes
everything and marks `Direct`.

**Scope-matched, SCRAM's non-dev set is a strict subset of syft's** — every
name syft reported, SCRAM has, plus 10 syft entries carrying version
`UNKNOWN`. Those 10 are npm workspace links (`node_modules/@nestjs/core` is
a `link: true` pointer whose real version lives in `packages/core`); syft
cannot follow them and emits a placeholder. SCRAM reports the actual
version. On a workspace monorepo, syft's placeholders match no package at
OSV and silently find nothing.

The same pattern on vscode and bitwarden: the residual is entirely
platform-specific optional packages (`@esbuild/darwin-arm64`,
`@rollup/rollup-win32-x64`) that syft catalogs and SCRAM's non-dev filter
drops, plus the same workspace-link placeholders.

### PyPI: syft requires exact pins, SCRAM reads ranges

Isolated to a two-line file:

    pendulum==2.1.2     ->  syft: 2 components
    pendulum>=2.1.2     ->  syft: 0 components

SCRAM resolves both, recording the range floor. This is why syft reports
**0** for `prefecthq/prefect` (22 ranged requirements, SCRAM: 22) and
**54** for `home-assistant/core` (SCRAM: 58, the difference being ranged
entries syft drops).

**SCRAM's ranges are a real limitation, not a free win.** A range's floor is
not the installed version: `pendulum>=2.1.2` may well resolve to 3.x
installed. It is the best available from a ranged declaration, and it is
documented in LIMITATIONS.md, but it is not equivalent to syft's exact-pin
reading of a lockfile.

### Go: syft needs the module graph, SCRAM reads checksums

syft reports **0** for both `consul` and `kubernetes` from a bare `go.sum`,
and still 0 when a `go.mod` is added alongside it. Syft's Go cataloger
resolves the module graph rather than reading checksums. SCRAM parses
`go.sum` directly: 309 components for consul, 204 for kubernetes.

This is the clearest place SCRAM is broader, and also the clearest caveat:
`go.sum` records what was downloaded, not what a fresh `go mod tidy` would
select. It cannot see a version that was never fetched.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
