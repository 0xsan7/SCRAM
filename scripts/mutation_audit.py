#!/usr/bin/env python3
"""Mutation audit: does the test suite actually catch each fix being reverted?

The project's own rule (TESTING.md) is that a guard which cannot fail is
worse than no guard. That applies to the tests themselves, so every fix
logged in DECISIONS.md is re-broken here and the suite is re-run.

Each mutant reverts ONE real fix. A mutant that leaves the suite green is a
vacuous test somewhere: either the fix is untested, or the test asserting it
does not actually exercise the code path it names.

Run: python3 scripts/mutation_audit.py [--jobs N] [--only NAME]
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Each mutant: (id, file, find, replace, which packages must fail)
# `find` must be present verbatim in the file, or the mutant is a no-op and
# is reported as BROKEN rather than silently passing.
MUTANTS = [
    # --- D01: npm v3 top-level "requires": true unmarshalled as a map -----
    ("D01-requires-bool", "internal/resolve/npm.go",
     "\tRequiresTrue bool `json:\"requires\"`",
     "\tRequiresTrue map[string]any `json:\"requires\"`",
     ["internal/resolve"]),

    # --- D22: array-valued npm license (nestjs/nest) ----------------------
    ("D22-license-array", "internal/resolve/npm.go",
     '*f = flexString(strings.Join(nonEmpty(arr), " OR "))',
     '*f = flexString(arr[0])',
     ["internal/resolve"]),

    # --- D23: PyPI ranged requirements silently dropped --------------------
    ("D23-py-range", "internal/resolve/pypi.go",
     "ver := specifierVersion(rest)",
     "ver := \"\"",
     ["internal/resolve"]),

    # --- D26: the silent-zero invariant ------------------------------------
    ("D26-silent-zero", "internal/resolve/resolve.go",
     "if n := declaredDependencies(full); n > 0 {",
     "if n := declaredDependencies(full); n > 0 && false {",
     ["internal/resolve", "internal/scan", "internal/cli"]),

    # --- D26: declaredDependencies TOML branch counted every line ----------
    ("D26-toml-counter", "internal/resolve/resolve.go",
     'case "pyproject.toml":',
     'case "pyproject.tomlDISABLED":',
     ["internal/resolve"]),

    # --- D27: python interpreter constraint is not a package ---------------
    ("D27-python-key", "internal/resolve/pyproject.go",
     "if isPythonConstraintKey(name) {",
     "if false && isPythonConstraintKey(name) {",
     ["internal/resolve"]),

    # --- D27: PEP 621 array branch -----------------------------------------
    ("D27-pep621", "internal/resolve/pyproject.go",
     "for _, c := range pep621Dependencies(doc) {",
     "for _, c := range []model.Component{} {",
     ["internal/resolve"]),

    # --- D28: registry replacement (two resolvers, one slot) ---------------
    ("D28-registry", "internal/resolve/resolve.go",
     "registry[r.Ecosystem()] = append(registry[r.Ecosystem()], r)",
     "registry[r.Ecosystem()] = []Resolver{r}",
     ["internal/resolve", "internal/scan"]),

    # --- D29: dispatch precedence ------------------------------------------
    ("D29-precedence", "internal/resolve/resolve.go",
     "if bestClaim == -1 || priorityOf(r) > priorityOf(rs[bestClaim]) {",
     "if bestClaim == -1 {",
     ["internal/resolve"]),

    # --- D30: npm v1 coverage warning --------------------------------------
    ("D30-v1-warning", "internal/resolve/npm.go",
     "if probe.LockfileVersion != nil && *probe.LockfileVersion > 1 {",
     "if probe.LockfileVersion != nil && *probe.LockfileVersion > 99 {",
     ["internal/resolve"]),

    # --- score: severity weighting ------------------------------------------
    ("SCORE-bucket-escalation", "internal/score/score.go",
     "if counts[model.BucketCritical] >= 1 || counts[model.BucketHigh] >= 10 {",
     "if counts[model.BucketCritical] >= 99 {",
     ["internal/score"]),

    # --- drift: new-component detection -------------------------------------
    ("DRIFT-added", "internal/drift/drift.go",
     "Change:     model.ChangeAdded,",
     "Change:     model.ChangeUnchanged,",
     ["internal/drift"]),

    # --- policy: fail-on threshold -----------------------------------------
    ("POLICY-threshold", "internal/policy/policy.go",
     'FailOn:  "high",',
     'FailOn:  "none",',
     ["internal/policy"]),

    # --- waiver expiry ------------------------------------------------------
    ("WAIVER-expiry", "internal/policy/policy.go",
     "if now.Before(*w.Expires) {",
     "if false {",
     ["internal/policy"]),

    # --- dedupe: alias-linked collapse (the wiring bug) ---------------------
    ("DEDUPE-alias", "internal/vuln/dedupe.go",
     "for _, a := range v.Aliases {",
     "for _, a := range []string(nil) {",
     ["internal/vuln"]),

    # --- CVSS scope ---------------------------------------------------------
    ("CVSS-scope", "internal/vuln/osv.go",
     "scopeWeight = 0.914",
     "scopeWeight = 1.0",
     ["internal/vuln"]),

    # --- A2: OpenSSF Scorecard maintenance term ---------------------------
    # Reverting the integration must be caught, not merely noticed.
    #
    # M-SCORE-MAINT-STUB restores the original hardcoded 0, which is the
    # exact state the term was in before this work.
    ("A2-maint-stubbed", "internal/score/score.go",
     "\treturn clamp(int(math.Round(v/10*float64(model.MaxMaintenancePoints))), 0, model.MaxMaintenancePoints)",
     "\t_ = v\n\treturn 0",
     ["internal/score"]),

    # Counting an inapplicable (-1) check as a zero would drag the average
    # down. NewResult drops them; this mutant puts them back.
    ("A2-inapplicable-averaged", "internal/scorecard/scorecard.go",
     "\t\tif c.Score < 0 {\n\t\t\tout.Inapplicable++\n\t\t\tcontinue\n\t\t}",
     "\t\tif c.Score < 0 {\n\t\t\tout.Inapplicable++\n\t\t}",
     ["internal/scorecard"]),

    # A project with no usable checks must contribute nothing rather than
    # being scaled from a meaningless aggregate of 0.
    ("A2-all-inapplicable-scales", "internal/score/score.go",
     "\tif e.maintenanceChecks == 0 {\n\t\treturn 0\n\t}",
     "\tif false {\n\t\treturn 0\n\t}",
     ["internal/score"]),

    # A 404 from the API must be a distinct "not scored" state, not a
    # silently swallowed error and not a zero score.
    ("A2-unscored-is-zero", "internal/scorecard/scorecard.go",
     "\tif resp.StatusCode == http.StatusNotFound {\n\t\treturn nil, &ErrNotScored{Repo: name}\n\t}",
     "\tif resp.StatusCode == http.StatusNotFound {\n\t\treturn &Result{}, nil\n\t}",
     ["internal/scorecard"]),

    # A 200 carrying no checks is a broken response; accepting it is the
    # silent-zero failure mode this project already has three instances of.
    ("A2-empty-checks-accepted", "internal/scorecard/scorecard.go",
     "\tif len(payload.Checks) == 0 {\n\t\treturn nil, fmt.Errorf(\"scorecard: %s: response contained no checks\", name)\n\t}",
     "\tif false {\n\t\treturn nil, nil\n\t}",
     ["internal/scorecard"]),
    # --- B1/B3: yarn, pnpm and cargo resolvers ---------------------
    # Each reverts a new resolver to the state that makes it inventory
    # nothing. The silent-zero invariant must catch that, or a real project
    # on that lockfile reports a clean scan.
    ("B1-yarn-returns-nothing", "internal/resolve/yarn.go",
     "func parseYarnLock(s string) []yarnEntry {",
     "func parseYarnLock(s string) []yarnEntry {\n\treturn nil",
     ["internal/resolve"]),
    ("B1-pnpm-returns-nothing", "internal/resolve/pnpm.go",
     "func parsePnpmLock(s string) []pnpmPackage {",
     "func parsePnpmLock(s string) []pnpmPackage {\n\treturn nil",
     ["internal/resolve"]),
    ("B3-cargo-returns-nothing", "internal/resolve/cargo.go",
     "func parseCargoLock(s string) []cargoPackage {",
     "func parseCargoLock(s string) []cargoPackage {\n\treturn nil",
     ["internal/resolve"]),
    # The pnpm key-format split. Before this fix, LastIndex("@") was applied
    # to a v9 `snapshots` key carrying a peer context, producing a component
    # named "@ai-sdk/anthropic@3.0.58(zod" at version "4.1.12" --
    # inventoried, never matched, and looking perfectly fine.
    ("B1-pnpm-peer-suffix-not-stripped", "internal/resolve/pnpm.go",
     "\t\tbase := stripPnpmPeerSuffix(key)",
     "\t\tbase := key",
     ["internal/resolve"]),
    # The yarn key splitter that tracks quote state. A naive comma split left
    # a leading quote on every scoped package in a Berry lockfile, and the
    # PURL it produced matched no OSV advisory that exists.
    ("B1-yarn-key-split-ignores-quotes", "internal/resolve/yarn.go",
     "\tif strings.Contains(key, `\"`) {",
     "\tif false {",
     ["internal/resolve"]),
    # The pnpm v5 slash-key scope. A SCOPED name makes the key three
    # segments, so parts[len-2] dropped the scope and the component was
    # filed under a name that does not exist.
    ("B1-pnpm-v5-scope-dropped", "internal/resolve/pnpm.go",
     "\tname := strings.Join(parts[:len(parts)-1], \"/\")",
     "\tname := parts[len(parts)-2]",
     ["internal/resolve"]),

    # --- B2: the go.mod fallback --------------------------------
    # The silent-zero failure itself: no go.sum, no inventory.
    ("B2-gomod-fallback-returns-nothing", "internal/resolve/golang.go",
     "\t\t\tif len(out) > 0 {\n\t\t\t\treturn out, nil\n\t\t\t}",
     "\t\t\tif false {\n\t\t\t\treturn out, nil\n\t\t\t}",
     ["internal/resolve"]),
    # The validation rule that rejected 467 of trivy's 472 requires: it
    # required the dot in the LAST path segment rather than the host.
    ("B2-gomod-host-dot-check", "internal/resolve/golang.go",
     "\thost := segments[0]\n\tdot := strings.Index(host, \".\")",
     "\thost := segments[len(segments)-1]\n\tdot := strings.Index(host, \".\")",
     ["internal/resolve"]),
    # The directive/comment filter, without which `go 1.24` and
    # `replace` lines become dependencies.
    # The `require` keyword is optional in the regex, so this line
    # distinguishes the single-line form from a bare path+version. Without
    # it, only `require x v1.0.0` is found and every requirement inside a
    # require ( ... ) block is missed.
    ("B2-gomod-require-keyword-required", "internal/resolve/golang.go",
     "^\\s*(?:require\\s+)?(\\S+)\\s+(v[0-9][\\w.\\-+]*)",
     "^\\s*(?:require\\s+)(\\S+)\\s+(v[0-9][\\w.\\-+]*)",
     ["internal/resolve"]),
    # --- C: the presented scale ----------------------------------
    # Presented() rescales onto 0-65. Removing it means the tool divides
    # by a denominator it cannot earn, which is the whole defect.
    ("C-presented-is-identity", "internal/score/score.go",
     "\tscaled := (total*model.PresentedMax + model.MaxScore/2) / model.MaxScore",
     "\tscaled := total",
     ["internal/score"]),
    # The clamp: without it a score above 65 prints as "66/65", a badge
    # claiming 101% of the maximum.
    ("C-presented-not-clamped", "internal/score/score.go",
     "\tif scaled > model.PresentedMax {\n\t\treturn model.PresentedMax\n\t}",
     "\tif false {\n\t\treturn model.PresentedMax\n\t}",
     ["internal/score"]),
    # The badge clamp, which is the last line of defence for a document
    # this tool does not control.
    ("C-badge-not-clamped", "internal/badge/badge.go",
     "\tif v > model.PresentedMax {\n\t\treturn model.PresentedMax\n\t}",
     "\tif false {\n\t\treturn model.PresentedMax\n\t}",
     ["internal/badge"]),
    # BucketForCVSS must keep the CVSS boundaries. Folding it back into
    # the presented scale would report a 9.8 critical as "high" in the two
    # call sites that decide whether a PR fails.
    ("C-cvss-uses-presented-buckets", "internal/score/score.go",
     "\tcase cvssTimesTen >= 90:",
     "\tcase cvssTimesTen >= criticalBucketMin:",
     ["internal/score"]),
    # --- the pnpm generation boundary at 6.0 --------------------
    # pnpm 6.0 is slash-PREFIXED but @-delimited, the only generation
    # that is both. Treating it as a 5.x file drops most of the
    # dependency tree: 361 components instead of 1523 from a real
    # pnpm 7 repository, with no error raised.
    ("B1-pnpm-6.0-treated-as-5.x", "internal/resolve/pnpm.go",
     "\t\tcase \"6\":",
     "\t\tcase \"never6\":",
     ["internal/resolve"]),
    # And the leading slash on a 6.0 key, which without stripping
    # leaves a "/" in the package name and builds a PURL that matches
    # nothing.
    ("B1-pnpm-6.0-leading-slash-kept", "internal/resolve/pnpm.go",
     "\t\tbase = strings.TrimPrefix(base, \"/\")",
     "\t\tbase = base",
     ["internal/resolve"]),
]


def run(cmd, cwd, timeout=600, env=None):
    return subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                          text=True, timeout=timeout, env=env)


def check_mutant(m, base, go_bin):
    """Apply one mutant to a real clone and see whether tests catch it.

    The mutant must be applied to a COMPLETE working tree. An earlier version
    copied the single mutated file into an empty temp directory and ran `go
    test` there, which has no go.mod and no package: every run failed to
    build, and the failure was then read as "no package failed" ->
    SURVIVED. Four mutants were reported as untested fixes when in fact the
    suite catches all of them. A harness that cannot tell a build error from
    a passing test is the same failure as a test that cannot fail.
    """
    mid, rel, find, repl, pkgs = m
    src_path = os.path.join(base, rel)
    if not os.path.exists(src_path):
        return {"id": mid, "status": "BROKEN", "why": f"{rel} missing"}
    src = open(src_path).read()
    if find not in src:
        return {"id": mid, "status": "BROKEN",
                "why": f"anchor not found in {rel}: {find[:60]!r}"}
    if find == repl:
        return {"id": mid, "status": "BROKEN", "why": "mutant is a no-op"}

    work = os.path.join(base, "m_" + mid)
    if os.path.exists(work):
        shutil.rmtree(work, ignore_errors=True)
    # Each mutant directory must be excluded: without this, copying `base`
    # into a subdirectory of `base` nests every other mutant inside this one,
    # and the run dies on recursive growth.
    shutil.copytree(base, work, symlinks=True,
                    ignore=shutil.ignore_patterns("*.pyc", "__pycache__", "m_*"))
    dest = os.path.join(work, rel)
    open(dest, "w").write(src.replace(find, repl, 1))

    env = os.environ.copy()
    env["PATH"] = go_bin + os.pathsep + env.get("PATH", "")
    try:
        failed, broken_build = [], []
        for pkg in pkgs:
            r = run(f"go test ./{pkg}/ -count=1", work, timeout=900, env=env)
            if r.returncode == 0:
                continue
            # A build failure is NOT evidence the mutant was caught: the
            # mutant may simply not compile, which says nothing about
            # whether a test guards the behaviour.
            if "build failed" in r.stdout or "cannot use" in r.stdout \
                    or "undefined:" in r.stdout:
                broken_build.append(pkg)
            else:
                failed.append(pkg)
        if failed:
            return {"id": mid, "status": "killed",
                    "why": f"caught by {' '.join(failed)}"}
        if broken_build:
            return {"id": mid, "status": "INVALID",
                    "why": f"mutant does not compile in {' '.join(broken_build)}; " +
                           "pick an anchor that changes behaviour, not syntax"}
        return {"id": mid, "status": "SURVIVED",
                "why": f"reverting this fix left {' '.join(pkgs)} green"}
    except subprocess.TimeoutExpired:
        return {"id": mid, "status": "BROKEN", "why": "go test timed out"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", default=None)
    args = ap.parse_args()

    go_bin = os.path.expanduser("~/.local/go/bin")
    base = tempfile.mkdtemp(prefix="mutation_audit_")
    # A full worktree copy is far too slow per mutant; instead hardlink-clone
    # the repo so each mutant gets its own tree cheaply.
    work = os.path.join(base, "repo")
    # Copy the WORKING TREE, not `git clone`: a clone tests HEAD, which
    # silently excludes any fix not yet committed. That produced a false
    # SURVIVED for the score escalation right after it was fixed.
    shutil.copytree(ROOT, work, symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__",
                                                  "m_*", "*.json.bak"))

    muts = [m for m in MUTANTS if not args.only or args.only in m[0]]
    print(f"running {len(muts)} mutants against {len(MUTANTS)} declared\n")
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(check_mutant, m, work, go_bin): m[0] for m in muts}
        for fut in cf.as_completed(futs):
            res = fut.result()
            results.append(res)
            mark = {"killed": "KILLED  ", "SURVIVED": "SURVIVED",
                    "BROKEN": "BROKEN  ", "INVALID": "INVALID "}[res["status"]]
            print(f"  {mark} {res['id']:22} {res['why']}")

    results.sort(key=lambda r: r["id"])
    killed = [r for r in results if r["status"] == "killed"]
    survived = [r for r in results if r["status"] == "SURVIVED"]
    broken = [r for r in results if r["status"] == "BROKEN"]
    invalid = [r for r in results if r["status"] == "INVALID"]
    print(f"\nkilled {len(killed)}  survived {len(survived)}  "
          f"invalid {len(invalid)}  broken {len(broken)}")
    if survived:
        print("\nSURVIVORS (each is a vacuous test, or an untested fix):")
        for r in survived:
            print(f"  - {r['id']}: {r['why']}")
    if invalid:
        print("\nINVALID (the mutant does not compile; it is not a behaviour test):")
        for r in invalid:
            print(f"  - {r['id']}: {r['why']}")
    if broken:
        print("\nBROKEN (the anchor moved; the mutant no longer represents its fix):")
        for r in broken:
            print(f"  - {r['id']}: {r['why']}")
    with open(os.path.join(ROOT, "scripts", "mutation_results.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    shutil.rmtree(base, ignore_errors=True)
    return 0 if not survived and not broken else 1


if __name__ == "__main__":
    sys.exit(main())
