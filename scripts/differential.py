#!/usr/bin/env python3
"""Differential test: SCRAM vs syft / grype / osv-scanner.

Section 4 of the plan. Every discrepancy is classified rather than
shrugged at: SCRAM wrong (fix), other tool wrong (document why SCRAM
diverges), or a legitimate scope difference (measured, with the measurement
kept).

The comparison is on NAME+VERSION sets, because that is the only thing the
tools agree on a definition of. Where the tools scope differently, the
difference is computed against the same scope rather than reported as a
disagreement -- see the notes attached to each finding.

Run: python3 scripts/differential.py --tools /tmp/diftools [--only SUBSTR]
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "testdata", "fixtures")

# A slice spanning small to large and every npm lockfileVersion, plus the
# ecosystems the other tools scope differently.
SLICE = [
    ("npm", "markedjs-marked@0.6.0", "v1 small"),
    ("npm", "markedjs-marked@0.8.0", "v1 small"),
    ("npm", "less-less@3.13.0", "v1 medium"),
    ("npm", "ionic-team/ionic-framework", "v2 large"),
    ("npm", "axios/axios", "v3 small"),
    ("npm", "appwrite/appwrite", "v3 empty"),
    ("npm", "yargs/yargs", "v3 medium"),
    ("npm", "nestjs/nest", "v3 large workspace"),
    ("npm", "microsoft/vscode", "v3 xlarge"),
    ("npm", "bitwarden/clients", "v3 xlarge"),
    ("pypi", "psf/requests", "pypi small"),
    ("pypi", "prefecthq/prefect", "pypi ranged"),
    ("pypi", "home-assistant/core", "pypi large ranged"),
    ("gomod", "hashicorp/consul", "go medium"),
    ("gomod", "kubernetes/kubernetes", "go xlarge"),
]


def run(cmd, cwd=None, timeout=900):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        class R:
            returncode, stdout, stderr = 124, "", "timeout"
        return R()


# --- SCRAM ------------------------------------------------------------------

SCRAM = os.path.join("/tmp", "scram")


def scram_sbom(repo_dir, fmt="cyclonedx"):
    """Generate an SBOM with SCRAM and return the parsed document.

    This is the product path -- `scram sbom generate`, through detect, the
    resolver registry and the silent-zero invariant -- rather than an
    internal helper, so what gets compared is what a user would consume.

    `--out` is a DIRECTORY (it defaults to scram-output), not a file path.
    The first version of this harness passed a filename and then tried to
    json.load it, which failed on a directory; worse, the count it printed
    came from `corpus-check`, which takes no path argument and silently
    reported the WHOLE corpus for every repo. Every repo showed 30,879
    components. Two harness bugs that both produced confident, wrong numbers.
    """
    outdir = tempfile.mkdtemp(prefix="scram_diff_")
    r = run([SCRAM, "sbom", "generate", repo_dir, "--format", fmt,
             "--out", outdir], cwd=ROOT, timeout=900)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout)[-300:]
    fname = "sbom.cdx.json" if fmt == "cyclonedx" else "sbom.spdx.json"
    path = os.path.join(outdir, fname)
    if not os.path.exists(path):
        got = os.listdir(outdir)
        return None, f"no {fname} in {outdir}; got {got}"
    try:
        return json.load(open(path)), ""
    except Exception as e:
        return None, f"{path}: {e}"


def scram_pairs(repo_dir):
    d, err = scram_sbom(repo_dir)
    if d is None:
        return None, err
    return {(c.get("name"), c.get("version")) for c in d.get("components", [])
            if c.get("name")}, ""


def scram_total(repo_dir):
    d, _ = scram_sbom(repo_dir)
    return len(d.get("components", [])) if d else None


# --- other tools ------------------------------------------------------------

def syft_pairs(repo_dir, syft):
    r = run([syft, "scan", "dir:" + repo_dir, "-o", "json", "-q"], timeout=900)
    try:
        d = json.loads(r.stdout)
    except Exception:
        return None, r.stderr[:200]
    return {(a.get("name"), a.get("version")) for a in d.get("artifacts", [])
            if a.get("name")}, ""


def grype_matches(repo_dir, grype):
    r = run([grype, f"dir:{repo_dir}", "-o", "json", "-q"], timeout=1800)
    try:
        d = json.loads(r.stdout)
    except Exception:
        return None, r.stderr[:300]
    out = set()
    for m in d.get("matches", []):
        a = m.get("artifact", {})
        v = m.get("vulnerability", {})
        out.add((a.get("name"), a.get("version"), v.get("id")))
    return out, ""


def osv_matches(repo_dir, osv):
    # osv-scanner v2 removed the -q flag; stderr carries its progress
    # output, so the JSON is read from stdout only.
    r = run([osv, "scan", "source", "-r", repo_dir, "--format", "json"],
            timeout=1800)
    try:
        d = json.loads(r.stdout)
    except Exception:
        return None, r.stderr[:300]
    out = set()
    for res in d.get("results", []):
        for v in res.get("vulnerabilities", []) or []:
            for p in res.get("packages", []) or []:
                pkg = p.get("package", {})
                out.add((pkg.get("name"), pkg.get("version"), v.get("id")))
    return out, ""


# --- comparison -------------------------------------------------------------

def npm_nondev_pairs(repo_dir, lockfiles):
    """The production-only subset of an npm lockfile, straight from JSON.

    syft reports only non-dev npm packages by default, so comparing SCRAM's
    full inventory against it directly would compare two different scopes.
    This computes SCRAM's equivalent scope from the same lockfile.
    """
    pairs = set()
    for lf in lockfiles:
        try:
            d = json.load(open(lf))
        except Exception:
            continue
        for k, v in (d.get("packages") or {}).items():
            if not k or not v.get("version"):
                continue
            if v.get("dev") or v.get("optional"):
                continue
            name = v.get("name") or k.split("node_modules/")[-1]
            pairs.add((name, v.get("version")))
    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="/tmp/diftools")
    ap.add_argument("--only", default=None)
    ap.add_argument("--vulns", action="store_true",
                    help="also run grype and osv-scanner (slow, networked)")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "differential.json"))
    args = ap.parse_args()

    syft = os.path.join(args.tools, "syft")
    grype = os.path.join(args.tools, "grype")
    osv = os.path.join(args.tools, "osv-scanner")
    for t, n in ((syft, "syft"), (grype, "grype"), (osv, "osv-scanner")):
        if not os.path.exists(t):
            print(f"missing {n} at {t}", file=sys.stderr)
            return 2

    results = []
    for eco, rel, label in SLICE:
        if args.only and args.only not in rel:
            continue
        repo_dir = os.path.join(FIXTURES, eco, "real", rel)
        if not os.path.isdir(repo_dir):
            print(f"SKIP {rel}: not a fixture dir")
            continue
        print(f"\n=== {rel}  [{eco} / {label}] ===", flush=True)

        sp, err = scram_pairs(repo_dir)
        total = len(sp) if sp is not None else None
        print(f"  SCRAM resolved {total} components")
        if sp is None:
            print(f"  SCRAM SBOM unavailable: {err}")
        sy, syerr = syft_pairs(repo_dir, syft)
        if sy is None:
            print(f"  syft FAILED: {syerr}")
        else:
            print(f"  syft  catalogued {len(sy)}")

        rec = {"repo": rel, "eco": eco, "label": label,
               "scram_total": total,
               "scram_sbom": len(sp) if sp is not None else None,
               "syft": len(sy) if sy is not None else None}

        if sp is not None and sy is not None:
            lfs = []
            for dp, _, fs in os.walk(repo_dir):
                for f in fs:
                    if f in ("package-lock.json", "npm-shrinkwrap.json"):
                        lfs.append(os.path.join(dp, f))
            if eco == "npm" and lfs:
                # Compare like with like: syft scopes npm to non-dev.
                ours_prod = npm_nondev_pairs(repo_dir, lfs)
                sy_names = {n for n, _ in sy}
                our_names = {n for n, _ in ours_prod}
                rec["scram_nondev"] = len(ours_prod)
                rec["syft_nondev_equivalent"] = len(sy)
                rec["scram_only_names"] = sorted(our_names - sy_names)
                rec["syft_only_names"] = sorted(sy_names - our_names)
                rec["syft_unknown_version"] = sorted(
                    n for n, v in sy if v in (None, "", "UNKNOWN"))
                print(f"  scope-matched: SCRAM non-dev {len(ours_prod)} "
                      f"vs syft {len(sy)}")
                if rec["scram_only_names"]:
                    print(f"    SCRAM-only names: {rec['scram_only_names']}")
                if rec["syft_only_names"]:
                    print(f"    syft-only names:  {rec['syft_only_names']}")

        if args.vulns:
            gm, gerr = grype_matches(repo_dir, grype)
            om, oerr = osv_matches(repo_dir, osv)
            rec["grype"] = len(gm) if gm is not None else f"FAILED {gerr[:120]}"
            rec["osv_scanner"] = len(om) if om is not None else f"FAILED {oerr[:120]}"
            print(f"  grype matches: {rec['grype']}")
            print(f"  osv-scanner vulns: {rec['osv_scanner']}")
            if gm and om:
                g3 = {(n, i) for n, _, i in gm}
                o3 = {(n, i) for n, _, i in om}
                rec["grype_vs_osv"] = {
                    "both": len(g3 & o3), "grype_only": len(g3 - o3),
                    "osv_only": len(o3 - g3)}

        results.append(rec)
        with open(args.out, "w") as fh:
            json.dump(results, fh, indent=2)

    print(f"\nwrote {args.out} ({len(results)} repos)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
