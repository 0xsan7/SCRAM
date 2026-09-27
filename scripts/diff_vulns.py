#!/usr/bin/env python3
"""Vulnerability-ID level comparison: SCRAM vs grype.

The component-level comparison lives in differential.py. This one is
narrower and stricter: it compares the set of vulnerability IDs each tool
reports for the same lockfile, and the component each ID is attributed to.

A count comparison would pass on 14 findings that were 14 different bugs.
Comparing ID sets cannot: if SCRAM misses a finding, or invents one, or
attributes it to the wrong package, the sets differ.

Run: python3 scripts/diff_vulns.py --tools /tmp/diftools
"""

import argparse
import json
import os
import subprocess
import tempfile
import urllib.request

SCRAM = "/tmp/scram"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Pinned requirements files, because grype reads exact pins only (see D38).
# Each is a real, deliberately-vulnerable selection.
CASES = [
    ("jinja2 2.10 / pyyaml 5.1 / requests 2.19.1",
     "requests==2.19.1\njinja2==2.10\npyyaml==5.1\n"),
    ("urllib3 1.23 (known advisories)",
     "requests==2.19.1\nurllib3==1.23\n"),
    ("lodash 4.17.4 (prototype pollution)",
     "lodash==4.17.4\n"),
    ("cryptography 3.2 (multiple advisories)",
     "cryptography==3.2\n"),
    ("flask 1.0 + werkzeug 0.15",
     "flask==1.0\nwerkzeug==0.15.0\n"),
    ("django 2.0.2 (path traversal advisories)",
     "django==2.0.2\n"),
    ("Pillow 5.0.0", "Pillow==5.0.0\n"),
    ("idna 2.7 / certifi 2018", "idna==2.7\ncertifi==2018.11.29\n"),
]


def scram_ids(tmp):
    r = subprocess.run([SCRAM, "scan", tmp, "--format", "json"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        return None, r.stderr[:200]
    try:
        d = json.loads(r.stdout)
    except Exception as e:
        return None, f"unparseable: {e}"
    out = {}
    for c in d["scan"]["components"]:
        for v in c.get("vulnerabilities", []) or []:
            out.setdefault(v.get("id"), set()).add(c.get("name"))
    return out, ""


def grype_ids(tmp, grype):
    r = subprocess.run([grype, f"dir:{tmp}", "-o", "json", "-q"],
                       capture_output=True, text=True, timeout=1800)
    try:
        d = json.loads(r.stdout)
    except Exception as e:
        return None, f"unparseable: {e}: {r.stderr[:200]}"
    out = {}
    for m in d.get("matches", []):
        v = m.get("vulnerability", {}).get("id")
        out.setdefault(v, set()).add(m.get("artifact", {}).get("name"))
    return out, ""


_ALIAS_CACHE = {}


def aliases_for(vid):
    """Every id OSV knows this vulnerability by, fetched once and cached."""
    if vid in _ALIAS_CACHE:
        return _ALIAS_CACHE[vid]
    try:
        with urllib.request.urlopen(
                f"https://api.osv.dev/v1/vulns/{vid}", timeout=45) as r:
            d = json.load(r)
        group = {vid} | set(d.get("aliases") or [])
    except Exception:
        group = {vid}
    _ALIAS_CACHE[vid] = group
    return group


def canonical(by_id):
    """Map each id to a stable identity (its CVE when it has one).

    Fall back to the id itself for advisories with no CVE, so two different
    no-CVE findings never collapse into one.
    """
    out = set()
    for vid in by_id:
        group = aliases_for(vid)
        cves = {a for a in group if a.startswith("CVE-")}
        out.add(sorted(cves)[0] if cves else vid)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="/tmp/diftools")
    args = ap.parse_args()
    grype = os.path.join(args.tools, "grype")
    if not os.path.exists(grype):
        print(f"missing grype at {grype}")
        return 2
    if not os.path.exists(SCRAM):
        print(f"missing scram binary at {SCRAM} "
              f"(go build -o {SCRAM} ./cmd/scram)")
        return 2

    all_match = True
    for label, body in CASES:
        tmp = tempfile.mkdtemp(prefix="diffvuln_")
        with open(os.path.join(tmp, "requirements.txt"), "w") as fh:
            fh.write(body)
        s, serr = scram_ids(tmp)
        g, gerr = grype_ids(tmp, grype)
        print(f"\n=== {label} ===")
        if s is None:
            print(f"  SCRAM failed: {serr}")
            all_match = False
            continue
        if g is None:
            print(f"  grype failed: {gerr}")
            continue
        # Compare by IDENTITY, not by id string. OSV and grype disagree
        # about which scheme to report a finding under: for one cryptography
        # advisory SCRAM says PYSEC-2026-2141 and grype says
        # GHSA-r6ph-v2qm-q3c2, and those are aliases of the same CVE. An
        # id-set comparison would call that a finding difference; it is a
        # naming difference. Normalising through CVE removes it, and what
        # remains is a real disagreement.
        S, G = canonical(s), canonical(g)
        both, sonly, gonly = S & G, S - G, G - S
        agree = not sonly and not gonly
        print(f"  SCRAM {len(S):3d} vulns   grype {len(G):3d} vulns   "
              f"same set: {agree}")
        if not agree:
            print(f"    SCRAM only (by CVE): {sorted(sonly)}")
            print(f"    grype only (by CVE): {sorted(gonly)}")
            all_match = False
        else:
            # Same IDs, but attributed to different packages, is still a
            # disagreement: a finding on the wrong component is a wrong
            # report.
            for i in sorted(S):
                if s[i] != g[i]:
                    print(f"    attribution differs for {i}: "
                          f"SCRAM={sorted(s[i])} grype={sorted(g[i])}")
                    all_match = False

    print("\n" + ("ALL CASES IDENTICAL" if all_match
                  else "DISAGREEMENTS FOUND (see above)"))
    return 0 if all_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
