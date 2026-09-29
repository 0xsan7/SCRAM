#!/usr/bin/env python3
"""Record real OSV responses for the known-vulnerable roundtrip test.

The roundtrip requirement in CONTRIBUTING.md says a resolver or vulnerability
matcher must be proven against a real package with a real, currently-open
advisory. This script fetches those responses once and commits them, so the
test runs in CI without depending on api.osv.dev being up or unchanged.

What gets recorded is NOT a hand-written stub. For each ecosystem below, the
real response body is fetched from https://api.osv.dev/v1/query and stored
verbatim, alongside the query that produced it. If a package stops being
vulnerable, the response comes back with no advisories and this script fails
loudly rather than recording an empty fixture that would let a broken lookup
key pass.

Re-run when a recorded package is patched, and update the expected advisory
ids at the same time:

    python3 scripts/record_osv_fixtures.py

It deliberately does not hammer OSV: one request per ecosystem, with a pause.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

OSV = "https://api.osv.dev/v1/query"
OUT = os.path.join(os.path.dirname(__file__), "..", "testdata", "osv")

# One known-vulnerable package per ecosystem OSV indexes.
#
# The Go entry is the regression: the go.mod fallback used to send
# "github.com/gin-gonic/gin" as "gin", which matches nothing. Re-recording is
# how that stays caught.
PROBES = {
    "npm": {"eco": "npm", "name": "lodash", "ver": "4.17.11"},
    "pypi": {"eco": "PyPI", "name": "pyyaml", "ver": "3.13"},
    "cargo": {"eco": "crates.io", "name": "anyhow", "ver": "1.0.100"},
    "go": {"eco": "Go", "name": "github.com/gin-gonic/gin", "ver": "1.6.0"},
}

# How many advisory ids to assert on. Three is enough to catch a partial or
# mis-keyed response without pinning the test to a set that grows monthly.
KEEP = 3


def _ssl_context():
    """Build an SSL context that works on a stock macOS python.

    urllib on some installations has no CA bundle of its own and fails with
    CERTIFICATE_VERIFY_FAILED even though the system trusts the host. The
    recorded fixtures are only ever read back by the test, so falling back to
    an unverified context here is acceptable and is confined to this
    development script -- never to the scanner, which has its own transport.
    Prefer the system store; only widen if it is actually needed.
    """
    for candidate in (
        "/etc/ssl/cert.pem",
        "/private/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
    ):
        if os.path.exists(candidate):
            ctx = ssl.create_default_context(cafile=candidate)
            if candidate:
                return ctx
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    return ssl._create_unverified_context()


def query(eco, name, version):
    body = json.dumps(
        {"package": {"name": name, "ecosystem": eco}, "version": version}
    ).encode()
    req = urllib.request.Request(
        OSV,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60, context=_ssl_context()) as r:
        return r.status, json.loads(r.read())


def main():
    os.makedirs(OUT, exist_ok=True)
    failed = False

    for stem, probe in PROBES.items():
        try:
            status, body = query(probe["eco"], probe["name"], probe["ver"])
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  {stem:6} ERROR {e}", file=sys.stderr)
            failed = True
            continue

        vulns = body.get("vulns", [])
        ids = [v["id"] for v in vulns if "id" in v]
        if status != 200 or not ids:
            print(
                f"  {stem:6} FAIL {probe['name']}@{probe['ver']} returned "
                f"{len(ids)} advisories (HTTP {status}). Pick a package that "
                f"is still vulnerable, or drop the ecosystem with a reason.",
                file=sys.stderr,
            )
            failed = True
            continue

        with open(os.path.join(OUT, f"{stem}.response.json"), "w") as f:
            json.dump(body, f, indent=1, sort_keys=True)
            f.write("\n")

        index = {
            "eco": probe["eco"],
            "name": probe["name"],
            "ver": probe["ver"],
            "count": len(ids),
            "ids": ids[:KEEP],
            "file": stem,
        }
        with open(os.path.join(OUT, f"{stem}.json"), "w") as f:
            json.dump(index, f, indent=2, sort_keys=True)
            f.write("\n")

        print(f"  {stem:6} {probe['eco']:10} {probe['name']}@{probe['ver']}"
              f"  {len(ids)} advisories, asserting {ids[:KEEP]}")
        time.sleep(1)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
