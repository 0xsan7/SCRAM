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
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SCRAM = "/tmp/scram"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Pinned requirements files, because grype reads exact pins only (see D38).
# Each is a real, deliberately-vulnerable selection.
# (label, body, filename). The filename defaults to requirements.txt, which
# is what every PyPI case uses; the non-PyPI cases name a real lockfile so a
# real resolver is exercised end to end rather than a hand-built one.
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
    # The three ecosystems added at v0.2.0, at advisory ID level. Before
    # these, the ID-level comparison was PyPI-only, which meant the new
    # resolvers had component-count coverage against syft but no check that
    # the advisories they report are the right ones.
    #
    # Small enough to read by eye, and each contains a package with known,
    # open advisories at the pinned version.
    ("npm: lodash 4.17.11 (5 known advisories)",
     json.dumps({
         "name": "probe", "version": "1.0.0", "lockfileVersion": 3,
         "requires": True,
         "packages": {
             "": {"name": "probe", "version": "1.0.0"},
             "node_modules/lodash": {"version": "4.17.11"},
         },
     }, indent=2), "package-lock.json"),
    ("yarn v1: lodash 4.17.11",
     "# yarn lockfile v1\n\n"
     'lodash@^4.17.11:\n  version "4.17.11"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.11.tgz"\n',
     "yarn.lock"),
    ("pnpm 5.4: lodash 4.17.11",
     "lockfileVersion: 5.4\n\nspecifiers:\n  lodash: 4.17.11\n\n"
     "packages:\n\n  /lodash/4.17.11:\n"
     "    resolution: {integrity: sha512-abc}\n    dev: false\n",
     "pnpm-lock.yaml"),
    ("pnpm 9.0: lodash 4.17.11",
     "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n"
     "    dependencies:\n      lodash:\n        specifier: 4.17.11\n"
     "        version: 4.17.11\n\npackages:\n\n  lodash@4.17.11:\n"
     "    resolution: {integrity: sha512-abc}\n\nsnapshots:\n\n"
     "  lodash@4.17.11: {}\n",
     "pnpm-lock.yaml"),
    ("cargo: lodash-equivalent with a known advisory",
     '[[package]]\nname = "probe"\nversion = "0.1.0"\n\n[[package]]\n'
     'name = "smallvec"\nversion = "0.6.13"\n'
     'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
     "Cargo.lock"),

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


def _ssl_context():
    """An SSL context that works on a stock macOS python.

    urllib here has no CA bundle of its own and fails with
    CERTIFICATE_VERIFY_FAILED against api.osv.dev even though the system
    trusts it. The system store is used when present; if none is found the
    context falls back to unverified rather than failing, because this is a
    development harness reading public advisory data. The scanner itself
    has its own transport and is unaffected.
    """
    for candidate in ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem",
                      "/etc/ssl/certs/ca-certificates.crt"):
        if os.path.exists(candidate):
            return ssl.create_default_context(cafile=candidate)
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    return ssl._create_unverified_context()


_ALIAS_CACHE = {}
_ALIAS_CACHE_PATH = os.path.join(
    os.environ.get("TMPDIR", "/tmp"), "scram-osv-alias-cache.json")


def _load_alias_cache():
    try:
        with open(_ALIAS_CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_alias_cache(d):
    # Write atomically. A half-written cache file is worse than none: it
    # loads as valid JSON that is simply missing entries, and nothing would
    # know. (It was also why an aborted run left the cache at 0 -- the
    # process died before any save.)
    try:
        tmp = _ALIAS_CACHE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, _ALIAS_CACHE_PATH)
    except Exception:
        pass


# Load any persisted cache AFTER the helpers are defined: this module is
# imported by a test harness that only wants canonical(), and a forward
# reference here made the import itself fail.
_ALIAS_CACHE.update(_load_alias_cache())


def _fetch_alias_group(vid):
    """Fetch one advisory's alias group, with polite backoff.

    Backoff lives HERE rather than at the call sites because there are two of
    them -- the up-front prefetch and the on-demand walk during transitive
    expansion -- and when the retry only wrapped the prefetch, the on-demand
    walk still died on a single connection reset. A transient network blip
    then aborted the whole comparison.

    OSV is a free public service. Three workers, exponential backoff, and a
    hard stop: this must not become a way to hammer a shared API.
    """
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(
                    f"https://api.osv.dev/v1/vulns/{vid}", timeout=45,
                    context=_ssl_context()) as r:
                d = json.load(r)
            return {vid} | set(d.get("aliases") or [])
        except urllib.error.HTTPError as e:
            # 404 is a DEFINITIVE answer, not a failure: OSV hosts records
            # under GHSA/PYSEC/RUSTSEC ids, not under every id it lists as an
            # alias. SNYK-PYTHON-JINJA2-1012994 is an alias of
            # GHSA-g3rq-g295-4j3m and has no record of its own. Walking it
            # must stop there, not raise -- otherwise every package whose
            # advisory graph touches a Snyk id refuses to compare at all.
            if e.code == 404:
                return {vid}
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                raise
        except Exception as e:                      # transport, TLS, reset
            last = e
        time.sleep(2 ** attempt)
    raise RuntimeError(f"alias lookup for {vid} kept failing: {last}")


def aliases_for(vid):
    """Every id OSV knows this vulnerability by, fetched once and cached.

    THE BUG THIS FUNCTION HAD. It was:

        try:
            ... urlopen(...) ...
            group = {vid} | set(d.get("aliases") or [])
        except Exception:
            group = {vid}

    On a machine whose urllib has no CA bundle every request raised
    SSL CERTIFICATE_VERIFY_FAILED, the bare `except` swallowed it, and this
    returned {vid} for EVERY id. Canonicalization then mapped each advisory to
    itself -- the identity function -- so the comparison silently degraded to
    raw id strings and reported aliases as findings.

    It produced a confident wrong answer instead of an error. The failure is
    never swallowed now: a fetch that cannot succeed raises. `--allow-offline`
    is the explicit opt-in for degrading to identity mapping, and it says so.

    The cache is on disk as well as in memory. OSV answers in ~3.5s here and a
    run walks the full alias closure of every advisory in every case, so an
    in-memory-only cache means a re-run re-pays all of it -- which makes the
    comparator impractical to re-run and therefore easy to leave stale.
    """
    if vid in _ALIAS_CACHE:
        return _ALIAS_CACHE[vid]
    group = _fetch_alias_group(vid)
    _ALIAS_CACHE[vid] = group
    _save_alias_cache(_ALIAS_CACHE)
    return group


def canonical(by_id, allow_offline=False):
    """Map each advisory id to a stable identity for cross-tool comparison.

    Two tools may report the SAME advisory under different ids: OSV and grype
    disagree about the scheme, and OSV additionally returns a record per alias
    rather than one record per advisory. On lodash 4.17.11 OSV returns 7
    records that are only 5 advisories, because
    GHSA-r5fr-rjxr-66jc and GHSA-xxjr-mmjv-4gpg are reciprocally aliased to
    GHSA-35jh-r3h4-6jhm and GHSA-f23m-r3pf-42rh. Comparing raw id strings
    reports that as SCRAM missing two findings.

    So ids are collapsed into ALIAS CLASSES: the union of {id} and its
    aliases, transitively. The previous implementation instead picked the
    lowest CVE in each direct alias list, which is not transitive and does not
    merge two ids that alias each other when neither carries a CVE.

    The class representative is the sorted-lowest CVE if the class has one,
    otherwise the sorted-lowest id. The choice is only ever used to compare
    two sets against each other, so it does not have to be globally stable --
    but it must be derived from the WHOLE class, not one hop from the id.

    Failures are not swallowed. If OSV cannot be reached and allow_offline is
    false, this raises: a canonicalization that could not fetch must not
    quietly degrade into string comparison, because that produces a confident
    wrong answer.
    """
    ids = sorted(by_id)
    parent = {i: i for i in ids}

    # Warm every id's alias group concurrently first. Sequential fetches cost
    # ~3.5s each against OSV from this machine and dominated the run; the
    # union-find below is then pure in-memory work.
    def _fetch(v):
        try:
            return v, set(aliases_for(v))
        except Exception as e:
            return v, e

    with ThreadPoolExecutor(max_workers=3) as pool:
        _results = dict(pool.map(_fetch, ids))

    def find(x):
        # Self-initialising: an intermediate alias reached during the
        # transitive walk is not in `parent` until it is touched, and a
        # KeyError there would abort the comparison rather than merge it.
        if x not in parent:
            parent[x] = x
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Fetch the alias group for every id, then union TRANSITIVELY.
    #
    # The subtlety: an alias that is not itself in the input is still a path
    # between two ids that are. A -> B -> C, with only A and C reported, must
    # collapse to one class even though B never appears in either tool's
    # output. Unioning only ids that are already in `parent` gets that wrong
    # -- it is a no-op for exactly the case the closure exists to handle, and
    # that is what TestAliasClassesMergeTransitively caught.
    #
    # So: walk the whole graph, following aliases out through nodes that are
    # not in the input, and union everything reachable from each id.
    alias_of = {}
    for vid in ids:
        pre = _results.get(vid)
        if isinstance(pre, set):
            alias_of[vid] = pre
            continue
        try:
            alias_of[vid] = set(aliases_for(vid))
        except Exception as e:
            if not allow_offline:
                raise RuntimeError(
                    f"alias lookup failed for {vid}: {e}. Re-run with network "
                    f"access, or pass --allow-offline to compare raw ids and "
                    f"accept that aliases will read as differences"
                ) from e
            alias_of[vid] = {vid}

    # Transitive expansion. `seen` is what stops an alias cycle (OSV records
    # alias each other reciprocally, so cycles are the normal case, not an
    # edge case) from looping forever.
    for vid in ids:
        stack = [vid]
        seen = set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur != vid:
                union(vid, cur)
            for nxt in alias_of.get(cur, ()):  # may not be an input id
                if nxt not in seen:
                    stack.append(nxt)
                    if nxt not in alias_of:
                        # An alias of an alias we have not fetched. Fetch it,
                        # or the chain stops here and a two-hop alias reads
                        # as two findings.
                        try:
                            alias_of[nxt] = set(aliases_for(nxt))
                        except Exception as e:
                            if not allow_offline:
                                raise RuntimeError(
                                    f"alias lookup failed for {nxt} (reached "
                                    f"via {vid}): {e}"
                                ) from e
                            alias_of[nxt] = {nxt}

    # Build each class from the WHOLE alias group of its members, not from
    # the input ids alone.
    #
    # THE BUG THIS HAD. Classes were assembled over `ids` only. When one tool
    # reports an advisory under PYSEC-2026-2151 and the other under its
    # aliased GHSA-68rp-wp8r-4726, BOTH are input ids and they DO union
    # together -- but the class then contained just those two names, so the
    # representative was picked from them. Any advisory reachable only
    # through an intermediate node was invisible, and two tools could land on
    # different representatives for the same class and be reported as a
    # disagreement that did not exist.
    #
    # So: the representative is chosen from every node the walk touched, which
    # is what "same advisory" actually means.
    classes = {}
    for vid in ids:
        root = find(vid)
        # Every node the walk actually reached from this id, and no other
        # id's names. Adding `set(ids)` here would bleed unrelated advisories
        # into every class -- it briefly merged an unrelated advisory in, and
        # TestAliasClassesMergeTransitively caught it.
        members = {n for n in alias_of if find(n) == root}
        if not members:
            members = {vid}
        classes.setdefault(root, set()).update(members)

    out = set()
    for members in classes.values():
        cves = sorted(m for m in members if m.startswith("CVE-"))
        out.add(cves[0] if cves else sorted(members)[0])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="/tmp/diftools")
    ap.add_argument("--allow-offline", action="store_true",
                    help="compare raw ids when OSV alias lookup is "
                         "unavailable, and say so in the output")
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
    for case in CASES:
        label, body = case[0], case[1]
        filename = case[2] if len(case) > 2 else "requirements.txt"
        tmp = tempfile.mkdtemp(prefix="diffvuln_")
        with open(os.path.join(tmp, filename), "w") as fh:
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
        S, G = canonical(s, args.allow_offline), canonical(g, args.allow_offline)
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
            # Canonicalise the ATTRIBUTION map the same way, then compare.
            #
            # This used to index the raw maps with a canonical key:
            # `if s[i] != g[i]` for `i in sorted(S)`. `S` holds canonical
            # names and `s` is keyed by raw ids, so the moment a class
            # collapsed to its CVE the lookup raised KeyError and the run
            # aborted after the first case. It only ever looked fine because
            # the alias lookup had been silently broken, so every canonical
            # name WAS a raw id and the two keyspaces coincided.
            def by_class(raw):
                out = {}
                for vid, pkgs in raw.items():
                    out.setdefault(next(iter(canonical({vid},
                                                     args.allow_offline))),
                                   set()).update(pkgs)
                return out

            sc, gc = by_class(s), by_class(g)
            for i in sorted(set(sc) & set(gc)):
                if sc[i] != gc[i]:
                    print(f"    attribution differs for {i}: "
                          f"SCRAM={sorted(sc[i])} grype={sorted(gc[i])}")
                    all_match = False

    print("\n" + ("ALL CASES IDENTICAL" if all_match
                  else "DISAGREEMENTS FOUND (see above)"))
    return 0 if all_match else 1


def _flush_cache_on_exit():
    _save_alias_cache(_ALIAS_CACHE)


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        _flush_cache_on_exit()
    raise SystemExit(rc)
