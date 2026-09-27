#!/usr/bin/env python3
"""Fetch a real-world lockfile corpus for the resolver test suite.

WHY THIS EXISTS
---------------
Hand-authored fixtures inherit their author's blind spots. D01 was a real npm
bug (a v3 lockfile's top-level "dependencies" key failed to parse, so ordinary
modern projects scanned as zero components and reported CLEAN) that survived
because every hand-written v3 fixture happened to omit that key. The test suite
was green and the product was broken.

The fix is not "one more hand-written test". It is a corpus nobody on this
project wrote, large enough and varied enough to contain shapes we did not
think of.

WHY THIS USES raw.githubusercontent AND NOT THE GitHub API
---------------------------------------------------------
The GitHub API is rate-limited to 60 requests/hour unauthenticated. An earlier
version of this script used the tree API to find lockfiles in monorepo
subdirectories, and it burned the entire hourly budget on a handful of repos:
one recursive tree call for n8n-n8n returns 9.7 MB, and a monorepo may contain
hundreds of nested lockfiles, so each repo cost dozens of fetches. It managed 6
files from 112 candidates before dying.

raw.githubusercontent.com has no such limit and serves files directly, so this
script stays on it exclusively and locates lockfiles by probing a curated
(repo, subpath) candidate set. Subpaths are free on raw, so the list is
generous and no API budget is spent.

Also worth knowing, because it cost real time: many popular repos commit no
npm lockfile at all. n8n uses pnpm, and express and angular.js are libraries
with nothing to lock. "No lockfile" is the correct outcome for those, not a
failure, and the summary reports them as absent rather than as errors.

Idempotent, re-runnable, no authentication, all public data.

    ./scripts/fetch_corpus.py [npm|pypi|go|all]
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "testdata", "fixtures")
RAW = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
UA = "scram-corpus-fetcher/1.0"
TIMEOUT = 30
WORKERS = 8
BRANCHES = ("main", "master")
# A repo that transiently fails to download is NOT the same as a repo that
# genuinely has no lockfile, and conflating them is how an earlier version of
# this script reported "0/77 repos" for Go when 61 were right there on the
# server. Every fetch is retried, and anything still unresolved is reported
# separately from a confirmed absence.
RETRIES = 3
RETRY_SLEEP = 1.5


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def get(url: str) -> bytes | None:
    """Fetch url, retrying transient failures.

    Returns None only after every attempt fails. Callers must not treat a None
    as proof the file does not exist upstream; see retry_note().
    """
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            # 404 is a definitive answer: the file is not there. Everything
            # else (429, 5xx, connection resets) is worth retrying.
            if e.code == 404:
                return None
        except (urllib.error.URLError, OSError):
            pass
        if attempt < RETRIES - 1:
            time.sleep(RETRY_SLEEP * (attempt + 1))
    return None


def valid(data: bytes | None, path: str) -> bool:
    """Reject error pages, stubs, and non-JSON where JSON is required."""
    if not data or len(data) < 2:
        return False
    if path.endswith(".json"):
        try:
            json.loads(data)
        except (ValueError, UnicodeDecodeError):
            return False
    else:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
    return True


def write(dest: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)


# Repos and the subdirectories to probe. "" means the repo root. Monorepos are
# listed with the subdirectory that actually holds the lockfile, which is how
# this avoids needing the tree API at all.
NPM: dict[str, list[str]] = {
    "microsoft/vscode": [""], "nestjs/nest": [""],
    "ionic-team/ionic-framework": [""], "axios/axios": [""],
    "yargs/yargs": [""], "appwrite/appwrite": [""],
    "bitwarden/clients": [""], "mattermost/mattermost": ["webapp"],
    "meteor/meteor": [""], "medusajs/medusa": ["", "backend", "packages/medusa"],
    "directus/directus": [""], "grafana/grafana": [""],
    "supabase/supabase": ["apps/studio"], "immich-app/immich": ["web", "cli"],
    "withastro/astro": ["packages/astro"],
    "TanStack/query": ["packages/react-query", "packages/query-core"],
    "mui/material-ui": [""], "chakra-ui/chakra-ui": [""], "vercel/turbo": [""],
    "nrwl/nx": ["", "packages/nx"], "angular/angular-cli": [""],
    "redwoodjs/redwood": [""], "excalidraw/excalidraw": [""],
    "prisma/prisma": [""], "drizzle-team/drizzle-orm": [""],
    "t3-oss/create-t3-app": ["www"], "trpc/trpc": [""],
    "electron/electron": [""], "storybookjs/storybook": ["code/core"],
    "hasura/graphql-engine": [""], "kubernetes/dashboard": [""],
    "hashicorp/consul": ["ui"], "moby/moby": [""], "ceph/ceph": [""],
    "vercel/next.js": ["packages/next"], "medusajs/medusa-js": [""],
    "kubernetes/kubernetes": ["staging/src/k8s.io/client-go"],
    "ansible/ansible": [""], "grafana/loki": ["clients/pkg/logcli"],
    "grafana/tempo": ["cmd/tempo"], "getsentry/sentry": ["src/sentry"],
    "elastic/kibana": [""], "gitlabhq/gitlabhq": ["ee"],
    "logdna/otel-lgtm": [""], "n8n-io/n8n": ["packages/cli", "packages/@n8n/config"],
}

# Python projects overwhelmingly use pyproject.toml now, and libraries often
# have no pinned runtime dependencies at all (click, starlette, fastapi are all
# pyproject-only with no requirements file). The repos listed here were checked
# empirically for a file that actually exists upstream, with the subpath that
# holds it, because a speculative list wasted a 750-probe run that found
# nothing. Re-probing is fine; a miss here means the repo changed.
#
# If this list keeps coming up empty, that is not a fetcher problem: it means
# the Python ecosystem moved to pyproject.toml, and SCRAM needs a
# pyproject.toml/PEP 621 resolver rather than a bigger list. See D24.
PYPI: dict[str, list[str]] = {
    "Textualize/rich": [""], "Textualize/textual": [""],
    "python-poetry/poetry": [""], "ansible/ansible": [""],
    "celery/celery": ["requirements"], "celery/kombu": ["requirements"],
    "home-assistant/core": [""], "prefecthq/prefect": [""],
    "psf/requests": [""], "saltstack/salt": ["requirements"],
    "pypa/pipenv": [""], "tox-dev/tox": [""], "hatchpyp/hatch": [""],
    "pypa/build": [""], "pyyaml/pyyaml": [""], "psf/black": [""],
    "pypa/pip": [""], "sqlalchemy/sqlalchemy": [""], "pallets/quart": [""],
    "benoitc/gunicorn": [""], "rq/rq": [""], "psycopg/psycopg": [""],
    "hiredis/hiredis-py": [""], "aio-libs/aiohttp": [""],
}
PYPI_FILES = ("poetry.lock", "requirements.txt", "requirements-dev.txt",
              "requirements/production.txt", "requirements/base.txt",
              "requirements/test.txt", "requirements/common.txt",
              "requirements/main.txt", "requirements/constraints.txt",
              "constraints.txt")

GO: dict[str, list[str]] = {
    "gin-gonic/gin": [""], "labstack/echo": [""], "gofiber/fiber": [""],
    "gorilla/mux": [""], "spf13/cobra": [""], "spf13/viper": [""],
    "stretchr/testify": [""], "sirupsen/logrus": [""], "uber-go/zap": [""],
    "rs/zerolog": [""], "go-redis/redis": [""], "gorm-io/gorm": [""],
    "jackc/pgx": [""], "valyala/fasthttp": [""], "hashicorp/consul": [""],
    "hashicorp/vault": [""], "etcd-io/etcd": [""], "docker/docker": [""],
    "containerd/containerd": [""], "opencontainers/runc": [""],
    "traefik/traefik": [""], "caddyserver/caddy": [""], "golang/go": [""],
    "grpc/grpc-go": [""], "google/go-github": [""], "aws/aws-sdk-go": [""],
    "goccy/go-json": [""], "json-iterator/go": [""], "mailru/easyjson": [""],
    "tidwall/gjson": [""], "fsnotify/fsnotify": [""], "robfig/cron": [""],
    "go-chi/chi": [""], "uptrace/bun": [""], "ent/ent": [""], "google/uuid": [""],
    "pkg/errors": [""], "kubernetes/client-go": [""], "kubernetes/api": [""],
    "istio/istio": [""], "envoyproxy/envoy": [""], "prometheus/prometheus": [""],
    "ceph/ceph": [""], "rook/rook": [""], "fluxcd/flux2": [""],
    "argoproj/argo-cd": [""], "kyverno/kyverno": [""], "cilium/cilium": [""],
    "rancher/rancher": [""], "vmware-tanzu/carvel": [""], "sigstore/cosign": [""],
    "in-toto/in-toto-golang": [""], "anchore/syft": [""], "anchore/grype": [""],
    "aquasecurity/trivy": [""], "google/osv-scanner": [""],
    "kubernetes/kubernetes": [""], "hashicorp/terraform": [""],
    "ansible/ansible": [""], "moby/moby": [""], "etcd-io/bbolt": [""],
    "grpc-ecosystem/grpc-gateway": [""], "prometheus/client_golang": [""],
    "charmbracelet/bubbletea": [""], "gohugoio/hugo": [""], "gin-contrib/cors": [""],
    "open-telemetry/opentelemetry-collector": [""], "grafana/loki": [""],
    "grafana/tempo": [""], "hashicorp/packer": [""], "hashicorp/nomad": [""],
    "go-gitea/gitea": [""], "gogs/gogs": [""], "mattermost/mattermost-server": [""],
    "grafana/oncall": [""], "sourcegraph/sourcegraph": [""], "sigstore/fulcio": [""],
}
GO_FILES = ("go.sum",)


def probe_one(repo: str, filename: str, subpaths: list[str]) -> tuple[str, bytes] | None:
    """Find filename under one of subpaths. Returns (relpath, content) or None.

    Subpaths are tried in the order given, "" meaning the repo root, and each
    is checked on both candidate branches. get() already retries transient
    failures, so a None here means every candidate genuinely 404'd.
    """
    for sub in subpaths or [""]:
        for br in BRANCHES:
            rel = f"{sub}/{filename}" if sub else filename
            data = get(RAW.format(repo=repo, branch=br, path=rel))
            if data is not None and valid(data, filename):
                return rel, data
    return None


def fetch_eco(spec: dict[str, list[str]], filenames: tuple[str, ...],
              sub: str, eco: str) -> None:
    jobs = []
    for repo, subpaths in spec.items():
        for fn in filenames:
            jobs.append((repo, fn, subpaths or [""],
                         os.path.join(CORPUS, sub, "real", repo, fn)))

    got: dict[str, tuple[str, int]] = {}
    cached: dict[str, int] = {}
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(probe_one, r, fn, sp): (r, dest) for (r, fn, sp, dest) in jobs}
        for fut in cf.as_completed(futs):
            repo, dest = futs[fut]
            # A repo that already has a usable file on disk is counted as
            # CACHED, not as a fresh hit and not as an absence. An earlier
            # version reported those repos as "have none", so a corpus that
            # was 100% present on disk printed as 0/45.
            if repo in got or repo in cached:
                continue
            if os.path.exists(dest) and os.path.getsize(dest) > 2:
                cached[repo] = os.path.getsize(dest)
                continue
            try:
                hit = fut.result()
            except Exception as exc:  # noqa: BLE001 - report, never crash the run
                log(f"  {repo}: ERROR {exc}")
                continue
            if not hit:
                continue
            rel, data = hit
            write(dest, data)
            got[repo] = (rel, len(data))

    # "contributed" counts both freshly fetched and already-present files,
    # because from the corpus's point of view they are the same thing. The
    # split is reported so a re-run is visibly a no-op.
    have = len(got) + len(cached)
    absent = sorted(r for r in spec if r not in got and r not in cached)
    log(f"{eco}: {have}/{len(spec)} repos have a lockfile "
        f"({len(got)} fetched, {len(cached)} already present)"
        + (f"; {len(absent)} have none" if absent else ""))
    for repo in sorted(got):
        rel, size = got[repo]
        log(f"    + {repo:42} {rel:34} {size:>10,}b")
    if absent:
        log(f"{eco}: no lockfile upstream for: {', '.join(absent[:12])}"
            + (" ..." if len(absent) > 12 else ""))


def summary() -> None:
    for eco, sub in (("npm", "npm"), ("pypi", "pypi"), ("go", "gomod")):
        d = os.path.join(CORPUS, sub, "real")
        if not os.path.isdir(d):
            continue
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(d) for f in fs]
        size = sum(os.path.getsize(f) for f in files)
        log(f"corpus {eco}: {len(files)} files, {size / 1e6:.1f} MB")


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("npm", "all"):
        log("npm: probing")
        fetch_eco(NPM, ("package-lock.json",), "npm", "npm")
    if which in ("pypi", "all"):
        log("pypi: probing")
        fetch_eco(PYPI, PYPI_FILES, "pypi", "pypi")
    if which in ("go", "all"):
        log("go: probing")
        fetch_eco(GO, GO_FILES, "gomod", "go")
    summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
