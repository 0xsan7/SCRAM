# SCRAM public demo — review proposal

Status: prepared static source, not deployed. Proposed address:
`https://scram.0xsan7.in`. The root portfolio stays unchanged.

Publish only the output of `node scripts/build-viewer.mjs`: `dist/viewer/`.
It contains the browser app, self-hosted fonts/licenses and four explicitly
synthetic examples. It must never include local reports, the repository's
working directory, `.git`, credentials or private scan output. Visitors select
their own files locally; this demo has no upload or live scanning service.

## Proposed GitHub Pages setup, after review

1. Merge the reviewed source and enable GitHub Actions as the SCRAM repository's
   Pages publishing source. Add a manually triggered workflow that tests the
   viewer, builds `dist/viewer/`, uploads only that directory and deploys it in
   the protected `github-pages` environment. No such workflow is enabled here.
2. Verify the domain in GitHub and configure `scram.0xsan7.in` in SCRAM's Pages
   settings before adding its DNS record. With an Actions publishing source,
   GitHub's custom-domain setting is authoritative; a CNAME file is not required.
3. At the DNS provider, add only a `CNAME` for name `scram`, target
   `0xsan7.github.io`. Preserve all existing root, www, email and other records.
   Confirm the provider's current zone state before making any change.
4. Once GitHub confirms domain/certificate readiness, enforce HTTPS. Verify
   fonts/modules and all examples from the subdomain, then file import,
   filtering, copy/export and mobile behavior. Do not publish an unverified
   report or imply that synthetic findings are live observations.

The artifact is portable to another static host if preferred. GitHub Pages
fits the existing repository and needs no application server or runtime secret.
Host availability and current Pages settings have not been verified yet.

References checked 19 November 2026:
[custom Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
and [custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site).
