# SCRAM hosted viewer

Published 19 November 2026 on Cloudflare Pages.

- Live viewer: https://scram.0xsan7.in
- Cloudflare hostname: https://scram-4su.pages.dev
- Project name: `scram`
- Repository: `0xsan7/SCRAM`
- Production branch: `codex/scram-usability`
- Framework preset: `None`
- Build command: `node --test web/*.test.mjs && node scripts/build-viewer.mjs`
- Build output directory: `dist/viewer`
- Root directory: repository root (default)
- Build environment: `NODE_VERSION=24`, `SKIP_DEPENDENCY_INSTALL=1`

Only the static output is published: the browser app, self-hosted fonts/licenses
and four explicitly synthetic examples. Local reports, Git metadata and working
directories are not part of that artifact. Visitors select their own files in
the browser; this site has no upload endpoint or public scan service.

## Domain connection

The domain is registered at GoDaddy but already uses Cloudflare nameservers.
The custom hostname was added through Pages > scram > Custom domains > Set up
a custom domain, then Cloudflare's proposed record was activated:

| Type | Name | Target | TTL |
| --- | --- | --- | --- |
| CNAME | scram | scram-4su.pages.dev | Auto |

Cloudflare reports the custom hostname Active with SSL enabled. No GoDaddy
nameserver change, root-domain record change or portfolio deployment was needed.
HTTPS was verified on the custom hostname. Its full-review fixture matched the
source, and the portfolio HTML matched its pre-deployment response after
normalizing Cloudflare's rotating email-protection encodings.

## Updating and future subdomains

Pushes to the configured production branch trigger a new tested deployment.
The branch was published directly to preserve `main`. A future approved merge
must also update the Pages production branch to `main` before deleting or
retiring this branch. Do not assume a main-branch push currently updates the
live viewer. Other branches may produce Cloudflare previews.

For another project: create its Pages site, confirm its build/output settings,
verify the pages.dev deployment, then add the intended hostname through that
project's Custom domains tab. Review the proposed DNS record before activation.
Use a distinct subdomain and preserve the existing portfolio records.

The published viewer reads saved reports; running a live scan of a repository
is still done with the CLI. Public scanning would require a separate design.

References checked 19 November 2026:
[Git integration](https://developers.cloudflare.com/pages/get-started/git-integration/),
[build runtime settings](https://developers.cloudflare.com/pages/configuration/build-image/),
and [custom domains](https://developers.cloudflare.com/pages/configuration/custom-domains/).
