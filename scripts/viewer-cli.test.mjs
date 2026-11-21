import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseReport, reportOverview, summaryText } from '../web/report.mjs';

test('CLI exit status, report viewer and SBOMs agree on a fresh inventory', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'scram-viewer-contract-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const binary = join(root, process.platform === 'win32' ? 'scram.exe' : 'scram');
  const build = spawnSync('go', ['build', '-o', binary, './cmd/scram'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    encoding: 'utf8',
  });
  assert.equal(build.status, 0, build.error?.message ?? build.stderr);
  const project = join(root, 'project');
  await mkdir(project);
  const digest = createHash('sha256').update('sample contents').digest();
  await writeFile(
    join(project, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/item': {
          version: '1.0.0',
          license: 'MIT',
          integrity: 'sha256-' + digest.toString('base64'),
        },
      },
    }),
  );

  for (const blocked of [false, true]) {
    if (blocked) await writeFile(join(project, '.scram.yml'), 'version: 1\nlicenses:\n  deny: [MIT]\n');
    const scan = spawnSync(
      binary,
      [
        'scan',
        '.',
        '--sbom-only',
        '--no-scorecard',
        '--no-trend',
        '--sbom',
        'both',
        '--out',
        root,
        '--format',
        'json',
      ],
      { cwd: project, encoding: 'utf8' },
    );
    assert.equal(scan.status, blocked ? 1 : 0, scan.error?.message ?? scan.stderr);
    const report = parseReport(scan.stdout);
    assert.equal(report.passed, !blocked);
    assert.equal(reportOverview(report).status, blocked ? 'blocked' : 'warning');
    assert.equal(reportOverview(report).newFindings, null);
    assert.match(summaryText(report), /vulnerability matching was skipped/);
    if (blocked) assert.match(summaryText(report), /MIT/);
  }
  const cdx = JSON.parse(await readFile(join(root, 'sbom.cdx.json'), 'utf8'));
  const spdx = JSON.parse(await readFile(join(root, 'sbom.spdx.json'), 'utf8'));
  assert.deepEqual(cdx.components[0].hashes, [{ alg: 'SHA-256', content: digest.toString('hex') }]);
  assert.deepEqual(spdx.packages.find((p) => p.name === 'item').checksums, [
    { algorithm: 'SHA256', checksumValue: digest.toString('hex') },
  ]);
});
