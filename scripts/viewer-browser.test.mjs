// Optional local browser run. See web/README.md for prerequisites.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

test('embedded viewer import, inspect, export and recovery', { timeout: 90000 }, async (t) => {
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
  const binary = resolve(process.env.SCRAM_BIN || './scram');
  const dir = await mkdtemp(join(tmpdir(), 'scram-browser-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(
    join(dir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/item': { version: '1.0.0' } },
    }),
  );
  const scan = spawnSync(
    binary,
    ['scan', '.', '--sbom-only', '--no-scorecard', '--no-trend', '--format', 'json'],
    { cwd: dir, encoding: 'utf8' },
  );
  assert.equal(scan.status, 0, scan.error?.message ?? scan.stderr);
  const report = join(dir, 'report.json');
  await writeFile(report, scan.stdout);
  const server = spawn(binary, ['view', report], { stdio: ['ignore', 'pipe', 'inherit'] });
  const stopped = once(server, 'exit');
  try {
    let output = '';
    let url;
    for await (const chunk of server.stdout) {
      output += chunk.toString();
      url = output.match(/(http:\/\/[^\s]+)\n/)?.[1];
      if (url) break;
    }
    assert.ok(url, 'viewer exited before printing its session URL');
    const browser = await chromium.launch({ executablePath: process.env.SCRAM_BROWSER, headless: true });
    try {
      for (const width of [1440, 390]) {
        const page = await browser.newPage({ viewport: { width, height: 900 }, acceptDownloads: true });
        page.setDefaultTimeout(7000);
        const errors = [];
        const origin = new URL(url).origin;
        page.on('pageerror', (e) => errors.push(e.message));
        await page.route('**/*', (route) =>
          new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
        );
        await page.goto(url);
        const $ = (s) => page.locator(s);
        await $('#warnings').waitFor();
        assert.match(await $('#warning-list').textContent(), /vulnerability matching was skipped/);
        assert.equal(await $('#component-count').textContent(), '1');
        await $('#report-file').setInputFiles({
          name: 'bad.json',
          mimeType: 'application/json',
          buffer: Buffer.from('{'),
        });
        await $('#error').waitFor();
        assert.match(await $('#error-detail').textContent(), /not valid JSON/);
        assert(await $('#report').isHidden());
        await $('#report-file').setInputFiles(report);
        await $('#report').waitFor();
        assert.match(await $('#report-context').textContent(), /report\.json/);
        assert(await $('#error').isHidden());
        await $('#report-file').setInputFiles({
          name: 'big.json',
          mimeType: 'application/json',
          buffer: Buffer.alloc(5 * 1024 * 1024 + 1, 32),
        });
        await page.waitForFunction(() =>
          document.querySelector('#error-detail').textContent.includes('5 MiB'),
        );
        const doc = JSON.parse(scan.stdout);
        const item = doc.scan.components[0];
        doc.scan.components = Array.from({ length: 32 }, (_, i) => ({
          ...item,
          name: 'item-' + i,
          purl: 'pkg:npm/item-' + i + '@1.0.0',
        }));
        doc.scan.summary.total_components = doc.scan.summary.counts_by_bucket.clean = 32;
        await page.evaluate((json) => {
          const transfer = new DataTransfer();
          transfer.items.add(new File([json], 'dropped.json', { type: 'application/json' }));
          document
            .querySelector('#drop-zone')
            .dispatchEvent(new DragEvent('drop', { bubbles: true, dataTransfer: transfer }));
        }, JSON.stringify(doc));
        await page.waitForFunction(() => document.querySelector('#component-count').textContent === '32');
        await $('#next').click();
        assert.equal(await $('#page-status').textContent(), '16–30 of 32');
        await $('#next').click();
        assert.equal(await $('#components tr').count(), 2);
        await $('#search').fill('item-31');
        await $('#components button').first().click();
        assert.match(await $('#detail-title').textContent(), /item-31/);
        if (width === 390) assert.equal(await page.evaluate(() => document.activeElement.id), 'detail-title');
        await $('#export-summary').click();
        const summary = await $('#export-text').textContent();
        assert.match(summary, /Selected inventory: 1 of 32/);
        assert.match(summary, /vulnerability matching was skipped/);
        const downloaded = page.waitForEvent('download');
        await $('#download-summary').click();
        const download = await downloaded;
        assert.equal(download.suggestedFilename(), 'scram-review.txt');
        assert.equal(await readFile(await download.path(), 'utf8'), summary);
        await page.getByText('Try a sample report', { exact: true }).click();
        await $('[data-example="blocked-new-finding"]').click();
        await page.waitForFunction(
          () => document.querySelector('#policy-title').textContent === 'Policy failed',
        );
        assert(await $('#export-panel').isHidden());
        assert.equal(await $('#export-text').textContent(), '');
        await page.getByRole('link', { name: 'SCRAM', exact: true }).click();
        const reveal = page.getByRole('button', { name: 'Replay the SCRAM logo reveal' });
        await reveal.click();
        assert(await page.locator('.brand-reveal img').evaluate(logo =>
          logo.getAnimations().some(animation => animation.animationName === 'mark-settle'),
        ));
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await reveal.waitFor({ state: 'hidden' });
        await page.emulateMedia({ reducedMotion: 'no-preference' });
        await page.getByRole('link', { name: 'Explore a sample' }).click();
        await page.getByRole('button', { name: 'Existing finding', exact: true }).click();
        await page.getByRole('link', { name: 'Open this sample' }).click();
        await page.waitForFunction(
          () => document.querySelector('#policy-title').textContent === 'Policy passed',
        );
        const footer = page.locator('.shutter-footer');
        const shutter = footer.getByRole('button', { name: 'Rotate the SCRAM shutter' });
        const letterR = footer.locator('.shutter-cell > svg > use');
        assert.equal(await letterR.getAttribute('href'), 'assets/footer-glyphs.svg#r');
        assert(await letterR.evaluate(glyph => glyph.getBBox().height) > 0);
        const movingR = footer.locator('.shutter-cell > svg');
        await shutter.hover({ position: { x: 6, y: 6 } });
        assert.notEqual(await movingR.evaluate(glyph => glyph.style.rotate), '');
        await page.mouse.move(1, 1);
        assert.equal(await movingR.evaluate(glyph => glyph.style.rotate), '');
        await shutter.focus();
        await page.keyboard.press('Enter');
        assert(await movingR.evaluate(glyph =>
          glyph.getAnimations().some(animation => animation.effect.getTiming().duration === 420),
        ));
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await shutter.hover({ position: { x: 6, y: 6 } });
        assert.equal(await movingR.evaluate(glyph => glyph.style.rotate), '');
        await shutter.focus();
        await page.keyboard.press('Enter');
        assert.equal(await footer.locator('.shutter-blades').getAttribute('transform'), 'rotate(180 50 50)');
        assert.equal(await footer.getByRole('link', { name: 'Report privacy' }).getAttribute('href'), './#report-privacy');
        assert.deepEqual(errors, []);
        t.diagnostic(browser.version() + ' at width ' + width);
        await page.close();
      }
    } finally {
      await browser.close();
    }
  } finally {
    server.kill('SIGINT');
    await stopped;
  }
});
