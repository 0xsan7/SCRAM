import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseReport, reportOverview, matchingComponents, safeAdvisoryURL, MAX_BYTES, MAX_COMPONENTS } from './report.mjs';

const fixture = async name => JSON.parse(await readFile(new URL(`../examples/report-viewer/fixtures/${name}.json`, import.meta.url), 'utf8'));
const parse = doc => parseReport(JSON.stringify(doc));

test('all production-generated examples retain their distinct policy meanings', async () => {
  const existing = parse(await fixture('passed-with-existing-finding'));
  assert.equal(reportOverview(existing).status, 'passed');
  assert.equal(existing.scan.summary.vuln_total, 1);
  assert.equal(reportOverview(existing).newFindings, 0);
  const blocked = parse(await fixture('blocked-new-finding'));
  assert.equal(reportOverview(blocked).status, 'blocked');
  assert.equal(reportOverview(blocked).newFindings, 1);
  assert.equal(reportOverview(blocked).changedDependencies, 0);
  const incomplete = parse(await fixture('incomplete-no-findings'));
  assert.equal(incomplete.scan.summary.vuln_total, 0);
  assert.equal(reportOverview(incomplete).status, 'blocked');
  assert.equal(reportOverview(incomplete).warningCount, 1);
});

test('missing drift is unknown, while accepted warnings stay visible', async () => {
  const doc = await fixture('passed-with-existing-finding');
  delete doc.drift;
  doc.scan.warnings = ['Partial data was explicitly accepted by the configured policy.'];
  const result = parse(doc);
  assert.equal(reportOverview(result).status, 'warning');
  assert.equal(reportOverview(result).newFindings, null);
});

test('malformed, unsupported and inconsistent reports are rejected', async () => {
  assert.throws(() => parseReport('{broken'), /not valid JSON/);
  assert.throws(() => parseReport('null'), /must be an object/);
  const cases = [
    [doc => { doc.schema_version = '1.0.0'; }, /unsupported/],
    [doc => { delete doc.passed; }, /outcome/],
    [doc => { doc.passed = 'false'; }, /outcome/],
    [doc => { delete doc.scan.components; }, /inventory is missing/],
    [doc => { delete doc.scan.components[0].vulnerabilities; }, /vulnerability list/],
    [doc => { doc.scan.summary.total_components = 42; }, /component count/],
    [doc => { doc.scan.summary.vuln_total = 42; }, /finding count/],
    [doc => { doc.scan.summary.repo_score_max = 0; }, /repo_score_max/],
    [doc => { doc.scan.summary.counts_by_bucket.clean = 1; }, /bucket counts/],
    [doc => { doc.scan.components[0].vulnerabilities[0].cvss_v3 = 99; }, /CVSS/],
    [doc => { doc.scan.components[0].vulnerabilities[0].epss = -1; }, /EPSS/],
    [doc => { doc.drift.drifts[0].change = 'invented'; }, /change type/],
  ];
  for (const [mutate, error] of cases) {
    const doc = await fixture('blocked-new-finding');
    mutate(doc);
    assert.throws(() => parse(doc), error);
  }
});

test('actual Go null lists normalize to empty without inventing findings', async () => {
  const doc = await fixture('incomplete-no-findings');
  doc.scan.components[0].vulnerabilities = null;
  doc.drift.drifts = null;
  assert.deepEqual(parse(doc).scan.components[0].vulnerabilities, []);
});

test('size and component limits apply before rendering', async () => {
  assert.throws(() => parseReport(' '.repeat(MAX_BYTES + 1)), /5 MiB/);
  const doc = await fixture('incomplete-no-findings');
  doc.scan.components = Array.from({ length: MAX_COMPONENTS + 1 }, () => doc.scan.components[0]);
  assert.throws(() => parse(doc), /10,000/);
});

test('component search and new-finding filter retain same-version disclosures', async () => {
  const doc = parse(await fixture('blocked-new-finding'));
  assert.equal(matchingComponents(doc, 'DEMO-HIGH', 'new').length, 1);
  assert.equal(matchingComponents(doc, '  VIEWER  ', 'direct').length, 1);
  assert.equal(matchingComponents(doc, 'missing').length, 0);
});

test('advisory links permit only explicit HTTP(S) URLs without embedded credentials', () => {
  for (const url of ['javascript:alert(1)', 'data:text/html,test', 'file:///etc/passwd', '//example.com', 'https://user:secret@example.com', 'not a URL']) assert.equal(safeAdvisoryURL(url), null);
  assert.equal(safeAdvisoryURL('https://osv.dev/vulnerability/GO-2024-0000'), 'https://osv.dev/vulnerability/GO-2024-0000');
});
