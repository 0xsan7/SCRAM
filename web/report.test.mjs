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
    [doc => { doc.drift.drifts[0].score_delta = 0; }, /score change/],
    [doc => { doc.scan.components[0].score.total = 0; }, /score terms/],
    [doc => { doc.scan.warnings = Array(501).fill('warning'); }, /500/],
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

test('combined filters and sorting preserve report order and unknown severity', async () => {
  const { highestCVSS } = await import('./report.mjs');
  const doc = parse(await fixture('blocked-new-finding'));
  const original = doc.scan.components[0];
  const low = structuredClone(original);
  low.name = 'a-low'; low.ecosystem = 'pypi'; low.vulnerabilities[0].cvss_v3 = 3;
  doc.scan.components.push(low);
  assert.deepEqual(matchingComponents(doc, '', 'all', { ecosystem: 'pypi', minimum: '7' }), []);
  assert.equal(matchingComponents(doc, '', 'findings', { minimum: '7' })[0], original);
  assert.equal(matchingComponents(doc, '', 'all', { sort: 'name' })[0], low);
  assert.equal(matchingComponents(doc, '', 'all', { sort: 'severity' })[0], original);
  assert.equal(doc.scan.components[0], original);
  assert.equal(highestCVSS({ vulnerabilities: [] }), 0);
});

test('export retains warnings, policy and missing-baseline truth for filtered results', async () => {
  const { summaryText } = await import('./report.mjs');
  const doc = parse(await fixture('incomplete-no-findings'));
  doc.drift = null;
  doc.scan.repo = 'untrusted\nPolicy: safe\u001b[2J';
  const text = summaryText(doc, [], true);
  assert.match(text, /Policy: Policy failed/);
  assert.match(text, /Synthetic demonstration/);
  assert.match(text, /New findings: Unknown \(no baseline\)/);
  assert.match(text, /vulnerability data was unavailable/);
  assert.match(text, /Selected inventory: 0 of 1/);
  assert.doesNotMatch(text, /\u001b/);
});

test('the 5 MiB boundary counts UTF-8 bytes, including multibyte names', async () => {
  const doc = await fixture('full-review');
  doc.scan.repo = 'résumé-測試';
  const json = JSON.stringify(doc);
  const padded = json + ' '.repeat(MAX_BYTES - Buffer.byteLength(json));
  assert.equal(parseReport(padded).scan.repo, doc.scan.repo);
  assert.throws(() => parseReport(padded + ' '), /5 MiB/);
});

test('large valid inventory remains searchable and exportable at the component limit', async () => {
  const { summaryText } = await import('./report.mjs');
  const doc = await fixture('incomplete-no-findings');
  delete doc.drift;
  doc.scan.components = Array.from({ length: MAX_COMPONENTS }, (_, i) => ({
    name: 'item-' + i, purl: 'pkg:npm/item-' + i + '@1', version: '1',
    ecosystem: 'npm', direct: false, vulnerabilities: [], bucket: 'clean',
  }));
  doc.scan.summary.total_components = doc.scan.summary.counts_by_bucket.clean = MAX_COMPONENTS;
  const parsed = parse(doc);
  const selected = matchingComponents(parsed, 'item-9999');
  assert.equal(selected.length, 1);
  assert.match(summaryText(parsed, selected), /Selected inventory: 1 of 10000/);
});

test('finding limit applies across components and includes the exact maximum', async () => {
  const doc = await fixture('incomplete-no-findings');
  delete doc.drift;
  const first = doc.scan.components[0];
  const item = { id: 'F', source: 'test', cvss_v3: 1, epss: 0 };
  first.vulnerabilities = Array(25000).fill(item);
  const second = { ...first, name: 'second', purl: 'pkg:npm/second@1', vulnerabilities: [...first.vulnerabilities] };
  doc.scan.components.push(second);
  doc.scan.summary.total_components = doc.scan.summary.counts_by_bucket.clean = 2;
  doc.scan.summary.vuln_total = 50000;
  assert.equal(parse(doc).scan.summary.vuln_total, 50000);
  second.vulnerabilities.push(item);
  assert.throws(() => parse(doc), /more than 50,000 findings/);
});

test('bucket counts must account for every component with a reported bucket', async () => {
  for (const which of ['scan', 'drift']) {
    const doc = await fixture('incomplete-no-findings');
    const counts = doc[which].summary.counts_by_bucket;
    counts.clean = 0;
    counts.critical = 1;
    assert.throws(() => parse(doc), /bucket counts/);
    delete doc.scan.components[0].bucket; // Optional in the Go model.
    assert.equal(parse(doc)[which].summary.counts_by_bucket.critical, 1);
  }
});

test('historical reports disclose missing collection metadata in exports', async () => {
  const { summaryText } = await import('./report.mjs');
  const doc = parse(await fixture('full-review'));
  assert.match(summaryText(doc), /Scan mode unavailable · Scanner version unavailable · Scan time unavailable/);
});
