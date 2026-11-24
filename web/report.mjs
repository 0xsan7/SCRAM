export const MAX_BYTES = 5 * 1024 * 1024;
export const MAX_COMPONENTS = 10_000;
const buckets = ['critical', 'high', 'medium', 'low', 'clean'];
const changes = ['added', 'removed', 'version_changed', 'unchanged'];

export class ReportError extends Error {}
const fail = message => { throw new ReportError(message); };
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object.`);
  return value;
}
function text(value, label, optional = false) {
  if (value === undefined && optional) return '';
  if (typeof value !== 'string' || value.length > 10_000) fail(`${label} must be text (at most 10,000 characters).`);
  return value;
}
function number(value, label, min = 0, max = Number.MAX_SAFE_INTEGER, whole = false) {
  if (!Number.isFinite(value) || value < min || value > max || (whole && !Number.isSafeInteger(value))) {
    fail(`${label} must be ${whole ? 'a whole number' : 'a number'} between ${min} and ${max}.`);
  }
  return value;
}
function array(value, label, max = 50_000) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > max) fail(`${label} must be a list of at most ${max.toLocaleString('en')} items.`);
  return value;
}
function strings(value, label, max = 50_000) {
  return array(value, label, max).map(item => text(item, label));
}
function schema(value, label) {
  if (typeof value !== 'string' || !/^2\.\d+\.\d+$/.test(value)) fail(`${label} is unsupported. Open a SCRAM schema 2.x report.`);
}
function summary(value, count, findings, reportedBuckets, label) {
  object(value, label);
  number(value.total_components, `${label}.total_components`, 0, MAX_COMPONENTS, true);
  if (value.total_components !== count) fail(`${label} component count does not match the inventory.`);
  number(value.vuln_total, `${label}.vuln_total`, 0, 50_000, true);
  if (value.vuln_total !== findings) fail(`${label} finding count does not match the inventory.`);
  number(value.repo_score_max, `${label}.repo_score_max`, 1, 10_000, true);
  number(value.repo_score, `${label}.repo_score`, 0, value.repo_score_max, true);
  if (!buckets.includes(value.repo_bucket)) fail(`${label}.repo_bucket is unsupported.`);
  object(value.counts_by_bucket, `${label}.counts_by_bucket`);
  const total = buckets.reduce((sum, bucket) => sum + number(value.counts_by_bucket[bucket], `${label}.counts_by_bucket.${bucket}`, 0, MAX_COMPONENTS, true), 0);
  if (total !== count || buckets.some(bucket => value.counts_by_bucket[bucket] < reportedBuckets[bucket])) fail(`${label} bucket counts do not match the inventory.`);
  number(value.new_high_count, `${label}.new_high_count`, 0, 50_000, true);
  number(value.new_critical_count, `${label}.new_critical_count`, 0, 50_000, true);
  strings(value.new_vuln_ids, `${label}.new_vuln_ids`);
}

export function parseReport(source) {
  if (typeof source !== 'string') fail('Choose a JSON report file.');
  if (source.length > MAX_BYTES || new TextEncoder().encode(source).length > MAX_BYTES) fail('This report is larger than 5 MiB. Export a smaller report.');
  let doc;
  try { doc = JSON.parse(source); } catch { fail('This file is not valid JSON. Choose a report exported with scram scan --format json.'); }
  object(doc, 'Report');
  schema(doc.schema_version, 'Report schema');
  if (typeof doc.passed !== 'boolean') fail('Report policy outcome (passed) is missing or invalid.');
  const scan = object(doc.scan, 'Scan');
  schema(scan.schema_version, 'Scan schema');
  if (!text(scan.repo, 'Repository').trim()) fail('Repository name is missing.');
  text(scan.commit, 'Commit', true);
  for (const field of ['started_at', 'scanner_version', 'mode']) text(scan[field], 'Scan ' + field, true);
  scan.warnings = strings(scan.warnings, 'Warnings', 500);
  doc.fail_reasons = strings(doc.fail_reasons, 'Failure reasons', 500);
  if (!Object.hasOwn(scan, 'components')) fail('The component inventory is missing.');
  scan.components = array(scan.components, 'Components', MAX_COMPONENTS);
  if (scan.osv_coverage !== undefined) {
    const coverage = object(scan.osv_coverage, 'OSV coverage');
    const total = ['checked', 'partial', 'unchecked'].reduce((sum, key) =>
      sum + number(coverage[key], 'OSV coverage ' + key, 0, scan.components.length, true), 0);
    if (total !== scan.components.length) fail('OSV coverage counts do not match the resolved inventory.');
  }
  let findings = 0;
  const reportedBuckets = Object.fromEntries(buckets.map(bucket => [bucket, 0]));
  for (const component of scan.components) {
    object(component, 'Component');
    for (const field of ['name', 'purl', 'version', 'ecosystem']) text(component[field], `Component ${field}`);
    if (!component.name.trim() || !component.purl.trim() || !component.ecosystem.trim()) fail('A component is missing its name, PURL or ecosystem.');
    if (typeof component.direct !== 'boolean') fail('Component direct/transitive classification is invalid.');
    text(component.license, 'License', true);
    if (component.bucket !== undefined && !buckets.includes(component.bucket)) fail('Component risk bucket is unsupported.');
    if (component.bucket !== undefined) reportedBuckets[component.bucket]++;
    if (component.score !== undefined) {
      object(component.score, 'Component score');
      for (const [field, max] of Object.entries({ total: 100, severity: 40, exploitability: 25, maintenance: 20, freshness: 15 })) number(component.score[field], `Component score ${field}`, 0, max, true);
      if (component.score.total !== component.score.severity + component.score.exploitability + component.score.maintenance + component.score.freshness) fail('Component score terms do not match its total.');
    }
    if (!Object.hasOwn(component, 'vulnerabilities')) fail('A component is missing its vulnerability list.');
    component.vulnerabilities = array(component.vulnerabilities, 'Vulnerabilities');
    findings += component.vulnerabilities.length;
    if (findings > 50_000) fail('This report contains more than 50,000 findings. Export a smaller report.');
    for (const vulnerability of component.vulnerabilities) {
      object(vulnerability, 'Finding');
      if (!text(vulnerability.id, 'Finding ID').trim()) fail('A finding is missing its ID.');
      text(vulnerability.source, 'Finding source');
      number(vulnerability.cvss_v3, 'CVSS v3', 0, 10);
      number(vulnerability.epss, 'EPSS', 0, 1);
      for (const field of ['summary', 'url', 'fixed_version', 'cvss_vector']) text(vulnerability[field], `Finding ${field}`, true);
      strings(vulnerability.aliases, 'Finding aliases');
    }
  }
  summary(scan.summary, scan.components.length, findings, reportedBuckets, 'Scan summary');
  doc.drift = doc.drift == null ? null : object(doc.drift, 'Drift');
  if (doc.drift) {
    schema(doc.drift.schema_version, 'Drift schema');
    text(doc.drift.base, 'Baseline', true);
    text(doc.drift.head, 'Head', true);
    doc.drift.drifts = array(doc.drift.drifts, 'Dependency changes', 2 * MAX_COMPONENTS);
    for (const change of doc.drift.drifts) {
      object(change, 'Dependency change');
      text(change.purl, 'Changed component PURL');
      if (!changes.includes(change.change)) fail('A dependency change has an unsupported change type.');
      for (const field of ['name', 'previous_version', 'new_version']) text(change[field], `Change ${field}`, true);
      change.new_vulnerabilities = strings(change.new_vulnerabilities, 'New findings');
      change.resolved_vulnerabilities = strings(change.resolved_vulnerabilities, 'Resolved findings');
      number(change.score_before, 'Previous raw score', 0, 100, true);
      number(change.score_after, 'Current raw score', 0, 100, true);
      number(change.score_delta, 'Raw score change', -100, 100, true);
      if (change.score_delta !== change.score_after - change.score_before) fail('Raw score change does not match its before/after values.');
    }
    summary(doc.drift.summary, scan.components.length, findings, reportedBuckets, 'Drift summary');
  }
  return doc;
}

export function severity(cvss) {
  return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : cvss > 0 ? 'low' : 'unknown';
}

export function safeAdvisoryURL(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

export function reportOverview(doc) {
  const drift = doc.drift?.drifts ?? [];
  const warningCount = doc.scan.warnings.length;
  return {
    status: !doc.passed ? 'blocked' : warningCount ? 'warning' : 'passed',
    headline: !doc.passed ? 'Policy failed' : warningCount ? 'Policy passed with warnings' : 'Policy passed',
    newFindings: doc.drift ? drift.reduce((sum, change) => sum + change.new_vulnerabilities.length, 0) : null,
    resolvedFindings: doc.drift ? drift.reduce((sum, change) => sum + change.resolved_vulnerabilities.length, 0) : null,
    changedDependencies: doc.drift ? drift.filter(change => change.change !== 'unchanged').length : null,
    warningCount,
  };
}

export function highestCVSS(component) {
  return component.vulnerabilities.reduce((max, finding) => Math.max(max, finding.cvss_v3), 0);
}

export function matchingComponents(doc, query = '', filter = 'all', options = {}) {
  const search = query.trim().toLocaleLowerCase();
  const fresh = new Set((doc.drift?.drifts ?? []).filter(change => change.new_vulnerabilities.length).map(change => change.purl));
  const matched = doc.scan.components.filter(component => {
    const matches = !search || `${component.name} ${component.purl} ${component.ecosystem} ${component.vulnerabilities.map(v => v.id).join(' ')}`.toLocaleLowerCase().includes(search);
    return matches && (!options.ecosystem || options.ecosystem === 'all' || component.ecosystem === options.ecosystem)
      && (!options.minimum || highestCVSS(component) >= Number(options.minimum))
      && (filter === 'all' || (filter === 'findings' && component.vulnerabilities.length > 0) || (filter === 'new' && fresh.has(component.purl)) || (filter === 'direct' && component.direct));
  });
  if (options.sort === 'severity') matched.sort((a, b) => highestCVSS(b) - highestCVSS(a) || a.name.localeCompare(b.name));
  if (options.sort === 'name') matched.sort((a, b) => a.name.localeCompare(b.name));
  return matched;
}

// Values are observations reported by the producer, including for imported files.
export function collectionDetails(scan) {
  const mode = scan.mode === 'inventory' ? 'Inventory only' : scan.mode === 'advisory' ? 'Advisory scan' : 'Scan mode unavailable';
  const version = scan.scanner_version ? 'SCRAM ' + scan.scanner_version : 'Scanner version unavailable';
  const start = scan.started_at ? 'Started ' + scan.started_at : 'Scan time unavailable';
  return [mode, version, start].join(' · ');
}

export function coverageDetails(scan) {
  if (scan.mode === 'inventory') return 'OSV matching skipped (inventory only)';
  const coverage = scan.osv_coverage;
  if (!coverage) return 'OSV matching coverage unavailable';
  return `OSV matching on resolved inventory: ${coverage.checked} checked, ${coverage.partial} partial, ${coverage.unchecked} unchecked`;
}

// Plain-text export keeps the policy and its caveats, even for a filtered list.
export function summaryText(doc, components = doc.scan.components, synthetic = false) {
  const line = value => String(value).replace(/[\u0000-\u001f\u007f]/g, ' ');
  const overview = reportOverview(doc);
  const lines = ['SCRAM dependency review', `Repository: ${line(doc.scan.repo)}`,
    `Policy: ${overview.headline}`, `Provenance: ${synthetic ? 'Synthetic demonstration' : 'Imported report; origin and completeness unverified'}`,
    `Reported repository score: ${doc.scan.summary.repo_score}/${doc.scan.summary.repo_score_max}`,
    `Known findings in full report: ${doc.scan.summary.vuln_total}`,
    `New findings: ${overview.newFindings ?? 'Unknown (no baseline)'}`,
    `Resolved findings: ${overview.resolvedFindings ?? 'Unknown (no baseline)'}`,
    line(collectionDetails(doc.scan)), coverageDetails(doc.scan), 'Policy is a configured decision, not a safety guarantee.', '',
    'Policy reasons:', ...(doc.fail_reasons.length ? doc.fail_reasons.map(x => `- ${line(x)}`) : ['- None provided']),
    '', 'Warnings:', ...(doc.scan.warnings.length ? doc.scan.warnings.map(x => `- ${line(x)}`) : ['- None provided; completeness is not established']), '',
    `Selected inventory: ${components.length} of ${doc.scan.components.length} dependencies`];
  for (const component of components) {
    lines.push('', `${line(component.name)} ${line(component.version)} (${line(component.ecosystem)}, ${component.direct ? 'direct' : 'transitive'})`, line(component.purl));
    if (!component.vulnerabilities.length) lines.push('  No known findings reported; check warnings.');
    for (const finding of component.vulnerabilities) lines.push(`  ${line(finding.id)} | ${severity(finding.cvss_v3)} | CVSS ${finding.cvss_v3}${finding.fixed_version ? ` | reported fixed version ${line(finding.fixed_version)}` : ''}`);
  }
  return lines.join('\n') + '\n';
}
