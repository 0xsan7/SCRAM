import { collectionDetails, coverageDetails, MAX_BYTES, parseReport, reportOverview, matchingComponents, safeAdvisoryURL, severity, highestCVSS, summaryText } from './report.mjs';

const $ = id => document.getElementById(id);
const format = new Intl.NumberFormat('en');
const PAGE_SIZE = 15;
const FINDING_PAGE_SIZE = 8;
let epoch = 0;
let state = { doc: null, selected: null, page: 0, driftPage: 0, findingPage: 0, source: null };

function el(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}
function button(label, action, className) {
  const node = el('button', className, label);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
}
function setList(id, values) { $(id).replaceChildren(...values.map(value => el('li', '', value))); }
function friendlyEcosystem(value) { return ({ npm: 'npm', pypi: 'PyPI', go: 'Go', cargo: 'Rust / Cargo' })[value] ?? value; }
function highestSeverity(component) {
  return severity(highestCVSS(component));
}
function filteredComponents() {
  return matchingComponents(state.doc, $('search').value, $('filter').value, { ecosystem: $('ecosystem').value, minimum: $('minimum').value, sort: $('sort').value });
}
function resetFilters() {
  $('search').value = ''; $('filter').value = 'all'; $('ecosystem').value = 'all'; $('minimum').value = '0'; $('sort').value = 'severity';
  state.page = 0;
}
function resetView() {
  state = { doc: null, selected: null, page: 0, driftPage: 0, findingPage: 0, source: null };
  $('report').hidden = true;
  $('welcome').hidden = true;
  $('error').hidden = true;
  $('schema-label').hidden = true;
  $('detail').replaceChildren();
  $('components').replaceChildren();
  $('drift-list').replaceChildren();
  resetFilters();
  $('export-summary').disabled = true;
  $('export-panel').hidden = true;
  $('export-text').textContent = '';
  $('action-status').textContent = '';
  $('report-context').textContent = 'Opening report…';
  document.querySelectorAll('[data-example]').forEach(node => node.setAttribute('aria-pressed', 'false'));
}
async function openReport(read, source) {
  const current = ++epoch;
  resetView();
  $('loading').hidden = false;
  $('main').setAttribute('aria-busy', 'true');
  try {
    const text = await read();
    if (current !== epoch) return;
    const doc = parseReport(text);
    state.doc = doc;
    state.source = source;
    state.selected = doc.scan.components[0] ?? null;
    renderReport();
  } catch (error) {
    if (current !== epoch) return;
    $('error-detail').textContent = error instanceof Error ? error.message : 'This report could not be read.';
    $('error').hidden = false;
    $('report-context').textContent = 'No report loaded.';
    $('error').focus();
  } finally {
    if (current === epoch) {
      $('loading').hidden = true;
      $('main').removeAttribute('aria-busy');
    }
  }
}
async function openExample(name) {
  await openReport(async () => {
    const response = await fetch(`fixtures/${encodeURIComponent(name)}.json`);
    if (!response.ok) throw new Error('The example could not be loaded. Try another example or choose a local report.');
    return response.text();
  }, { kind: 'example', name });
}
function renderReport() {
  const { doc, source } = state;
  const overview = reportOverview(doc);
  $('report').hidden = false;
  $('export-summary').disabled = false;
  $('ecosystem').replaceChildren(new Option('All ecosystems', 'all'), ...[...new Set(doc.scan.components.map(c => c.ecosystem))].sort().map(value => new Option(friendlyEcosystem(value), value)));
  $('report-context').textContent = `${doc.scan.repo} · ${source.kind === 'example' ? 'Bundled example' : source.name}`;
  $('schema-label').textContent = `Schema ${doc.schema_version}`;
  $('schema-label').hidden = false;
  const synthetic = source.kind === 'example' || doc.scan.components.some(component => component.vulnerabilities.some(v => v.source === 'synthetic'));
  state.synthetic = synthetic;
  $('provenance').textContent = synthetic ? 'Synthetic demonstration. Invented identifiers; no live vulnerability observations.' : 'Local report. Origin, scan mode and completeness have not been independently verified.';
  $('policy').className = `policy ${overview.status}`;
  $('policy-title').textContent = overview.headline;
  $('policy-symbol').setAttribute('d', overview.status === 'passed' ? 'm8 12 3 3 5-6' : 'M12 7v6m0 3h.01');
  $('policy-explanation').textContent = overview.warningCount ? 'Read the warnings before interpreting any finding count or score.' : doc.passed ? 'The configured gate passed. Existing findings may still require attention.' : 'The configured gate did not pass. Review its reasons and the evidence below.';
  setList('reasons', doc.fail_reasons.length ? doc.fail_reasons : doc.passed ? [] : ['No failure reason was included in this report.']);
  setList('warning-list', doc.scan.warnings);
  $('warnings').hidden = !overview.warningCount;
  $('matching-coverage').textContent = coverageDetails(doc.scan);
  $('component-count').textContent = format.format(doc.scan.components.length);
  $('finding-count').textContent = format.format(doc.scan.summary.vuln_total);
  for (const [id, value] of [['new-count', overview.newFindings], ['resolved-count', overview.resolvedFindings]]) {
    $(id).textContent = value === null ? 'No baseline' : format.format(value);
    $(id).classList.toggle('unknown', value === null);
  }
  $('repo-score').replaceChildren(document.createTextNode(format.format(doc.scan.summary.repo_score)), el('span', '', `/ ${doc.scan.summary.repo_score_max}`));
  $('report-footer-detail').textContent = `${source.kind === 'example' ? 'Synthetic data' : 'Local report'} · ${collectionDetails(doc.scan)}`;
  document.querySelectorAll('[data-example]').forEach(node => node.setAttribute('aria-pressed', String(source.kind === 'example' && node.dataset.example === source.name)));
  $('filter').querySelector('[value="new"]').disabled = !doc.drift;
  renderComponents();
  renderDrift();
}
function renderComponents() {
  const { doc } = state;
  const matched = filteredComponents();
  const pages = Math.ceil(matched.length / PAGE_SIZE);
  state.page = Math.min(state.page, Math.max(0, pages - 1));
  if (!matched.includes(state.selected)) {
    state.selected = matched[0] ?? null;
    state.findingPage = 0;
  }
  const page = matched.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
  if (page.length && !page.includes(state.selected)) { state.selected = page[0]; state.findingPage = 0; }
  $('inventory-total').textContent = `${format.format(matched.length)} of ${format.format(doc.scan.components.length)}`;
  const rows = page.map(component => {
    const row = el('tr', state.selected === component ? 'selected' : '');
    const name = el('td');
    const choose = button(component.name, () => {
      state.selected = component;
      state.findingPage = 0;
      renderComponents();
      document.querySelector('#components tr.selected .row-select')?.focus({ preventScroll: true });
      if (matchMedia('(max-width: 1240px)').matches) { $('detail-title').focus(); $('inspector').scrollIntoView({ block: 'start' }); }
    }, 'row-select');
    choose.setAttribute('aria-pressed', String(component === state.selected));
    choose.setAttribute('aria-label', `Inspect ${component.name} version ${component.version || 'not provided'}`);
    name.append(choose, el('div', 'component-meta', `${component.version || 'Version not provided'} · ${component.direct ? 'Direct' : 'Transitive'}`));
    const ecosystem = el('td', 'ecosystem', friendlyEcosystem(component.ecosystem));
    const findings = el('td', 'finding-cell', format.format(component.vulnerabilities.length));
    if (component.vulnerabilities.length) {
      const level = highestSeverity(component);
      findings.append(el('span', `finding-severity severity-${level}`, `${level} advisory`));
    } else findings.append(el('span', 'finding-severity', 'None reported'));
    row.append(name, ecosystem, findings);
    return row;
  });
  $('components').replaceChildren(...rows);
  $('no-components').hidden = matched.length > 0;
  $('no-components-detail').textContent = doc.scan.components.length ? 'Try another search or filter.' : 'This report contains no dependency components. That alone does not establish a complete assessment.';
  $('clear-filters').hidden = !doc.scan.components.length;
  $('page-status').textContent = matched.length ? `${state.page * PAGE_SIZE + 1}–${Math.min((state.page + 1) * PAGE_SIZE, matched.length)} of ${format.format(matched.length)}` : '0 dependencies shown';
  $('previous').disabled = state.page === 0;
  $('next').disabled = state.page >= pages - 1;
  renderDetail();
}
function fact(label, value) {
  const node = el('div');
  node.append(el('dt', '', label), el('dd', '', value));
  return node;
}
function renderDetail() {
  const component = state.selected;
  if (!component) {
    const title = el('h3', '', 'No dependency selected');
    title.id = 'detail-title';
    $('detail').replaceChildren(title, el('p', 'detail-empty', 'Choose a dependency from the inventory to inspect its report details.'));
    return;
  }
  const title = el('h3', '', component.name);
  title.id = 'detail-title';
  title.tabIndex = -1;
  const purl = el('p', 'detail-purl identifier', component.purl);
  const facts = el('dl', 'detail-facts');
  facts.append(fact('Version', component.version || 'Not provided'), fact('Relationship', component.direct ? 'Direct' : 'Transitive'), fact('License', component.license || 'Not provided'));
  const scoring = el('section', 'detail-section');
  const heading = el('h3', '', 'Score breakdown');
  if (component.score) {
    heading.append(el('span', 'score-total', `${component.score.total} / 100 raw`));
    const scores = el('dl', 'score-list');
    for (const [key, label, max] of [['severity', 'Severity', 40], ['exploitability', 'Exploitability', 25], ['maintenance', 'Maintenance', 20], ['freshness', 'Freshness', 15]]) {
      const row = el('div', 'score-row');
      row.append(el('dt', '', label), el('dd', '', `${component.score[key]} / ${max}`));
      scores.append(row);
    }
    scoring.append(heading, scores, el('p', 'help', 'Raw component terms use a 100-point budget. The repository score above uses its reported denominator. Zero points may reflect missing inputs.'));
  } else scoring.append(heading, el('p', 'help', 'No component score was provided.'));
  const findings = el('section', 'detail-section');
  findings.append(el('h3', '', `Known findings · ${format.format(component.vulnerabilities.length)}`));
  const newIDs = new Set((state.doc.drift?.drifts ?? []).filter(change => change.purl === component.purl).flatMap(change => change.new_vulnerabilities));
  const sorted = [...component.vulnerabilities].sort((a, b) => Number(newIDs.has(b.id)) - Number(newIDs.has(a.id)) || b.cvss_v3 - a.cvss_v3);
  const pages = Math.ceil(sorted.length / FINDING_PAGE_SIZE);
  state.findingPage = Math.min(state.findingPage, Math.max(0, pages - 1));
  for (const finding of sorted.slice(state.findingPage * FINDING_PAGE_SIZE, (state.findingPage + 1) * FINDING_PAGE_SIZE)) {
    const entry = el('article', 'finding');
    const top = el('div', 'finding-heading');
    const level = severity(finding.cvss_v3);
    top.append(el('h4', 'finding-id', finding.id), el('span', `severity-tag severity-${level}`, `${newIDs.has(finding.id) ? 'New · ' : ''}${level} · CVSS ${finding.cvss_v3}`));
    entry.append(top);
    if (finding.summary) entry.append(el('p', '', finding.summary));
    entry.append(el('p', 'help', `Source: ${finding.source || 'Not provided'} · ${finding.epss > 0 ? `Reported EPSS ${(finding.epss * 100).toFixed(2)}%` : 'EPSS availability not established'}`));
    if (finding.fixed_version) entry.append(el('p', 'help', `Reported fixed version: ${finding.fixed_version}. No upgrade was applied.`));
    const url = safeAdvisoryURL(finding.url);
    if (url && finding.source !== 'synthetic') {
      const link = el('a', '', 'Open advisory');
      link.href = url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      entry.append(link);
    }
    findings.append(entry);
  }
  if (!sorted.length) findings.append(el('p', 'help', 'No known findings were included for this component. Check the report warnings and provenance before drawing a conclusion.'));
  if (pages > 1) {
    const pager = el('div', 'pagination finding-pager');
    const previous = button('Previous findings', () => { state.findingPage--; renderDetail(); });
    const next = button('Next findings', () => { state.findingPage++; renderDetail(); });
    previous.disabled = state.findingPage === 0;
    next.disabled = state.findingPage >= pages - 1;
    const actions = el('div');
    actions.append(previous, next);
    pager.append(el('span', 'help', `${state.findingPage + 1} / ${pages}`), actions);
    findings.append(pager);
  }
  $('detail').replaceChildren(title, purl, facts, scoring, findings);
}
function renderDrift() {
  const { doc } = state;
  const list = $('drift-list');
  list.replaceChildren();
  if (!doc.drift) {
    $('drift-count').textContent = 'Not provided';
    $('drift-context').textContent = 'This report has no baseline comparison. New and resolved findings are unknown.';
    $('drift-pagination').hidden = true;
    return;
  }
  const meaningful = doc.drift.drifts.filter(change => change.change !== 'unchanged' || change.new_vulnerabilities.length || change.resolved_vulnerabilities.length);
  $('drift-count').textContent = `${format.format(meaningful.length)} reported changes`;
  $('drift-context').textContent = 'Finding changes can occur even when a dependency version stays the same. Score changes below are raw component points.';
  const pages = Math.ceil(meaningful.length / PAGE_SIZE);
  state.driftPage = Math.min(state.driftPage, Math.max(0, pages - 1));
  for (const change of meaningful.slice(state.driftPage * PAGE_SIZE, (state.driftPage + 1) * PAGE_SIZE)) {
    const row = el('div', 'drift-row');
    const name = el('div', 'drift-name', change.name || change.purl);
    name.append(el('code', '', change.purl));
    const changeLabel = ({ version_changed: 'Version changed', unchanged: 'Version unchanged', added: 'Dependency added', removed: 'Dependency removed' })[change.change];
    const description = el('div', 'drift-description', change.change === 'version_changed' ? `${change.previous_version} → ${change.new_version}` : changeLabel);
    if (change.new_vulnerabilities.length) description.append(el('span', '', `New: ${change.new_vulnerabilities.join(', ')}`));
    if (change.resolved_vulnerabilities.length) description.append(el('span', '', `Resolved: ${change.resolved_vulnerabilities.join(', ')}`));
    row.append(name, description, el('span', 'change-tag', `Raw score ${change.score_delta > 0 ? '+' : ''}${change.score_delta}`));
    list.append(row);
  }
  if (!meaningful.length) list.append(el('p', 'drift-empty', 'No dependency or finding changes were reported against this baseline. Existing findings may still be present.'));
  $('drift-pagination').hidden = pages <= 1;
  $('drift-page-status').textContent = `${state.driftPage + 1} / ${pages}`;
  $('drift-previous').disabled = state.driftPage === 0;
  $('drift-next').disabled = state.driftPage >= pages - 1;
}

document.querySelectorAll('[data-example]').forEach(node => node.addEventListener('click', () => { $('report-file').value = ''; openExample(node.dataset.example); }));
function openFile(file) {
  if (!file) return;
  openReport(async () => {
    if (file.size > MAX_BYTES) throw new Error('This report is larger than 5 MiB. Export a smaller report.');
    return file.text();
  }, { kind: 'local', name: file.name });
}
$('report-file').addEventListener('change', event => openFile(event.target.files[0]));
for (const id of ['search', 'filter', 'ecosystem', 'minimum', 'sort']) $(id).addEventListener(id === 'search' ? 'input' : 'change', () => { if (state.doc) { state.page = 0; renderComponents(); } });
for (const id of ['clear-filters','reset-filters']) $(id).addEventListener('click', () => { resetFilters(); renderComponents(); $('search').focus(); });
for (const event of ['dragenter','dragover']) $('drop-zone').addEventListener(event, e => { if (e.dataTransfer?.types.includes('Files')) { e.preventDefault(); $('drop-zone').classList.add('drag-active'); } });
$('drop-zone').addEventListener('dragleave', () => $('drop-zone').classList.remove('drag-active'));
$('drop-zone').addEventListener('drop', event => {
  event.preventDefault(); $('drop-zone').classList.remove('drag-active');
  const files = event.dataTransfer?.files;
  if (files?.length !== 1) { openReport(() => { throw new Error('Choose one JSON report at a time.'); }, { kind: 'local', name: '' }); return; }
  $('report-file').value = ''; openFile(files[0]);
});
$('copy-command').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('scan-command').textContent); $('copy-status').textContent = 'Scan command copied.'; }
  catch { $('copy-status').textContent = 'Select and copy the command above.'; }
});
$('export-summary').addEventListener('click', () => {
  if (!state.doc) return;
  $('export-text').textContent = summaryText(state.doc, filteredComponents(), state.synthetic);
  $('export-panel').hidden = false; $('export-panel').open = true;
  $('export-text').focus();
  $('action-status').textContent = 'Review summary ready. Copy it or download a text file below.';
});
$('copy-summary').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('export-text').textContent); $('action-status').textContent = 'Review summary copied.'; }
  catch { $('action-status').textContent = 'Select and copy the summary text above.'; }
});
$('download-summary').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([$('export-text').textContent], { type: 'text/plain;charset=utf-8' }));
  const link = el('a'); link.href = url; link.download = 'scram-review.txt';
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  $('action-status').textContent = 'Text download requested. If your browser blocks it, use Copy summary.';
});
for (const [id, delta] of [['previous', -1], ['next', 1]]) $(id).addEventListener('click', () => { state.page += delta; renderComponents(); });
for (const [id, delta] of [['drift-previous', -1], ['drift-next', 1]]) $(id).addEventListener('click', () => { state.driftPage += delta; renderDrift(); });
if (new URL(location.href).searchParams.get('local') === '1') {
  openReport(async () => { const response = await fetch('report.json'); if (!response.ok) throw new Error('No local report is available at this address. Choose a file or an example.'); return response.text(); }, { kind: 'local', name: 'Report opened by SCRAM' });
} else openExample('full-review');
