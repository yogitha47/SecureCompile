'use strict';
/* SecureCompile front end. All dynamic text is inserted with textContent (never innerHTML). */

const $ = (id) => document.getElementById(id);
const codeInput = $('codeInput'), fileInput = $('fileInput'), analyzeForm = $('analyzeForm');
const analyzeButton = $('analyzeButton'), charCount = $('charCount'), statusPill = $('statusPill');
const resultSubtitle = $('resultSubtitle'), emptyState = $('emptyState'), errorBox = $('errorBox');
const loadingBox = $('loadingBox'), summary = $('summary'), findingsBox = $('findings');
const shareStatus = $('shareStatus'), restoreButton = $('restoreButton'), fixPanel = $('fixPanel');

const state = { result: null, analyzedSource: null, restoreSource: null, proposal: null };

const ENGINE_LABELS = { 'ast-rule': 'AST rule', 'source-rule': 'Text-pattern rule', ml: 'ML model', compiler: 'Compiler', parser: 'Parser' };
const SAMPLES = {
  vulnerable: `#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nint main(void) {\n    char name[16];\n    char buf[8];\n    gets(buf);\n    strcpy(name, buf);\n    printf(name);\n    int *ptr;\n    free(ptr);\n    int divisor = 0;\n    int result = 100 / divisor;\n    return result;\n}\n`,
  syntax: `#include <stdio.h>\n\nint main(void) {\n    int total = 0\n    int count = 3\n    char buf[8];\n    gets(buf);\n    total = total + count\n    printf("%d\\n", total);\n    return 0;\n}\n`,
  safe: `#include <stdio.h>\n\nint main(void) {\n    char buf[16];\n    if (fgets(buf, sizeof(buf), stdin) != NULL) {\n        printf("%s", buf);\n    }\n    return 0;\n}\n`,
};

/* ---------------------------------------------------------------- helpers */
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function chip(text, cls, title) { const c = el('span', `chip ${cls || ''}`, text); if (title) c.title = title; return c; }
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function updateCount() { charCount.textContent = `${codeInput.value.length.toLocaleString()} characters`; }
function lineText(n) { return codeInput.value.split(/\r?\n/)[n - 1] || ''; }
function jumpToLine(lineNo) {
  const lines = codeInput.value.split(/\r?\n/);
  const line = Math.max(1, Math.min(Number(lineNo) || 1, lines.length));
  const start = lines.slice(0, line - 1).reduce((n, s) => n + s.length + 1, 0);
  codeInput.focus();
  codeInput.setSelectionRange(start, start + (lines[line - 1] || '').length);
}
async function postJson(url, body) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  let data = null;
  try { data = await response.json(); } catch { /* non-JSON error body */ }
  if (!response.ok || !data || data.ok === false) {
    const message = (data && data.error) || (response.status === 413 ? 'That request is too large.' : `The server returned an error (${response.status}).`);
    throw new Error(message);
  }
  return data;
}
function setStatus(kind, text) { statusPill.className = `status-pill ${kind}`; statusPill.textContent = text; }
function showError(message) {
  emptyState.hidden = true; loadingBox.hidden = true; errorBox.hidden = false; errorBox.textContent = message;
  setStatus('bad', 'Needs attention'); resultSubtitle.textContent = 'Analysis could not be completed.';
}
function hideResultBlocks() {
  for (const id of ['engineStrip', 'summary', 'syntaxPanel', 'filterBar', 'mlPanel', 'compilerPanel', 'memoryPanel', 'resultsActions']) $(id).hidden = true;
  clear(findingsBox);
}

/* ---------------------------------------------------------------- editor controls */
codeInput.addEventListener('input', updateCount);
$('exampleSelect').addEventListener('change', (event) => {
  const key = event.target.value;
  if (!key) return;
  codeInput.value = SAMPLES[key]; fileInput.value = ''; updateCount(); event.target.value = '';
  shareStatus.textContent = 'Example loaded. Click “Analyze code” to scan it.';
});
fileInput.addEventListener('change', async () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.c')) { showError('Please choose a .c source file.'); fileInput.value = ''; return; }
  if (file.size > 400000) { showError('That file is too large (limit about 400 KB).'); fileInput.value = ''; return; }
  codeInput.value = await file.text(); $('fileLabel').textContent = file.name; updateCount();
});

/* ---------------------------------------------------------------- analysis */
async function runAnalysis() {
  const source = codeInput.value;
  errorBox.hidden = true; emptyState.hidden = true; loadingBox.hidden = false; hideResultBlocks();
  analyzeButton.disabled = true; analyzeButton.textContent = 'Analyzing…'; setStatus('idle', 'Running');
  resultSubtitle.textContent = 'Parsing, running rules, compiler and ML…';
  try {
    const result = await postJson('/api/analyze', { code: source });
    state.result = result; state.analyzedSource = source;
    loadingBox.hidden = true;
    renderResults(result);
  } catch (error) {
    state.result = null;
    showError(error instanceof TypeError ? 'Could not reach the local analyzer. Check that the SecureCompile server is running.' : error.message);
  } finally {
    analyzeButton.disabled = false; analyzeButton.innerHTML = 'Analyze code <span>→</span>';
  }
}
analyzeForm.addEventListener('submit', (event) => { event.preventDefault(); runAnalysis(); });

function renderResults(result) {
  const syntaxCount = result.syntax_diagnostics.length;
  const mlOnly = result.findings.filter((f) => f.origin === 'ml').length;
  renderEngineStrip(result);
  const counts = result.counts || {};
  summary.hidden = false; clear(summary);
  for (const [label, key] of [['HIGH', 'high'], ['MEDIUM', 'medium'], ['LOW', 'low']]) {
    const item = el('div', `summary-item ${key}`); item.append(el('strong', '', counts[label] || 0), el('span', '', label)); summary.append(item);
  }
  const syn = el('div', 'summary-item syntax'); syn.append(el('strong', '', syntaxCount), el('span', '', 'SYNTAX')); summary.append(syn);
  resultSubtitle.textContent = `${result.total} finding${result.total === 1 ? '' : 's'}`
    + (mlOnly ? ` (${mlOnly} ML-only lead${mlOnly === 1 ? '' : 's'})` : '')
    + (syntaxCount ? `, ${syntaxCount} syntax diagnostic${syntaxCount === 1 ? '' : 's'} listed separately.` : '.')
    + (result.analysis_note ? ` ${result.analysis_note}` : '');
  if (result.parse.status === 'failed') setStatus('bad', 'Parse failed');
  else if (syntaxCount || result.total) setStatus('warn', result.total ? 'Review findings' : 'Syntax issues');
  else setStatus('good', 'No findings');
  renderSyntax(result);
  setupFilters(result);
  renderFindings();
  renderMl(result);
  renderCompiler(result);
  renderMemory(result.memory_model || []);
  $('resultsActions').hidden = false;
}

function renderEngineStrip(result) {
  const strip = $('engineStrip'); strip.hidden = false; clear(strip);
  const parseKind = { complete: 'good', recovered: 'warn', failed: 'bad' }[result.parse.status];
  strip.append(chip(`Parser: ${result.parse.status}${result.parse.diagnostic_count ? ` (${result.parse.diagnostic_count} diagnostics)` : ''}`, parseKind, result.analysis_mode));
  const c = result.compiler;
  if (c.ran) strip.append(chip(`${c.compiler}: ${c.error_count} error(s), ${c.warning_count} warning(s)`, c.error_count ? 'warn' : 'good', c.note));
  else strip.append(chip('Compiler: not run', 'idle', c.note));
  const ml = result.ml;
  if (ml.status === 'ok') strip.append(chip('ML: model loaded', 'good', ml.scope_note));
  else strip.append(chip(`ML: ${ml.status}`, 'idle', ml.message));
  if (result.disagreements.length) strip.append(chip(`${result.disagreements.length} engine disagreement(s) to review`, 'warn'));
}

function renderSyntax(result) {
  const panel = $('syntaxPanel'); clear(panel);
  const diags = result.syntax_diagnostics;
  if (!diags.length) { panel.hidden = true; return; }
  panel.hidden = false;
  panel.append(el('h3', '', 'Syntax diagnostics (separate from security findings)'));
  panel.append(el('p', 'compiler-note', 'These come from the parser, not the security rules. Findings below a syntax error carry higher uncertainty because that region may not have been parsed.'));
  diags.forEach((d) => {
    const row = el('div', 'diagnostic error');
    const head = el('div', 'diagnostic-head', `${d.kind.toUpperCase()} · line ${d.line}${d.column ? `, column ${d.column}` : ''}`);
    head.append(chip(d.classification || 'syntax', d.classification === 'unsupported-construct' ? 'idle' : 'warn', d.note || ''));
    head.append(chip(ENGINE_LABELS[d.engine] || d.engine, 'engine'));
    row.append(head, el('p', '', d.message));
    if (d.note) row.append(el('p', 'muted', d.note));
    if (d.recovery === 'semicolon-inserted') row.append(el('p', 'muted', 'Recovery: parsing continued as if ‘;’ were present. Your code was not changed.'));
    const jump = el('button', 'text-button', 'Show line'); jump.type = 'button'; jump.addEventListener('click', () => jumpToLine(d.line)); row.append(jump);
    panel.append(row);
  });
  if (result.syntax_repairs.length) {
    const button = el('button', 'secondary small', `Propose ${result.syntax_repairs.length} syntax repair${result.syntax_repairs.length === 1 ? '' : 's'} (preview only)`);
    button.type = 'button'; button.addEventListener('click', () => generateCorrected(button)); panel.append(button);
  }
}

/* ---------------------------------------------------------------- filters */
function setupFilters(result) {
  const bar = $('filterBar'); bar.hidden = !result.findings.length;
  const select = $('filterCategory'); const previous = select.value; clear(select);
  select.append(new Option('All categories', ''));
  [...new Set(result.findings.map((f) => f.category))].sort().forEach((c) => select.append(new Option(c, c)));
  select.value = [...select.options].some((o) => o.value === previous) ? previous : '';
}
function activeFilters() {
  return { q: $('filterSearch').value.trim().toLowerCase(), severity: $('filterSeverity').value, category: $('filterCategory').value,
    engine: $('filterEngine').value, review: $('filterReview').value, uncertain: $('filterUncertain').checked };
}
function passesFilters(f, flt) {
  if (flt.severity && f.severity !== flt.severity) return false;
  if (flt.category && f.category !== flt.category) return false;
  if (flt.engine && !f.engines.includes(flt.engine)) return false;
  if (flt.review && (!f.review || f.review.status !== flt.review)) return false;
  if (flt.uncertain && f.uncertainty.level === 'low') return false;
  if (flt.q) {
    const hay = [f.title, f.message, f.explanation, f.rule_id, f.cwe, f.category, f.evidence.snippet].join(' ').toLowerCase();
    if (!hay.includes(flt.q)) return false;
  }
  return true;
}
for (const id of ['filterSearch', 'filterSeverity', 'filterCategory', 'filterEngine', 'filterReview', 'filterUncertain']) {
  $(id).addEventListener(id === 'filterSearch' ? 'input' : 'change', () => state.result && renderFindings());
}
$('filterClear').addEventListener('click', () => {
  $('filterSearch').value = ''; for (const id of ['filterSeverity', 'filterCategory', 'filterEngine', 'filterReview']) $(id).value = '';
  $('filterUncertain').checked = false; if (state.result) renderFindings();
});

/* ---------------------------------------------------------------- findings */
function renderFindings() {
  clear(findingsBox);
  const result = state.result; if (!result) return;
  if (!result.findings.length) {
    const none = el('div', 'no-findings'); none.append(el('strong', '', 'No security findings from the implemented checks.'), el('br'),
      document.createTextNode('Syntax diagnostics, compiler output and security findings are reported separately. A clean result does not guarantee that code is secure.'));
    findingsBox.append(none); $('filterCount').textContent = ''; return;
  }
  const flt = activeFilters();
  const shown = result.findings.filter((f) => passesFilters(f, flt));
  $('filterCount').textContent = `Showing ${shown.length} of ${result.findings.length}`;
  if (!shown.length) { findingsBox.append(el('div', 'no-findings', 'No findings match the current filters.')); return; }
  shown.forEach((f) => findingsBox.append(findingCard(f)));
}

function findingCard(f) {
  const card = el('article', `finding${f.origin === 'ml' ? ' ml-origin' : ''}`);
  const top = el('div', 'finding-top'); const title = el('div');
  title.append(el('h3', '', f.title));
  title.append(el('div', 'rule-line', [f.rule_id || 'ML model', f.cwe, f.category].filter(Boolean).join(' · ')));
  top.append(title, el('span', `severity ${f.severity}`, f.severity)); card.append(top);

  const badges = el('div', 'badge-row');
  f.engines.forEach((e) => badges.append(chip(ENGINE_LABELS[e] || e, 'engine', 'Engine that reported this')));
  if (f.origin === 'rule') badges.append(chip(`Rule confidence: ${f.confidence}`, 'idle', 'Heuristic confidence of the rule, not a probability'));
  if (f.ml_confidence !== null && f.ml_confidence !== undefined) badges.append(chip(`ML confidence ${f.ml_confidence.toFixed(2)} (threshold ${f.ml_threshold.toFixed(2)})`, 'ml'));
  badges.append(chip(`Uncertainty: ${f.uncertainty.level}`, f.uncertainty.level === 'low' ? 'good' : f.uncertainty.level === 'medium' ? 'warn' : 'bad'));
  if (f.review) badges.append(chip({ agreement: 'Rules and ML agree', 'rule-only': 'Rule only', 'ml-only': 'ML only' }[f.review.status], f.review.status === 'agreement' ? 'good' : 'warn'));
  card.append(badges);

  card.append(el('p', '', f.message), el('p', '', f.explanation));
  if (f.review && f.review.status !== 'agreement') card.append(el('div', 'review-note', f.review.note));

  const loc = f.location;
  const where = loc.support === 'exact' ? `Line ${loc.line}, column ${loc.column} (exact)` : loc.support === 'line' ? `Line ${loc.line} (line-level)`
    : loc.support === 'function' ? `Function starting at line ${loc.line} (no specific line)` : 'No source location available';
  card.append(el('div', 'loc-line', where));
  card.append(el('pre', 'source-line', f.evidence.snippet ? `${loc.line ? String(loc.line).padStart(3, ' ') + ' | ' : ''}${f.evidence.snippet}` : 'Source line unavailable'));

  const details = el('details', 'engine-details'); details.append(el('summary', '', 'Why this level of uncertainty / engine reports'));
  const list = el('ul'); f.uncertainty.reasons.forEach((r) => list.append(el('li', '', r)));
  f.engine_reports.forEach((r) => list.append(el('li', '', `${ENGINE_LABELS[r.engine] || r.engine}: ${r.message}${typeof r.confidence === 'number' ? ` (score ${r.confidence})` : ` (confidence ${r.confidence})`}`)));
  details.append(list); card.append(details);

  const fix = el('div', 'fix'); fix.append(el('b', '', 'Suggested next step'), el('span', '', f.suggestion)); card.append(fix);

  const actions = el('div', 'finding-actions');
  const jump = el('button', 'text-button', f.line ? `Jump to line ${f.line}` : 'Show source'); jump.type = 'button';
  jump.addEventListener('click', () => jumpToLine(f.line)); actions.append(jump);
  const fixButton = el('button', 'text-button strong', 'Fix this issue'); fixButton.type = 'button';
  if (f.origin === 'ml') { fixButton.disabled = true; fixButton.title = 'Fixes are never generated from an ML prediction alone; they need rule evidence and source context.'; }
  else fixButton.addEventListener('click', () => fixFinding(f, fixButton));
  actions.append(fixButton); card.append(actions);
  return card;
}

/* ---------------------------------------------------------------- ML panel */
function renderMl(result) {
  const panel = $('mlPanel'); clear(panel); panel.hidden = false;
  panel.append(el('h3', '', 'ML predictions'));
  const ml = result.ml;
  if (ml.status !== 'ok') {
    panel.append(el('div', 'review-note', `ML analysis did not run (${ml.status}). ${ml.message || ''} Rule-based results above are unaffected.`)); return;
  }
  panel.append(el('p', 'compiler-note', `${ml.model.name} · features: ${ml.model.feature_set} · trained on ${ml.model.dataset}. ${ml.model.caveat} ${ml.scope_note}`));
  ml.scopes.forEach((scope) => {
    const details = el('details', 'engine-details');
    const label = scope.kind === 'function' ? `${scope.name}() lines ${scope.start_line}-${scope.end_line}` : 'Whole file';
    const sum = el('summary', '', `${label} — ${scope.predicted.length ? 'flagged: ' + scope.predicted.join(', ') : 'nothing above threshold'}`);
    details.append(sum);
    Object.entries(scope.probabilities).sort((a, b) => b[1] - a[1]).forEach(([cat, p]) => {
      const row = el('div', 'prob-row'); row.append(el('span', 'prob-name', cat));
      const bar = el('div', 'prob-bar'); const fill = el('div', `prob-fill${p >= ml.thresholds[cat] ? ' hit' : ''}`); fill.style.width = `${Math.round(p * 100)}%`;
      const mark = el('div', 'prob-threshold'); mark.style.left = `${Math.round(ml.thresholds[cat] * 100)}%`; mark.title = `threshold ${ml.thresholds[cat]}`;
      bar.append(fill, mark); row.append(bar, el('span', 'prob-val', p.toFixed(2))); details.append(row);
    });
    panel.append(details);
  });
}

/* ---------------------------------------------------------------- compiler + memory */
function renderCompiler(result) {
  const panel = $('compilerPanel'); clear(panel); panel.hidden = false;
  panel.append(el('h3', '', 'Compiler syntax & type diagnostics'));
  const c = result.compiler;
  panel.append(el('p', 'compiler-note', `${c.compiler || 'Compiler frontend'}: ${c.note || ''}`));
  if (!c.ran) return;
  if (!c.diagnostics.length) { panel.append(el('div', 'compiler-clean', 'No compiler diagnostics were reported for this source.')); return; }
  c.diagnostics.forEach((d) => {
    const row = el('div', `diagnostic ${d.severity}`);
    row.append(el('div', 'diagnostic-head', `${d.severity.toUpperCase()} · line ${d.line}, column ${d.column}`), el('p', '', d.message));
    const jump = el('button', 'text-button', 'Show line'); jump.type = 'button'; jump.addEventListener('click', () => jumpToLine(d.line)); row.append(jump);
    panel.append(row);
  });
}
function renderMemory(entries) {
  const panel = $('memoryPanel'), map = $('memoryMap'); clear(map);
  if (!entries.length) { panel.hidden = true; return; }
  panel.hidden = false;
  entries.forEach((item) => {
    const card = el('div', 'memory-node');
    card.append(el('span', 'memory-kind', 'POINTER / STACK'), el('strong', '', item.name), el('div', 'memory-arrow', '↓ points to'), el('div', 'memory-target', item.target), el('p', '', item.state));
    map.append(card);
  });
}

/* ---------------------------------------------------------------- fixes */
async function fixFinding(finding, button) {
  const label = button.textContent; button.disabled = true; button.textContent = 'Preparing fix…';
  try {
    const data = await postJson('/api/fix', { code: state.analyzedSource, finding_id: finding.id });
    state.proposal = { data, original: state.analyzedSource };
    renderFixPanel(data, `Fix: ${finding.title}`);
  } catch (error) { renderFixError(error.message); }
  finally { button.disabled = false; button.textContent = label; }
}
async function generateCorrected(button) {
  if (!state.result) return;
  const label = button.textContent; button.disabled = true; button.textContent = 'Generating…';
  try {
    const data = await postJson('/api/fix_all', { code: state.analyzedSource });
    state.proposal = { data, original: state.analyzedSource };
    renderFixPanel(data, 'Corrected code for the whole program');
  } catch (error) { renderFixError(error.message); }
  finally { button.disabled = false; button.textContent = label; }
}
$('fixAllButton').addEventListener('click', (event) => generateCorrected(event.currentTarget));

function renderFixError(message) {
  clear(fixPanel); fixPanel.hidden = false; fixPanel.append(el('h2', '', 'Fix could not be prepared'), el('div', 'error-box', message));
  fixPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
const CHECK_ICON = { passed: '✔', failed: '✖', warning: '⚠', skipped: '⏭' };

function renderFixPanel(data, heading) {
  clear(fixPanel); fixPanel.hidden = false;
  const head = el('div', 'fix-head'); head.append(el('h2', '', heading));
  if (data.validation) head.append(chip(`Validation: ${data.validation.status}`, { Passed: 'good', Failed: 'bad', 'Unable to verify': 'warn' }[data.validation.status]));
  fixPanel.append(head, el('p', 'compiler-note', data.note));
  fixPanel.append(el('p', 'micro-status', `Original SHA-256 ${data.original_sha256.slice(0, 16)}… (your code is unchanged until you click Apply)`));

  if (data.summary) fixPanel.append(el('p', 'fix-summary', data.summary));
  if (data.assumptions && data.assumptions.length) {
    const box = el('div', 'review-note'); box.append(el('b', '', 'Assumptions behind this change'));
    const ul = el('ul'); data.assumptions.forEach((a) => ul.append(el('li', '', a))); box.append(ul); fixPanel.append(box);
  }
  if (data.items && (data.items.length > 1 || !data.changed)) renderFixItems(data.items);

  if (data.changed) {
    fixPanel.append(el('h3', '', 'What changes and why'));
    data.changes.forEach((c) => {
      const row = el('div', 'change-row');
      row.append(el('div', 'change-title', `Line ${c.line}${c.rule_id ? ` · ${c.rule_id}` : ''}: ${c.explanation}`));
      row.append(el('pre', 'diff-line del', `- ${c.before.trim()}`), el('pre', 'diff-line add', `+ ${c.after.trim()}`));
      fixPanel.append(row);
    });
    fixPanel.append(el('h3', '', 'Original vs proposed (unified diff)'));
    const diff = el('pre', 'diff');
    data.diff.split('\n').forEach((line) => {
      const cls = line.startsWith('+++') || line.startsWith('---') ? 'meta' : line.startsWith('@@') ? 'hunk' : line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : '';
      diff.append(el('span', `d-line ${cls}`, line + '\n'));
    });
    fixPanel.append(diff);
  }
  if (data.validation) renderValidation(data.validation);

  const actions = el('div', 'fix-actions');
  if (data.changed) {
    const apply = el('button', 'primary small', 'Apply to editor'); apply.type = 'button'; apply.addEventListener('click', applyProposal);
    const copy = el('button', 'secondary small', 'Copy corrected code'); copy.type = 'button';
    copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(data.proposed_source); copy.textContent = 'Copied'; } catch { copy.textContent = 'Copy failed'; } });
    const save = el('button', 'secondary small', 'Download corrected.c'); save.type = 'button'; save.addEventListener('click', () => downloadText('corrected.c', data.proposed_source));
    actions.append(apply, copy, save);
  }
  const reject = el('button', 'secondary small', data.changed ? 'Reject proposal' : 'Dismiss'); reject.type = 'button';
  reject.addEventListener('click', () => { fixPanel.hidden = true; clear(fixPanel); state.proposal = null; });
  actions.append(reject); fixPanel.append(actions);
  fixPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderFixItems(items) {
  fixPanel.append(el('h3', '', 'Per-finding outcome'));
  const table = el('table', 'batch-table'); const thead = el('thead'); const hr = el('tr');
  ['Status', 'Rule', 'Line', 'What happens'].forEach((h) => hr.append(el('th', '', h))); thead.append(hr); table.append(thead);
  const tbody = el('tbody');
  const labels = { fixed: 'Fixed in proposal', 'review-required': 'Needs developer review', unavailable: 'No automatic fix', conflict: 'Skipped (conflict)' };
  items.forEach((item) => {
    const tr = el('tr'); const status = el('td'); status.append(chip(labels[item.status] || item.status, item.status === 'fixed' ? 'good' : 'warn'));
    const info = el('td'); info.append(el('div', '', item.summary || ''));
    if (item.reason) info.append(el('div', 'muted', item.reason));
    if (item.guidance) info.append(el('div', 'muted', item.guidance));
    if (item.guidance_snippet) info.append(el('pre', 'source-line', item.guidance_snippet));
    (item.assumptions || []).forEach((a) => info.append(el('div', 'muted', `Assumption: ${a}`)));
    tr.append(status, el('td', '', item.rule_id || ''), el('td', '', item.line || ''), info); tbody.append(tr);
  });
  table.append(tbody); fixPanel.append(table);
}

function renderValidation(v) {
  fixPanel.append(el('h3', '', 'Post-fix validation (only checks that actually ran)'));
  const list = el('ul', 'check-list');
  v.checks.forEach((c) => {
    const li = el('li', `check ${c.status}`); li.append(el('span', 'check-icon', CHECK_ICON[c.status] || '•'), el('b', '', ` ${c.name}: ${c.status}. `), document.createTextNode(c.detail)); list.append(li);
  });
  fixPanel.append(list);
  fixPanel.append(el('p', 'micro-status', `Ran: ${v.checks_run.join('; ') || 'nothing'}. Not run: ${v.checks_not_run.join('; ') || 'nothing'}.`));
  if (v.new_findings.length) {
    const box = el('div', 'error-box'); box.append(el('b', '', 'Newly introduced findings'));
    const ul = el('ul'); v.new_findings.forEach((f) => ul.append(el('li', '', `${f.rule_id} on line ${f.line}: ${f.message}`))); box.append(ul); fixPanel.append(box);
  }
  v.warnings.forEach((w) => fixPanel.append(el('div', 'review-note', w)));
  fixPanel.append(el('p', 'micro-status', v.disclaimer));
}

function applyProposal() {
  const proposal = state.proposal; if (!proposal) return;
  if (codeInput.value !== proposal.original && !confirm('The editor has changed since this proposal was generated. Applying it replaces your current edits (you can still restore the code the proposal was based on). Continue?')) return;
  state.restoreSource = proposal.original;
  codeInput.value = proposal.data.proposed_source; updateCount();
  restoreButton.hidden = false;
  shareStatus.textContent = 'Proposal applied to the editor and re-analyzed. Use “Restore original” to go back.';
  fixPanel.hidden = true; clear(fixPanel); state.proposal = null;
  runAnalysis();
}
restoreButton.addEventListener('click', () => {
  if (state.restoreSource === null) return;
  codeInput.value = state.restoreSource; state.restoreSource = null; restoreButton.hidden = true; updateCount();
  shareStatus.textContent = 'Original code restored.'; runAnalysis();
});
function downloadText(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/x-csrc' }));
  const a = el('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url);
}

/* ---------------------------------------------------------------- report + share + batch */
$('downloadButton').addEventListener('click', async () => {
  if (!state.result) return;
  try {
    const response = await fetch('/api/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source: state.analyzedSource }) });
    if (!response.ok) throw new Error();
    const blob = await response.blob(); const url = URL.createObjectURL(blob);
    const a = el('a'); a.href = url; a.download = 'securecompile_report.json'; a.click(); URL.revokeObjectURL(url);
  } catch { showError('The report could not be downloaded. Please rerun the analysis and try again.'); }
});
$('shareButton').addEventListener('click', async () => {
  const source = codeInput.value;
  if (!source.trim()) { shareStatus.textContent = 'Add code before creating a share link.'; return; }
  if (source.length > 5000) { shareStatus.textContent = 'This source is too large for a compact share link (limit 5,000 characters).'; return; }
  const bytes = new TextEncoder().encode(source); let binary = ''; bytes.forEach((b) => { binary += String.fromCharCode(b); });
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const link = `${location.origin}${location.pathname}#code=${encoded}`;
  try { await navigator.clipboard.writeText(link); shareStatus.textContent = 'Share link copied. It contains your code in the URL fragment; recipients need access to this website.'; }
  catch { shareStatus.textContent = 'Copy this link: ' + link; }
});
function loadCodeFromHash() {
  const match = location.hash.match(/#code=([A-Za-z0-9_-]+)/); if (!match) return;
  try {
    const binary = atob(match[1].replace(/-/g, '+').replace(/_/g, '/'));
    codeInput.value = new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0))); updateCount();
    shareStatus.textContent = 'Code loaded from this share link. Run analysis when ready.';
  } catch { shareStatus.textContent = 'The shared code fragment could not be decoded.'; }
}
$('batchButton').addEventListener('click', async () => {
  const input = $('batchFiles'), out = $('batchResults'), files = Array.from(input.files || []);
  out.hidden = false; clear(out);
  if (!files.length) { out.textContent = 'Select one or more .c files first.'; return; }
  out.append(el('h3', '', 'Multi-file review summary'));
  const rows = [];
  for (const file of files) {
    if (!file.name.toLowerCase().endsWith('.c')) continue;
    try {
      const r = await postJson('/api/analyze', { code: await file.text() });
      rows.push({ name: file.name, ok: true, total: r.total, high: r.counts.HIGH, syntax: r.syntax_diagnostics.length, errors: r.compiler.error_count || 0 });
    } catch { rows.push({ name: file.name, ok: false, total: 0, high: 0, syntax: 0, errors: 0 }); }
  }
  if (!rows.length) { out.textContent = 'No .c files were selected.'; return; }
  const table = el('table', 'batch-table'); const thead = el('thead'); const hr = el('tr');
  ['File', 'Findings', 'High', 'Syntax diagnostics', 'Compiler errors', 'Status'].forEach((h) => hr.append(el('th', '', h))); thead.append(hr); table.append(thead);
  const tbody = el('tbody');
  rows.forEach((r) => { const tr = el('tr'); [r.name, r.total, r.high, r.syntax, r.errors, r.ok ? 'Analyzed' : 'Failed'].forEach((v) => tr.append(el('td', '', v))); tbody.append(tr); });
  table.append(tbody); out.append(table);
});

/* ---------------------------------------------------------------- measured evaluation */
async function loadEvaluation() {
  const intro = $('evalIntro'), body = $('evalBody');
  try {
    const response = await fetch('/api/evaluation'); const data = await response.json();
    if (!data.available) { intro.textContent = data.message; return; }
    const fmt = (v) => (v === null || v === undefined ? 'n/a' : Number(v).toFixed(3));
    intro.textContent = `Measured on ${data.test_samples} held-out test functions (${data.dataset.name}, split seed ${data.dataset.split_seed}). Generated by src/ml/evaluate.py; the values below are read from that report.`;
    const table = el('table', 'batch-table'); const hr = el('tr');
    ['Configuration', 'Precision', 'Recall', 'Micro F1', '95% CI (micro F1)', 'Macro F1'].forEach((h) => hr.append(el('th', '', h)));
    const thead = el('thead'); thead.append(hr); table.append(thead); const tbody = el('tbody');
    [['Rule-based only', 'rule_only'], ['ML only', 'ml_only'], [`Hybrid (${data.hybrid_policy})`, 'hybrid']].forEach(([label, key]) => {
      const s = data.summary[key]; const ci = data.ci[key].micro_f1;
      const tr = el('tr'); [label, fmt(s.precision), fmt(s.recall), fmt(s.micro_f1), ci ? `${fmt(ci[0])} – ${fmt(ci[1])}` : 'n/a', fmt(s.macro_f1)].forEach((v) => tr.append(el('td', '', v))); tbody.append(tr);
    });
    table.append(tbody); clear(body); body.append(table);
    const s = data.sanity;
    const warn = el('div', 'review-note');
    warn.append(el('b', '', 'Read this before trusting the ML numbers. '),
      document.createTextNode(`Juliet is synthetic and templated, so these scores do not estimate real-world accuracy. On ${s.vulnerable_cases_in_ml_scope} hand-written vulnerable snippets outside Juliet, the ML model flagged the expected category in ${s.ml_detected_expected_category} and the rules in ${s.rules_detected_expected_category} (the rules were written for those snippets, so that figure is optimistic). Rule localisation: ${data.localisation.localised}/${data.localisation.detected_with_flaw_annotation} detected flaws were reported within ±${data.localisation.tolerance_lines} lines of the annotated flaw.`));
    body.append(warn);
    const det = el('details', 'engine-details'); det.append(el('summary', '', 'Per-category results (test split)'));
    const pt = el('table', 'batch-table'); const ph = el('tr');
    ['Category', 'Support', 'Rule F1 (FP/FN)', 'ML F1 (FP/FN)', 'Hybrid F1 (FP/FN)'].forEach((h) => ph.append(el('th', '', h)));
    const pth = el('thead'); pth.append(ph); pt.append(pth); const ptb = el('tbody');
    Object.keys(data.per_category.ml_only).forEach((cat) => {
      const cell = (k) => { const m = data.per_category[k][cat]; return `${fmt(m.f1)} (${m.fp}/${m.fn})`; };
      const tr = el('tr'); [cat, data.per_category.ml_only[cat].support, cell('rule_only'), cell('ml_only'), cell('hybrid')].forEach((v) => tr.append(el('td', '', v))); ptb.append(tr);
    });
    pt.append(ptb); det.append(pt); body.append(det);
  } catch { intro.textContent = 'Evaluation results could not be loaded.'; }
}

updateCount(); loadCodeFromHash(); loadEvaluation();
