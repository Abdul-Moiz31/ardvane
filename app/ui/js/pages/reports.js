// @ts-check
import { errorText } from '../feedback.js';
import { api } from '../api.js';
import { h, card, pageHead, empty, skeleton } from '../dom.js';
import { fmtTime } from '../format.js';
import { history } from '../charts.js';
import { S, loadReports, rerender } from '../store.js';
import { levelPill } from '../components.js';

const FILTERS = [['all', 'All'], ['daily', 'Daily checks'], ['scan', 'Scans']];

export function renderReports() {
  const head = pageHead('Reports', 'Every scan and daily check, kept on this computer in ~/.checkrepo/reports.', filterTabs());
  if (!S.reports) { loadReports(); return [head, h('div', { class: 'card' }, skeleton(4))]; }
  const rows = S.reports.filter(r => S.reportFilter === 'all' || r.kind === S.reportFilter);
  if (!S.reportId && rows.length) S.reportId = rows[0].id;
  if (S.reportId && !S.reportText) loadReport(S.reportId);
  const list = h('div', { class: 'card' }, rows.length ? h('div', { class: 'side-list' }, rows.map(r =>
    h('button', { class: 'side-item' + (r.id === S.reportId ? ' active' : ''), type: 'button', onclick: () => { S.reportId = r.id; S.reportText = ''; rerender(); } },
      h('div', { class: 'row' }, h('strong', { text: r.kind === 'daily' ? 'Daily check' : 'Scan' }), h('div', { class: 'spacer' }), levelPill(r.level)),
      h('div', { class: 'muted small', text: fmtTime(r.time) })))) : empty('file', 'No reports yet.'));
  const view = h('div', { class: 'card' }, S.reportId ? h('pre', { class: 'report-text mono', text: S.reportText || 'Loading…' }) : empty('file', 'Choose a report.'));
  return [head, card('Last 90 days', 'chart', h('div', { class: 'card-pad' }, history(S.reports, 90))), h('div', { class: 'split' }, list, view)];
}

function filterTabs() {
  return h('div', { class: 'tabs', role: 'tablist' }, FILTERS.map(([k, label]) =>
    h('button', { class: S.reportFilter === k ? 'on' : '', type: 'button', role: 'tab', 'aria-selected': String(S.reportFilter === k),
      onclick: () => { S.reportFilter = k; S.reportId = ''; S.reportText = ''; rerender(); } }, label)));
}

/** @param {string} id */
async function loadReport(id) {
  try {
    const r = await api('/api/report?id=' + encodeURIComponent(id));
    if (S.reportId === id) S.reportText = r.text || '(empty report)';
  } catch (e) { S.reportText = errorText(e); }
  rerender();
}
