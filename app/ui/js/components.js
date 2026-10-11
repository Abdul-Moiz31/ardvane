// @ts-check
// Building blocks used on more than one page.
import { h, pill, button, linkButton, empty, skeleton } from './dom.js';
import { icon } from './icons.js';
import { fmtTime } from './format.js';
import { S, refresh } from './store.js';
import { installFlow } from './actions.js';
import { api } from './api.js';
import { toast, errorText } from './feedback.js';

/** @param {string} level */
export function levelPill(level) {
  /** @type {Record<string, HTMLElement>} */
  const map = { ok: pill('ok', 'Clean', 'check'), warn: pill('warn', 'Worth a look'), danger: pill('danger', 'Action needed') };
  return map[level] || pill('neutral', 'Unknown');
}

/**
 * @param {string} label @param {string} value @param {string} foot @param {string} ic @param {Node} [visual]
 */
export function tile(label, value, foot, ic, visual) {
  return h('div', { class: 'card tile' + (visual ? ' tile-visual' : '') },
    h('div', { class: 'grow' }, h('div', { class: 'tile-label' }, icon(ic), label), h('div', { class: 'tile-value', text: value }), h('div', { class: 'tile-foot', text: foot })),
    visual || null);
}

/**
 * A removable list (project folders, GitHub repositories): one row per item with an × button.
 * @param {string[]} items @param {string} ic @param {(item: string) => void} onRemove
 */
export function chipList(items, ic, onRemove) {
  return h('div', { class: 'chips' }, items.map(item => h('div', { class: 'chip' }, icon(ic), h('span', { class: 'mono', text: item }),
    button('', () => onRemove(item), 'btn-sm btn-ghost', 'x', { 'aria-label': 'Remove ' + item, title: 'Remove' }))));
}

/**
 * Change a saved list in Settings. Sends only the change ({add} / {remove}) or a whole new list, so a page showing an
 * out-of-date list can't drop entries. Returns the error text, or '' when saved.
 * @param {string} key 'folders' | 'github_repos' @param {string[]|{add: string}|{remove: string}} change @param {string} done
 */
export async function changeList(key, change, done) {
  try { await api('/api/settings', { [key]: change }); await refresh(); toast(done); return ''; }
  catch (e) { return errorText(e); }
}

/** @param {number} [limit] */
export function recentReports(limit = 5) {
  if (!S.reports) return skeleton(3);
  if (!S.reports.length) return empty('file', 'No reports yet. Your scans and daily checks will appear here.');
  return h('div', { class: 'list' }, S.reports.slice(0, limit).map(r =>
    h('div', { class: 'list-row clickable', role: 'link', tabindex: '0', onclick: () => openReport(r.id),
      onkeydown: /** @param {KeyboardEvent} e */ e => { if (e.key === 'Enter') openReport(r.id); } },
      h('div', { class: 'row-icon ' + (r.level === 'unknown' ? '' : r.level) }, icon(r.kind === 'daily' ? 'clock' : 'radar')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: r.kind === 'daily' ? 'Daily check' : 'Scan' }), h('div', { class: 'desc', text: fmtTime(r.time) })),
      levelPill(r.level))));
}

/** @param {string} id */
export function openReport(id) {
  S.reportId = id;
  S.reportText = '';
  location.hash = '#reports';
}

/**
 * Rows describing each protection. compact = overview (no descriptions or buttons).
 * @param {boolean} compact
 */
export function protectionRows(compact) {
  const p = S.data.protection;
  /** @param {boolean} b @param {string} [yes] @param {string} [no] */
  const status = (b, yes, no) => b ? pill('ok', yes || 'On', 'check') : pill('neutral', no || 'Off');
  /**
   * @param {string} ic @param {boolean} good @param {string} title @param {string} desc @param {HTMLElement} st @param {HTMLElement|null} [action]
   */
  const row = (ic, good, title, desc, st, action) => h('div', { class: 'list-row' },
    h('div', { class: 'row-icon ' + (good ? 'ok' : 'warn') }, icon(ic)),
    h('div', { class: 'grow' }, h('div', { class: 'title', text: title }), compact ? null : h('div', { class: 'desc', text: desc })),
    st, compact ? null : (action || null));
  const turnOn = (/** @type {string} */ label) => button(label, () => installFlow(), 'btn-sm');
  const rows = [
    row('code', p.installed && p.hooks, 'Scan every clone, pull and push',
      p.hooks_other ? `Your git uses its own hooks folder (${p.hooks_other}). Re-run the installer with --force-hooks to use the kit's hooks; yours are restored on uninstall.`
        : 'Infected repositories are flagged before you open them, and infected code can\'t be pushed.',
      status(p.installed && p.hooks), !p.installed ? button('Turn on', () => installFlow(), 'btn-sm btn-primary') : null),
    row('terminal', p.safeclone, 'Safe clone in the terminal', 'git clone checks a repository before any of its files are written to your disk.',
      status(p.safeclone), !p.safeclone ? turnOn('Turn on') : null),
    row('package', p.npm !== false, 'Block npm install scripts', 'Packages can\'t run code while they install. Allow it for one trusted project with npm install --ignore-scripts=false.',
      p.npm === null ? pill('neutral', 'npm not installed') : status(p.npm), p.npm === false ? turnOn('Turn on') : null),
  ];
  for (const e of p.editors) {
    const good = e.auto_tasks_off && e.trust_on;
    rows.push(row('code', good, `${e.editor}: nothing runs when you open a folder`, 'Automatic tasks are off and Workspace Trust is on, so opening a project can\'t start code.',
      status(good, 'Safe', 'Not hardened'), good ? null : turnOn('Harden')));
  }
  rows.push(row('clock', p.routine.on, 'Daily check', p.routine.on ? `Runs every day at ${p.routine.time}.` : 'Checks your computer, projects and protections every day.',
    status(p.routine.on, p.routine.time ? `Daily ${p.routine.time}` : 'On'), linkButton('Change', '#settings', 'btn-sm')));
  return rows;
}
