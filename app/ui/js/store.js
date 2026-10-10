// @ts-check
// Shared state and the status rules every page uses.
import { api } from './api.js';
import { plural, duration } from './format.js';

/**
 * @typedef {{level: 'danger'|'warn'|'ok'|'info', text: string, path: string, key: string, dismissed: boolean}} Finding
 * @typedef {{title: string, items: Finding[]}} Section
 * @typedef {{id: string, mode: string, running: boolean, cancelled: boolean, phase: string, started: number, finished: number|null,
 *   progress: string|null, report: string|null, steps_total: number, steps_done: number, sections: Section[], github_user: string,
 *   danger: number, warn: number, ok: number}} Scan
 * @typedef {{id: string, kind: string, time: number, verdict: string, level: string, danger: number, warn: number}} Report
 */

export const S = {
  /** @type {any} */ data: null,
  /** @type {Scan|null} */ scan: null,
  /** @type {Report[]|null} */ reports: null,
  /** @type {{group: string, path: string, title: string}[]|null} */ docs: null,
  /** @type {any} */ tasks: null,
  docPath: '', docText: '', reportId: '', reportText: '', reportFilter: 'all', showPassed: false, folderErr: '',
  scanOpts: { mode: 'full', where: 'home', /** @type {boolean|null} */ github: null },
};

/** @type {() => void} */
let renderer = () => {};
/** @param {() => void} fn */
export function setRenderer(fn) { renderer = fn; }
export function rerender() { renderer(); }

export async function refresh() {
  S.data = await api('/api/state');
  S.scan = S.data.scan;
  S.tasks = null;                        // the list may have changed (new findings, protection switched on)
  if (S.scanOpts.github === null) S.scanOpts.github = !!S.data.settings.github_enabled;
  document.querySelectorAll('[data-app-name]').forEach(el => { el.textContent = S.data.app; });
  document.title = S.data.app;
  rerender();
}

/** Use a fresh task list everywhere: the To-do page, the menu badge and the overview. @param {any} list */
export function applyTasks(list) {
  S.tasks = list;
  if (S.data) S.data.todo = list.counts;
  rerender();
}

export async function loadTasks() {
  try { applyTasks(await api('/api/tasks')); } catch (e) { applyTasks({ tasks: [], counts: { open: 0 } }); }
}

export async function loadReports() {
  try { S.reports = (await api('/api/reports')).reports; } catch (e) { S.reports = []; }
  rerender();
}

/** Route of the recovery guide, linked from every DANGER result. */
export const INFECTED_GUIDE = '#learn/after-a-scan/if-danger-found.md';

export const STEP_NAMES = ['Known malware locations', 'Running processes', 'Programs that start automatically',
  'Shell startup files and hosts file', 'Connections to known attacker servers', 'Code editor settings and extensions',
  'Your projects', 'Known malicious packages', 'Built-in protections'];

export const fileManagerLabel = () => (S.data && S.data.os === 'windows') ? 'Show in Explorer' : (S.data && S.data.os === 'mac') ? 'Show in Finder' : 'Show folder';

/** The newest result: this session's scan or the last daily check. */
export function latestResult() {
  const sc = S.scan && !S.scan.running && !S.scan.cancelled ? S.scan : null;
  const daily = S.data.last_daily;
  const fromScan = sc ? { kind: 'scan', time: sc.finished || 0, level: sc.danger ? 'danger' : sc.warn ? 'warn' : 'ok', danger: sc.danger, warn: sc.warn, verdict: '' } : null;
  const fromDaily = daily ? { kind: 'daily', time: daily.time, level: daily.level, danger: daily.danger, warn: daily.warn, verdict: daily.verdict } : null;
  if (fromScan && (!fromDaily || fromScan.time >= fromDaily.time)) return fromScan;
  return fromDaily;
}

/** @param {any} p */
export function protectionItems(p) {
  return [
    { key: 'hooks', on: p.installed && p.hooks },
    { key: 'safeclone', on: p.safeclone },
    { key: 'npm', on: p.npm !== false },
    { key: 'editors', on: p.editors.every(/** @param {any} e */ e => e.auto_tasks_off && e.trust_on) },
    { key: 'routine', on: p.routine.on },
  ];
}
/** @param {any} p */
export function protectionCount(p) {
  const items = protectionItems(p);
  return { on: items.filter(i => i.on).length, total: items.length };
}

/** Headline for the overview: tone, icon, title, text and an optional fix. */
export function heroState() {
  const p = S.data.protection, r = latestResult();
  if (S.scan && S.scan.running) return { tone: 'neutral', icon: 'radar', title: 'Scanning your computer…',
    text: `Step ${Math.min(S.scan.steps_done + 1, S.scan.steps_total)} of ${S.scan.steps_total} · ${duration(S.scan.started)}` };
  if (r && r.level === 'danger') return { tone: 'danger', icon: 'shieldAlert', title: 'Action needed',
    text: r.kind === 'scan' ? `${plural(r.danger, 'serious finding')}. Don't open the affected projects or run npm install in them.` : r.verdict };
  const todo = S.data.todo;
  if (todo && todo.incident_total && todo.incident_done < todo.incident_total) return { tone: 'danger', icon: 'shieldAlert', fix: 'todo',
    title: 'Finish your recovery checklist', text: `${todo.incident_done} of ${todo.incident_total} recovery steps done. Until they're all done, the attacker may still have access.` };
  if (!p.installed) return { tone: 'warn', icon: 'shield', fix: 'protect',
    title: r && r.level === 'ok' ? 'Clean — but automatic protection is off' : 'Automatic protection is off',
    text: 'Clones, pulls and pushes aren\'t checked yet. Turning protection on takes about a minute.' };
  if (!p.hooks) return { tone: 'warn', icon: 'shieldAlert', fix: 'protect', title: 'Git protection is switched off',
    text: p.hooks_other ? `Your git uses its own hooks folder (${p.hooks_other}), so clones and pushes aren't checked.`
      : 'Something turned off the git hooks. Turn protection on again.' };
  if (r && r.level === 'warn') return { tone: 'warn', icon: 'shieldCheck', title: 'No malware found — some items are worth a look',
    text: r.kind === 'scan' ? `${plural(r.warn, 'item')} to review. They're often harmless — something you installed yourself.` : r.verdict };
  if (r && r.level === 'ok') return { tone: 'ok', icon: 'shieldCheck', title: "You're protected",
    text: 'No signs of malware, and every clone, pull and push is checked automatically.' };
  return { tone: 'neutral', icon: 'shield', title: 'Run your first scan',
    text: 'A full scan checks this computer and every project in your home folder. It only reads files — nothing is changed.' };
}

export function scopeText() {
  const s = S.data.settings;
  return `this computer, ${plural(s.folders.length, 'project folder')}` + (s.github_enabled && s.github_user ? ` and GitHub @${s.github_user}` : '');
}
