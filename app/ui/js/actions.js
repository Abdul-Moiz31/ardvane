// @ts-check
// User actions shared by several pages: protection, daily check, app icon, scans.
import { api } from './api.js';
import { h, button, busy, $ } from './dom.js';
import { toast, modal, closeModal, confirmBox, outputBox, showError, errorText } from './feedback.js';
import { plural } from './format.js';
import { S, refresh, rerender } from './store.js';

/** What the installer does, in plain language (the exact steps are shown underneath). */
const INSTALL_CHANGES = [
  'Installs the read-only scanner in a hidden folder in your home folder (.checkrepo).',
  'Tells git to check every clone, pull and checkout, and to block pushes that contain malware.',
  'Makes "git clone" in the terminal check a repository before its files are written.',
  'Stops npm packages from running scripts while they install.',
  'Turns off automatic tasks in VS Code, Cursor and Windsurf, and keeps Workspace Trust on.',
];

/** Preview the installer's exact changes, then apply them. @param {boolean} [update] */
export async function installFlow(update) {
  const title = update ? 'Update protection' : 'Turn on protection';
  modal(title, [h('p', { text: 'Checking what will change on your computer…' }), h('div', { class: 'skeleton' })], [button('Cancel', closeModal, 'btn-ghost')]);
  let preview;
  try { preview = await api('/api/preview-install'); } catch (e) { return outputBox(title, false, errorText(e)); }
  const go = button(update ? 'Update' : 'Turn on protection', () => busy(go, async () => {
    try {
      const r = await api('/api/protect', { action: 'install' });
      await refresh();
      if (!r.ok) return outputBox(title, false, r.output);
      closeModal();
      toast(update ? 'Protection updated' : 'Protection is on. Open a new terminal window for safe clone to start working.');
      if (!S.data.protection.routine.on && S.data.protection.routine.available) offerRoutine();
    } catch (e) { outputBox(title, false, errorText(e)); }
  }), 'btn-primary', 'shield');
  modal(title, [
    h('p', { text: 'This is what will change. Every file that is edited is backed up first, and "Remove protection" undoes all of it.' }),
    h('ul', { class: 'change-list' }, INSTALL_CHANGES.map(t => h('li', { text: t }))),
    h('details', { class: 'tech' }, h('summary', { text: 'Show the exact technical steps' }), h('pre', { text: String(preview.output || '').trim() }))],
  [button('Cancel', closeModal, 'btn-ghost'), go]);
}

export async function uninstallFlow() {
  if (!await confirmBox('Remove protection?', 'Git hooks, safe clone and the daily check will be turned off and your previous settings restored. Your reports stay on this computer.', 'Remove protection', true)) return;
  try {
    const r = await api('/api/protect', { action: 'uninstall' });
    await refresh();
    r.ok ? toast('Protection removed') : outputBox('Remove protection', false, r.output);
  } catch (e) { showError(e); }
}

function offerRoutine() {
  const t = h('input', { type: 'time', value: '09:00', 'aria-label': 'Daily check time' });
  modal('Check your computer every day?', [
    h('p', { text: 'A short, read-only check runs at this time every day and shows a notification with the result.' }),
    h('div', { class: 'row' }, h('label', { text: 'Time' }), t)],
  [button('Not now', closeModal, 'btn-ghost'),
    button('Schedule daily check', async () => { closeModal(); await setRoutine(true, /** @type {HTMLInputElement} */ (t).value); }, 'btn-primary', 'clock')]);
}

/**
 * @param {boolean} on
 * @param {string|null} time "HH:MM"
 * @param {HTMLElement} [btn]
 */
export async function setRoutine(on, time, btn) {
  if (on && !S.data.protection.installed) {
    if (await confirmBox('Turn on protection first', 'The daily check uses the installed scanner. Turn on protection now? You\'ll see every change before it\'s made.', 'Continue')) installFlow();
    return;
  }
  const run = async () => {
    try {
      const r = await api('/api/routine', { on, time: time || '09:00' });
      await refresh();
      r.ok ? toast(on ? `Daily check set for ${time} every day` : 'Daily check turned off') : outputBox('Daily check', false, r.output);
    } catch (e) { showError(e); }
  };
  return btn ? busy(btn, run) : run();
}

/** @param {'install'|'remove'} action @param {HTMLElement} btn */
export async function launcherAction(action, btn) {
  await busy(btn, async () => {
    try {
      const r = await api('/api/launcher', { action });
      await refresh();
      r.ok ? toast(r.output) : outputBox('App icon', false, r.output);
    } catch (e) { showError(e); }
  });
}

/** @type {number|null} */
let pollTimer = null;

/** Poll the running scan once a second; tell the user when it's done. */
export function pollScan() {
  if (pollTimer !== null) return;
  pollTimer = window.setInterval(async () => {
    try {
      const wasRunning = !!(S.scan && S.scan.running);
      S.scan = (await api('/api/scan')).scan;
      if (S.scan && S.scan.running) return rerender();
      if (pollTimer !== null) window.clearInterval(pollTimer);
      pollTimer = null;
      if (!wasRunning || !S.scan) return rerender();
      S.reports = null;
      await refresh();
      if (S.scan.cancelled) return;
      const sc = S.scan;
      toast(sc.danger ? `Scan finished: ${plural(sc.danger, 'serious finding')}` : sc.warn ? `Scan finished: no malware, ${plural(sc.warn, 'item')} worth a look` : 'Scan finished: no signs of malware',
        sc.danger ? 'danger' : 'ok');
    } catch (e) { /* the offline banner is already showing */ }
  }, 1000);
}

/** @param {string} [mode] 'full' | 'quick' */
export async function startScan(mode) {
  const o = S.scanOpts, set = S.data.settings;
  const folders = o.where === 'folders' && (mode || o.mode) === 'full'
    ? set.folders.map(/** @param {string} f */ f => f.replace(/^~(?=$|[\\/])/, S.data.home)) : [];
  try {
    const r = await api('/api/scan', { mode: mode || o.mode, folders, github: !!(o.github && set.github_user) });
    S.scan = r.scan;
    S.showPassed = false;
    location.hash = '#scan';
    rerender();
    pollScan();
  } catch (e) { showError(e); }
}

export async function cancelScan() {
  try { await api('/api/scan/cancel', {}); } catch (e) { showError(e); }
}

/** @param {string} path */
export async function reveal(path) {
  try { await api('/api/reveal', { path }); } catch (e) { showError(e); }
}

/** @param {string} key @param {boolean} undo */
export async function dismiss(key, undo) {
  try {
    await api('/api/dismiss', { key, undo });
    S.scan = (await api('/api/scan')).scan;
    S.tasks = null;                      // the matching to-do closes (or reopens) too
    rerender();
  } catch (e) { showError(e); }
}

/** @param {boolean} off */
export function setOfflineBanner(off) { const el = $('#offline'); if (el) el.hidden = !off; }
