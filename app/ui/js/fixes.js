// @ts-check
// Fixes the kit can make for you (scanner/autofix.py does the work). Shared by Overview, Scan, To-do and Protection.
import { api } from './api.js';
import { h, button, pill, card, busy, empty } from './dom.js';
import { icon } from './icons.js';
import { toast, modal, closeModal, showError } from './feedback.js';
import { fmtTime, plural } from './format.js';
import { S, rerender, refresh, loadOnce } from './store.js';

/**
 * @typedef {{id: string, kind: string, title: string, detail: string, auto: boolean, target: string, changes: string[], undoable: boolean}} Fix
 * @typedef {{id: string, fix: string, kind: string, title: string, target: string, how: string, time: number, ok: boolean,
 *   verified: boolean, undoable: boolean, undone_at: number|null, error?: string}} FixEntry
 */

const MALWARE_KINDS = ['quarantine', 'process'];
const STOLEN_NOTE = 'The malware is gone from this computer, but anything it stole before is still stolen. Keep going with the recovery checklist in your to-do list.';

export function loadFixes() {
  return loadOnce('fixes', async () => {
    try { S.fixes = await api('/api/fixes'); } catch (e) { S.fixes = { mode: 'ask', available: [], history: [] }; }
    rerender();
  });
}

/** @param {any} r */
async function applyResult(r) {
  S.fixes = r.fixes;
  await refresh();                       // protection status, to-do list and badges change after a fix
}

/** Ask, show exactly what will change, then fix. @param {Fix} f */
export function confirmFix(f) {
  const go = button(f.kind === 'process' ? 'Stop the process' : 'Fix it', () => busy(go, async () => {
    try {
      const r = await api('/api/fix', { id: f.id });
      const e = /** @type {FixEntry} */ (r.entry);
      closeModal();
      await applyResult(r);
      if (!e.ok) return showError(new Error(`${e.title}: ${e.error || 'failed'}`));
      toast(MALWARE_KINDS.includes(f.kind) ? `${e.title} — done. ${STOLEN_NOTE}` : `${e.title} — done${e.verified ? ' and checked' : ''}.`);
    } catch (err) { closeModal(); showError(err); }
  }), f.kind === 'process' ? 'btn-danger-solid' : 'btn-primary', 'check');
  modal(f.title, [
    h('p', { text: f.detail }),
    h('p', { class: 'strong', text: 'What will change:' }),
    h('ul', { class: 'change-list' }, f.changes.map(c => h('li', { text: c }))),
    h('p', { class: 'help', text: f.undoable ? 'You can undo this any time under Protection → Fix history.' : 'This can\'t be undone.' })],
  [button('Cancel', closeModal, 'btn-ghost'), go]);
}

/** Apply every fix that is safe enough for Automatic mode, after one confirmation. */
async function fixAllSafe() {
  const safe = /** @type {Fix[]} */ (S.fixes.available).filter(f => f.auto);
  const go = button(`Fix ${plural(safe.length, 'item')}`, () => busy(go, async () => {
    let failed = 0, malware = false;
    for (const f of safe) {
      try {
        const r = await api('/api/fix', { id: f.id });
        if (!r.entry.ok) failed++;
        malware = malware || MALWARE_KINDS.includes(f.kind);
        S.fixes = r.fixes;
      } catch (e) { failed++; }
    }
    closeModal();
    await refresh();
    toast(failed ? `${safe.length - failed} fixed, ${failed} failed — see Fix history` : `${plural(safe.length, 'item')} fixed.${malware ? ' ' + STOLEN_NOTE : ''}`, failed ? 'danger' : 'ok');
  }), 'btn-primary', 'check');
  modal('Fix all safe items?', [h('p', { text: 'These are the fixes that are safe enough to run on their own. Each one can be undone.' }),
    h('ul', { class: 'change-list' }, safe.map(f => h('li', { text: f.title })))], [button('Cancel', closeModal, 'btn-ghost'), go]);
}

/** Card listing what can be fixed now. Returns null when there's nothing (or fixes are off). @param {string} [title] */
export function fixesCard(title) {
  if (!S.fixes) { loadFixes(); return null; }
  if (S.fixes.mode === 'off' || !S.fixes.available.length) return null;
  const list = /** @type {Fix[]} */ (S.fixes.available);
  const safe = list.filter(f => f.auto);
  return card(title || `Can be fixed now · ${list.length}`, 'check', h('div', { class: 'list' }, list.map(f => h('div', { class: 'list-row' },
    h('div', { class: 'row-icon ' + (MALWARE_KINDS.includes(f.kind) ? 'danger' : 'warn') }, icon(f.kind === 'process' ? 'stop' : MALWARE_KINDS.includes(f.kind) ? 'shieldAlert' : 'settings')),
    h('div', { class: 'grow' }, h('div', { class: 'title', text: f.title }), h('div', { class: 'desc', text: f.detail })),
    f.auto ? pill('ok', 'Safe') : pill('warn', 'Check first'),
    button(f.kind === 'process' ? 'Stop…' : 'Fix…', () => confirmFix(f), 'btn-sm btn-primary')))),
  safe.length > 1 ? button(`Fix all ${safe.length} safe items`, () => fixAllSafe(), 'btn-sm') : null);
}

/** Banner after a scan in Automatic mode. @param {FixEntry[]} entries */
export function autofixedBanner(entries) {
  if (!entries || !entries.length) return null;
  const ok = entries.filter(e => e.ok), malware = ok.some(e => MALWARE_KINDS.includes(e.kind));
  return h('div', { class: 'banner ok' }, h('div', { class: 'bicon' }, icon('check')),
    h('div', { class: 'grow' }, h('h3', { text: `Fixed automatically: ${plural(ok.length, 'item')}` }),
      h('ul', { class: 'change-list' }, entries.map(e => h('li', { text: e.ok ? e.title : `${e.title} — failed: ${e.error}` }))),
      malware ? h('p', { text: STOLEN_NOTE }) : null),
    h('a', { class: 'btn btn-sm', href: '#protection' }, 'Fix history'));
}

/** Everything the fixer did, with undo. */
export function historyCard() {
  if (!S.fixes) { loadFixes(); return null; }
  const items = /** @type {FixEntry[]} */ (S.fixes.history);
  const body = items.length ? h('div', { class: 'list' }, items.map(e => {
    const state = e.undone_at ? pill('neutral', 'Undone') : e.ok ? pill('ok', e.verified ? 'Fixed · checked' : 'Fixed', 'check') : pill('danger', 'Failed');
    const undoBtn = e.ok && e.undoable && !e.undone_at ? button('Undo', () => busy(undoBtn, () => undo(e)), 'btn-sm btn-ghost', 'refresh') : null;
    return h('div', { class: 'list-row' },
      h('div', { class: 'row-icon ' + (e.ok && !e.undone_at ? 'ok' : '') }, icon(e.how === 'auto' ? 'clock' : 'check')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: e.title }),
        h('div', { class: 'desc', text: `${e.how === 'auto' ? 'Automatically' : 'By you'} · ${fmtTime(e.time)}${e.error ? ' · ' + e.error : ''}` })),
      state, undoBtn);
  })) : empty('check', 'Nothing has been fixed yet.');
  return card('Fix history', 'refresh', body, h('span', { class: 'muted small', text: 'Quarantined files: ~/.checkrepo/quarantine' }));
}

/** @param {FixEntry} e */
async function undo(e) {
  try { await applyResult(await api('/api/fix/undo', { id: e.id })); toast(`Undone: ${e.title}`); } catch (err) { showError(err); }
}
