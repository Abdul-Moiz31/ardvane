// @ts-check
import { api } from '../api.js';
import { h, button, pill, pageHead, skeleton, busy } from '../dom.js';
import { icon } from '../icons.js';
import { toast, confirmBox, showError } from '../feedback.js';
import { fmtTime, plural } from '../format.js';
import { ring } from '../charts.js';
import { S, applyTasks, loadTasks, fileManagerLabel } from '../store.js';
import { reveal } from '../actions.js';
import { fixesCard } from '../fixes.js';

/**
 * @typedef {{text: string, link: string, done: boolean}} Step
 * @typedef {{id: string, group: string, level: string, title: string, detail: string, link: string, steps: Step[],
 *   finding: string, path: string, created: number, done_at: number|null, resolution: string|null, reopened: string,
 *   status: 'open'|'done'|'scheduled', due_at: number|null, every_days?: number, auto: boolean}} Task
 */

const SECTIONS = [
  { key: 'incident', title: 'Recovery checklist', hint: 'Do these in order — cutting off access comes before cleaning.', icon: 'shieldAlert' },
  { key: 'finding', title: 'From your scans', hint: 'Each item the scans found, with what to do about it.', icon: 'radar' },
  { key: 'setup', title: 'Get set up', hint: 'One-time steps that make the next attack much harder.', icon: 'shield' },
  { key: 'routine', title: 'Routine checks', hint: 'Small habits that catch a compromise early.', icon: 'clock' },
];

export function renderTodo() {
  const head = pageHead('To-do', 'Practical steps from your scans and checks. Tick each one off when you\'ve done it.');
  if (!S.tasks) { loadTasks(); return [head, h('div', { class: 'card' }, skeleton(4))]; }
  const all = /** @type {Task[]} */ (S.tasks.tasks);
  const out = [head, fixesCard('Fix these first — the app can do it for you'), progress(all)];
  for (const sec of SECTIONS) {
    const items = all.filter(t => t.group === sec.key);
    const open = items.filter(t => t.status === 'open');
    if (!items.length) continue;
    const later = items.filter(t => t.status === 'scheduled');
    const done = items.filter(t => t.status === 'done');
    out.push(h('section', { class: 'stack' },
      h('div', { class: 'section-title' }, icon(sec.icon), h('h2', { text: sec.title }),
        open.length ? pill(sec.key === 'incident' || open.some(t => t.level === 'danger') ? 'danger' : 'warn', `${open.length} to do`) : pill('ok', 'All done', 'check'),
        h('span', { class: 'muted small grow', text: sec.hint })),
      open.length ? open.map(taskCard) : null,
      later.length ? collapsed(`Coming up (${later.length})`, later.map(taskCard)) : null,
      done.length ? collapsed(`Done (${done.length})`, done.map(taskCard)) : null));
  }
  return out;
}

/** @param {Task[]} all */
function progress(all) {
  const relevant = all.filter(t => t.status !== 'scheduled');
  const done = relevant.filter(t => t.status === 'done').length;
  const openCount = relevant.length - done;
  return h('div', { class: 'card card-pad row progress-card' }, ring(done, relevant.length || 1, { size: 64, label: `${done} of ${relevant.length} done` }),
    h('div', { class: 'grow' },
      h('h2', { text: openCount ? `${plural(openCount, 'step')} left` : 'Everything is done' }),
      h('p', { class: 'muted', text: openCount ? 'Work from the top: the most important steps come first.' : 'Nice work. Routine checks come back here when they\'re due.' })));
}

/** @param {string} label @param {Node[]} kids */
function collapsed(label, kids) {
  return h('details', { class: 'more' }, h('summary', { text: label }), h('div', { class: 'stack' }, kids));
}

/** @param {Task} t */
function taskCard(t) {
  const isDone = t.status !== 'open';
  const allTicked = t.steps.every(s => s.done);
  const ic = t.level === 'danger' ? 'xCircle' : t.level === 'warn' ? 'warn' : t.group === 'routine' ? 'clock' : 'checkCircle';
  const meta = t.status === 'done' ? (t.resolution === 'auto' ? 'Done automatically' : t.resolution === 'mine' ? `Marked as yours ${fmtTime(t.done_at)}` : `Done ${fmtTime(t.done_at)}`)
    : t.status === 'scheduled' ? `Next due ${fmtTime(t.due_at)}` : t.group === 'routine' ? `Every ${t.every_days} days` : t.created ? `Added ${fmtTime(t.created)}` : '';

  const steps = h('ol', { class: 'task-steps' }, t.steps.map((s, i) => {
    const box = /** @type {HTMLInputElement} */ (h('input', { type: 'checkbox', disabled: isDone || t.auto, 'aria-label': s.text }));
    box.checked = s.done || isDone;
    box.addEventListener('change', () => setStep(t, i, box.checked));
    return h('li', { class: s.done || isDone ? 'ticked' : '' }, h('label', { class: 'task-step' }, box, h('span', { text: s.text })), s.link ? stepLink(s.link) : null);
  }));

  const actions = h('div', { class: 'row task-actions' });
  if (!isDone && !t.auto) {
    const doneBtn = button(t.group === 'routine' ? 'Done for now' : 'Mark as done', () => busy(doneBtn, () => markDone(t, allTicked)), allTicked ? 'btn-primary btn-sm' : 'btn-sm', 'check');
    actions.append(doneBtn);
  }
  if (!isDone && t.group === 'finding' && t.level === 'warn') {
    actions.append(button('It\'s mine — not a problem', () => markMine(t), 'btn-ghost btn-sm', 'eyeOff'));
  }
  if (t.path && !isDone) actions.append(button(fileManagerLabel(), () => reveal(t.path), 'btn-ghost btn-sm', 'folder'));
  if (t.link) actions.append(h('a', { class: 'btn btn-ghost btn-sm', href: t.link }, icon('book'), 'Guide'));
  if (isDone && t.status === 'done' && !t.auto) actions.append(button('Undo', () => undo(t), 'btn-ghost btn-sm', 'refresh'));

  return h('article', { class: `task task-${t.level}${isDone ? ' task-done' : ''}` },
    h('div', { class: 'task-head' }, h('span', { class: 'ficon' }, icon(isDone ? 'checkCircle' : ic)),
      h('div', { class: 'grow' }, h('h3', { text: t.title }), h('div', { class: 'muted small', text: meta }))),
    t.reopened ? h('div', { class: 'reopened' }, icon('refresh'), t.reopened) : null,
    t.finding ? h('div', { class: 'task-finding mono', text: t.finding }) : null,
    h('p', { class: 'task-detail', text: t.detail }),
    isDone && t.status === 'done' ? null : steps,
    actions.childNodes.length ? actions : null);
}

/** @param {string} link */
function stepLink(link) {
  return /^https:\/\//.test(link)
    ? h('a', { class: 'step-link', href: link, target: '_blank', rel: 'noopener noreferrer' }, 'Open', icon('external'))
    : h('a', { class: 'step-link', href: link }, 'Open');
}

/** @param {Task} t @param {number} step @param {boolean} done */
async function setStep(t, step, done) {
  try { applyTasks(await api('/api/task', { id: t.id, step, done })); } catch (e) { showError(e); }
}

/** @param {Task} t @param {boolean} allTicked */
async function markDone(t, allTicked) {
  if (!allTicked && !await confirmBox('Mark as done?', 'Not every step is ticked. Have you really done all of them?', 'Yes, it\'s done')) return;
  try {
    applyTasks(await api('/api/task', { id: t.id, done: true }));
    toast(t.group === 'finding' || t.group === 'incident' ? 'Marked as done. Run a scan to confirm it\'s fixed — if it\'s still there, this comes back.' : 'Marked as done');
  } catch (e) { showError(e); }
}

/** @param {Task} t */
async function markMine(t) {
  try { applyTasks(await api('/api/task', { id: t.id, done: true, resolution: 'mine' })); toast('Hidden — it won\'t be reported again'); }
  catch (e) { showError(e); }
}

/** @param {Task} t */
async function undo(t) {
  try { applyTasks(await api('/api/task', { id: t.id, done: false })); } catch (e) { showError(e); }
}
