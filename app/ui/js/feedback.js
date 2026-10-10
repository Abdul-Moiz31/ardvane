// @ts-check
// Toast messages and modal dialogs.
import { $, h, button } from './dom.js';
import { icon } from './icons.js';

/** Message of any thrown value. @param {unknown} e */
export function errorText(e) { return e instanceof Error ? e.message : String(e); }

/** Show an error as a red toast. @param {unknown} e */
export function showError(e) { toast(errorText(e), 'danger'); }

/** @param {string} text @param {'ok'|'danger'} [level] */
export function toast(text, level = 'ok') {
  const t = h('div', { class: 'toast ' + level, role: 'status' }, icon(level === 'danger' ? 'xCircle' : 'checkCircle'), h('div', { text }));
  $('#toasts').append(t);
  setTimeout(() => t.remove(), level === 'danger' ? 8000 : 4500);
}

let lastFocus = null;
export function modal(title, body, actions) {
  lastFocus = document.activeElement;
  $('#modal-title').textContent = title;
  $('#modal-body').replaceChildren(...[].concat(body).filter(Boolean));
  $('#modal-actions').replaceChildren(...actions);
  $('#modal').hidden = false;
  (actions[actions.length - 1] || $('#modal')).focus();
}

export function closeModal() {
  $('#modal').hidden = true;
  if (lastFocus && lastFocus.focus) lastFocus.focus();
}

export function confirmBox(title, text, okLabel, danger) {
  return new Promise(resolve => {
    const done = v => { closeModal(); resolve(v); };
    modal(title, h('p', { text }), [
      button('Cancel', () => done(false), 'btn-ghost'),
      button(okLabel, () => done(true), danger ? 'btn-danger-solid' : 'btn-primary'),
    ]);
  });
}

export function outputBox(title, ok, output, after) {
  modal(title, [h('p', { text: ok ? 'Done.' : 'Something went wrong — the details are below.' }), output ? h('pre', { text: output }) : null],
    [button('Close', () => { closeModal(); if (after) after(); }, 'btn-primary')]);
}

export function initModal() {
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#modal').hidden) closeModal(); });
  $('#modal').addEventListener('click', e => { if (/** @type {HTMLElement} */ (e.target).id === 'modal') closeModal(); });
}
