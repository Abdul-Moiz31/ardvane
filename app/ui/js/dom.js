// @ts-check
// Tiny DOM toolkit: every string goes in as text (never as HTML), so data can't inject markup.
import { icon } from './icons.js';

/**
 * querySelector for elements the page always contains.
 * @param {string} sel @param {ParentNode} [root] @returns {HTMLElement}
 */
export const $ = (sel, root) => /** @type {HTMLElement} */ ((root || document).querySelector(sel));

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function pill(level, text, ic) {
  return h('span', { class: 'pill ' + level }, ic ? icon(ic) : null, text);
}

export function button(label, onclick, cls, ic, attrs) {
  return h('button', Object.assign({ class: 'btn ' + (cls || ''), type: 'button', onclick }, attrs || {}), ic ? icon(ic) : null, label || null);
}

export function linkButton(label, href, cls, ic) {
  return h('a', { class: 'btn ' + (cls || ''), href }, ic ? icon(ic) : null, label);
}

export function switchEl(checked, onchange, label, disabled) {
  const input = h('input', { type: 'checkbox', role: 'switch', 'aria-label': label, onchange, disabled: !!disabled });
  input.checked = !!checked;
  return h('label', { class: 'switch' }, input, h('span'));
}

// A large radio / checkbox card
export function choice(type, on, title, desc, onpick, disabled, recommended) {
  const input = h('input', { type, checked: on, disabled: !!disabled, onchange: onpick });
  return h('label', { class: 'choice' + (on ? ' on' : '') + (disabled ? ' disabled' : '') }, input,
    h('span', { class: type === 'radio' ? 'radio' : 'checkbox' }),
    h('span', {}, h('div', { class: 'ctitle' }, title, recommended ? h('span', { class: 'badge-rec', text: 'Recommended' }) : null),
      h('div', { class: 'cdesc' }, desc)));
}

export function card(title, ic, body, extra) {
  return h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', {}, ic ? icon(ic) : null, title), extra || null),
    body);
}

export function banner(level, ic, title, text, action) {
  return h('div', { class: 'banner ' + level }, h('div', { class: 'bicon' }, icon(ic)),
    h('div', { class: 'grow' }, h('h3', { text: title }), text ? h('p', { text }) : null), action || null);
}

export function empty(ic, text) {
  return h('div', { class: 'empty' }, icon(ic), h('div', { text }));
}

export function skeleton(lines = 2) {
  return h('div', { class: 'card-pad stack' }, Array.from({ length: lines }, () => h('div', { class: 'skeleton' })));
}

export function pageHead(title, subtitle, side) {
  return h('div', { class: 'page-head' }, h('div', {}, h('h1', { text: title }), subtitle ? h('p', { text: subtitle }) : null), side || null);
}

// Show a spinner on a button while an async action runs
export async function busy(btn, fn) {
  const old = Array.from(btn.childNodes);
  btn.disabled = true;
  btn.replaceChildren(icon('spinner', 'spin'), h('span', { text: 'Working…' }));
  try { return await fn(); } finally { btn.disabled = false; btn.replaceChildren(...old); }
}
