// @ts-check
import { api } from '../api.js';
import { h, button, banner, pageHead, skeleton } from '../dom.js';
import { showError, errorText } from '../feedback.js';
import { markdown } from '../markdown.js';
import { S, rerender, INFECTED_GUIDE } from '../store.js';

const START = INFECTED_GUIDE.replace('#learn/', '');
const REPO_URL = 'https://github.com/Abdul-Moiz31/ardvane/blob/main/';

/** @param {string} sub path of the guide inside docs/ */
export function renderLearn(sub) {
  const head = pageHead('Learn', 'How these attacks work, and exactly what to do if you\'re hit. Works offline.');
  if (!S.docs) {
    api('/api/docs').then(r => { S.docs = r.docs; rerender(); }).catch(e => showError(e));
    return [head, h('div', { class: 'card' }, skeleton(4))];
  }
  const path = sub || START;
  if (path !== S.docPath) loadDoc(path);
  const urgent = banner('danger', 'alert', 'Think you\'re infected right now?', 'Cut off the attacker\'s access before cleaning anything — the order of the steps matters.',
    path !== START ? button('Start here', () => { location.hash = INFECTED_GUIDE; }, 'btn-danger-solid') : undefined);
  return [head, urgent, h('div', { class: 'split' }, nav(path), h('div', { class: 'card' }, article(path)))];
}

/** @param {string} path */
function loadDoc(path) {
  S.docPath = path;
  S.docText = '';
  api('/api/doc?path=' + encodeURIComponent(path))
    .then(r => { if (S.docPath === path) { S.docText = r.text; rerender(); } })
    .catch(e => { S.docText = '# Not found\n\n' + errorText(e); rerender(); });
}

/** @param {string} current */
function nav(current) {
  const list = h('nav', { class: 'card side-list', 'aria-label': 'Guides' });
  let group = '';
  for (const d of S.docs || []) {
    if (d.group !== group) { group = d.group; list.append(h('div', { class: 'side-group', text: group })); }
    list.append(h('a', { class: 'side-item' + (d.path === current ? ' active' : ''), href: '#learn/' + d.path }, d.title));
  }
  return list;
}

/** @param {string} path */
function article(path) {
  const doc = h('article', { class: 'doc' });
  if (!S.docText) { doc.append(h('div', { class: 'skeleton' })); return doc; }
  doc.innerHTML = markdown(S.docText);            // markdown() escapes all text; only its own tags are produced
  doc.querySelectorAll('a[data-md-link]').forEach(a => fixLink(/** @type {HTMLAnchorElement} */ (a), path));
  return doc;
}

/** Turn a relative link inside a guide into an in-app link, or an external link to the repository. */
function fixLink(/** @type {HTMLAnchorElement} */ a, /** @type {string} */ from) {
  const href = a.getAttribute('href') || '';
  const external = () => { a.target = '_blank'; a.rel = 'noopener noreferrer'; };
  if (/^https:\/\//.test(href)) return external();
  if (!/^[\w./#-]+$/.test(href) || href.startsWith('#')) { a.removeAttribute('href'); return; }   // nothing else is a link
  const parts = ('docs/' + from).split('/');
  parts.pop();
  for (const seg of href.split('#')[0].split('/')) { if (seg === '..') parts.pop(); else if (seg && seg !== '.') parts.push(seg); }
  const full = parts.join('/');
  const known = (/** @type {string} */ p) => (S.docs || []).some(d => 'docs/' + d.path === p);
  if (known(full)) a.setAttribute('href', '#learn/' + full.slice(5));
  else if (known(full + '/README.md')) a.setAttribute('href', '#learn/' + full.slice(5) + '/README.md');
  else { a.setAttribute('href', REPO_URL + full); external(); }
}
