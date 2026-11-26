// @ts-check
// Secrets: credentials that sit in plain text files, and the steps to move off them. Read-only: Ardvane never edits
// these files or shows a secret; it tells you which file holds one and what to do, in order.
import { api } from '../api.js';
import { h, button, card, banner, pageHead, pill } from '../dom.js';
import { icon } from '../icons.js';
import { errorText, toast } from '../feedback.js';
import { plural } from '../format.js';
import { S, rerender } from '../store.js';

export function renderSecrets() {
  if (S.secrets === undefined) { S.secrets = null; load(); }
  const s = S.secrets;
  return [
    pageHead('Secrets', 'Stealers and worms go straight for the same few files. A login in the keychain, or one that expires in hours, is much harder to take.',
      button('Check again', () => { S.secrets = undefined; rerender(); }, 'btn-sm', 'refresh')),
    !s ? card('Looking', 'lock', h('div', { class: 'card-pad' }, h('div', { class: 'skeleton' }))) :
      s.error ? banner('warn', 'alert', 'Couldn\'t check', s.error) :
      !s.items.length ? banner('ok', 'shieldCheck', 'No credentials in plain text', `Checked ${s.checked} well-known credential files in your home folder (AWS, GitHub CLI, npm, Docker, git, PyPI, Kubernetes, Google Cloud).`) :
      h('div', { class: 'stack' }, banner('warn', 'lock', `${plural(s.items.length, 'place')} keep${s.items.length === 1 ? 's' : ''} a credential in plain text`,
        'Ardvane only reads these files and never shows a secret. The steps below are yours to run, in order: the new login first, the old key last.'), s.items.map(item)),
    h('p', { class: 'help', text: 'Looks only at well-known files in your home folder. How old a file is shows when it last changed, which is a lower bound on how long its credential has been there.' }),
  ];
}

async function load() {
  try { S.secrets = await api('/api/secrets'); } catch (e) { S.secrets = { items: [], checked: 0, error: errorText(e) }; }
  rerender();
}

/** @param {any} it */
function item(it) {
  const age = it.age_days === null ? null : it.old ? pill('warn', `Not changed in ${it.age_days} days`, 'clock') : pill('neutral', `Changed ${it.age_days === 0 ? 'today' : it.age_days + ' days ago'}`, 'clock');
  return h('div', { class: 'card' },
    h('div', { class: 'card-pad stack' },
      h('div', { class: 'row' }, h('div', { class: 'row-icon warn' }, icon('lock')),
        h('div', { class: 'grow' }, h('div', { class: 'title', text: it.title }), h('div', { class: 'desc mono', text: it.path })),
        age, it.readable_by_others ? pill('danger', 'Readable by other users') : null),
      h('p', { text: it.summary }),
      it.detail.length ? h('ul', { class: 'help mono' }, it.detail.map(/** @param {string} d */ d => h('li', { text: d }))) : null,
      h('p', { class: 'help', text: it.why }),
      h('div', { class: 'section-head', text: 'What to do, in order' }),
      h('ol', { class: 'change-list' }, it.steps.map(/** @param {string} s */ s => h('li', { text: s }))),
      it.links.length ? h('div', { class: 'row' }, it.links.map(/** @param {string[]} l */ l => h('a', { class: 'btn btn-sm', href: l[1], target: '_blank', rel: 'noopener' }, icon('code'), l[0]))) : null,
      h('div', { class: 'row' }, button('Copy the steps', async () => {
        try { await navigator.clipboard.writeText(it.title + '\n' + it.path + '\n\n' + it.steps.map(/** @param {string} s @param {number} i */ (s, i) => `${i + 1}. ${s}`).join('\n')); toast('Steps copied'); } catch (e) { toast(errorText(e), 'danger'); }
      }, 'btn-sm btn-ghost', 'file'))));
}
