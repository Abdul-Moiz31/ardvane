// @ts-check
// History: check every commit, branch and tag of a repository for malware, and clean it out of the history.
// The work is done by scanner/history.py in the background (app/backend/historyjob.py); this page starts it, shows
// progress and results, and asks for confirmation before anything is rewritten or pushed.
import { api } from '../api.js';
import { h, button, card, banner, pageHead, pill, busy } from '../dom.js';
import { icon } from '../icons.js';
import { modal, closeModal, toast, showError } from '../feedback.js';
import { fmtTime, plural } from '../format.js';
import { S, rerender } from '../store.js';

/** @type {number|null} */
let poller = null;

export function renderHistory() {
  if (S.hjob === undefined) { S.hjob = null; load(); }
  const j = S.hjob;
  return [
    pageHead('History', 'Malware committed to a repository stays in its history: in old commits, in branches nobody opens and in tags. Check every commit, then clean it out.'),
    picker(j),
    j ? jobView(j) : null,
    explainer(),
  ];
}

async function load() {
  try { S.hjob = (await api('/api/history')).job; } catch (e) { /* offline banner shows */ }
  if (S.hjob && S.hjob.running) poll();
  rerender();
}

function poll() {
  if (poller !== null) return;
  poller = window.setInterval(async () => {
    try {
      S.hjob = (await api('/api/history')).job;
      if (!S.hjob || !S.hjob.running) { if (poller !== null) window.clearInterval(poller); poller = null; done(); }
      rerender();
    } catch (e) { /* keep polling until it answers again */ }
  }, 1000);
}

function done() {
  const j = S.hjob;
  if (!j) return;
  if (j.error) return toast(j.error, 'danger');
  if (j.action === 'scan') toast(j.result.findings.some(/** @param {any} f */ f => f.severity === 'DANGER') ? 'Malware found in the history' : 'No malware in the history', j.result.findings.length ? 'danger' : 'ok');
  if (j.action === 'clean') toast(j.result.state === 'ready' ? 'Clean history ready - review it, then push' : 'Clean history prepared', 'ok');
  if (j.action === 'push') toast('The clean history was pushed', 'ok');
}

/** @param {string} action @param {string} target @param {string} [confirm] */
async function start(action, target, confirm) {
  try {
    S.hjob = (await api('/api/history', { action, target, confirm })).job;
    poll();
    rerender();
  } catch (e) { showError(e); }
}

/** @param {any} j */
function picker(j) {
  const repos = /** @type {string[]} */ (S.data.settings.github_repos || []);
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Repository to check',
    placeholder: 'owner/name, or a folder like ~/code/my-app', list: 'history-repos', value: S.historyDraft || '' }));
  input.addEventListener('input', () => { S.historyDraft = input.value; });
  const go = () => { const v = input.value.trim(); if (v) start('scan', v); };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  const running = !!(j && j.running);
  const choose = button('Choose folder…', async () => {
    try {
      const r = await api('/api/pick-folder', {});
      if (r.path) { S.historyDraft = r.path; rerender(); }
    } catch (e) { showError(e); }
  }, '', 'folder');
  return card('Check a repository', 'radar', h('div', { class: 'card-pad stack' },
    h('div', { class: 'row' }, input, choose, button('Check history', go, 'btn-primary', 'play', running ? { disabled: '' } : undefined)),
    h('datalist', { id: 'history-repos' }, repos.map(r => h('option', { value: r }))),
    h('p', { class: 'help', text: 'A local repository is read where it is. A GitHub repository is downloaded with its full history into a temporary folder, checked and deleted again - nothing is changed. Private repositories need the GitHub CLI (gh auth login).' })));
}

/** @param {any} j */
function jobView(j) {
  if (j.running) {
    const bar = h('div');
    bar.style.width = j.progress && j.progress[1] ? Math.max(4, Math.round(100 * j.progress[0] / j.progress[1])) + '%' : '8%';
    return card(j.action === 'scan' ? 'Checking the history' : j.action === 'clean' ? 'Preparing a clean history' : 'Pushing the clean history', 'radar',
      h('div', { class: 'card-pad stack' },
        h('div', { class: 'row' }, h('div', { class: 'loading-spinner' }), h('div', { class: 'grow' }, h('div', { class: 'title', text: j.target }),
          h('div', { class: 'help', text: j.phase }))),
        h('div', { class: 'progress' }, bar)),
      button('Stop', async () => { try { await api('/api/history/cancel', {}); } catch (e) { showError(e); } }, 'btn-ghost', 'stop'));
  }
  if (j.error) return banner('danger', 'alert', j.action === 'push' ? 'Nothing was pushed' : 'This didn\'t work', j.error);
  if (j.action === 'scan') return scanResult(j);
  if (j.action === 'clean') return planView(j.result, j);
  return pushed(j.result);
}

/** @param {any} j */
function scanResult(j) {
  const r = j.result, dangers = r.findings.filter(/** @param {any} f */ f => f.severity === 'DANGER');
  const head = h('div', { class: 'card-pad stack' },
    h('div', { class: 'row' },
      h('div', { class: 'row-icon ' + (dangers.length ? 'danger' : r.findings.length ? 'warn' : 'ok') }, icon(dangers.length ? 'shieldAlert' : 'shieldCheck')),
      h('div', { class: 'grow' },
        h('div', { class: 'title', text: dangers.length ? `Malware in the history of ${r.target}` : r.findings.length ? `Worth a look in ${r.target}` : `No malware in the history of ${r.target}` }),
        h('div', { class: 'help', text: `${plural(r.commits, 'commit')}, ${plural(r.refs, 'branch and tag', 'branches and tags')}, ${plural(r.checked, 'file version')} checked` })),
      dangers.length && r.github ? button('Clean history…', () => confirmClean(r.github, dangers.length), 'btn-danger-solid', 'shield') : null),
    dangers.length && !r.github ? h('p', { class: 'help', text: 'This repository has no GitHub remote, so Ardvane can\'t clean its history for you. Follow the cleanup guide, or check the GitHub repository instead.' }) : null,
    r.notes.length ? h('p', { class: 'help', text: r.notes.join(' · ') }) : null);
  const list = r.findings.length ? h('div', { class: 'list' }, r.findings.map(/** @param {any} f */ f =>
    h('div', { class: 'finding ' + (f.severity === 'DANGER' ? 'danger' : 'warn') },
      h('div', { class: 'ficon' }, icon(f.severity === 'DANGER' ? 'xCircle' : 'warn')),
      h('div', { class: 'ftext' }, h('strong', { text: f.path }), h('div', { text: f.detail }),
        h('div', { class: 'muted', text: f.where })),
      h('div', { class: 'factions' }, pill(f.live_refs.length ? 'danger' : 'warn', f.live_refs.length ? 'In current files' : 'Old commits only'))))) : null;
  return h('div', { class: 'card' }, head, list);
}

/** @param {string} repo @param {number} n */
function confirmClean(repo, n) {
  modal(`Clean the history of ${repo}?`, [
    h('p', { text: `Ardvane prepares a clean history for ${plural(n, 'malware finding')}. Nothing is pushed yet - you review the result first.` }),
    h('ol', { class: 'change-list' },
      h('li', { text: 'A complete backup of the repository is kept on this computer (~/.checkrepo/history).' }),
      h('li', { text: 'Every commit on every branch and tag is rewritten: files that are only malware are left out; your own files (a build config, .gitignore, package.json) lose only the injected part.' }),
      h('li', { text: 'The new history is checked again and must be clean. You see what changes on each branch.' })),
    h('p', { class: 'help', text: 'Only for repositories you administer on GitHub. Commit IDs change; signed commits lose their signature.' })],
    [button('Cancel', () => closeModal(), 'btn-ghost'), button('Prepare clean history', () => { closeModal(); start('clean', repo); }, 'btn-primary', 'shield')]);
}

/** @param {any} p @param {any} j */
function planView(p, j) {
  const refs = Object.entries(p.changes || {});
  const states = {
    'nothing-to-clean': ['ok', 'Nothing to clean', 'No malware was found in the history.'],
    'manual-only': ['warn', 'Can\'t be cleaned automatically', 'What was found (a malicious or hijacked package in package.json, for example) needs a person: update the dependency in a new commit.'],
    'still-infected': ['danger', 'Not clean yet', 'After rewriting, malware was still found - nothing will be pushed. See the cleanup guide.'],
    'unchanged': ['warn', 'Nothing changed', 'The rewrite didn\'t change any branch.'],
    ready: ['ok', 'Clean history ready', `${plural(refs.length, 'branch or tag', 'branches and tags')} will be replaced. Review the changes, then push.`],
  };
  const [lvl, title, text] = states[p.state] || ['warn', p.state, ''];
  const body = h('div', { class: 'card-pad stack' },
    banner(lvl, lvl === 'ok' ? 'shieldCheck' : 'alert', title, text,
      p.state === 'ready' ? button('Push clean history…', () => confirmPush(p), 'btn-danger-solid', 'shield') : null),
    h('p', { class: 'help mono', text: `Backup: ${p.workdir}/backup.git · prepared ${fmtTime(p.created)}` }),
    refs.length ? h('div', { class: 'list' }, refs.slice(0, 40).map(([ref, c]) => h('div', { class: 'list-row' },
      h('div', { class: 'grow' }, h('div', { class: 'title mono', text: ref.replace(/^refs\/(heads|tags)\//, '') }),
        h('div', { class: 'desc mono', text: /** @type {any} */ (c).files.slice(0, 6).join('   ') + (/** @type {any} */ (c).files.length > 6 ? '   …' : '') }))))) : null,
    p.manual && p.manual.length ? h('p', { class: 'help', text: 'Left for you: ' + p.manual.map(/** @param {any} m */ m => `${m.path} (${m.detail})`).join('; ') }) : null);
  return card(`History of ${j.target}`, 'shield', body);
}

/** @param {any} p */
function confirmPush(p) {
  const n = Object.keys(p.changes).length;
  const field = /** @type {HTMLInputElement} */ (h('input', { type: 'text', 'aria-label': 'Repository name', placeholder: p.target, autocomplete: 'off', spellcheck: 'false' }));
  const go = button(`Replace ${plural(n, 'branch and tag', 'branches and tags')}`, () => busy(go, async () => { closeModal(); await start('push', p.workdir, field.value.trim()); }), 'btn-danger-solid', 'shield', { disabled: '' });
  field.addEventListener('input', () => { /** @type {HTMLButtonElement} */ (go).disabled = field.value.trim() !== p.target; });
  modal(`Push the clean history to ${p.target}?`, [
    h('p', { text: 'This replaces the history on GitHub. It is refused if anyone pushed since it was prepared, and the backup stays on this computer.' }),
    h('ul', { class: 'change-list' },
      h('li', { text: 'Everyone who has a copy must clone the repository again; old copies still hold the malware.' }),
      h('li', { text: 'Branch protection that blocks force-pushes has to be relaxed for this push - turn it back on afterwards.' }),
      h('li', { text: 'Old commits stay reachable through pull requests and forks until GitHub Support removes them.' })),
    h('div', { class: 'field' }, h('label', { text: `Type ${p.target} to confirm` }), field)],
    [button('Cancel', () => closeModal(), 'btn-ghost'), go]);
}

/** @param {any} p */
function pushed(p) {
  return card('Clean history pushed', 'shieldCheck', h('div', { class: 'card-pad stack' },
    banner('ok', 'checkCircle', `${p.target}'s history is clean on GitHub`, `${plural(Object.keys(p.changes).length, 'branch and tag', 'branches and tags')} replaced. The backup stays in ${p.workdir}/backup.git.`),
    h('ol', { class: 'change-list' },
      h('li', { text: 'Clone the repository again on every computer; delete the old copies.' }),
      h('li', { text: 'Ask collaborators to do the same, and to rebase open work onto the new branches.' }),
      h('li', { text: 'Turn branch protection back on: block force-pushes and deletions.' }),
      h('li', {}, 'Ask GitHub Support to remove cached views and pull-request references of the old commits: ',
        h('a', { href: 'https://support.github.com/contact', target: '_blank', rel: 'noopener', text: 'support.github.com' })))));
}

function explainer() {
  return card('How cleaning works', 'info', h('div', { class: 'card-pad' }, h('ul', { class: 'help' },
    h('li', { text: 'Checking reads every distinct version of every file in the history with the same rules as a normal scan, and tells you whether malware is in a branch\'s current files or only in older commits.' }),
    h('li', { text: 'Cleaning works on a copy: a full backup is kept, the copy is rewritten, checked again, and only pushed after you confirm by typing the repository\'s name.' }),
    h('li', { text: 'Malicious or hijacked packages in package.json and lockfiles aren\'t rewritten out of history - update them in a new commit.' }))));
}
