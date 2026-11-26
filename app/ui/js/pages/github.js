// @ts-check
// GitHub: block force pushes on your repositories, and tell the owner of a shared repository what you found in it.
// Both are done by scanner scripts the command line runs too (github_protect.py, report_owner.py); this page asks
// before anything is changed, and shows exactly what will be sent.
import { api } from '../api.js';
import { h, button, card, banner, pageHead, pill, busy } from '../dom.js';
import { icon } from '../icons.js';
import { modal, closeModal, toast, showError, errorText } from '../feedback.js';
import { plural } from '../format.js';
import { S, rerender } from '../store.js';

/** @type {number|null} */
let poller = null;

export function renderGithub() {
  if (S.ghBranches === undefined) { S.ghBranches = null; loadBranches(); }
  if (S.rjob === undefined) { S.rjob = null; loadReport(); }
  return [
    pageHead('GitHub', 'Make a stolen token less useful, and warn the people whose repositories you can reach.'),
    !S.data.settings.gh ? banner('warn', 'github', 'The GitHub CLI isn\'t installed',
      'Both tools below use your signed-in GitHub CLI, so your token stays inside it. Install it from cli.github.com, run gh auth login in a terminal, then come back.') : null,
    protectCard(),
    ownerCard(),
  ];
}

async function loadBranches() {
  try { S.ghBranches = await api('/api/github/branches'); } catch (e) { S.ghBranches = { exposed: [], protected: [], gh: false, audited: null, err: errorText(e) }; }
  rerender();
}

// ---------------------------------------------------------------------------------------------- block force pushes
function protectCard() {
  const b = S.ghBranches;
  if (!b) return card('Block force pushes', 'shield', h('div', { class: 'card-pad' }, h('div', { class: 'skeleton' })));
  const exposed = /** @type {any[]} */ (b.exposed), done = /** @type {any[]} */ (b.protected);
  const intro = h('p', { class: 'help', text: 'The PolinRider worm force-pushes into every repository a stolen token can reach. A GitHub ruleset that blocks force pushes turns that into a refused push. Ardvane adds one to the default branch, for you to review first, and can take it off again.' });
  /** @type {(Node|null)[]} */
  const body = [h('div', { class: 'card-pad stack' }, intro)];
  if (!b.audited) {
    body.push(h('div', { class: 'card-pad' }, banner('info', 'info', 'Run a scan with the GitHub check on first',
      'Ardvane finds which of your repositories are open to force pushes while it checks your GitHub account. Turn that check on in Settings, then scan.',
      button('Open Scan', () => { location.hash = '#scan'; }, 'btn-primary', 'radar'))));
  } else if (!exposed.length && !done.length) {
    body.push(h('div', { class: 'card-pad' }, banner('ok', 'shieldCheck', 'No repository is open to force pushes', 'The last GitHub check found every repository you administer already blocks them.')));
  }
  if (exposed.length) {
    body.push(h('div', { class: 'list' }, exposed.map(r => h('div', { class: 'list-row' },
      h('div', { class: 'row-icon warn' }, icon('alert')),
      h('div', { class: 'grow' }, h('div', { class: 'title mono', text: r.repo }), h('div', { class: 'desc', text: `Anyone with a token that can push can rewrite ${r.branch}` })),
      r.private ? pill('neutral', 'Private', 'lock') : null,
      button('Protect', () => confirmProtect([r]), 'btn-sm btn-primary', 'shield')))));
    if (exposed.length > 1) body.push(h('div', { class: 'card-pad row' }, h('div', { class: 'grow help', text: `${plural(exposed.length, 'repository', 'repositories')} are open.` }),
      button(`Protect all ${exposed.length}`, () => confirmProtect(exposed), 'btn-primary', 'shield')));
  }
  if (done.length) {
    body.push(h('div', { class: 'section-head', text: 'Protected by Ardvane' }));
    body.push(h('div', { class: 'list' }, done.map(r => h('div', { class: 'list-row' },
      h('div', { class: 'row-icon ok' }, icon('shieldCheck')),
      h('div', { class: 'grow' }, h('div', { class: 'title mono', text: r.repo }), h('div', { class: 'desc', text: `Force pushes and deleting the default branch are blocked (added ${r.added})` })),
      button('Undo', () => undo(r.repo), 'btn-sm btn-ghost', 'refresh')))));
  }
  if (b.err) body.push(h('div', { class: 'card-pad' }, banner('warn', 'alert', 'Couldn\'t read the last check', b.err)));
  return card('Block force pushes', 'shield', h('div', {}, body));
}

/** @param {any[]} repos */
function confirmProtect(repos) {
  const go = button(repos.length === 1 ? 'Add the ruleset' : `Add to ${repos.length} repositories`, () => busy(go, async () => {
    try {
      const r = await api('/api/github/branches', { action: 'protect', repos: repos.map(x => x.repo) });
      S.ghBranches = r;
      closeModal();
      const ok = r.results.filter(/** @param {any} x */ x => x.status === 'protected' || x.status === 'already').length;
      const bad = r.results.filter(/** @param {any} x */ x => x.status === 'failed');
      toast(ok ? `Force pushes are now blocked on ${plural(ok, 'repository', 'repositories')}` : 'Nothing was changed', ok ? 'ok' : 'danger');
      if (bad.length) modal('Some repositories could not be changed', [h('ul', { class: 'change-list' }, bad.map(/** @param {any} x */ x => h('li', { text: `${x.repo}: ${x.message}` })))],
        [button('Close', () => closeModal(), 'btn-primary')]);
      rerender();
    } catch (e) { closeModal(); showError(e); }
  }), 'btn-primary', 'shield');
  modal(repos.length === 1 ? `Block force pushes on ${repos[0].repo}?` : `Block force pushes on ${repos.length} repositories?`, [
    h('p', { text: 'This adds one ruleset to each repository on GitHub, named "Ardvane: block force pushes". It applies to the default branch and:' }),
    h('ul', { class: 'change-list' },
      h('li', { text: 'refuses force pushes, so history can\'t be rewritten, whoever pushes' }),
      h('li', { text: 'refuses deleting the default branch' }),
      h('li', { text: 'has no exceptions, not even for you. Normal pushes and pull requests work as before' })),
    h('p', { class: 'help', text: 'Someone holding a token with admin rights on the repository can still remove the ruleset; that takes an extra step, shows in the repository\'s audit log, and the next Ardvane check lists the repository as open again. If you later push a cleaned history from the History page, undo the ruleset first (a clean-up is a force push) and add it back afterwards. Private repositories need a paid GitHub plan for rulesets.' }),
    repos.length > 1 ? h('ul', { class: 'change-list mono' }, repos.slice(0, 8).map(r => h('li', { text: r.repo })), repos.length > 8 ? h('li', { text: `…and ${repos.length - 8} more` }) : null) : null],
    [button('Cancel', () => closeModal(), 'btn-ghost'), go]);
}

/** @param {string} repo */
async function undo(repo) {
  try {
    const r = await api('/api/github/branches', { action: 'undo', repos: [repo] });
    S.ghBranches = r;
    toast(r.results[0].status === 'removed' ? `Ruleset removed from ${repo}` : r.results[0].message, r.results[0].status === 'removed' ? 'ok' : 'danger');
    rerender();
  } catch (e) { showError(e); }
}

// ---------------------------------------------------------------------------------------------- tell the owner
async function loadReport() {
  try { S.rjob = (await api('/api/github/report')).job; } catch (e) { /* offline banner shows */ }
  if (S.rjob && S.rjob.running) pollReport();
  rerender();
}

function pollReport() {
  if (poller !== null) return;
  poller = window.setInterval(async () => {
    try {
      S.rjob = (await api('/api/github/report')).job;
      if (!S.rjob || !S.rjob.running) { if (poller !== null) window.clearInterval(poller); poller = null; }
      rerender();
    } catch (e) { /* keep polling */ }
  }, 1200);
}

/** @param {string} repo */
async function writeReport(repo) {
  try { S.rjob = (await api('/api/github/report', { repo })).job; pollReport(); rerender(); } catch (e) { showError(e); }
}

async function loadShared() {
  const P = S.ghPick;
  if (P.repos || P.loading) return;
  P.loading = true; rerender();
  try { P.repos = (await api('/api/github/repos')).repos; } catch (e) { P.err = errorText(e); }
  P.loading = false; rerender();
}

function ownerCard() {
  const j = S.rjob, P = S.ghPick;
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Repository to report', placeholder: 'owner/name, e.g. a repository shared with you',
    list: 'owner-repos', value: S.ownerDraft || '' }));
  input.addEventListener('input', () => { S.ownerDraft = input.value; });
  const go = () => { const v = input.value.trim(); if (v) writeReport(v); };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  const shared = (P.repos || []).filter(/** @param {any} r */ r => r.kind === 'shared');
  const running = !!(j && j.running);
  const body = h('div', { class: 'card-pad stack' },
    h('p', { class: 'help', text: 'When malware is in a repository somebody else owns (a teammate\'s, a client\'s), its owner is usually unaware. Ardvane scans every branch on GitHub without cloning anything, then writes the report they need: what was found and where, why it matters, and what to do, in order. Nothing is sent anywhere unless you choose to open an issue.' }),
    h('div', { class: 'row' }, input, button('Write the report', go, 'btn-primary', 'file', running ? { disabled: '' } : undefined)),
    h('datalist', { id: 'owner-repos' }, shared.map(/** @param {any} r */ r => h('option', { value: r.repo }))),
    P.repos ? (shared.length ? h('p', { class: 'help', text: `${plural(shared.length, 'repository', 'repositories')} shared with you appear as you type.` })
      : h('p', { class: 'help', text: 'No repositories shared with you were found.' }))
      : button(P.loading ? 'Loading…' : 'Show repositories shared with me', () => loadShared(), 'btn-sm btn-ghost', 'github', P.loading ? { disabled: '' } : undefined),
    P.err ? h('p', { class: 'help', text: P.err }) : null);
  return h('div', {}, card('Tell the owner', 'file', body), j ? reportView(j) : null);
}

/** @param {any} j */
function reportView(j) {
  if (j.running) return card(`Checking ${j.repo}`, 'radar', h('div', { class: 'card-pad row' }, h('div', { class: 'loading-spinner' }),
    h('div', { class: 'grow' }, h('div', { class: 'title', text: j.repo }), h('div', { class: 'help', text: 'Reading every branch on GitHub. A large repository can take a few minutes.' }))));
  if (j.error) return banner('danger', 'alert', 'No report was written', j.error);
  const r = j.result;
  if (r.clean) return banner('ok', 'shieldCheck', `Nothing to report in ${r.repo}`, `${plural(r.branches, 'branch', 'branches')} were scanned and none shows signs of malware.`);
  const text = /** @type {string} */ (r.report);
  const copy = button('Copy report', async () => { try { await navigator.clipboard.writeText(text); toast('Report copied'); } catch (e) { showError(e); } }, 'btn-primary', 'file');
  const save = button('Save as file', () => {
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/markdown' })), download: `malware-report-${r.repo.replace('/', '-')}.md` });
    document.body.append(a); a.click(); a.remove();
  }, '', 'file');
  return card(`Report for ${r.repo}`, 'file', h('div', { class: 'card-pad stack' },
    banner('danger', 'shieldAlert', `${plural(r.findings, 'finding')} in ${r.repo}`,
      r.public ? 'This repository is public: a report posted as an issue is readable by everyone. Send it privately if you can.' : 'The repository is private: an issue is visible only to people who can read it.'),
    h('div', { class: 'row' }, copy, save, r.can_issue ? button('Open an issue…', () => confirmIssue(r), 'btn-danger', 'github') : null,
      r.link ? h('a', { class: 'btn', href: r.link, target: '_blank', rel: 'noopener' }, icon('lock'), 'Report privately on GitHub') : null),
    h('pre', { class: 'report-preview', text }),
    h('p', { class: 'help', text: 'The report contains nothing about your computer: no folder names, no user name.' })));
}

/** @param {any} r */
function confirmIssue(r) {
  const field = /** @type {HTMLInputElement} */ (h('input', { type: 'text', 'aria-label': 'Repository name', placeholder: r.repo, autocomplete: 'off', spellcheck: 'false' }));
  const go = button('Open the issue', () => busy(go, async () => {
    try {
      const out = await api('/api/github/issue', { confirm: field.value.trim() });
      closeModal();
      modal('Issue opened', [h('p', {}, 'The owner was notified by GitHub. ', out.url ? h('a', { href: out.url, target: '_blank', rel: 'noopener', text: out.url }) : null)],
        [button('Close', () => closeModal(), 'btn-primary')]);
    } catch (e) { closeModal(); showError(e); }
  }), 'btn-danger-solid', 'github', { disabled: '' });
  field.addEventListener('input', () => { /** @type {HTMLButtonElement} */ (go).disabled = field.value.trim().toLowerCase() !== r.repo.toLowerCase(); });
  modal(`Open an issue in ${r.repo}?`, [
    h('p', { text: r.public ? 'This repository is public. Everyone, including the attacker, can read the issue, and it can\'t be fully taken back once posted.'
      : 'This repository is private. The issue is visible to the people who can read it.' }),
    h('p', { class: 'help', text: 'It is posted from your GitHub account, with the report text shown on this page and nothing else.' }),
    h('div', { class: 'field' }, h('label', { text: `Type ${r.repo} to confirm` }), field)],
    [button('Cancel', () => closeModal(), 'btn-ghost'), go]);
}
