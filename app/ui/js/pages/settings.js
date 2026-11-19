// @ts-check
import { api } from '../api.js';
import { h, button, pill, switchEl, choice, card, banner, pageHead, busy } from '../dom.js';
import { icon } from '../icons.js';
import { toast, errorText, showError } from '../feedback.js';
import { nextRun, fmtTime } from '../format.js';
import { S, refresh, rerender } from '../store.js';
import { setRoutine, setOfflineBanner, updateFlow, checkForUpdate } from '../actions.js';
import { chipList, changeList } from '../components.js';

export function renderSettings() {
  return [pageHead('Settings', 'Choose when the daily check runs, what it covers and what the app may fix for you.'), dailyCheck(), folders(), autofixMode(), github(), detections(), privacy(), about()];
}

function dailyCheck() {
  const rt = S.data.protection.routine;
  const time = /** @type {HTMLInputElement} */ (h('input', { type: 'time', value: rt.time || '09:00', 'aria-label': 'Daily check time' }));
  const save = button(rt.on ? 'Save time' : 'Turn on', () => setRoutine(true, time.value, save), 'btn-primary');
  const toggle = rt.available ? switchEl(rt.on, (/** @type {Event} */ e) => setRoutine(/** @type {HTMLInputElement} */ (e.target).checked, time.value), 'Daily check on or off') : null;
  return card('Daily check', 'clock', h('div', { class: 'card-pad stack' },
    rt.available ? h('div', { class: 'field' }, h('label', { text: 'Run every day at' }), h('div', { class: 'row' }, time, save))
      : h('p', { class: 'muted', text: 'Scheduled checks are available on macOS and Windows.' }),
    h('p', { class: 'help', text: rt.on
      ? `Next run ${nextRun(rt.time)}. If your computer is asleep at that time, the check runs when it wakes up, and you get a notification with the result.`
      : 'Off. Turn it on to check your computer, your projects and your protections automatically every day.' })), toggle);
}

function folders() {
  const s = S.data.settings;
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Folder to add', value: S.folderDraft, placeholder: S.data.os === 'windows' ? 'C:\\Users\\you\\code' : '~/code' }));
  const save = async (/** @type {{add: string}|{remove: string}|{reset: boolean}} */ change) => {
    S.folderErr = await changeList('folders', change, 'Folders saved');
    S.folderDraft = S.folderErr && 'add' in change ? change.add : '';       // a typo stays in the box to fix
    rerender();
  };
  const add = () => { const v = input.value.trim(); if (v) { input.value = ''; delete input.dataset.dirty; save({ add: v }); } };
  const choose = async () => {
    try {
      const r = await api('/api/pick-folder', {});
      if (r.path) return s.folders.includes(r.path) ? toast(`${r.path} is already in the list`) : save({ add: r.path });
      if (r.unavailable) { input.focus(); toast('No folder picker on this system — type the path instead', 'danger'); }
      if (r.busy) toast('A folder window is already open — look for it behind this one', 'danger');
    } catch (e) { showError(e); }
  };
  const chooseBtn = button(S.data.os === 'mac' ? 'Choose folder in Finder…' : 'Choose folder…', () => busy(chooseBtn, choose), 'btn-primary', 'folder');
  input.addEventListener('keydown', e => { if (e.key === 'Enter') add(); });
  return card('What gets scanned', 'folder', h('div', { class: 'card-pad stack' },
    h('div', { class: 'row' }, h('div', { class: 'row-icon ok' }, icon('laptop')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: 'This computer' }),
        h('div', { class: 'help', text: 'Malware locations, startup items, network connections, editor settings and your protections. Always included.' })),
      pill('ok', 'Always', 'check')),
    h('div', { class: 'divider' }),
    h('div', { class: 'field' }, h('label', { text: 'Project folders' }),
      h('div', { class: 'help', text: 'The daily check scans every git project inside these folders, plus your Downloads folder.' + (s.folders_custom ? '' : ' These are the defaults.') })),
    (s.folder_info || []).length
      ? h('div', { class: 'chips' }, s.folder_info.map(f => h('div', { class: 'chip' + (f.exists ? '' : ' chip-missing') }, icon('folder'),
          h('span', { class: 'mono grow', text: f.path }),
          f.exists ? null : h('span', { title: 'This folder is not on this computer right now (deleted, renamed or on a drive that is not plugged in). It is skipped until it is back.' }, pill('warn', 'Not found', 'alert')),
          button('', () => save({ remove: f.path }), 'btn-sm btn-ghost', 'x', { 'aria-label': 'Remove ' + f.path, title: 'Remove' }))))
      : h('p', { class: 'help', text: 'No project folders: the daily check only scans your Downloads folder. Add the folders where you keep your code.' }),
    h('div', { class: 'row' }, chooseBtn, h('span', { class: 'muted small', text: 'or type a path' }), input, button('Add', add, '', 'plus'),
      s.folders_custom ? button('Reset to defaults', () => save({ reset: true }), 'btn-ghost') : null),
    S.folderErr ? h('div', { class: 'err', role: 'alert', text: S.folderErr }) : null));
}

const FIX_MODES = [
  ['ask', 'Ask me', 'Each fix shows exactly what will change and waits for you to confirm.', true],
  ['auto', 'Automatic: safe fixes', 'Your editor, npm and git settings, and malware in known malware locations, as soon as a scan or the daily check finds them.', false],
  ['all', 'Automatic: remove malware too', 'Also removes everything else Ardvane finds: stops malware processes, quarantines malware files and extensions, and cuts injected code out of your projects.', false],
  ['off', 'Off', 'Only report problems — you fix everything yourself.', false],
];

function autofixMode() {
  const current = S.data.settings.autofix;
  const pick = (/** @type {string} */ m) => async () => {
    try { await api('/api/settings', { autofix: m }); await refresh(); toast(`Fixes: ${FIX_MODES.find(x => x[0] === m)[1]}`); } catch (e) { showError(e); }
  };
  return card('Fixes', 'check', h('div', { class: 'card-pad stack' },
    h('div', { class: 'choices' }, FIX_MODES.map(([m, title, desc, rec]) => choice('radio', current === m, String(title), String(desc), pick(String(m)), false, !!rec))),
    h('div', { class: 'help' },
      h('strong', { text: 'Nothing is ever deleted: ' }), 'malware is moved to quarantine and kept as evidence, an edited file keeps its original there, and every fix except stopping a process can be undone from Protection → Fix history.',
      h('br'), h('strong', { text: 'Inside a project, ' }), 'only the parts flagged as malware are removed (a line of injected code, a fake font, a worm\'s install script) — your own code stays. Moving a whole project always asks first.',
      h('br'), h('strong', { text: 'Never automatic: ' }), 'anything on GitHub, rotating secrets, updating a hijacked package — those stay in your to-do list.')));
}

function github() {
  const s = S.data.settings;
  const user = /** @type {HTMLInputElement} */ (h('input', { type: 'text', value: s.github_user, placeholder: 'your-username', 'aria-label': 'GitHub username', autocomplete: 'off', spellcheck: 'false' }));
  const err = h('div', { class: 'err', role: 'alert' });
  const save = async (/** @type {boolean} */ enabled) => {
    try {
      await api('/api/settings', { github_user: user.value, github_enabled: enabled });
      await refresh();
      toast(enabled ? `GitHub @${user.value.trim().replace(/^@/, '')} will be checked` : 'GitHub check turned off');
    } catch (e) { err.textContent = errorText(e); }
  };
  const toggle = switchEl(s.github_enabled, (/** @type {Event} */ e) => {
    const box = /** @type {HTMLInputElement} */ (e.target);
    if (box.checked && !user.value.trim()) { box.checked = false; err.textContent = 'Enter your GitHub username first.'; user.focus(); return; }
    save(box.checked);
  }, 'Check my GitHub account');
  const saveBtn = button('Save', () => busy(saveBtn, () => save(s.github_enabled || !s.github_user)), 'btn-primary');
  return card('GitHub', 'github', h('div', { class: 'card-pad stack' },
    h('p', { class: 'help', text: 'The worm uses stolen access to push itself into every repository you can reach. When this is on, scans and the daily check also look at your GitHub account:' }),
    h('ul', { class: 'help' },
      h('li', { text: 'Warns when many repositories were pushed within one hour.' }),
      h('li', { text: 'Downloads the main branch of each recently pushed repository into a temporary folder, scans it and deletes it. Nothing is ever run.' })),
    h('div', { class: 'field' }, h('label', { text: 'Username' }), h('div', { class: 'row' }, user, saveBtn)), err,
    githubScope(),
    h('div', { class: 'divider' }),
    githubRepos(),
    banner('neutral', s.gh ? 'checkCircle' : 'info', s.gh ? 'GitHub CLI found' : 'Public repositories only',
      s.gh ? 'If you\'re logged in with `gh auth login`, private repositories are checked too. Your token stays inside the GitHub CLI; this app never sees it.'
        : 'To include private repositories, install the GitHub CLI and run `gh auth login`. This app never asks for or stores a password or token.')), toggle);
}

const SCOPES = [
  ['all', 'Every repository I can push to', 'Yours, your organizations\' and ones shared with you. The worm spreads through all of them.', true],
  ['owned', 'Mine and my organizations\'', 'Skips repositories other people shared with you, even if you can push to them.', false]];

function githubScope() {
  const current = S.data.settings.github_scope || 'all';
  const pick = (/** @type {string} */ m) => async () => {
    try { await api('/api/settings', { github_scope: m }); await refresh(); toast(m === 'owned' ? 'Your and your organizations\' repositories will be checked' : 'Every repository you can push to will be checked'); }
    catch (e) { showError(e); }
  };
  return h('div', { class: 'field' }, h('label', { text: 'Which repositories' }),
    h('div', { class: 'choices' }, SCOPES.map(([m, title, desc, rec]) => choice('radio', current === m, String(title), String(desc), pick(String(m)), false, !!rec))));
}

/** Choose repositories from the GitHub login's list instead of typing their names. */
function repoPicker() {
  const P = S.ghPick, chosen = new Set(S.data.settings.github_repos.map((/** @type {string} */ r) => r.toLowerCase()));
  const load = async () => {
    P.open = true; P.loading = true; P.err = ''; rerender();
    try { P.repos = (await api('/api/github/repos')).repos; } catch (e) { P.err = errorText(e); }
    P.loading = false; rerender();
  };
  if (!P.open) return button('Choose from my GitHub repositories', load, '', 'github');
  if (P.loading) return h('div', { class: 'row help' }, h('div', { class: 'loading-spinner' }), 'Listing your repositories…');
  if (P.err || !P.repos) return h('div', { class: 'stack' }, h('div', { class: 'err', role: 'alert', text: P.err || 'Could not list your repositories.' }), button('Try again', load, 'btn-sm', 'refresh'));
  const repos = /** @type {any[]} */ (P.repos);
  const list = h('div', { class: 'list pick-list' });
  const fill = () => {
    const q = P.q.trim().toLowerCase();
    const shown = (/** @type {any} */ r) => P.filter === 'all' ? true : P.filter === 'chosen' ? chosen.has(r.repo.toLowerCase()) : r.kind === P.filter;
    const rows = repos.filter(r => shown(r) && (!q || r.repo.toLowerCase().includes(q)));
    list.replaceChildren(...(rows.length ? rows.slice(0, 200).map(r => {
      const on = chosen.has(r.repo.toLowerCase());
      return h('label', { class: 'list-row pick-row' + (on ? ' on' : '') },
        h('input', { type: 'checkbox', checked: on, onchange: async () => {
          S.repoErr = await changeList('github_repos', on ? { remove: S.data.settings.github_repos.find((/** @type {string} */ x) => x.toLowerCase() === r.repo.toLowerCase()) } : { add: r.repo },
            on ? `Stopped scanning ${r.repo}` : `${r.repo} will be scanned on every branch`);
          rerender();
        } }),
        h('div', { class: 'grow' }, h('div', { class: 'title mono', text: r.repo }),
          h('div', { class: 'desc', text: ({ yours: 'yours', org: `${r.owner} organization`, shared: `shared with you by ${r.owner}` }[/** @type {'yours'|'org'|'shared'} */ (r.kind)] || r.owner)
            + (r.private ? ' · private' : '') + (r.pushed_at ? ` · pushed ${String(r.pushed_at).slice(0, 10)}` : '') })),
        r.kind === 'shared' ? pill('warn', 'Shared') : r.kind === 'org' ? pill('neutral', 'Organization') : null);
    }) : [h('p', { class: 'help card-pad', text: 'No repositories match.' })]));
  };
  const search = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', value: P.q, placeholder: `Search ${repos.length} repositories`, 'aria-label': 'Search repositories', autocomplete: 'off', spellcheck: 'false' }));
  search.addEventListener('input', () => { P.q = search.value; fill(); });
  const counts = { all: repos.length, chosen: chosen.size, yours: 0, org: 0, shared: 0 };
  repos.forEach(r => { counts[/** @type {'yours'|'org'|'shared'} */ (r.kind)] += 1; });
  const tabs = h('div', { class: 'tabs', role: 'tablist' }, [['all', 'All'], ['yours', 'Yours'], ['org', 'Organizations'], ['shared', 'Shared with you'], ['chosen', 'Chosen']].map(([k, label]) =>
    h('button', { type: 'button', role: 'tab', class: P.filter === k ? 'on' : '', 'aria-selected': String(P.filter === k),
      onclick: () => { P.filter = k; rerender(); } }, `${label} ${counts[/** @type {'all'|'yours'|'org'|'shared'|'chosen'} */ (k)]}`)));
  fill();
  return h('div', { class: 'stack' }, h('div', { class: 'row wrap' }, tabs, h('span', { class: 'grow' }), button('Done', () => { P.open = false; rerender(); }, 'btn-sm')),
    search, list);
}

function githubRepos() {
  const s = S.data.settings;
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Repository to add',
    placeholder: 'owner/name or https://github.com/owner/name', autocomplete: 'off', spellcheck: 'false' }));
  const save = async (/** @type {{add: string}|{remove: string}} */ change) => { S.repoErr = await changeList('github_repos', change, 'Repositories saved'); rerender(); };
  const add = () => { const v = input.value.trim(); if (v) { input.value = ''; delete input.dataset.dirty; save({ add: v }); } };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') add(); });
  return h('div', { class: 'stack' },
    h('div', { class: 'field' }, h('label', { text: 'Repositories to scan' }),
      h('div', { class: 'help', text: 'Every branch of these repositories is checked with each scan and daily check: yours, your organization\'s or a teammate\'s - any repository your GitHub login can read. Works without a username too.' })),
    s.github_repos.length ? chipList(s.github_repos, 'github', r => save({ remove: r })) : null,
    h('div', { class: 'row' }, input, button('Add', add, '', 'plus')),
    repoPicker(),
    S.repoErr ? h('div', { class: 'err', role: 'alert', text: S.repoErr }) : null);
}

function detections() {
  const s = S.data.settings, f = S.data.feed;
  const updateBtn = button('Update now', () => busy(updateBtn, async () => {
    try { const r = await api('/api/feed/update', {}); await refresh(); toast(r.message, r.ok ? undefined : 'danger'); } catch (e) { showError(e); }
  }), '', 'refresh');
  const toggle = switchEl(s.feed_updates, async (/** @type {Event} */ e) => {
    const on = /** @type {HTMLInputElement} */ (e.target).checked;
    try { await api('/api/settings', { feed_updates: on }); await refresh(); toast(on ? 'Detections update automatically' : 'Automatic detection updates off'); } catch (err) { showError(err); }
  }, 'Update detections automatically');
  return card('Detections', 'shieldCheck', h('div', { class: 'card-pad stack' },
    h('p', { class: 'help', text: 'Attackers change their code to slip past scanners. Besides the detections built into this version, Ardvane downloads a signed list of new ones - attacker servers, malware fingerprints, malicious packages - before each scan and daily check, so it keeps up without an update.' }),
    h('div', { class: 'row' },
      h('div', { class: 'row-icon ' + (f ? 'ok' : '') }, icon(f ? 'checkCircle' : 'info')),
      h('div', { class: 'grow' },
        h('div', { class: 'title', text: f ? `Detection list from ${f.published}` : 'No detection list downloaded yet' }),
        h('div', { class: 'help', text: f ? `${f.count} detections added to the ones built in.` : 'Only the built-in detections are used until the first update.' })),
      updateBtn),
    h('p', { class: 'help', text: 'Every update is checked against Ardvane\'s signing key before it is used, an older list is never accepted, and it can only add detections - never remove any, or change your files. It is one download from GitHub; nothing about this computer is sent.' }),
    h('div', { class: 'divider' }),
    h('div', { class: 'row' },
      h('div', { class: 'grow' }, h('div', { class: 'title', text: 'Check packages online before they install' }),
        h('div', { class: 'help', text: 'Safe install also asks OSV.dev (Google\'s open database, which includes the OpenSSF list of malicious packages) about the packages an install would add. It covers many more packages than Ardvane\'s own list and learns new ones within hours. Only public package names and versions are sent - never packages from a private registry. Off: Ardvane\'s own list only.' })),
      switchEl(s.package_lookups, async (/** @type {Event} */ e) => {
        const on = /** @type {HTMLInputElement} */ (e.target).checked;
        try { await api('/api/settings', { package_lookups: on }); await refresh(); toast(on ? 'Packages are also checked online' : 'Packages are checked against Ardvane\'s list only'); } catch (err) { showError(err); }
      }, 'Check packages online before they install'))), toggle);
}

function privacy() {
  return card('Privacy', 'lock', h('div', { class: 'card-pad' }, h('ul', { class: 'help' },
    h('li', { text: 'Runs only on this computer. The dashboard is served from 127.0.0.1 and refuses requests from other websites.' }),
    h('li', { text: 'No account, no telemetry, no tracking. Reports stay in ~/.checkrepo/reports.' }),
    h('li', { text: 'Internet connections: GitHub, to download the signed detection list, for the GitHub check and to look for a new Ardvane version (PyPI instead for pipx installs); and OSV.dev, to look up public package names when you install packages. Each can be turned off under Detections, GitHub and Updates.' }),
    h('li', { text: 'Scans only read files. Nothing is changed unless you press a button that says so.' }))));
}

function about() {
  const d = S.data, u = d.update || {};
  const checkBtn = button('Check now', () => busy(checkBtn, () => checkForUpdate()), '', 'refresh');
  const line = u.available ? `Ardvane ${u.latest} is available.` : u.error ? u.error : u.latest ? 'You have the latest version.' : 'Not checked yet.';
  const toggle = switchEl(!!d.settings.update_checks, async (/** @type {Event} */ e) => {
    const on = /** @type {HTMLInputElement} */ (e.target).checked;
    try { await api('/api/settings', { update_checks: on }); await refresh(); toast(on ? 'Ardvane checks for updates' : 'Update checks off'); } catch (err) { showError(err); }
  }, 'Check for updates');
  return card('Updates', 'refresh', h('div', { class: 'card-pad stack' },
    h('div', { class: 'row' },
      h('div', { class: 'row-icon ' + (u.available ? 'ok' : '') }, icon(u.available ? 'refresh' : 'checkCircle')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: `${d.app} ${d.version}` }),
        h('div', { class: 'help', text: line + (u.checked ? ` Checked ${fmtTime(u.checked)}.` : '') })),
      u.available && u.can_update ? button(`Update to ${u.latest}`, () => updateFlow(), 'btn-primary', 'refresh') : checkBtn),
    u.available && !u.can_update ? h('p', { class: 'help', text: `To update: ${u.how}.` }) : null,
    h('p', { class: 'help', text: 'Ardvane looks for a new version about twice a day while the dashboard is open: one download from GitHub (or PyPI for pipx) that sends nothing about this computer. Updating shows you what\'s new first, then installs it the way you installed Ardvane, refreshes your protection and restarts the dashboard.' }),
    h('div', { class: 'divider' }),
    h('div', { class: 'row' }, h('div', { class: 'grow help mono', text: d.kit }),
      button('Stop dashboard', async () => { try { await api('/api/quit', {}); } catch (e) { /* already stopped */ } setOfflineBanner(true); }, 'btn-ghost', 'power'))), toggle);
}
