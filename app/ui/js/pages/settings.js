// @ts-check
import { api } from '../api.js';
import { h, button, pill, switchEl, choice, card, banner, pageHead, busy } from '../dom.js';
import { icon } from '../icons.js';
import { toast, errorText, showError } from '../feedback.js';
import { nextRun } from '../format.js';
import { S, refresh, rerender } from '../store.js';
import { setRoutine, setOfflineBanner } from '../actions.js';
import { chipList, changeList } from '../components.js';

export function renderSettings() {
  return [pageHead('Settings', 'Choose when the daily check runs, what it covers and what the app may fix for you.'), dailyCheck(), folders(), autofixMode(), github(), privacy(), about()];
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
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Folder to add', placeholder: S.data.os === 'windows' ? 'C:\\Users\\you\\code' : '~/code' }));
  const save = async (/** @type {string[]|{add: string}|{remove: string}} */ change) => { S.folderErr = await changeList('folders', change, 'Folders saved'); rerender(); };
  const add = () => { const v = input.value.trim(); if (v) save({ add: v }); };
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
    chipList(s.folders, 'folder', f => save({ remove: f })),
    h('div', { class: 'row' }, chooseBtn, h('span', { class: 'muted small', text: 'or type a path' }), input, button('Add', add, '', 'plus'),
      s.folders_custom ? button('Reset to defaults', () => save(s.default_folders), 'btn-ghost') : null),
    S.folderErr ? h('div', { class: 'err', role: 'alert', text: S.folderErr }) : null));
}

const FIX_MODES = [
  ['ask', 'Ask me', 'Each fix shows exactly what will change and waits for you to confirm.', true],
  ['auto', 'Automatic', 'Safe fixes run as soon as a scan or the daily check finds the problem. You get a summary and can undo any of them.', false],
  ['off', 'Off', 'Only report problems — you fix everything yourself.', false],
];

function autofixMode() {
  const current = S.data.settings.autofix;
  const pick = (/** @type {string} */ m) => async () => {
    try { await api('/api/settings', { autofix: m }); await refresh(); toast(`Fixes: ${FIX_MODES.find(x => x[0] === m)[1]}`); } catch (e) { showError(e); }
  };
  return card('Fixes', 'check', h('div', { class: 'card-pad stack' },
    h('div', { class: 'choices choices-3' }, FIX_MODES.map(([m, title, desc, rec]) => choice('radio', current === m, String(title), String(desc), pick(String(m)), false, !!rec))),
    h('div', { class: 'help' },
      h('strong', { text: 'Safe to fix automatically: ' }), 'editor auto-run settings, npm install scripts, switched-off git protection, and malware in known malware locations (moved to quarantine, never deleted).',
      h('br'), h('strong', { text: 'Always asks first: ' }), 'stopping a running process, moving one of your projects, and anything that only might be malware.',
      h('br'), h('strong', { text: 'Never automatic: ' }), 'anything on GitHub, rotating secrets — those stay in your to-do list.')));
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
    h('div', { class: 'divider' }),
    githubRepos(),
    banner('neutral', s.gh ? 'checkCircle' : 'info', s.gh ? 'GitHub CLI found' : 'Public repositories only',
      s.gh ? 'If you\'re logged in with `gh auth login`, private repositories are checked too. Your token stays inside the GitHub CLI; this app never sees it.'
        : 'To include private repositories, install the GitHub CLI and run `gh auth login`. This app never asks for or stores a password or token.')), toggle);
}

function githubRepos() {
  const s = S.data.settings;
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Repository to add',
    placeholder: 'owner/name or https://github.com/owner/name', autocomplete: 'off', spellcheck: 'false' }));
  const save = async (/** @type {{add: string}|{remove: string}} */ change) => { S.repoErr = await changeList('github_repos', change, 'Repositories saved'); rerender(); };
  const add = () => { const v = input.value.trim(); if (v) save({ add: v }); };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') add(); });
  return h('div', { class: 'stack' },
    h('div', { class: 'field' }, h('label', { text: 'Repositories to scan' }),
      h('div', { class: 'help', text: 'Every branch of these repositories is checked with each scan and daily check: yours, your organization\'s or a teammate\'s - any repository your GitHub login can read. Works without a username too.' })),
    s.github_repos.length ? chipList(s.github_repos, 'github', r => save({ remove: r })) : null,
    h('div', { class: 'row' }, input, button('Add', add, '', 'plus')),
    S.repoErr ? h('div', { class: 'err', role: 'alert', text: S.repoErr }) : null);
}

function privacy() {
  return card('Privacy', 'lock', h('div', { class: 'card-pad' }, h('ul', { class: 'help' },
    h('li', { text: 'Runs only on this computer. The dashboard is served from 127.0.0.1 and refuses requests from other websites.' }),
    h('li', { text: 'No account, no telemetry, no tracking. Reports stay in ~/.checkrepo/reports.' }),
    h('li', { text: 'The only internet connection is to GitHub\'s API, and only while the GitHub check is on or repositories are listed.' }),
    h('li', { text: 'Scans only read files. Nothing is changed unless you press a button that says so.' }))));
}

function about() {
  const d = S.data;
  return h('div', { class: 'card card-pad row' },
    h('div', { class: 'grow' }, h('h3', { text: `${d.app} ${d.version}` }), h('div', { class: 'help mono', text: d.kit })),
    button('Stop dashboard', async () => { try { await api('/api/quit', {}); } catch (e) { /* already stopped */ } setOfflineBanner(true); }, 'btn-ghost', 'power'));
}
