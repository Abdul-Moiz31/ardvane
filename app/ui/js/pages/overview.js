// @ts-check
// Overview = the security dashboard: one status, four numbers, what needs attention, and the trend. Details live on
// their own pages (To-do, Scan, Protection, Reports).
import { h, button, pill, card, banner, pageHead, empty, skeleton, busy } from '../dom.js';
import { icon } from '../icons.js';
import { modal, closeModal, toast, showError } from '../feedback.js';
import { api } from '../api.js';
import { fmtTime, nextRun, plural } from '../format.js';
import { ring, history } from '../charts.js';
import { S, refresh, rerender, loadTasks, loadReports, heroState, latestResult, protectionCount, scopeText, INFECTED_GUIDE } from '../store.js';
import { installFlow, setRoutine, startScan, updateFlow, launcherAction } from '../actions.js';
import { recentReports, protectionRows } from '../components.js';
import { loadFixes, confirmFix } from '../fixes.js';

const ATTENTION_LIMIT = 5;

export function renderOverview() {
  if (!S.reports) loadReports();
  if (!S.tasks) loadTasks();
  if (!S.fixes) loadFixes();
  return [
    pageHead('Overview', 'Your computer\'s security at a glance.'),
    statusBar(),
    updateBanner(),
    blockedFolders(),
    githubHint(),
    kpis(),
    h('div', { class: 'overview-grid' }, attention(),
      card('Last 30 days', 'chart', h('div', { class: 'card-pad' }, S.reports ? history(S.reports) : h('div', { class: 'skeleton chart-skeleton' })),
        h('a', { href: '#reports', text: 'All reports' }))),
    h('div', { class: 'grid grid-2' },
      card('Protection', 'shield', h('div', { class: 'list' }, protectionRows(true)), h('a', { href: '#protection', text: 'Manage' })),
      card('Recent activity', 'file', recentReports(4), h('a', { href: '#reports', text: 'All reports' }))),
  ];
}

/** The GitHub check is opt-in and easy to miss. When the GitHub CLI is already signed in, offer to turn it on in one click. */
function githubHint() {
  const s = S.data.settings;
  let dismissed = false;
  try { dismissed = localStorage.getItem('ardvane-github-hint') === '1'; } catch (e) { /* private window */ }
  if (s.github_enabled || dismissed || !s.gh || (S.scan && S.scan.running)) return null;
  if (S.ghLogin === undefined) {
    S.ghLogin = null;
    api('/api/github/login').then(r => { S.ghLogin = r.login || ''; rerender(); }).catch(() => { S.ghLogin = ''; });
  }
  if (!S.ghLogin) return null;
  /** @type {HTMLElement|null} */
  let on = null;
  on = button('Turn on', () => busy(/** @type {HTMLButtonElement} */ (on), async () => {
    try { await api('/api/github/enable', {}); await refresh(); toast(`GitHub @${S.ghLogin} will be checked: scans and the daily check now include it`, 'ok'); }
    catch (e) { showError(e); }
  }), 'btn-primary', 'github');
  const later = button('Not now', () => { try { localStorage.setItem('ardvane-github-hint', '1'); } catch (e) { /* ignore */ } rerender(); }, 'btn-ghost');
  return banner('ok', 'github', `Check GitHub @${S.ghLogin} too?`,
    'The worm spreads through your GitHub access. Ardvane can audit the account (runners, deploy keys, webhooks, force-push exposure) and scan recently pushed repositories, live while a scan runs. Your token stays inside the GitHub CLI.',
    h('div', { class: 'row' }, on, later));
}

/** A newer Ardvane: what's new, and one button to update. */
function updateBanner() {
  const u = S.data.update;
  if (!u || !u.available) return null;
  const first = (u.notes && u.notes[0] && u.notes[0].notes.split('\n').find(/** @param {string} l */ l => /^\s*[-*]\s+\*\*/.test(l))) || '';
  const teaser = first.replace(/^\s*[-*]\s+/, '').replace(/\*\*/g, '').split('. ')[0];
  return banner('ok', 'refresh', `Ardvane ${u.latest} is available`,
    `You have ${u.current}.` + (teaser ? ` New: ${teaser}.` : '') + (u.can_update ? '' : ` To update: ${u.how}.`),
    u.can_update ? button('See what\'s new', () => updateFlow(), 'btn-primary', 'refresh') : null);
}

/** Folders the daily check couldn't open: macOS keeps background jobs out of Documents, Desktop and Downloads. */
function blockedFolders() {
  const list = /** @type {string[]} */ (S.data.blocked_folders || []);
  if (!list.length || (S.scan && S.scan.running)) return null;
  const app = S.data.daily_app || {};
  const scan = button('Scan them now', () => startScan('full', list), app.ready ? '' : 'btn-primary', 'radar');
  /** @type {HTMLElement|null} */
  let allow = null;
  if (app.ready) {
    allow = button('Allow access', () => busy(/** @type {HTMLButtonElement} */ (allow), async () => {
      try {
        await api('/api/daily/run-now', {});
        toast('The daily check is running - click "Allow" when macOS asks whether Ardvane Daily Check may read your folders', 'ok');
      } catch (e) { showError(e); }
    }), 'btn-primary', 'lock');
  } else if (S.data.os === 'mac') {
    allow = button('Add the Ardvane app', () => launcherAction('install', /** @type {HTMLButtonElement} */ (allow)), 'btn-primary', 'app');
  }
  const how = app.ready
    ? 'Press "Allow access": the daily check runs once now, and macOS asks whether "Ardvane Daily Check" may read these folders. Allow it once and every daily check covers them.'
    : S.data.os === 'mac' ? 'Add the Ardvane app, then allow it to read these folders once: from then on every daily check covers them.' : '';
  return banner('warn', 'lock', `The daily check couldn't read ${list.join(', ')}`,
    'macOS doesn\'t let background jobs open Documents, Desktop or Downloads, so the projects there weren\'t checked. ' + how,
    h('div', { class: 'row' }, allow, scan));
}

// ------------------------------------------------------------------------------------------------ status
function statusBar() {
  const st = heroState(), r = latestResult(), sc = S.scan, rt = S.data.protection.routine;
  const actions = h('div', { class: 'status-actions' });
  if (sc && sc.running) {
    actions.append(button('View progress', () => { location.hash = '#scan'; }, 'btn-primary', 'radar'));
  } else {
    const primary = st.tone === 'danger'
      ? (st.fix === 'todo' || st.fix === 'fixes' ? button('Open checklist', () => { location.hash = '#todo'; }, 'btn-danger-solid', 'checkCircle')
        : button('What to do now', () => { location.hash = INFECTED_GUIDE; }, 'btn-danger-solid', 'alert'))
      : st.fix === 'protect' ? button('Turn on protection', () => installFlow(), 'btn-primary', 'shield') : null;
    if (primary) actions.append(primary);
    actions.append(button('Scan now', () => startScan(), primary ? '' : 'btn-primary', 'play'));
  }
  let detail;
  if (sc && sc.running) {
    const bar = h('div');
    bar.style.width = Math.max(4, Math.round(100 * sc.steps_done / sc.steps_total)) + '%';
    detail = h('div', { class: 'progress hero-progress' }, bar);
  } else {
    detail = h('div', { class: 'hero-meta' },
      h('span', {}, icon('clock'), r ? `Last ${r.kind === 'scan' ? 'scan' : 'daily check'} ${fmtTime(r.time)}` : 'Never scanned'),
      h('span', {}, icon('refresh'), rt.on ? `Daily check at ${rt.time}` : 'Daily check off'),
      h('span', {}, icon('lock'), 'Nothing leaves this computer'));
  }
  return h('div', { class: 'hero status tone-' + st.tone + (sc && sc.running ? ' scanning' : '') },
    h('div', { class: 'hero-icon' }, icon(st.icon)),
    h('div', { class: 'hero-text' }, h('h1', { text: st.title }), h('p', { text: st.text }), detail),
    actions);
}

// ------------------------------------------------------------------------------------------------ numbers
function kpis() {
  const p = S.data.protection, r = latestResult(), pc = protectionCount(p), rt = p.routine;
  const latest = r ? `latest ${r.kind === 'scan' ? 'scan' : 'daily check'}` : 'no scan yet';
  return h('div', { class: 'grid grid-4' },
    kpi('Threats found', r ? String(r.danger || 0) : '–', latest, 'shieldAlert', r && r.danger ? 'danger' : ''),
    kpi('Worth a look', r ? String(r.warn || 0) : '–', 'often harmless', 'warn', r && r.warn ? 'warn' : ''),
    kpi('Protection', pc.on === pc.total ? 'All on' : `${pc.on} of ${pc.total}`, pc.on === pc.total ? 'everything is on' : 'some protection is off', 'shield', '',
      ring(pc.on, pc.total, { size: 52, label: `${pc.on} of ${pc.total} protections on` }), () => { location.hash = '#protection'; }),
    kpi('Daily check', rt.on ? rt.time : 'Off', rt.on ? `next ${nextRun(rt.time)}` : rt.available ? 'not scheduled' : 'macOS and Windows only', 'clock', rt.on ? '' : 'warn',
      rt.available ? button(rt.on ? 'Change' : 'Turn on', () => scheduleDialog(), rt.on ? 'btn-sm' : 'btn-sm btn-primary') : null));
}

/**
 * @param {string} label @param {string} value @param {string} foot @param {string} ic @param {string} tone
 * @param {Node|null} [side] @param {() => void} [onclick]
 */
function kpi(label, value, foot, ic, tone, side, onclick) {
  return h('div', { class: 'card tile tile-visual' + (onclick ? ' clickable' : ''), onclick: onclick || null },
    h('div', { class: 'grow' }, h('div', { class: 'tile-label' }, icon(ic), label),
      h('div', { class: 'tile-value ' + tone, text: value }), h('div', { class: 'tile-foot', text: foot })),
    side || null);
}

function scheduleDialog() {
  const rt = S.data.protection.routine;
  const time = /** @type {HTMLInputElement} */ (h('input', { type: 'time', value: rt.time || '09:00', 'aria-label': 'Daily check time' }));
  modal(rt.on ? 'Change the daily check time' : 'Check this computer every day', [
    h('p', { text: `A short, read-only check of ${scopeText()}. If your computer is asleep at that time, it runs when it wakes.` }),
    h('div', { class: 'row' }, h('label', { text: 'Every day at' }), time)],
  [rt.on ? button('Turn off', () => { closeModal(); setRoutine(false, null); }, 'btn-ghost btn-danger') : button('Cancel', closeModal, 'btn-ghost'),
    button(rt.on ? 'Save' : 'Turn on', () => { closeModal(); setRoutine(true, time.value); }, 'btn-primary', 'clock')]);
}

// ------------------------------------------------------------------------------------------------ what to do next
/** Fixes the app can make, then the most important open to-dos — one list, most urgent first. */
function attention() {
  const loading = !S.tasks || !S.fixes;
  const fixList = S.fixes && S.fixes.mode !== 'off' ? S.fixes.available : [];
  const todo = S.tasks ? S.tasks.tasks.filter(/** @param {any} t */ t => t.status === 'open') : [];
  const total = fixList.length + todo.length;
  const rows = [
    ...fixList.map(/** @param {any} f */ f => h('div', { class: 'list-row' },
      h('div', { class: 'row-icon ' + (f.kind === 'quarantine' || f.kind === 'process' ? 'danger' : 'warn') }, icon(f.kind === 'process' ? 'stop' : 'shieldAlert')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: f.title }), h('div', { class: 'desc', text: f.auto ? 'Can be fixed for you' : 'Can be fixed for you — check it first' })),
      button('Fix…', () => confirmFix(f), 'btn-sm btn-primary'))),
    ...todo.map(/** @param {any} t */ t => h('a', { class: 'list-row clickable', href: '#todo' },
      h('div', { class: 'row-icon ' + (t.level === 'info' ? 'brand' : t.level) }, icon(t.level === 'danger' ? 'xCircle' : t.level === 'warn' ? 'warn' : t.group === 'routine' ? 'clock' : 'checkCircle')),
      h('div', { class: 'grow' }, h('div', { class: 'title', text: t.title }),
        h('div', { class: 'desc', text: `${t.steps.filter(/** @param {any} s */ s => s.done).length} of ${plural(t.steps.length, 'step')} done` })),
      icon('chevron'))),
  ].slice(0, ATTENTION_LIMIT);
  const body = loading ? skeleton(4) : rows.length ? h('div', { class: 'list' }, rows,
    total > ATTENTION_LIMIT ? h('a', { class: 'list-row list-more', href: '#todo', text: `See all ${total}` }) : null)
    : empty('checkCircle', 'Nothing needs your attention. Routine checks will show up here when they\'re due.');
  return card('Needs your attention', 'checkCircle', body, total ? pill(fixList.length || todo.some(/** @param {any} t */ t => t.level === 'danger') ? 'danger' : 'warn', String(total)) : null);
}
