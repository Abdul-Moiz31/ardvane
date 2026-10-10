// @ts-check
// Overview = the security dashboard: one status, four numbers, what needs attention, and the trend. Details live on
// their own pages (To-do, Scan, Protection, Reports).
import { h, button, pill, card, pageHead, empty, skeleton } from '../dom.js';
import { icon } from '../icons.js';
import { modal, closeModal } from '../feedback.js';
import { fmtTime, nextRun, plural } from '../format.js';
import { ring, history } from '../charts.js';
import { S, loadTasks, loadReports, heroState, latestResult, protectionCount, scopeText, INFECTED_GUIDE } from '../store.js';
import { installFlow, setRoutine, startScan } from '../actions.js';
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
    kpis(),
    h('div', { class: 'overview-grid' }, attention(),
      card('Last 30 days', 'chart', h('div', { class: 'card-pad' }, S.reports ? history(S.reports) : h('div', { class: 'skeleton chart-skeleton' })),
        h('a', { href: '#reports', text: 'All reports' }))),
    h('div', { class: 'grid grid-2' },
      card('Protection', 'shield', h('div', { class: 'list' }, protectionRows(true)), h('a', { href: '#protection', text: 'Manage' })),
      card('Recent activity', 'file', recentReports(4), h('a', { href: '#reports', text: 'All reports' }))),
  ];
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
  return h('div', { class: 'hero status tone-' + st.tone },
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
