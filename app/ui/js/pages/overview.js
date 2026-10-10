// @ts-check
import { h, button, pill, card, pageHead } from '../dom.js';
import { icon } from '../icons.js';
import { fmtTime, nextRun } from '../format.js';
import { ring, history } from '../charts.js';
import { S, loadTasks, heroState, latestResult, protectionCount, scopeText, loadReports, INFECTED_GUIDE } from '../store.js';
import { installFlow, setRoutine, startScan } from '../actions.js';
import { tile, recentReports, protectionRows } from '../components.js';
import { todoPreview } from './todo.js';
import { fixesCard } from '../fixes.js';

export function renderOverview() {
  if (!S.reports) loadReports();
  if (!S.tasks) loadTasks();
  const todo = S.data.todo || { open: 0 };
  return [pageHead('Overview', 'Your computer\'s protection at a glance.'), hero(), fixesCard(),
    card(todo.open ? `Your to-do · ${todo.open} open` : 'Your to-do', 'checkCircle', todoPreview(), h('a', { href: '#todo', text: 'Open to-do' })),
    schedule(), tiles(),
    card('Last 30 days', 'chart', h('div', { class: 'card-pad' }, S.reports ? history(S.reports) : h('div', { class: 'skeleton chart-skeleton' })),
      h('a', { href: '#reports', text: 'All reports' })),
    h('div', { class: 'grid grid-2' },
      card('Protection', 'shield', h('div', { class: 'list' }, protectionRows(true)), h('a', { href: '#protection', text: 'Manage' })),
      card('Recent activity', 'file', recentReports(), h('a', { href: '#reports', text: 'All reports' })))];
}

function hero() {
  const st = heroState(), r = latestResult(), rt = S.data.protection.routine, sc = S.scan;
  const actions = h('div', { class: 'hero-actions' });
  if (sc && sc.running) {
    actions.append(button('View progress', () => { location.hash = '#scan'; }, 'btn-primary btn-lg', 'radar'));
  } else {
    if (st.tone === 'danger') actions.append(button('What to do now', () => { location.hash = INFECTED_GUIDE; }, 'btn-danger-solid btn-lg', 'alert'));
    actions.append(button('Scan now', () => startScan(), st.tone === 'danger' ? 'btn-lg' : 'btn-primary btn-lg', 'play'));
    if (st.fix === 'protect') actions.append(button('Turn on protection', () => installFlow(), '', 'shield'));
    else if (st.fix === 'todo' || st.fix === 'fixes') actions.append(button('Open checklist', () => { location.hash = '#todo'; }, '', 'checkCircle'));
    else if (r) actions.append(button('See results', () => { location.hash = r.kind === 'scan' ? '#scan' : '#reports'; }, '', 'file'));
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
  return h('div', { class: 'hero tone-' + st.tone },
    h('div', { class: 'hero-icon' }, icon(st.icon)),
    h('div', { class: 'hero-text' }, h('h1', { text: st.title }), h('p', { text: st.text }), detail),
    actions);
}

// The daily schedule is the setting people care most about, so it sits on the first screen.
function schedule() {
  const rt = S.data.protection.routine;
  const time = /** @type {HTMLInputElement} */ (h('input', { type: 'time', value: rt.time || '09:00', 'aria-label': 'Daily check time', step: '60' }));
  const status = rt.on ? `Every day · next run ${nextRun(rt.time)} · checks ${scopeText()}`
    : rt.available ? 'Choose a time and your computer is checked automatically every day.' : 'Scheduled checks are available on macOS and Windows.';
  return h('div', { class: 'card schedule' },
    h('div', { class: 'schedule-icon' }, icon('clock')),
    h('div', { class: 'grow' },
      h('div', { class: 'muted small', text: 'Daily check' }),
      h('div', { class: 'row' }, h('span', { class: 'schedule-time', text: rt.on ? rt.time : 'Off' }), rt.on ? pill('ok', 'On', 'check') : pill('neutral', 'Not scheduled')),
      h('div', { class: 'muted small', text: status })),
    rt.available ? h('div', { class: 'row' }, time,
      button(rt.on ? 'Change time' : 'Turn on', e => setRoutine(true, time.value, /** @type {HTMLElement} */ (e.currentTarget)), rt.on ? '' : 'btn-primary'),
      rt.on ? button('Turn off', e => setRoutine(false, null, /** @type {HTMLElement} */ (e.currentTarget)), 'btn-ghost') : null) : null);
}

function tiles() {
  const p = S.data.protection, r = latestResult(), pc = protectionCount(p), set = S.data.settings;
  const latest = r ? `latest ${r.kind === 'scan' ? 'scan' : 'daily check'}` : 'no scan yet';
  return h('div', { class: 'grid grid-4' },
    tile('Threats found', r ? String(r.danger || 0) : '–', latest, 'shieldAlert'),
    tile('Worth a look', r ? String(r.warn || 0) : '–', 'often harmless', 'warn'),
    tile('Protection', pc.on === pc.total ? 'All on' : `${pc.on} of ${pc.total}`, pc.on === pc.total ? 'everything is on' : 'some protection is off', 'shield',
      ring(pc.on, pc.total, { size: 52, label: `${pc.on} of ${pc.total} protections on` })),
    tile('Watched', String(set.folders.length), set.github_enabled ? `folders + GitHub @${set.github_user}` : 'project folders', 'folder'));
}
