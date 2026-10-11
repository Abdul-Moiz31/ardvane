// @ts-check
import { h, button, pill, choice, switchEl, banner, empty, card, pageHead, busy } from '../dom.js';
import { icon } from '../icons.js';
import { fmtTime, duration, plural } from '../format.js';
import { donut } from '../charts.js';
import { S, STEP_NAMES, fileManagerLabel, rerender, INFECTED_GUIDE, githubLabel } from '../store.js';
import { startScan, cancelScan, reveal, dismiss } from '../actions.js';
import { openReport } from '../components.js';
import { fixesCard, autofixedBanner } from '../fixes.js';

export function renderScan() {
  const head = pageHead('Scan', 'Read-only: a scan never changes, deletes or runs anything from your files.');
  const sc = S.scan;
  if (sc && sc.running) return [head, progress(sc)];
  return [head, sc ? results(sc) : null, setup()].filter(Boolean);
}

function setup() {
  const o = S.scanOpts, set = S.data.settings;
  const pick = (/** @type {() => void} */ fn) => () => { fn(); rerender(); };
  const gh = githubLabel(set.github_user, set.github_repos);
  const covers = [set.github_user ? 'recently pushed repositories' : '', set.github_repos.length ? 'every branch of the repositories you listed' : ''].filter(Boolean).join(', and ');
  const ghDesc = gh
    ? covers.charAt(0).toUpperCase() + covers.slice(1) + (set.gh ? ' (private ones too when you are logged in to the GitHub CLI).' : ' (public repositories only).')
    : h('span', {}, 'Add your username or repositories in ', h('a', { href: '#settings', text: 'Settings' }), ' first.');
  const body = h('div', { class: 'card-pad stack' },
    h('h3', { text: 'Type' }),
    h('div', { class: 'choices' },
      choice('radio', o.mode === 'full', 'Full scan', 'This computer plus every project and installed package. Takes a few minutes.', pick(() => { o.mode = 'full'; }), false, true),
      choice('radio', o.mode === 'quick', 'Quick scan', 'Malware locations, startup items, network and editors. About 15 seconds.', pick(() => { o.mode = 'quick'; }))),
    h('h3', { text: 'Projects to include' }),
    h('div', { class: 'choices' },
      choice('radio', o.where === 'home', 'Whole home folder', 'Finds every git project up to 6 folders deep.', pick(() => { o.where = 'home'; }), o.mode === 'quick'),
      choice('radio', o.where === 'folders', `My project folders (${set.folders.length})`, set.folders.slice(0, 3).join(', ') + (set.folders.length > 3 ? '…' : ''),
        pick(() => { o.where = 'folders'; }), o.mode === 'quick')),
    h('h3', { text: 'Also check' }),
    h('div', { class: 'choices' },
      choice('checkbox', !!(o.github && gh), gh ? `GitHub: ${gh}` : 'GitHub', ghDesc, pick(() => { o.github = !o.github; }), !gh)),
    h('div', { class: 'row' }, h('div', { class: 'spacer' }),
      button(o.mode === 'quick' ? 'Start quick scan' : 'Start full scan', () => startScan(), 'btn-primary btn-lg', 'play')));
  return card(S.scan ? 'Scan again' : 'New scan', 'radar', body);
}

/** @param {import('../store.js').Scan} sc */
function progress(sc) {
  const gh = githubLabel(sc.github_user, sc.github_repos || []);
  const names = STEP_NAMES.concat(gh ? ['GitHub'] : []);
  const current = sc.phase === 'github' ? names.length - 1 : Math.max(0, sc.sections.length - 1);
  const steps = h('div', { class: 'steps' }, names.map((name, i) => {
    const sec = sc.sections[i];
    const state = i < current ? 'done' : i === current ? 'current' : '';
    const flag = sec && sec.items.some(x => x.level === 'danger') ? 'danger' : sec && sec.items.some(x => x.level === 'warn' && !x.dismissed) ? 'warn' : '';
    return h('div', { class: `step ${state}${state === 'done' && flag ? ' flag-' + flag : ''}` },
      h('span', { class: 'dot' }, state === 'done' ? icon(flag === 'danger' ? 'x' : flag === 'warn' ? 'alert' : 'check') : null), name);
  }));
  const bar = h('div');
  bar.style.width = Math.max(4, Math.round(100 * current / names.length)) + '%';
  const now = sc.phase === 'feed' ? 'Updating detections…' : sc.phase === 'github' ? `Checking GitHub: ${gh}…` : sc.progress ? `Scanning project ${sc.progress}` : `${names[current]}…`;
  const cancel = button('Cancel', () => busy(cancel, cancelScan), 'btn-sm', 'stop');
  return card(`${sc.mode === 'quick' ? 'Quick' : 'Full'} scan in progress`, 'radar',
    h('div', { class: 'card-pad stack' },
      h('div', { class: 'progress' }, bar), h('div', { class: 'now', text: now }),
      (sc.danger || sc.warn) ? h('div', { class: 'row' }, sc.danger ? pill('danger', plural(sc.danger, 'serious finding')) : null,
        sc.warn ? pill('warn', `${plural(sc.warn, 'item')} to review`) : null) : null,
      steps,
      h('p', { class: 'help', text: 'You can leave this page — the scan keeps running and you\'ll get a message when it\'s done.' })),
    h('div', { class: 'row' }, h('span', { class: 'muted', text: duration(sc.started) }), cancel));
}

/** @param {import('../store.js').Scan} sc */
function results(sc) {
  const level = sc.cancelled ? 'neutral' : sc.danger ? 'danger' : sc.warn ? 'warn' : 'ok';
  const title = sc.cancelled ? 'Scan cancelled' : sc.danger ? `Malware found — ${plural(sc.danger, 'serious finding')}`
    : sc.warn ? `No malware found · ${plural(sc.warn, 'item')} worth a look` : 'No signs of malware';
  const text = sc.cancelled ? 'Partial results are shown below.'
    : sc.danger ? 'Don\'t open the affected projects in your editor and don\'t run npm install in them. Follow the recovery guide — the order of the steps matters.'
    : sc.warn ? 'These are unusual but often harmless. Review each one, and mark it as yours if you recognise it.'
    : `Finished ${fmtTime(sc.finished)} in ${duration(sc.started, sc.finished || undefined)}.`;
  const top = banner(level, level === 'danger' ? 'shieldAlert' : level === 'ok' ? 'shieldCheck' : level === 'warn' ? 'alert' : 'info', title, text,
    sc.danger ? button('What to do now', () => { location.hash = INFECTED_GUIDE; }, 'btn-danger-solid', 'alert') : undefined);

  const passedSections = sc.sections.filter(s => !s.items.some(i => i.level === 'danger' || (i.level === 'warn' && !i.dismissed))).length;
  const summary = card('Summary', 'chart', h('div', { class: 'card-pad summary' },
    donut([{ label: 'Checks passed', value: passedSections, level: 'ok' },
      { label: 'Worth a look', value: sc.sections.length - passedSections - sc.sections.filter(s => s.items.some(i => i.level === 'danger')).length, level: 'warn' },
      { label: 'Threats', value: sc.sections.filter(s => s.items.some(i => i.level === 'danger')).length, level: 'danger' }],
    `${passedSections}/${sc.sections.length}`, 'checks passed'),
    h('div', { class: 'summary-facts' },
      fact('Type', sc.mode === 'quick' ? 'Quick scan' : 'Full scan'), fact('Started', fmtTime(sc.started)),
      fact('Took', duration(sc.started, sc.finished || undefined)), fact('GitHub', githubLabel(sc.github_user, sc.github_repos || []) || 'not included'),
      fact('Detections', sc.feed || 'built-in (feed updates are off)'),
      sc.report ? h('div', {}, button('Open full report', () => openReport('scan:' + String(sc.report).split(/[\\/]/).pop()), 'btn-sm', 'file')) : null)));

  const list = h('div', { class: 'card' });
  for (const sec of sc.sections) {
    const shown = sec.items.filter(i => S.showPassed || i.level === 'danger' || i.level === 'warn');
    if (!shown.length && !S.showPassed) continue;
    const d = sec.items.filter(i => i.level === 'danger').length, w = sec.items.filter(i => i.level === 'warn' && !i.dismissed).length;
    list.append(h('div', { class: 'section-head' }, h('span', { class: 'grow', text: sec.title }),
      d ? pill('danger', plural(d, 'threat')) : null, w ? pill('warn', `${w} to review`) : null, !d && !w ? pill('ok', 'Passed', 'check') : null));
    shown.forEach(it => list.append(findingRow(it)));
  }
  if (!list.childNodes.length) list.append(empty('checkCircle', 'Every check passed.'));
  const tools = h('div', { class: 'row' },
    h('label', { class: 'row small' }, switchEl(S.showPassed, () => { S.showPassed = !S.showPassed; rerender(); }, 'Show passed checks'), 'Show passed checks'));
  const next = (sc.danger || sc.warn) && !sc.cancelled ? h('div', { class: 'banner neutral' }, h('div', { class: 'bicon' }, icon('checkCircle')),
    h('div', { class: 'grow' }, h('h3', { text: 'Your next steps are in the to-do list' }),
      h('p', { text: 'Every finding has a short checklist. Tick each step off as you go — a later scan tells you if something is still there.' })),
    button('Open to-do', () => { location.hash = '#todo'; }, 'btn-primary', 'checkCircle')) : null;
  return h('div', { class: 'stack' }, top, autofixedBanner(sc.autofixed), fixesCard(), next, summary, tools, list);
}

/** @param {string} label @param {string} value */
function fact(label, value) {
  return h('div', { class: 'fact' }, h('div', { class: 'muted small', text: label }), h('div', { class: 'fact-value', text: value }));
}

/** @param {import('../store.js').Finding} it */
function findingRow(it) {
  const actions = h('div', { class: 'factions' });
  if (it.path && (it.level === 'danger' || it.level === 'warn')) actions.append(button(fileManagerLabel(), () => reveal(it.path), 'btn-sm', 'folder'));
  if (it.level === 'danger') actions.append(button('What to do', () => { location.hash = INFECTED_GUIDE; }, 'btn-sm', 'book'));
  if (it.level === 'warn' && /^[0-9a-f]{16}$/.test(it.key) && it.key !== '0'.repeat(16)) {
    actions.append(button(it.dismissed ? 'Undo' : 'It\'s mine', () => dismiss(it.key, it.dismissed), 'btn-sm btn-ghost', it.dismissed ? 'refresh' : 'eyeOff',
      { title: 'Hide this item in future results (it stays in the report)' }));
  }
  /** @type {Record<string, string>} */
  const ic = { danger: 'xCircle', warn: 'warn', ok: 'checkCircle', info: 'info' };
  return h('div', { class: `finding ${it.level}${it.dismissed ? ' dismissed' : ''}` },
    h('span', { class: 'ficon' }, icon(ic[it.level])), h('div', { class: 'ftext', text: it.text }), actions.childNodes.length ? actions : null);
}
