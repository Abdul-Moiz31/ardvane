// @ts-check
import { h, button, pill, banner, pageHead } from '../dom.js';
import { icon } from '../icons.js';
import { ring } from '../charts.js';
import { S, protectionCount } from '../store.js';
import { installFlow, uninstallFlow, launcherAction } from '../actions.js';
import { protectionRows } from '../components.js';
import { historyCard } from '../fixes.js';

export function renderProtection() {
  const p = S.data.protection, pc = protectionCount(p);
  return [
    pageHead('Protection', 'What runs automatically to keep malware out. Every change is shown to you before it\'s made, and can be undone.'),
    statusBanner(p, pc),
    h('div', { class: 'card' }, h('div', { class: 'list' }, protectionRows(false))),
    appIcon(p),
    historyCard(),
    p.installed ? h('div', { class: 'card card-pad row' },
      h('div', { class: 'grow' }, h('h3', { text: 'Remove protection' }),
        h('div', { class: 'help', text: 'Turns off the git hooks, safe clone and daily check and restores your previous settings. Reports are kept.' })),
      button('Remove protection', () => uninstallFlow(), 'btn-danger', 'trash')) : null,
  ].filter(Boolean);
}

/** @param {any} p @param {{on: number, total: number}} pc */
function statusBanner(p, pc) {
  if (!p.git) return banner('warn', 'alert', 'Git is not installed', 'Install git first (on a Mac: xcode-select --install), then come back here.');
  if (!p.installed) return banner('warn', 'shield', 'Automatic protection is off',
    'Turn it on to check every clone, pull and push, block npm install scripts and stop editors from auto-running code. You\'ll see exactly what changes first.',
    button('Turn on protection', () => installFlow(), 'btn-primary', 'shield'));
  if (!p.up_to_date) return banner('warn', 'refresh', 'An update is available', 'The installed scanner is older than this copy of the kit. Updating keeps your settings.',
    button('Update protection', () => installFlow(true), 'btn-primary', 'refresh'));
  return h('div', { class: 'banner ok' }, h('div', { class: 'bicon' }, ring(pc.on, pc.total, { size: 48 })),
    h('div', { class: 'grow' }, h('h3', { text: pc.on === pc.total ? 'Fully protected' : `${pc.on} of ${pc.total} protections on` }),
      h('p', { text: 'The scanner is installed and up to date.' })));
}

/** @param {any} p */
function appIcon(p) {
  /** @type {Record<string, string>} */
  const where = { mac: 'Open this dashboard from Launchpad or Spotlight — no terminal needed.',
    windows: 'Open this dashboard from the Start menu — no terminal needed.', linux: 'Open this dashboard from your applications menu.' };
  const btn = button(p.launcher ? 'Remove' : 'Add app icon', () => launcherAction(p.launcher ? 'remove' : 'install', btn), p.launcher ? 'btn-sm btn-ghost' : 'btn-sm btn-primary');
  return h('div', { class: 'card' }, h('div', { class: 'list' }, h('div', { class: 'list-row' },
    h('div', { class: 'row-icon brand' }, icon('app')),
    h('div', { class: 'grow' }, h('div', { class: 'title', text: 'App icon' }), h('div', { class: 'desc', text: where[S.data.os] })),
    p.launcher ? pill('ok', 'Added', 'check') : pill('neutral', 'Not added'), btn)));
}
