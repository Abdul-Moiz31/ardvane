// @ts-check
import { api } from '../api.js';
import { h, button, card, pill, banner, pageHead, busy } from '../dom.js';
import { modal, closeModal, toast, showError, errorText } from '../feedback.js';
import { rerender } from '../store.js';
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
    sandboxCard(),
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
  /** @type {Record<string, string[]>} [what adding does, how to open it once added] */
  const where = {
    mac: ['Adds Ardvane to your Applications folder, so you can open it like any other app: from Launchpad, Spotlight or the Dock. No Terminal needed.',
      'Open Ardvane from Launchpad, or press ⌘ Space and type "Ardvane". To keep it in the Dock: open it, then right-click its Dock icon → Options → Keep in Dock.'],
    windows: ['Adds Ardvane to your Start menu, so you can open it like any other app. No terminal needed.',
      'Open Ardvane from the Start menu, or press the Windows key and type "Ardvane".'],
    linux: ['Adds Ardvane to your applications menu, so you can open it like any other app.', 'Open Ardvane from your applications menu.'],
  };
  const [what, how] = where[S.data.os] || where.linux;
  const btn = button(p.launcher ? 'Remove' : 'Add app icon', () => launcherAction(p.launcher ? 'remove' : 'install', btn), p.launcher ? 'btn-sm btn-ghost' : 'btn-sm btn-primary');
  return h('div', { class: 'card' }, h('div', { class: 'list' }, h('div', { class: 'list-row' },
    h('div', { class: 'row-icon brand' }, icon('app')),
    h('div', { class: 'grow' }, h('div', { class: 'title', text: 'Ardvane app icon' }), h('div', { class: 'desc', text: p.launcher ? how : what })),
    p.launcher ? pill('ok', 'Added', 'check') : pill('neutral', 'Not added'), btn)));
}

// ---------------------------------------------------------------------------------------------- open safely
async function loadSandbox() {
  try { S.sandbox = await api('/api/sandbox'); } catch (e) { S.sandbox = { runtime: null, ready: false, message: errorText(e) }; }
  rerender();
}

function sandboxCard() {
  if (S.sandbox === undefined) { S.sandbox = null; loadSandbox(); }
  const sb = S.sandbox;
  const input = /** @type {HTMLInputElement} */ (h('input', { type: 'text', class: 'grow', 'aria-label': 'Repository or folder to open safely',
    placeholder: 'owner/name of a coding test, or a folder', value: S.sandboxDraft || '' }));
  input.addEventListener('input', () => { S.sandboxDraft = input.value; });
  const open = button('Open safely', () => busy(open, async () => {
    const target = input.value.trim();
    if (!target) { toast('Type a repository (owner/name) or choose a folder first', 'danger'); return; }
    try {
      const r = await api('/api/sandbox', { target });
      if (r.needs === 'install') installModal(r);
      else if (r.launched) toast(sb && sb.ready ? 'Opened in a terminal window: it scans first, then starts the container'
        : 'Opened in a terminal window: it starts Docker, scans, then starts the container');
      else modal('Run this in a terminal', [h('p', { text: 'Ardvane could not open a terminal window itself. Run:' }), h('pre', { text: r.command })], [button('Close', () => closeModal(), 'btn-primary')]);
    } catch (e) { showError(e); }
  }), 'btn-primary', 'package');
  const choose = button('Choose folder…', async () => {
    try { const r = await api('/api/pick-folder', {}); if (r.path) { S.sandboxDraft = r.path; rerender(); } } catch (e) { showError(e); }
  }, '', 'folder');
  const ready = !!(sb && sb.ready);
  const status = !sb ? null : ready ? pill('ok', sb.runtime === 'podman' ? 'Podman ready' : 'Docker ready', 'check')
    : sb.runtime ? pill('warn', sb.can_start ? 'Not running' : 'Not running', 'alert') : pill('warn', 'Not installed', 'alert');
  const note = !sb ? '' : ready ? 'From a terminal: ardvane sandbox owner/name'
    : sb.runtime ? (sb.can_start ? 'Docker isn\'t running. Open safely starts it for you, then continues.' : sb.message)
    : 'Docker or Podman is needed. Open safely shows where to get one.';
  const again = button('Check again', async () => { try { S.sandbox = await api('/api/sandbox?fresh=1'); rerender(); } catch (e) { showError(e); } }, 'btn-sm btn-ghost', 'refresh');
  return card('Open a coding test safely', 'package', h('div', { class: 'card-pad stack' },
    h('p', { class: 'help', text: 'A take-home test can run code the moment you open it. This scans it first, then opens it in a throwaway container that shares none of your files, keys or environment, and deletes the container when you leave. Run the test in there. The first time downloads a one-off image of about 1.6 GB.' }),
    h('div', { class: 'row' }, input, choose, open),
    h('div', { class: 'row' }, status, h('span', { class: 'help', text: note }), again)));
}

/** @param {any} r */
function installModal(r) {
  modal('Docker or Podman is needed', [
    h('p', { text: 'The sandbox runs the test in a container, and neither Docker nor Podman is installed on this computer. Install one, then press Open safely again: from then on Ardvane starts it for you when it isn\'t running.' }),
    h('div', { class: 'row' }, (r.links || []).map(/** @param {string[]} l */ l => h('a', { class: 'btn', href: l[1], target: '_blank', rel: 'noopener' }, icon('code'), l[0])))],
    [button('Close', () => closeModal(), 'btn-primary')]);
}
