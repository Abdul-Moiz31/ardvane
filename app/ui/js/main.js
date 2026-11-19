// @ts-check
// Entry point: routing, rendering and start-up.
import { api, onOffline } from './api.js';
import { $, h } from './dom.js';
import { hydrateIcons, icon } from './icons.js';
import { initModal, errorText } from './feedback.js';
import { S, refresh, setRenderer } from './store.js';
import { pollScan, setOfflineBanner } from './actions.js';
import { renderOverview } from './pages/overview.js';
import { renderScan } from './pages/scan.js';
import { renderProtection } from './pages/protection.js';
import { renderReports } from './pages/reports.js';
import { renderLearn } from './pages/learn.js';
import { renderSettings } from './pages/settings.js';
import { renderTodo } from './pages/todo.js';
import { renderHistory } from './pages/history.js';

/** @type {Record<string, (sub: string) => (Node|null)[]>} */
const PAGES = { overview: renderOverview, todo: renderTodo, scan: renderScan, history: renderHistory, protection: renderProtection, reports: renderReports, learn: renderLearn, settings: renderSettings };

function route() {
  const [page, ...rest] = (location.hash || '#overview').slice(1).split('/');
  return { page: page in PAGES ? page : 'overview', sub: decodeURIComponent(rest.join('/')) };
}

function render() {
  if (!S.data) return;
  const { page, sub } = route();
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('active', /** @type {HTMLElement} */ (a).dataset.page === page));
  document.querySelectorAll('.nav a').forEach(a => a.toggleAttribute('aria-current', /** @type {HTMLElement} */ (a).dataset.page === page));
  document.querySelectorAll('.page').forEach(el => { /** @type {HTMLElement} */ (el).hidden = el.id !== 'page-' + page; });
  const dot = $('#nav-scan-dot');
  if (dot) dot.hidden = !(S.scan && S.scan.running);
  const badge = $('#nav-todo-count'), open = S.data.todo ? S.data.todo.open : 0;
  badge.hidden = !open;
  badge.textContent = String(open);
  badge.classList.toggle('danger', !!(S.data.todo && S.data.todo.danger));
  const help = $('.help-link');                    // red only while something serious is open
  if (help) help.classList.toggle('alert', !!(S.data.todo && S.data.todo.danger));
  const target = $('#page-' + page);
  if (!target) return;
  // Animate a page in when you open it, never when it is redrawn with new data (that would flicker)
  const entering = page !== lastPage;
  lastPage = page;
  target.classList.toggle('enter', entering);
  keepTyping(target, () => target.replaceChildren(...PAGES[page](sub).filter(Boolean)));
  if (entering) countUp(target);
}

/** @type {string} */
let lastPage = '';

/** Whole numbers in the stat tiles count up from zero when a page opens. @param {Element} root */
function countUp(root) {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  root.querySelectorAll('.tile-value, .hstat-value').forEach(el => {
    const text = el.textContent || '';
    if (!/^\d{1,4}$/.test(text)) return;
    const to = Number(text), start = performance.now();
    if (!to) return;
    const step = (/** @type {number} */ now) => {
      const p = Math.min(1, (now - start) / 800);
      el.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(step);
    };
    el.textContent = '0';
    requestAnimationFrame(step);
  });
}

const TYPED = 'input[type=text], input[type=time], input[type=search], input:not([type]), textarea';

/**
 * Pages are rebuilt whenever new data arrives (a scan update, the to-do list loading, the tab coming back into view).
 * Whatever the user is typing - and where the cursor is - must survive that.
 * @param {Element} target @param {() => void} build
 */
function keepTyping(target, build) {
  const key = (/** @type {Element} */ el) => el.getAttribute('aria-label') || el.getAttribute('name') || el.id;
  /** @type {Map<string, string>} */
  const typed = new Map();
  /** @type {{k: string, s: number|null, e: number|null}|null} */
  let focus = null;
  target.querySelectorAll(TYPED).forEach(n => {
    const el = /** @type {HTMLInputElement} */ (n), k = key(el);
    if (!k || !el.dataset.dirty) return;
    typed.set(k, el.value);
    if (el === document.activeElement) focus = { k, s: el.selectionStart, e: el.selectionEnd };
  });
  build();
  target.querySelectorAll(TYPED).forEach(n => {
    const el = /** @type {HTMLInputElement} */ (n), k = key(el);
    if (!k) return;
    const v = typed.get(k);
    if (v !== undefined) { el.value = v; el.dataset.dirty = '1'; }
    if (focus && focus.k === k) {
      el.focus({ preventScroll: true });
      try { el.setSelectionRange(focus.s, focus.e); } catch (e) { /* type=time has no selection */ }
    }
  });
}
// An input the user has typed into keeps its text across re-renders until the page itself clears it.
document.addEventListener('input', e => {
  const el = /** @type {HTMLElement} */ (e.target);
  if (el && el.matches && el.matches(TYPED)) el.dataset.dirty = '1';
});

setRenderer(render);
onOffline(setOfflineBanner);
initModal();
hydrateIcons();
themeSwitch();

/** System / Light / Dark buttons in the sidebar (js/theme.js applies the choice). */
function themeSwitch() {
  const theme = /** @type {any} */ (window).guardTheme;
  const box = $('#theme-switch');
  if (!theme || !box) return;
  const draw = () => box.replaceChildren(...[['system', 'Auto', 'monitor'], ['light', 'Light', 'sun'], ['dark', 'Dark', 'moon']].map(([value, label, ic]) =>
    h('button', { type: 'button', 'aria-pressed': String(theme.get() === value), title: value === 'system' ? 'Follow your computer\'s setting' : `${label} mode`,
      onclick: () => { theme.set(value); draw(); } }, icon(ic), label)));
  draw();
}
window.addEventListener('hashchange', () => { render(); /** @type {HTMLElement} */ ($('#main')).focus({ preventScroll: true }); window.scrollTo(0, 0); });

// Keep the server alive while the tab is open; refresh when the tab comes back into view.
setInterval(() => { api('/api/ping').catch(() => {}); }, 30000);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && S.data && !(S.scan && S.scan.running)) refresh().catch(() => {});
});

refresh().then(() => { if (S.scan && S.scan.running) pollScan(); }).catch(e => {
  const main = $('#main');
  if (main) main.prepend(h('div', { class: 'offline' }, h('strong', { text: 'Can\'t load the dashboard. ' }), errorText(e)));
});
