// @ts-check
// Entry point: routing, rendering and start-up.
import { api, onOffline } from './api.js';
import { $, h } from './dom.js';
import { hydrateIcons } from './icons.js';
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

/** @type {Record<string, (sub: string) => (Node|null)[]>} */
const PAGES = { overview: renderOverview, todo: renderTodo, scan: renderScan, protection: renderProtection, reports: renderReports, learn: renderLearn, settings: renderSettings };

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
  const target = $('#page-' + page);
  if (target) target.replaceChildren(...PAGES[page](sub).filter(Boolean));
}

setRenderer(render);
onOffline(setOfflineBanner);
initModal();
hydrateIcons();
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
