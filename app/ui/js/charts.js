// @ts-check
// Small SVG charts. No chart library: every shape is built here, so nothing external is loaded.
import { h } from './dom.js';
import { fmtDay, plural } from './format.js';

const NS = 'http://www.w3.org/2000/svg';

/**
 * @param {string} tag
 * @param {Record<string, string|number>} [attrs]
 * @param {...(Node|string)} kids
 * @returns {SVGElement}
 */
function s(tag, attrs, ...kids) {
  const el = /** @type {SVGElement} */ (document.createElementNS(NS, tag));
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const kid of kids) el.append(typeof kid === 'string' ? document.createTextNode(kid) : kid);
  return el;
}

/**
 * Progress ring, e.g. "4 of 5 protections on".
 * @param {number} value
 * @param {number} total
 * @param {{size?: number, label?: string}} [opts]
 */
export function ring(value, total, opts = {}) {
  const size = opts.size || 56, stroke = size / 8, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const frac = total ? Math.max(0, Math.min(1, value / total)) : 0;
  const tone = frac >= 1 ? 'ok' : frac >= 0.6 ? 'warn' : 'danger';
  const svg = s('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, class: 'ring ring-' + tone, role: 'img',
    'aria-label': opts.label || `${value} of ${total}` },
    s('circle', { cx: size / 2, cy: size / 2, r, class: 'ring-track', 'stroke-width': stroke }),
    s('circle', { cx: size / 2, cy: size / 2, r, class: 'ring-value', 'stroke-width': stroke,
      'stroke-dasharray': `${c * frac} ${c}`, transform: `rotate(-90 ${size / 2} ${size / 2})` }),
    s('text', { x: '50%', y: '50%', 'dominant-baseline': 'central', 'text-anchor': 'middle', class: 'ring-text' }, `${value}/${total}`));
  return svg;
}

/**
 * Donut of scan results with a legend.
 * @param {{label: string, value: number, level: string}[]} parts
 * @param {string} centerValue
 * @param {string} centerLabel
 */
export function donut(parts, centerValue, centerLabel) {
  const size = 132, stroke = 16, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const total = parts.reduce((a, p) => a + p.value, 0);
  const svg = s('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, class: 'donut', role: 'img',
    'aria-label': parts.map(p => `${p.value} ${p.label}`).join(', ') },
    s('circle', { cx: size / 2, cy: size / 2, r, class: 'ring-track', 'stroke-width': stroke }));
  let offset = 0;
  const gap = parts.filter(p => p.value).length > 1 ? 2 : 0;
  for (const p of parts) {
    if (!p.value) continue;
    const len = (c * p.value) / total;
    svg.append(s('circle', { cx: size / 2, cy: size / 2, r, class: 'seg seg-' + p.level, 'stroke-width': stroke,
      'stroke-dasharray': `${Math.max(0, len - gap)} ${c}`, 'stroke-dashoffset': String(-offset),
      transform: `rotate(-90 ${size / 2} ${size / 2})` }, s('title', {}, `${p.value} ${p.label}`)));
    offset += len;
  }
  svg.append(s('text', { x: '50%', y: '46%', 'text-anchor': 'middle', class: 'donut-value' }, centerValue),
    s('text', { x: '50%', y: '62%', 'text-anchor': 'middle', class: 'donut-label' }, centerLabel));
  const legend = h('div', { class: 'legend' }, parts.map(p =>
    h('div', { class: 'legend-row' }, h('span', { class: 'swatch swatch-' + p.level }), h('span', { class: 'grow', text: p.label }), h('strong', { text: String(p.value) }))));
  return h('div', { class: 'donut-wrap' }, svg, legend);
}

const RANK = { none: 0, unknown: 1, ok: 2, warn: 3, danger: 4 };

/**
 * One column per day: colour = worst result that day, height = number of findings.
 * @param {{kind: string, time: number, level: string, danger: number, warn: number}[]} reports
 * @param {number} [days]
 */
export function history(reports, days = 30) {
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const buckets = Array.from({ length: days }, (_, i) => {
    const d = new Date(today); d.setDate(d.getDate() - (days - 1 - i));
    return { date: d, level: 'none', danger: 0, warn: 0, runs: 0 };
  });
  for (const r of reports) {
    const d = new Date(r.time * 1000); d.setHours(0, 0, 0, 0);
    const idx = Math.round((d.getTime() - buckets[0].date.getTime()) / 86400000);
    const b = buckets[idx];
    if (!b) continue;
    b.runs++;
    b.danger += r.danger || 0;
    b.warn += r.warn || 0;
    if ((RANK[r.level] || 0) > (RANK[b.level] || 0)) b.level = r.level;
  }
  const W = 640, H = 140, top = 8, bottom = 24, gap = 4;
  const bw = (W - gap * (days - 1)) / days;
  const max = Math.max(1, ...buckets.map(b => b.danger + b.warn));
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'history', role: 'img', preserveAspectRatio: 'none',
    'aria-label': `Results of the last ${days} days` });
  const plotH = H - top - bottom;
  [0.5, 1].forEach(f => svg.append(s('line', { x1: 0, x2: W, y1: top + plotH * (1 - f), y2: top + plotH * (1 - f), class: 'gridline' })));
  buckets.forEach((b, i) => {
    const n = b.danger + b.warn;
    const frac = b.level === 'none' ? 0.06 : n ? 0.3 + 0.7 * (n / max) : 0.22;
    const bh = Math.max(3, plotH * frac);
    const x = i * (bw + gap);
    const tip = `${fmtDay(b.date)}: ` + (b.level === 'none' ? 'no check' :
      b.level === 'danger' ? `${plural(b.danger, 'serious finding')}` : b.level === 'warn' ? `${plural(b.warn, 'item')} worth a look` :
      b.level === 'ok' ? 'clean' : 'unknown') + (b.runs > 1 ? ` (${b.runs} runs)` : '');
    svg.append(s('rect', { x, y: top + plotH - bh, width: bw, height: bh, rx: Math.min(4, bw / 3), class: 'bar bar-' + b.level }, s('title', {}, tip)));
  });
  [[0, 'start'], [Math.floor(days / 2), 'middle'], [days - 1, 'end']].forEach(([i, anchor]) => {
    const x = Number(i) * (bw + gap) + (anchor === 'start' ? 0 : anchor === 'end' ? bw : bw / 2);
    svg.append(s('text', { x, y: H - 6, 'text-anchor': String(anchor), class: 'axis' }, i === days - 1 ? 'Today' : fmtDay(buckets[Number(i)].date)));
  });
  const checked = buckets.filter(b => b.level !== 'none').length;
  const bad = buckets.filter(b => b.level === 'danger').length;
  const review = buckets.filter(b => b.level === 'warn').length;
  const summary = h('div', { class: 'history-summary' },
    stat(String(checked), `of ${days} days checked`), stat(String(bad), bad === 1 ? 'day with threats' : 'days with threats', bad ? 'danger' : ''),
    stat(String(review), review === 1 ? 'day to review' : 'days to review', review ? 'warn' : ''));
  const legend = h('div', { class: 'legend legend-inline' },
    [['ok', 'Clean'], ['warn', 'Worth a look'], ['danger', 'Threats'], ['none', 'No check']].map(([lvl, label]) =>
      h('span', { class: 'legend-row' }, h('span', { class: 'swatch swatch-' + lvl }), label)));
  return h('div', { class: 'history-wrap' }, summary, svg, legend);
}

/** @param {string} value @param {string} label @param {string} [tone] */
function stat(value, label, tone) {
  return h('div', { class: 'hstat' }, h('span', { class: 'hstat-value ' + (tone || ''), text: value }), h('span', { class: 'muted small', text: label }));
}
