// @ts-check
// Dates, durations and counts in plain language.
const clock = d => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const dayStart = d => new Date(d.getFullYear(), d.getMonth(), d.getDate());

export function plural(n, one, many) { return `${n} ${n === 1 ? one : (many || one + 's')}`; }

export function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const days = Math.round((dayStart(new Date()) - dayStart(d)) / 86400000);
  if (days === 0) return 'today at ' + clock(d);
  if (days === 1) return 'yesterday at ' + clock(d);
  return d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ' at ' + clock(d);
}

export function fmtDay(date) {
  return date.toLocaleDateString([], { day: 'numeric', month: 'short' });
}

// "today at 09:00 (in 3 h 12 min)" for a daily HH:MM time
export function nextRun(hhmm) {
  if (!hhmm) return '';
  const [H, M] = hhmm.split(':').map(Number);
  const now = new Date();
  const next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), H, M);
  if (next <= now) next.setDate(next.getDate() + 1);
  const mins = Math.round((next - now) / 60000);
  const when = (next.getDate() === now.getDate() ? 'today' : 'tomorrow') + ' at ' + clock(next);
  return `${when} (in ${mins < 60 ? mins + ' min' : Math.floor(mins / 60) + ' h ' + (mins % 60) + ' min'})`;
}

export function duration(from, to) {
  const s = Math.max(0, Math.round((to || Date.now() / 1000) - from));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}
