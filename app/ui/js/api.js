// @ts-check
// Talking to the local server. The private key arrives in the URL fragment (browsers never send fragments to a
// server), is kept for this tab only, and is removed from the address bar straight away.
const STORE = 'guard-key';
let memoryKey = '';
const offlineListeners = [];

(function takeKeyFromUrl() {
  const m = location.hash.match(/k=([A-Za-z0-9_-]{20,})/);
  if (!m) return;
  try { sessionStorage.setItem(STORE, m[1]); } catch (e) { memoryKey = m[1]; }
  history.replaceState(null, '', location.pathname + '#overview');
})();

function key() {
  try { return sessionStorage.getItem(STORE) || memoryKey; } catch (e) { return memoryKey; }
}

export function onOffline(fn) { offlineListeners.push(fn); }
function setOffline(off) { offlineListeners.forEach(fn => fn(off)); }

export async function api(path, body) {
  /** @type {Record<string, string>} */
  const headers = { 'X-Guard-Key': key() };
  /** @type {RequestInit} */
  const opts = { headers, cache: 'no-store' };
  if (body !== undefined) {
    opts.method = 'POST';
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opts); } catch (e) { setOffline(true); throw new Error('The dashboard is not running.'); }
  setOffline(false);
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (res.status === 403) throw new Error('This tab has no access key. Open the dashboard again from its app icon.');
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
