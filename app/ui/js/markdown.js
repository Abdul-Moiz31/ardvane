// @ts-check
// Minimal Markdown → HTML for the kit's own guides. Every piece of text is HTML-escaped first, so the output can
// only contain the tags created here.

/** @param {string} s */
export function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** @param {string} s */
function inline(s) {
  /** @type {string[]} */
  const codes = [];
  let out = esc(s).replace(/`([^`]+)`/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, text, url) => `<a href="${url}" data-md-link>${text}</a>`)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
    .replace(/(^|[\s(])_([^_\s][^_]*)_(?=[\s).,;:]|$)/g, '$1<em>$2</em>');
  return out.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${codes[Number(i)]}</code>`);
}

const LIST_ITEM = /^\s*([-*]|\d+\.)\s+/;
const TABLE_ROW = /^\s*\|.*\|\s*$/;
const TABLE_SEP = /^\s*\|[\s:|-]+\|\s*$/;
const BLOCK_START = /^(#{1,4}\s|```|>|\s*([-*]|\d+\.)\s|\s*\|)/;

/** @param {string} src @returns {string} */
export function markdown(src) {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  /** @type {string[]} */
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {                                   // code block
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
      continue;
    }
    if (/^\s*$/.test(line) || /^<\/?[a-z][^>]*>\s*$/i.test(line)) { i++; continue; }   // blank / raw HTML layout line
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) { const n = heading[1].length; out.push(`<h${n}>${inline(heading[2])}</h${n}>`); i++; continue; }
    if (/^(-{3,}|\*{3,})\s*$/.test(line)) { out.push('<hr>'); i++; continue; }
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
      out.push(`<blockquote>${inline(buf.join(' '))}</blockquote>`);
      continue;
    }
    if (TABLE_ROW.test(line) && TABLE_SEP.test(lines[i + 1] || '')) {
      /** @param {string} row */
      const cells = row => row.trim().replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim()));
      const head = cells(line);
      i += 2;
      const body = [];
      while (i < lines.length && TABLE_ROW.test(lines[i])) body.push(cells(lines[i++]));
      out.push('<table><thead><tr>' + head.map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>'
        + body.map(r => '<tr>' + r.map(c => `<td>${c}</td>`).join('') + '</tr>').join('') + '</tbody></table>');
      continue;
    }
    if (LIST_ITEM.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      /** @type {string[]} */
      const items = [];
      while (i < lines.length && (LIST_ITEM.test(lines[i]) || (items.length && /^\s{2,}\S/.test(lines[i])))) {
        const l = lines[i++];
        if (LIST_ITEM.test(l)) items.push(l.replace(LIST_ITEM, ''));
        else items[items.length - 1] += ' ' + l.trim();
      }
      const tag = ordered ? 'ol' : 'ul';
      out.push(`<${tag}>` + items.map(t => {
        const task = t.match(/^\[([ xX])\]\s+(.*)$/);
        return task ? `<li class="task"><input type="checkbox" disabled${task[1] !== ' ' ? ' checked' : ''}>${inline(task[2])}</li>`
          : `<li>${inline(t)}</li>`;
      }).join('') + `</${tag}>`);
      continue;
    }
    const buf = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !BLOCK_START.test(lines[i])) buf.push(lines[i++]);
    if (!buf.length) buf.push(lines[i++]);
    out.push(`<p>${inline(buf.join(' '))}</p>`);
  }
  return out.join('\n');
}
