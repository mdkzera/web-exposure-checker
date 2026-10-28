// Optional: URL of the TCP-check backend (see worker.js). Empty = browser-only mode.
const BACKEND_URL = '';

const MAX = 50, TIMEOUT = 8000, CONCURRENCY = 6;

function parseInput(text) {
  const seen = new Set(), items = [], invalid = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const explicit = /^[a-z][a-z0-9+.-]*:\/\//i.test(line);
    let u;
    try { u = new URL(explicit ? line : 'http://' + line); } catch { invalid.push(line); continue; }
    const h = u.hostname;
    const isV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(h);
    const ok = /^https?:$/.test(u.protocol) && (
      /^\[[0-9a-f:.]+\]$/i.test(h) || isV4 ||
      /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$/i.test(h));
    if (!ok) { invalid.push(line); continue; }
    const key = u.href.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ label: line, url: u, explicit });
  }
  return { items, invalid };
}

// Browser can only prove "open" (a response arrived). A failure never proves "closed".
async function probe(url) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), TIMEOUT);
  try {
    await fetch(url, { mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: c.signal });
    return true;
  } catch { return false; } finally { clearTimeout(t); }
}

async function browserCheck(it) {
  const h = it.url.hostname, path = it.url.pathname + it.url.search;
  // http:// requests from an https page are blocked as mixed content -> not testable.
  const canHttp = location.protocol === 'http:';
  const cands = (it.explicit ? [it.url.href] : [`https://${h}${path}`, `http://${h}${path}`])
    .filter(u => canHttp || u.startsWith('https:'));
  const [s443, s80] = await Promise.all([probe(`https://${h}/`), canHttp ? probe(`http://${h}/`) : false]);
  let web = false;
  for (const u of cands) if (await probe(u)) { web = true; break; }
  const v = b => (b ? 'YES' : 'UNKNOWN');
  return { web: v(web), p80: v(s80), p443: v(s443) };
}

async function backendCheck(it) {
  if (!BACKEND_URL) return null;
  const c = new AbortController(), t = setTimeout(() => c.abort(), 20000);
  try {
    const r = await fetch(BACKEND_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: it.url.hostname }), signal: c.signal
    });
    return r.ok ? await r.json() : null;
  } catch { return null; } finally { clearTimeout(t); }
}

const clean = v => (v === 'YES' || v === 'NO' ? v : 'UNKNOWN');
// YES from either side is positive evidence; NO only comes from the backend; else UNKNOWN.
const merge = (a, b) => (a === 'YES' || clean(b) === 'YES' ? 'YES' : clean(b) === 'NO' ? 'NO' : 'UNKNOWN');

function init() {
  const $ = id => document.getElementById(id);
  const input = $('input'), count = $('count'), msg = $('msg'), start = $('start'),
        csv = $('csv'), prog = $('prog'), rows = $('rows'), wrap = $('wrap');
  let results = [];

  function refresh() {
    const { items, invalid } = parseInput(input.value);
    count.textContent = `${items.length}/${MAX}`;
    count.className = items.length > MAX ? 'err' : '';
    const parts = [];
    if (items.length > MAX) parts.push(`Limit is ${MAX} assets per scan. Remove ${items.length - MAX}.`);
    if (invalid.length) parts.push(`Ignored ${invalid.length} invalid: ${invalid.slice(0, 2).join(', ')}${invalid.length > 2 ? '…' : ''}`);
    msg.textContent = parts.join(' ');
    msg.className = items.length > MAX ? 'err' : '';
    start.disabled = items.length === 0 || items.length > MAX;
    return items;
  }

  function cell(tr, v) {
    const td = tr.insertCell();
    td.textContent = v || '…';
    td.className = v ? v.toLowerCase() : 'pend';
  }

  async function scan() {
    const items = refresh();
    if (!items.length || items.length > MAX) return;
    start.disabled = csv.disabled = input.disabled = true;
    rows.replaceChildren(); wrap.hidden = false;
    results = items.map(it => ({ label: it.label, web: '', p80: '', p443: '' }));
    const trs = items.map(it => { const tr = rows.insertRow(); tr.insertCell().textContent = it.label; [1, 2, 3].forEach(() => cell(tr)); return tr; });
    prog.max = items.length; prog.value = 0;
    let next = 0, done = 0;
    async function worker() {
      while (next < items.length) {
        const k = next++;
        let r = { web: 'UNKNOWN', p80: 'UNKNOWN', p443: 'UNKNOWN' };
        try {
          const [a, b] = await Promise.all([browserCheck(items[k]), backendCheck(items[k])]);
          r = { web: merge(a.web, b?.web), p80: merge(a.p80, b?.p80), p443: merge(a.p443, b?.p443) };
        } catch { /* keep UNKNOWN and continue */ }
        Object.assign(results[k], r);
        while (trs[k].cells.length > 1) trs[k].deleteCell(1);
        cell(trs[k], r.web); cell(trs[k], r.p80); cell(trs[k], r.p443);
        prog.value = ++done;
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, worker));
    input.disabled = false; csv.disabled = false; refresh();
  }

  function exportCsv() {
    const esc = s => { s = String(s); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
    const lines = [['URL', 'Web Interface', 'Port 80 Open', 'Port 443 Open'].map(esc).join(',')]
      .concat(results.map(r => [r.label, r.web, r.p80, r.p443].map(esc).join(',')));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['\uFEFF' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }));
    a.download = `web-exposure-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}.csv`;
    a.click(); URL.revokeObjectURL(a.href);
  }

  input.addEventListener('input', refresh);
  start.addEventListener('click', scan);
  csv.addEventListener('click', exportCsv);
  refresh();
}

if (typeof document !== 'undefined') init(); else module.exports = { parseInput, merge };
