'use strict';
// All server-provided strings (emails, reasons...) are attacker-influenced, so they are only
// ever written with textContent — never innerHTML.
let token = null, timer = null;
const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...(opts.headers || {}), Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' } });
  if (r.status === 401) { signOut(); throw new Error('session expired'); }
  return r;
}

function signOut() {
  token = null; clearInterval(timer);
  $('app').hidden = true; $('login').hidden = false; $('status').textContent = 'signed out';
}

$('loginBtn').onclick = async () => {
  $('loginErr').textContent = '';
  try {
    const r = await fetch('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: $('email').value, password: $('password').value }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'login failed');
    token = d.access_token; $('password').value = '';
    $('login').hidden = true; $('app').hidden = false; $('status').textContent = 'signed in';
    refresh(); timer = setInterval(refresh, 5000);
  } catch (e) { $('loginErr').textContent = e.message; }
};
$('refresh').onclick = refresh;
$('fDecision').onchange = refresh;

function parseMetrics(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^([a-z_]+)(\{.*\})?\s+([0-9.eE+-]+)$/);
    if (!m) continue;
    const labels = {};
    (m[2] || '').replace(/(\w+)="([^"]*)"/g, (_, k, v) => { labels[k] = v; return ''; });
    out.push({ name: m[1], labels, value: parseFloat(m[3]) });
  }
  return out;
}

async function refresh() {
  if (!token) return;
  try {
    const [mr, lr] = await Promise.all([api('/metrics'), api('/audit-logs?limit=100' + ($('fDecision').value ? '&decision=' + $('fDecision').value : ''))]);
    if (mr.ok) renderMetrics(parseMetrics(await mr.text()));
    if (lr.ok) renderLogs((await lr.json()).logs);
    $('status').textContent = 'signed in · updated ' + new Date().toLocaleTimeString();
  } catch (e) { $('status').textContent = e.message; }
}

function renderMetrics(ms) {
  const sum = (f) => ms.filter(f).reduce((a, m) => a + m.value, 0);
  const ra = (m) => m.name === 'zt_events_total' && m.labels.action === 'resource_access';
  $('cAllow').textContent = sum((m) => ra(m) && m.labels.decision === 'allow');
  $('cDeny').textContent = sum((m) => ra(m) && m.labels.decision === 'deny');
  $('cLogin').textContent = sum((m) => m.name === 'zt_login_failures_total');
  $('cRate').textContent = sum((m) => m.name === 'zt_rate_limited_total');
  const h = sum((m) => m.name === 'zt_policy_cache_hits_total'), mi = sum((m) => m.name === 'zt_policy_cache_misses_total');
  $('cCache').textContent = h + mi ? Math.round((100 * h) / (h + mi)) + '%' : '–';
  const s = sum((m) => m.name === 'zt_request_seconds_sum'), c = sum((m) => m.name === 'zt_request_seconds_count');
  $('cLat').textContent = c ? ((1000 * s) / c).toFixed(1) : '–';

  const reasons = {};
  ms.filter((m) => m.name === 'zt_events_total' && m.labels.decision === 'deny').forEach((m) => { reasons[m.labels.reason] = (reasons[m.labels.reason] || 0) + m.value; });
  const entries = Object.entries(reasons).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;
  const box = $('reasons'); box.replaceChildren();
  for (const [name, n] of entries) {
    const row = document.createElement('div'); row.className = 'bar';
    const a = document.createElement('span'); a.className = 'name'; a.textContent = name;
    const b = document.createElement('span'); b.className = 'fill'; b.style.width = Math.max(2, (300 * n) / max) + 'px';
    const c2 = document.createElement('span'); c2.className = 'n'; c2.textContent = n;
    row.append(a, b, c2); box.append(row);
  }
}

function renderLogs(logs) {
  const body = $('rows'); body.replaceChildren();
  for (const l of logs) {
    const tr = document.createElement('tr');
    const cells = [new Date(l.ts * 1000).toLocaleTimeString(), l.email || '(anonymous)', l.resource_id || '', l.action, l.decision, l.reason, l.ip];
    cells.forEach((v, i) => { const td = document.createElement('td'); td.textContent = v; if (i === 4) td.className = l.decision; tr.append(td); });
    body.append(tr);
  }
}
