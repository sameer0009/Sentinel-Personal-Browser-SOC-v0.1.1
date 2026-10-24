/* Sentinel SOC · console application logic */
'use strict';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const OPEN = ['new', 'ack', 'investigating'];
const CIRC = 2 * Math.PI * 62;

// Standalone preview fallback (when viewed outside extension context, e.g. local browser or screenshot tools)
if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
  const MOCK_TIME = Date.now();
  window.chrome = window.chrome || {};
  chrome.runtime = chrome.runtime || {
    getURL: (path) => path.replace(/^\//, '')
  };
  chrome.storage = chrome.storage || {
    local: {
      get: async () => ({
        stats: { installedAt: MOCK_TIME - 7 * 86400000, trackersBlockedTotal: 142 },
        settings: { phishingDetection: true, autoBlock: true, notifications: true, trackerBlocking: true },
        whitelist: ['my-internal-dev.example'],
        scoreHistory: [
          { ts: MOCK_TIME - 6 * 86400000, score: 98 },
          { ts: MOCK_TIME - 5 * 86400000, score: 95 },
          { ts: MOCK_TIME - 4 * 86400000, score: 91 },
          { ts: MOCK_TIME - 3 * 86400000, score: 87 },
          { ts: MOCK_TIME - 2 * 86400000, score: 88 },
          { ts: MOCK_TIME - 1 * 86400000, score: 84 },
          { ts: MOCK_TIME, score: 84 }
        ],
        alerts: [
          {
            id: 'alt-1', ts: MOCK_TIME - 12 * 60000, severity: 4, confidence: 'high', module: 'M1',
            title: 'Threat-listed domain visited: paypal-secure-login.test',
            detail: 'Matched the local threat-intel list (Sentinel sample threat list). Warning interstitial shown.',
            url: 'https://paypal-secure-login.test/auth/signin?target=account',
            domain: 'paypal-secure-login.test', status: 'new', occurrences: 1
          },
          {
            id: 'alt-2', ts: MOCK_TIME - 45 * 60000, severity: 3, confidence: 'medium', module: 'M1',
            title: 'Possible typosquat of paypal.com: paypa1.com',
            detail: 'This domain is one character off paypal.com. Treat logins and downloads here as hostile until verified.',
            url: 'http://paypa1.com/login',
            domain: 'paypa1.com', status: 'ack', occurrences: 2
          },
          {
            id: 'alt-3', ts: MOCK_TIME - 95 * 60000, severity: 3, confidence: 'high', module: 'M3',
            title: 'Password field on unencrypted HTTP page: insecure-login.example',
            detail: 'Credentials entered here travel in cleartext. Do not log in on this page.',
            url: 'http://insecure-login.example/portal',
            domain: 'insecure-login.example', status: 'investigating', occurrences: 1
          },
          {
            id: 'alt-4', ts: MOCK_TIME - 180 * 60000, severity: 2, confidence: 'medium', module: 'M5',
            title: 'Possible browser fingerprinting on tracker-network.example',
            detail: 'Canvas read-back (toDataURL) after text rendering detected — a common fingerprinting pattern.',
            url: 'https://tracker-network.example/ad-frame.html',
            domain: 'tracker-network.example', status: 'resolved', occurrences: 3
          }
        ],
        events: [
          { id: 'ev-1', ts: MOCK_TIME - 2 * 60000, type: 'ALERT', detail: 'Threat-listed domain visited: paypal-secure-login.test', domain: 'paypal-secure-login.test', severity: 4 },
          { id: 'ev-2', ts: MOCK_TIME - 3 * 60000, type: 'RESPONSE', detail: 'Analyst inspected block warning on paypal-secure-login.test', domain: 'paypal-secure-login.test', severity: 4 },
          { id: 'ev-3', ts: MOCK_TIME - 15 * 60000, type: 'FORM', detail: 'Login form detected (1 password field)', domain: 'paypa1.com' },
          { id: 'ev-4', ts: MOCK_TIME - 25 * 60000, type: 'NAV', detail: 'HTTPS visit', domain: 'github.com' },
          { id: 'ev-5', ts: MOCK_TIME - 35 * 60000, type: 'HYGIENE', detail: 'HSTS now observed on github.com', domain: 'github.com' },
          { id: 'ev-6', ts: MOCK_TIME - 50 * 60000, type: 'TRIAGE', detail: 'Alert ack: Possible typosquat of paypal.com: paypa1.com', domain: 'paypa1.com', severity: 3 },
          { id: 'ev-7', ts: MOCK_TIME - 75 * 60000, type: 'CHAIN', detail: 'Redirect chain of 4 hops', domain: 'ad-click-tracker.example' },
          { id: 'ev-8', ts: MOCK_TIME - 110 * 60000, type: 'SYS', detail: 'Daily snapshot: security score 84', severity: 1 }
        ],
        sites: {
          'github.com': { domain: 'github.com', visits: 48, httpsVisits: 48, trackersSeen: 0, trackersBlocked: 0, alerts: 0, hsts: true, fingerprinting: false, lastSeen: MOCK_TIME - 20 * 60000 },
          'google.com': { domain: 'google.com', visits: 62, httpsVisits: 62, trackersSeen: 14, trackersBlocked: 14, alerts: 0, hsts: true, fingerprinting: false, lastSeen: MOCK_TIME - 15 * 60000 },
          'paypa1.com': { domain: 'paypa1.com', visits: 3, httpsVisits: 0, trackersSeen: 2, trackersBlocked: 2, alerts: 1, hsts: false, fingerprinting: false, lastSeen: MOCK_TIME - 45 * 60000 },
          'paypal-secure-login.test': { domain: 'paypal-secure-login.test', visits: 1, httpsVisits: 1, trackersSeen: 0, trackersBlocked: 0, alerts: 1, hsts: false, fingerprinting: false, lastSeen: MOCK_TIME - 12 * 60000 },
          'tracker-network.example': { domain: 'tracker-network.example', visits: 5, httpsVisits: 5, trackersSeen: 18, trackersBlocked: 18, alerts: 1, hsts: true, fingerprinting: true, lastSeen: MOCK_TIME - 180 * 60000 }
        }
      }),
      set: async () => {},
      clear: async () => {}
    },
    onChanged: { addListener: () => {} }
  };
}

let STORE = null;
let DATA = { threatlist: { domains: [] }, brands: {}, popular: [] };
let curTab = (location.hash ? location.hash.replace('#', '') : '') || 'overview';
if (!['overview', 'feed', 'alerts', 'sites', 'intel', 'reports', 'settings'].includes(curTab)) curTab = 'overview';
let alertFilter = { status: 'open', severity: 'all' };
let feedFilter = 'all';

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
const fmtDT = (ts) => new Date(ts).toLocaleString();

function scoreColor(s) {
  return s >= 90 ? '#22c55e' : s >= 75 ? '#84cc16' : s >= 60 ? '#f59e0b' : '#ef4444';
}

/* Local mirror of the background score computation (same formula). */
function computeScore(store) {
  let score = 100; const deductions = [];
  const open = (store.alerts || []).filter(a => OPEN.includes(a.status));
  const c = (n) => open.filter(a => a.severity === n).length;
  const s4 = c(4), s3 = c(3), s2 = c(2);
  if (s4) { const d = Math.min(45, s4 * 15); score -= d; deductions.push(`${s4} critical alert${s4 > 1 ? 's' : ''} open (−${d})`); }
  if (s3) { const d = Math.min(32, s3 * 8); score -= d; deductions.push(`${s3} high alert${s3 > 1 ? 's' : ''} open (−${d})`); }
  if (s2) { const d = Math.min(15, s2 * 3); score -= d; deductions.push(`${s2} medium alert${s2 > 1 ? 's' : ''} open (−${d})`); }
  const domains = Object.values(store.sites || {});
  const visits = domains.reduce((n, s) => n + (s.visits || 0), 0);
  const httpsVisits = domains.reduce((n, s) => n + (s.httpsVisits || 0), 0);
  if (visits >= 10) {
    const share = httpsVisits / visits;
    if (share < 0.9) {
      const d = Math.min(15, Math.round((0.9 - share) * 100 * 0.5));
      score -= d; deductions.push(`Only ${Math.round(share * 100)}% of browsing over HTTPS (−${d})`);
    }
  }
  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, deductions, open: open.length, visits, httpsVisits };
}

async function refresh() {
  STORE = await chrome.storage.local.get(null);
  STORE.alerts = STORE.alerts || []; STORE.events = STORE.events || [];
  STORE.sites = STORE.sites || {}; STORE.whitelist = STORE.whitelist || [];
  STORE.settings = STORE.settings || {};
  STORE.stats = STORE.stats || {}; STORE.scoreHistory = STORE.scoreHistory || [];
  try {
    const base = chrome.runtime.getURL('data/');
    const [tl, br, pop] = await Promise.all([
      fetch(base + 'threatlist.json').then(r => r.json()),
      fetch(base + 'brands.json').then(r => r.json()),
      fetch(base + 'popular.json').then(r => r.json()),
    ]);
    DATA = { threatlist: tl, brands: br, popular: pop };
  } catch (e) { /* data files missing; degrade gracefully */ }
  updateBadge();
  render();
}

function updateBadge() {
  const n = STORE.alerts.filter(a => a.status === 'new').length;
  const b = $('navAlertBadge');
  b.style.display = n ? '' : 'none';
  b.textContent = n;
}

/* ------------------------------- OVERVIEW ------------------------------ */

function renderOverview() {
  const sc = computeScore(STORE);
  const col = scoreColor(sc.score);
  const last24 = STORE.events.filter(e => e.ts > Date.now() - 86400000);
  const crit24 = STORE.alerts.filter(a => a.ts > Date.now() - 86400000 && a.severity >= 3).length;

  // hourly event sparkline (last 24h)
  const buckets = new Array(24).fill(0);
  last24.forEach(e => { const h = Math.floor((Date.now() - e.ts) / 3600000); if (h < 24) buckets[23 - h]++; });
  const max = Math.max(1, ...buckets);

  // score trend (last 14 snapshots)
  const hist = STORE.scoreHistory.slice(-14);
  let trend = '';
  if (hist.length > 1) {
    const pts = hist.map((h, i) =>
      `${(i / (hist.length - 1) * 100).toFixed(1)},${(100 - h.score).toFixed(1)}`).join(' ');
    trend = `<div class="panel"><h3>Score trend <span class="hint">— last ${hist.length} snapshots</span></h3>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" style="width:100%;height:90px">
        <polyline points="${pts}" fill="none" stroke="${col}" stroke-width="2.5"/></svg></div>`;
  }

  $('tab-overview').innerHTML = `
    <div class="panel"><div class="score-wrap">
      <div class="ring">
        <svg width="150" height="150" viewBox="0 0 150 150">
          <circle cx="75" cy="75" r="62" fill="none" stroke="#1e293b" stroke-width="11"/>
          <circle cx="75" cy="75" r="62" fill="none" stroke="${col}" stroke-width="11"
                  stroke-linecap="round" stroke-dasharray="${CIRC.toFixed(1)}"
                  stroke-dashoffset="${(CIRC * (1 - sc.score / 100)).toFixed(1)}"/>
        </svg>
        <div class="val"><b style="color:${col}">${sc.score}</b><small>GRADE ${sc.grade}</small></div>
      </div>
      <div class="deductions"><h3>Score breakdown</h3>
        ${sc.deductions.length
          ? '<ul>' + sc.deductions.map(d => `<li>▸ ${esc(d)}</li>`).join('') + '</ul>'
          : '<p class="none">✓ No active deductions. Clean posture.</p>'}
      </div>
    </div></div>
    ${trend}
    <div class="cards">
      <div class="card"><div class="k">Open alerts</div><div class="v">${sc.open}</div>
        <div class="s">${crit24} critical/high in last 24h</div></div>
      <div class="card"><div class="k">Events (24h)</div><div class="v">${last24.length}</div>
        <div class="s">telemetry captured by sensors</div></div>
      <div class="card"><div class="k">Trackers blocked</div><div class="v">${STORE.stats.trackersBlockedTotal || 0}</div>
        <div class="s">by the M5 shield, all time</div></div>
      <div class="card"><div class="k">Sites profiled</div><div class="v">${Object.keys(STORE.sites).length}</div>
        <div class="s">${sc.visits} page visits · ${sc.visits ? Math.round(sc.httpsVisits / sc.visits * 100) : 100}% HTTPS</div></div>
    </div>
    <div class="panel"><h3>Sensor activity <span class="hint">— events per hour, last 24h</span></h3>
      <div class="spark">${buckets.map(b =>
        `<div style="height:${Math.max(4, b / max * 100)}%" title="${b} events"></div>`).join('')}</div>
    </div>`;
}

/* -------------------------------- FEED --------------------------------- */

const EV_LABEL = { NAV: 'NAV', ALERT: 'ALERT', CHAIN: 'CHAIN', FORM: 'FORM', HYGIENE: 'HYGIENE', PERM: 'PERM', TRIAGE: 'TRIAGE', RESPONSE: 'RESPONSE', SYS: 'SYS' };

function renderFeed() {
  const types = ['all', ...new Set(STORE.events.map(e => e.type))];
  const evs = STORE.events.filter(e => feedFilter === 'all' || e.type === feedFilter).slice(0, 120);
  $('tab-feed').innerHTML = `
    <div class="toolbar">
      <select id="feedSel">${types.map(t =>
        `<option value="${t}"${t === feedFilter ? ' selected' : ''}>${t === 'all' ? 'All types' : t}</option>`).join('')}</select>
      <span style="color:var(--faint);font-size:12px">${evs.length} shown · live</span>
    </div>
    <div class="panel" style="padding:6px 18px">
      ${evs.length ? `<table>${evs.map(e => `
        <tr><td style="width:70px"><span class="ev-type ${e.type}">${EV_LABEL[e.type] || esc(e.type)}</span></td>
            <td>${esc(e.detail)}${e.domain ? ` <span class="tag mono">${esc(e.domain)}</span>` : ''}</td>
            <td class="time" style="width:130px">${timeAgo(e.ts)}</td></tr>`).join('')}</table>`
        : '<div class="empty">No events yet. Browse the web — Sentinel records everything.</div>'}
    </div>`;
  $('feedSel').addEventListener('change', (ev) => { feedFilter = ev.target.value; renderFeed(); });
}

/* -------------------------------- ALERTS -------------------------------- */

function renderAlerts() {
  let list = STORE.alerts;
  if (alertFilter.status === 'open') list = list.filter(a => OPEN.includes(a.status));
  else if (alertFilter.status !== 'all') list = list.filter(a => a.status === alertFilter.status);
  if (alertFilter.severity !== 'all') list = list.filter(a => String(a.severity) === alertFilter.severity);

  $('tab-alerts').innerHTML = `
    <div class="toolbar">
      <select id="fStatus">
        ${['open', 'all', 'new', 'ack', 'investigating', 'resolved', 'false_positive'].map(s =>
          `<option value="${s}"${s === alertFilter.status ? ' selected' : ''}>${s.replace('_', ' ')}</option>`).join('')}
      </select>
      <select id="fSev">
        ${['all', '4', '3', '2', '1'].map(s =>
          `<option value="${s}"${s === alertFilter.severity ? ' selected' : ''}>${s === 'all' ? 'All severities' : 'Severity ' + s}</option>`).join('')}
      </select>
      <span style="color:var(--faint);font-size:12px">${list.length} alert${list.length === 1 ? '' : 's'}</span>
    </div>
    ${list.length ? list.slice(0, 100).map(a => `
      <div class="panel" style="padding:14px 18px">
        <div style="display:flex;gap:10px;align-items:flex-start">
          <span class="sev s${a.severity}">${a.severity}</span>
          <div style="flex:1">
            <div style="font-weight:600">${esc(a.title)}</div>
            <div class="alert-detail">${esc(a.detail || '')}</div>
            <div style="margin-top:6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span class="tag">${esc(a.module)}</span>
              ${a.domain ? `<span class="tag mono">${esc(a.domain)}</span>` : ''}
              <span class="tag">confidence: ${esc(a.confidence || 'n/a')}</span>
              ${a.occurrences > 1 ? `<span class="tag">×${a.occurrences} occurrences</span>` : ''}
              <span class="status ${a.status}">${a.status.replace('_', ' ')}</span>
              <span class="time">${fmtDT(a.ts)} · ${timeAgo(a.ts)}</span>
            </div>
            ${a.url ? `<div class="alert-detail mono" style="font-size:11px">${esc(a.url.slice(0, 140))}</div>` : ''}
            ${OPEN.includes(a.status) ? `
            <div class="alert-actions">
              <button class="btn" data-act="ack" data-id="${a.id}">Acknowledge</button>
              <button class="btn" data-act="investigating" data-id="${a.id}">Investigating</button>
              <button class="btn" data-act="resolved" data-id="${a.id}">Resolve</button>
              <button class="btn" data-act="false_positive" data-id="${a.id}">False positive</button>
            </div>` : ''}
          </div>
        </div>
      </div>`).join('')
      : '<div class="panel"><div class="empty">No alerts match this filter. The queue is clear — good.</div></div>'}`;

  $('fStatus').addEventListener('change', (e) => { alertFilter.status = e.target.value; renderAlerts(); });
  $('fSev').addEventListener('change', (e) => { alertFilter.severity = e.target.value; renderAlerts(); });
  document.querySelectorAll('#tab-alerts [data-act]').forEach(b =>
    b.addEventListener('click', () => triageAlert(b.dataset.id, b.dataset.act)));
}

async function triageAlert(id, status) {
  const a = STORE.alerts.find(x => x.id === id);
  if (!a) return;
  a.status = status;
  a.history = a.history || [];
  a.history.push({ ts: Date.now(), by: 'analyst', action: `status -> ${status}` });
  STORE.events.unshift({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    ts: Date.now(), type: 'TRIAGE',
    detail: `Alert ${status.replace('_', ' ')}: ${a.title}`,
    domain: a.domain, severity: a.severity,
  });
  STORE.events = STORE.events.slice(0, 300);
  await chrome.storage.local.set({ alerts: STORE.alerts, events: STORE.events });
  updateBadge(); render();
}

/* --------------------------------- SITES -------------------------------- */

function renderSites() {
  const rows = Object.values(STORE.sites).sort((a, b) => (b.visits || 0) - (a.visits || 0)).slice(0, 150);
  $('tab-sites').innerHTML = `
    <div class="panel" style="padding:6px 18px">
    ${rows.length ? `<table>
      <tr><th>Domain</th><th>Visits</th><th>HTTPS</th><th>Trackers seen</th><th>Blocked</th>
          <th>Alerts</th><th>HSTS</th><th>Flags</th><th>Last seen</th></tr>
      ${rows.map(s => {
        const httpsPct = s.visits ? Math.round((s.httpsVisits || 0) / s.visits * 100) : 100;
        return `<tr>
          <td class="mono">${esc(s.domain)}</td><td>${s.visits || 0}</td><td>${httpsPct}%</td>
          <td>${s.trackersSeen || 0}</td><td>${s.trackersBlocked || 0}</td><td>${s.alerts || 0}</td>
          <td>${s.hsts === null || s.hsts === undefined ? '<span style="color:var(--faint)">?</span>' : s.hsts ? '<span style="color:var(--ok)">yes</span>' : '<span style="color:var(--s3)">no</span>'}</td>
          <td>${s.fingerprinting ? '<span class="tag" style="border-color:var(--s3);color:#fcd34d">fingerprinting</span>' : ''}</td>
          <td class="time">${timeAgo(s.lastSeen)}</td></tr>`;
      }).join('')}</table>`
      : '<div class="empty">No sites profiled yet.</div>'}
    </div>`;
}

/* ------------------------------ INTEL LOOKUP ---------------------------- */

const TWO_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.mx', 'org.mx', 'edu.mx', 'gob.mx',
  'com.tr', 'edu.tr', 'gov.tr', 'org.tr',
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw',
  'com.hk', 'org.hk', 'gov.hk', 'edu.hk',
  'co.za', 'org.za', 'gov.za',
  'co.kr', 'ne.kr', 're.kr', 'pe.kr'
]);

function registrable(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h === 'localhost') return h;
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function splitSld(domain) {
  const parts = domain.split('.');
  if (parts.length > 2 && TWO_PART_TLDS.has(parts.slice(-2).join('.'))) {
    return { sld: parts[parts.length - 3], tld: parts.slice(-2).join('.') };
  }
  return { sld: parts[0], tld: parts.slice(1).join('.') };
}
function lev(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

function runIntelLookup(input) {
  let host = input.trim().toLowerCase();
  try {
    if (host.includes('://')) host = new URL(host).hostname;
    else host = new URL('https://' + host).hostname;
  } catch (e) { return { error: 'Could not parse that as a URL or domain.' }; }
  const domain = registrable(host);
  const findings = [];
  let verdict = 'good', headline = `${domain} looks clean against local intel.`;

  if (DATA.threatlist.domains.includes(domain) || DATA.threatlist.domains.includes(host)) {
    verdict = 'bad'; headline = `${domain} is on the Sentinel threat list.`;
    findings.push('Exact match in the local threat-intel list — treat as hostile.');
  }
  if (/(^|\.)xn--/.test(host)) {
    if (verdict === 'good') verdict = 'warn';
    findings.push('Punycode hostname — possible IDN homograph attack.');
    headline = `${domain} shows homograph-phishing indicators.`;
  }

  const dParts = splitSld(domain);
  const dSld = dParts.sld;

  if (dSld && dSld.length >= 3) {
    for (const p of DATA.popular) {
      const pLow = p.toLowerCase();
      if (domain === pLow || domain.endsWith('.' + pLow)) break;
      const pParts = splitSld(pLow);
      const pSld = pParts.sld;
      if (!pSld || pSld.length < 3) continue;

      if (dSld === pSld && dParts.tld !== pParts.tld) {
        if (verdict === 'good') verdict = 'warn';
        findings.push(`TLD-swap candidate: ${domain} mimics official ${p} on .${dParts.tld}.`);
        headline = `${domain} mimics brand ${p} — verify before trusting.`;
        break;
      }

      const d = lev(dSld, pSld);
      const th = pSld.length >= 8 ? 2 : 1;
      if (d > 0 && d <= th) {
        if (verdict === 'good') verdict = 'warn';
        findings.push(`Typosquat candidate: ${d} character${d > 1 ? 's' : ''} away from ${p}.`);
        headline = `${domain} resembles ${p} — verify before trusting.`;
        break;
      }
    }
  }
  if (STORE.whitelist.includes(domain)) findings.push('Note: this domain is on your Sentinel whitelist.');
  const dossier = STORE.sites[domain];
  if (dossier) {
    findings.push(`Profiled: ${dossier.visits || 0} visits, ${dossier.alerts || 0} alerts, ${dossier.trackersBlocked || 0} trackers blocked` +
      (dossier.fingerprinting ? ', fingerprinting observed' : '') + '.');
  } else findings.push('No local browsing history for this domain.');
  return { verdict, headline, findings, domain };
}

function renderIntel() {
  $('tab-intel').innerHTML = `
    <div class="panel">
      <h3>Manual indicator lookup <span class="hint">— runs Sentinel's local checks on any URL or domain</span></h3>
      <div class="toolbar">
        <input type="text" id="intelInput" placeholder="e.g. paypa1-secure-login.test or https://example.com/login">
        <button class="btn primary" id="intelGo">Analyze</button>
      </div>
      <div id="intelOut"></div>
    </div>
    <div class="panel"><h3>How it works</h3>
      <p style="color:var(--mut);font-size:13px;line-height:1.6">The lookup runs the same M1 checks the
      background engine uses on every navigation: threat-list match, punycode detection, and typosquat
      scoring against ${DATA.popular.length} popular domains — plus your local site dossier and whitelist
      state. Everything runs locally; nothing is sent anywhere.</p></div>`;

  const go = () => {
    const r = runIntelLookup($('intelInput').value);
    const box = $('intelOut');
    if (r.error) { box.innerHTML = `<div class="verdict warn"><h4>⚠ ${esc(r.error)}</h4></div>`; return; }
    const icon = r.verdict === 'bad' ? '🛑' : r.verdict === 'warn' ? '⚠️' : '✅';
    box.innerHTML = `<div class="verdict ${r.verdict}"><h4>${icon} ${esc(r.headline)}</h4>
      <ul>${r.findings.map(f => `<li>${esc(f)}</li>`).join('')}</ul></div>`;
  };
  $('intelGo').addEventListener('click', go);
  $('intelInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
}

/* -------------------------------- REPORTS ------------------------------- */

function download(name, content, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

function renderReports() {
  const sc = computeScore(STORE);
  const bySev = [4, 3, 2, 1].map(s => STORE.alerts.filter(a => a.severity === s).length);
  $('tab-reports').innerHTML = `
    <div class="cards">
      <div class="card"><div class="k">Security score</div><div class="v" style="color:${scoreColor(sc.score)}">${sc.score} <small style="font-size:14px;color:var(--dim)">${sc.grade}</small></div></div>
      <div class="card"><div class="k">Total alerts</div><div class="v">${STORE.alerts.length}</div>
        <div class="s">S4:${bySev[0]} · S3:${bySev[1]} · S2:${bySev[2]} · S1:${bySev[3]}</div></div>
      <div class="card"><div class="k">Events logged</div><div class="v">${STORE.events.length}</div>
        <div class="s">last 30 days retained</div></div>
      <div class="card"><div class="k">Since install</div><div class="v" style="font-size:18px">${new Date(STORE.stats.installedAt || Date.now()).toLocaleDateString()}</div>
        <div class="s">${sc.visits} page visits tracked</div></div>
    </div>
    <div class="panel"><h3>Export</h3>
      <p style="color:var(--mut);font-size:13px;margin-bottom:12px">Download your SOC data for
      records, coursework, or analysis elsewhere. Generated locally, timestamped.</p>
      <button class="btn primary" id="expJson">⬇ Full dossier (JSON)</button>
      <button class="btn" id="expCsv">⬇ Alerts (CSV)</button>
    </div>`;

  $('expJson').addEventListener('click', () => {
    download(`sentinel-dossier-${new Date().toISOString().slice(0, 10)}.json`,
      JSON.stringify({ exportedAt: new Date().toISOString(), score: sc,
        alerts: STORE.alerts, events: STORE.events, sites: STORE.sites,
        whitelist: STORE.whitelist, scoreHistory: STORE.scoreHistory }, null, 2),
      'application/json');
  });
  $('expCsv').addEventListener('click', () => {
    const csvSafe = (val) => `"${String(val ?? '').replace(/"/g, '""')}"`;
    const rows = [['timestamp', 'severity', 'module', 'status', 'title', 'domain', 'url', 'occurrences'].map(csvSafe)];
    STORE.alerts.forEach(a => rows.push([
      csvSafe(new Date(a.ts).toISOString()),
      csvSafe(a.severity),
      csvSafe(a.module),
      csvSafe(a.status),
      csvSafe(a.title),
      csvSafe(a.domain),
      csvSafe(a.url),
      csvSafe(a.occurrences || 1),
    ].join(',')));
    download(`sentinel-alerts-${new Date().toISOString().slice(0, 10)}.csv`,
      rows.join('\n'), 'text/csv');
  });
}

/* -------------------------------- SETTINGS ------------------------------ */

function renderSettings() {
  const s = { phishingDetection: true, autoBlock: true, notifications: true, trackerBlocking: true, ...(STORE.settings || {}) };
  const toggles = [
    ['phishingDetection', 'Phishing detection (M2)', 'Brand-impersonation checks on login pages.'],
    ['autoBlock', 'Auto-response interstitial', 'Redirect to a Sentinel warning page on threat-list hits (severity 4).'],
    ['notifications', 'Desktop notifications', 'OS notification for severity 3+ alerts.'],
    ['trackerBlocking', 'Tracker blocking (M5)', 'Enable/disable the declarativeNetRequest tracker ruleset.'],
  ];
  $('tab-settings').innerHTML = `
    <div class="panel"><h3>Detection modules</h3>
      ${toggles.map(([k, t, d]) => `
        <div class="set-row"><div><div class="t">${t}</div><div class="d">${d}</div></div>
          <label class="switch"><input type="checkbox" data-set="${k}"${s[k] ? ' checked' : ''}><span class="sl"></span></label>
        </div>`).join('')}
    </div>
    <div class="panel"><h3>Whitelist <span class="hint">— domains exempt from auto-block</span></h3>
      <div class="toolbar"><input type="text" id="wlInput" placeholder="domain, e.g. example.com" style="min-width:200px">
        <button class="btn" id="wlAdd">Add</button></div>
      <div>${STORE.whitelist.length ? STORE.whitelist.map(d =>
        `<span class="tag mono">${esc(d)} <a href="#" data-wl="${esc(d)}" style="color:var(--s4)">✕</a></span>`).join(' ')
        : '<span style="color:var(--faint);font-size:13px">Empty.</span>'}</div>
    </div>
    <div class="panel"><h3>Threat intel</h3>
      <p style="color:var(--mut);font-size:13px;line-height:1.6">
        Local list: <b>${DATA.threatlist.name || 'Sentinel sample list'}</b> ·
        ${DATA.threatlist.domains.length} domains · updated ${esc(DATA.threatlist.updated || 'n/a')}.<br>
        Brand map: ${Object.keys(DATA.brands).length} brands · Typosquat reference: ${DATA.popular.length} popular domains.<br>
        <span style="color:var(--faint)">Edit <span class="mono">data/threatlist.json</span> and reload the extension to use a real feed.</span></p>
    </div>
    <div class="panel"><h3 style="color:#fca5a5">Danger zone</h3>
      <button class="btn danger" id="wipe">Erase all Sentinel data</button>
      <span style="color:var(--faint);font-size:12px;margin-left:8px">alerts, events, dossiers, whitelist, score history</span>
    </div>`;

  document.querySelectorAll('#tab-settings [data-set]').forEach(cb =>
    cb.addEventListener('change', async () => {
      STORE.settings[cb.dataset.set] = cb.checked;
      await chrome.storage.local.set({ settings: STORE.settings });
      if (cb.dataset.set === 'trackerBlocking') {
        try {
          await chrome.declarativeNetRequest.updateEnabledRulesets({
            enableRulesetIds: cb.checked ? ['sentinel_trackers'] : [],
            disableRulesetIds: cb.checked ? [] : ['sentinel_trackers'],
          });
        } catch (e) { /* non-fatal */ }
      }
    }));
  $('wlAdd').addEventListener('click', async () => {
    const v = $('wlInput').value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!v) return;
    if (!STORE.whitelist.includes(v)) STORE.whitelist.push(v);
    await chrome.storage.local.set({ whitelist: STORE.whitelist });
    renderSettings();
  });
  document.querySelectorAll('#tab-settings [data-wl]').forEach(a =>
    a.addEventListener('click', async (e) => {
      e.preventDefault();
      STORE.whitelist = STORE.whitelist.filter(d => d !== a.dataset.wl);
      await chrome.storage.local.set({ whitelist: STORE.whitelist });
      renderSettings();
    }));
  $('wipe').addEventListener('click', async () => {
    if (!confirm('Erase ALL Sentinel data? This cannot be undone.')) return;
    await chrome.storage.local.clear();
    location.reload();
  });
}

/* ------------------------------ navigation ----------------------------- */

const TITLES = {
  overview: ['Overview', 'Your personal security operations picture'],
  feed: ['Live Feed', 'Every sensor event, newest first'],
  alerts: ['Alerts', 'Triage queue — you are the analyst'],
  sites: ['Site Dossiers', 'Per-domain security profiles'],
  intel: ['Intel Lookup', 'Manual indicator analysis'],
  reports: ['Reports', 'Export your SOC data'],
  settings: ['Settings', 'Modules, whitelist, data'],
};

function render() {
  const fn = { overview: renderOverview, feed: renderFeed, alerts: renderAlerts, sites: renderSites, intel: renderIntel, reports: renderReports, settings: renderSettings }[curTab];
  $('pageTitle').textContent = TITLES[curTab][0];
  $('pageSub').textContent = TITLES[curTab][1];
  fn();
  const inst = STORE.stats.installedAt ? new Date(STORE.stats.installedAt).toLocaleDateString() : '—';
  $('sideFoot').innerHTML = `Developed by <b>dev-hunters studio</b><br>Monitoring since ${inst}<br>${STORE.events.length} events · ${Object.keys(STORE.sites).length} sites`;
}

document.querySelectorAll('#nav button').forEach(b =>
  b.addEventListener('click', () => {
    document.querySelectorAll('#nav button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    document.querySelectorAll('.tabpage').forEach(p => p.classList.remove('active'));
    curTab = b.dataset.tab;
    $('tab-' + curTab).classList.add('active');
    render();
  }));

// live updates (debounced)
let rt = null;
chrome.storage.onChanged.addListener(() => {
  clearTimeout(rt);
  rt = setTimeout(async () => { await refresh(); }, 600);
});

$('logo').src = chrome.runtime.getURL('icons/icon48.png');
refresh();
