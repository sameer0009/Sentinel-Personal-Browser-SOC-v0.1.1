/* Sentinel SOC · popup logic */
'use strict';

const $ = (id) => document.getElementById(id);
if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
  const MOCK_TIME = Date.now();
  window.chrome = window.chrome || {};
  chrome.runtime = chrome.runtime || {
    getURL: (p) => p.replace(/^\//, ''),
    sendMessage: async () => ({ score: 84, grade: 'B' })
  };
  chrome.storage = chrome.storage || {
    local: {
      get: async () => ({
        stats: { trackersBlockedTotal: 142 },
        sites: { 'github.com': {}, 'google.com': {}, 'paypa1.com': {}, 'paypal-secure-login.test': {}, 'tracker-network.example': {} },
        alerts: [
          { severity: 4, title: 'Threat-listed domain visited: paypal-secure-login.test', domain: 'paypal-secure-login.test', status: 'new', ts: MOCK_TIME - 12 * 60000, occurrences: 1 },
          { severity: 3, title: 'Possible typosquat of paypal.com: paypa1.com', domain: 'paypa1.com', status: 'ack', ts: MOCK_TIME - 45 * 60000, occurrences: 2 },
          { severity: 3, title: 'Password field on unencrypted HTTP page: insecure-login.example', domain: 'insecure-login.example', status: 'investigating', ts: MOCK_TIME - 95 * 60000, occurrences: 1 }
        ]
      })
    }
  };
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function scoreColor(score) {
  return score >= 90 ? '#22c55e' : score >= 75 ? '#84cc16' : score >= 60 ? '#f59e0b' : '#ef4444';
}

async function render() {
  $('logo').src = chrome.runtime.getURL('icons/icon48.png');
  const store = await chrome.storage.local.get(null);
  const alerts = store.alerts || [];
  const sites = store.sites || {};
  const open = alerts.filter(a => ['new', 'ack', 'investigating'].includes(a.status));

  // Query authoritative score from background engine
  let scoreData = null;
  try {
    scoreData = await chrome.runtime.sendMessage({ type: 'GET_SCORE' });
  } catch (e) { /* fallback if worker is waking up */ }

  let score = scoreData?.score;
  let grade = scoreData?.grade;

  if (score === undefined || grade === undefined) {
    score = 100;
    const s4 = open.filter(a => a.severity === 4).length;
    const s3 = open.filter(a => a.severity === 3).length;
    const s2 = open.filter(a => a.severity === 2).length;
    score -= Math.min(45, s4 * 15) + Math.min(32, s3 * 8) + Math.min(15, s2 * 3);
    const domains = Object.values(sites);
    const visits = domains.reduce((n, s) => n + (s.visits || 0), 0);
    const httpsVisits = domains.reduce((n, s) => n + (s.httpsVisits || 0), 0);
    if (visits >= 10 && httpsVisits / visits < 0.9) {
      score -= Math.min(15, Math.round((0.9 - httpsVisits / visits) * 100 * 0.5));
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
    grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  }

  $('scoreNum').textContent = score;
  $('grade').textContent = 'GRADE ' + grade;
  const arc = $('arc');
  arc.style.strokeDashoffset = String(CIRC * (1 - score / 100));
  arc.style.stroke = scoreColor(score);
  $('scoreNum').style.color = scoreColor(score);

  $('mAlerts').textContent = open.length;
  $('mTrackers').textContent = store.stats?.trackersBlockedTotal ?? 0;
  $('mSites').textContent = Object.keys(sites).length;

  const box = $('alerts');
  const recent = alerts.slice(0, 5);
  if (!recent.length) {
    box.innerHTML = '<div class="empty">No alerts yet. Browse and Sentinel will watch.</div>';
  } else {
    box.innerHTML = recent.map(a => `
      <div class="alert s${a.severity}">
        <div class="t">${escapeHtml(a.title)}</div>
        <div class="d">${escapeHtml(a.domain || '')} · ${escapeHtml(a.status)}</div>
        <div class="when">${timeAgo(a.ts)}${a.occurrences > 1 ? ` · ×${a.occurrences}` : ''}</div>
      </div>`).join('');
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

$('openConsole').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  window.close();
});

render();
