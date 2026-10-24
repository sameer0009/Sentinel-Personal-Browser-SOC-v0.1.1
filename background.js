/* Sentinel — Personal Browser SOC · v0.1.0
 * Background service worker: event bus, detection engine (M1/M2/M3/M5),
 * alert manager, security scoring, auto-response (warning interstitial).
 * Manifest V3: no persistent globals — in-memory caches are best-effort and
 * everything authoritative lives in chrome.storage.local.
 */

'use strict';

/* ============================== utilities ============================== */

const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
const now = () => Date.now();

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

function registrableDomain(hostname) {
  if (!hostname) return '';
  const h = hostname.toLowerCase().replace(/\.$/, '');
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

function isHttpUrl(u) {
  return typeof u === 'string' && (u.startsWith('http://') || u.startsWith('https://'));
}

function isPunycode(host) {
  return /(^|\.)xn--/.test(host.toLowerCase());
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

/** Typosquat test of a registrable domain against the popular-domains list. */
function typosquatMatch(domain, popular) {
  const d = domain.toLowerCase();
  const dParts = splitSld(d);
  const dSld = dParts.sld;
  if (!dSld || dSld.length < 3) return null;

  for (const p of popular) {
    const pLow = p.toLowerCase();
    if (d === pLow) return null;
    if (d.endsWith('.' + pLow)) return null;

    const pParts = splitSld(pLow);
    const pSld = pParts.sld;
    if (!pSld || pSld.length < 3) continue;

    // 1. TLD swap impersonation (e.g. paypal.xyz, amazon.co)
    if (dSld === pSld && dParts.tld !== pParts.tld) {
      return p;
    }

    // 2. SLD edit-distance typosquatting (e.g. paypa1 vs paypal)
    const dist = levenshtein(dSld, pSld);
    const threshold = pSld.length >= 8 ? 2 : 1;
    if (dist > 0 && dist <= threshold) {
      return p;
    }

    // 3. Fallback: whole-domain distance
    const fullDist = levenshtein(d, pLow);
    if (fullDist > 0 && fullDist <= (pLow.length >= 12 ? 2 : 1)) {
      return p;
    }
  }
  return null;
}

/* ============================ data loading ============================= */

let CACHE = { threatlist: null, brands: null, popular: null, trackers: null };

async function loadData() {
  if (CACHE.threatlist) return CACHE;
  const base = chrome.runtime.getURL('data/');
  const [threatlist, brands, popular, trackers] = await Promise.all([
    fetch(base + 'threatlist.json').then(r => r.json()),
    fetch(base + 'brands.json').then(r => r.json()),
    fetch(base + 'popular.json').then(r => r.json()),
    fetch(base + 'trackers.json').then(r => r.json()),
  ]);
  CACHE = { threatlist, brands, popular, trackers };
  return CACHE;
}

/* ============================== storage ================================ */

const DEFAULT_SETTINGS = {
  phishingDetection: true,
  autoBlock: true,          // warning interstitial on threat-list hits
  notifications: true,      // OS notifications for severity >= 3
  trackerBlocking: true,    // declarativeNetRequest ruleset enabled
};

async function getStore() {
  const s = await chrome.storage.local.get(null);
  return {
    alerts: s.alerts || [],
    events: s.events || [],
    sites: s.sites || {},
    whitelist: s.whitelist || [],
    settings: { ...DEFAULT_SETTINGS, ...(s.settings || {}) },
    stats: s.stats || { installedAt: now(), trackersBlockedTotal: 0 },
    scoreHistory: s.scoreHistory || [],
  };
}

async function setStore(patch) {
  await chrome.storage.local.set(patch);
}

/* ========================= alerts & event feed ========================= */

const OPEN_STATUSES = ['new', 'ack', 'investigating'];

async function addEvent(type, detail, meta = {}) {
  const store = await getStore();
  store.events.unshift({ id: uid(), ts: now(), type, detail, ...meta });
  if (store.events.length > 300) store.events.length = 300;
  await setStore({ events: store.events });
}

async function touchSite(store, domain, patch = {}) {
  if (!domain) return;
  const s = store.sites[domain] || {
    domain, firstSeen: now(), lastSeen: now(), visits: 0,
    httpsVisits: 0, trackersSeen: 0, trackersBlocked: 0,
    alerts: 0, hsts: null, fingerprinting: false,
  };
  Object.assign(s, patch, { lastSeen: now() });
  store.sites[domain] = s;
}

async function addAlert({ severity, confidence, module, title, detail, url, domain }) {
  const store = await getStore();
  const cutoff = now() - 60 * 60 * 1000;
  // Dedupe: same module+domain+title within the hour and still open -> bump count.
  const dupe = store.alerts.find(a =>
    a.module === module && a.domain === domain && a.title === title &&
    a.ts > cutoff && OPEN_STATUSES.includes(a.status));
  if (dupe) {
    dupe.occurrences = (dupe.occurrences || 1) + 1;
    dupe.ts = now();
    await setStore({ alerts: store.alerts });
    return dupe;
  }
  const alert = {
    id: uid(), ts: now(), severity, confidence, module,
    title, detail, url: url || '', domain: domain || '',
    status: 'new', occurrences: 1, history: [{ ts: now(), by: 'system', action: 'created' }],
  };
  store.alerts.unshift(alert);
  if (store.alerts.length > 500) store.alerts.length = 500;
  if (domain) {
    await touchSite(store, domain, {});
    store.sites[domain].alerts = (store.sites[domain].alerts || 0) + 1;
    await setStore({ sites: store.sites });
  }
  await setStore({ alerts: store.alerts });
  await addEvent('ALERT', `${title} (${domain || 'n/a'})`, { domain, severity });

  if (severity >= 3 && store.settings.notifications) {
    try {
      await chrome.notifications.create('sentinel-' + alert.id, {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon48.png'),
        title: `Sentinel SOC — severity ${severity} alert`,
        message: title,
        priority: severity === 4 ? 2 : 1,
      });
    } catch (e) { /* notifications may be denied; non-fatal */ }
  }
  return alert;
}

/* ============================ M1 · URL monitor ========================= */

const chains = new Map(); // tabId -> [urls] (best-effort, in-memory)

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) return;
  const arr = chains.get(details.tabId) || [];
  arr.push(details.url);
  if (arr.length > 12) arr.shift();
  chains.set(details.tabId, arr);
});

chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId === 0) chains.delete(details.tabId);
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) return;
  const url = new URL(details.url);
  const host = url.hostname;
  const domain = registrableDomain(host);
  const chain = chains.get(details.tabId) || [];
  chains.delete(details.tabId);

  const store = await getStore();
  await touchSite(store, domain, {
    visits: (store.sites[domain]?.visits || 0) + 1,
    httpsVisits: (store.sites[domain]?.httpsVisits || 0) + (url.protocol === 'https:' ? 1 : 0),
  });
  await setStore({ sites: store.sites });
  await addEvent('NAV', `${url.protocol === 'https:' ? 'HTTPS' : 'HTTP'} visit`, { domain, url: details.url });

  // Long redirect chain (M1)
  const uniq = [...new Set(chain)];
  if (uniq.length >= 4) {
    await addEvent('CHAIN', `Redirect chain of ${uniq.length} hops`, { domain, url: details.url });
  }

  const data = await loadData();

  // Threat-list hit -> severity 4 + auto-response interstitial (M1)
  if (data.threatlist.domains.includes(domain) || data.threatlist.domains.includes(host)) {
    const whitelisted = store.whitelist.includes(domain);
    await addAlert({
      severity: 4, confidence: 'high', module: 'M1',
      title: `Threat-listed domain visited: ${domain}`,
      detail: `Matched the local threat-intel list (${data.threatlist.name}). ` +
              (whitelisted ? 'Domain is whitelisted — no interstitial shown.' : 'Warning interstitial shown.'),
      url: details.url, domain,
    });
    if (store.settings.autoBlock && !whitelisted && details.tabId >= 0) {
      const warnUrl = chrome.runtime.getURL('warning.html') +
        '?target=' + encodeURIComponent(details.url) +
        '&reason=' + encodeURIComponent('Matched the Sentinel threat-intel list') +
        '&domain=' + encodeURIComponent(domain);
      try { await chrome.tabs.update(details.tabId, { url: warnUrl }); } catch (e) { /* tab gone */ }
    }
    return;
  }

  // Punycode / IDN homograph (M1)
  if (isPunycode(host)) {
    await addAlert({
      severity: 3, confidence: 'medium', module: 'M1',
      title: `Suspicious internationalized domain: ${host}`,
      detail: 'Punycode (xn--) hostnames are a classic homograph-phishing technique. Verify this is the site you intended.',
      url: details.url, domain,
    });
  }

  // Typosquat vs popular domains (M1)
  const spoofed = typosquatMatch(domain, data.popular);
  if (spoofed) {
    await addAlert({
      severity: 3, confidence: 'medium', module: 'M1',
      title: `Possible typosquat of ${spoofed}: ${domain}`,
      detail: `This domain is one or two characters off ${spoofed}. Treat logins and downloads here as hostile until verified.`,
      url: details.url, domain,
    });
  }

  // Plain-HTTP main page (M3 hygiene signal)
  if (url.protocol === 'http:') {
    await addEvent('HYGIENE', 'Page loaded over unencrypted HTTP', { domain, url: details.url });
  }
});

/* ================== M3 · headers / mixed content (M3) ================= */

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== 'main_frame' || !isHttpUrl(details.url)) return;
    const url = new URL(details.url);
    if (url.protocol !== 'https:') return;
    const headers = details.responseHeaders || [];
    const hsts = headers.some(h => h.name.toLowerCase() === 'strict-transport-security');
    const store = await getStore();
    const domain = registrableDomain(url.hostname);
    const prev = store.sites[domain]?.hsts;
    await touchSite(store, domain, { hsts });
    await setStore({ sites: store.sites });
    if (prev === false && hsts) await addEvent('HYGIENE', `HSTS now observed on ${domain}`, { domain });
    else if (hsts === false && prev !== false) await addEvent('HYGIENE', `No HSTS header on ${domain}`, { domain });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// Mixed content: http subresources on https pages
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (!details.url.startsWith('http://') || details.tabId < 0) return;
    try {
      const tab = await chrome.tabs.get(details.tabId);
      if (tab.url && tab.url.startsWith('https://')) {
        const domain = registrableDomain(new URL(tab.url).hostname);
        await addEvent('HYGIENE', 'Mixed content: HTTP subresource on HTTPS page', { domain, url: details.url });
      }
    } catch (e) { /* tab gone */ }
  },
  { urls: ['http://*/*'] }
);

/* ===================== M5 · tracker shield (basic) ===================== */

let trackerSet = null;
async function getTrackerSet() {
  if (!trackerSet) {
    const data = await loadData();
    trackerSet = new Set(data.trackers.map(t => t.toLowerCase()));
  }
  return trackerSet;
}

// Observe (count) tracker requests per site
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId < 0) return;
    const set = await getTrackerSet();
    let host;
    try { host = new URL(details.url).hostname.toLowerCase(); } catch (e) { return; }
    const hit = [...set].some(t => host === t || host.endsWith('.' + t));
    if (!hit) return;
    try {
      const tab = await chrome.tabs.get(details.tabId);
      if (!tab.url || !isHttpUrl(tab.url)) return;
      const domain = registrableDomain(new URL(tab.url).hostname);
      const store = await getStore();
      await touchSite(store, domain, { trackersSeen: (store.sites[domain]?.trackersSeen || 0) + 1 });
      await setStore({ sites: store.sites });
    } catch (e) { /* tab gone */ }
  },
  { urls: ['<all_urls>'] }
);

// Count what declarativeNetRequest actually blocked (works for unpacked extensions)
if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
    const store = await getStore();
    store.stats.trackersBlockedTotal = (store.stats.trackersBlockedTotal || 0) + 1;
    let domain = '';
    if (info.tabId >= 0) {
      try {
        const tab = await chrome.tabs.get(info.tabId);
        if (tab.url && isHttpUrl(tab.url)) domain = registrableDomain(new URL(tab.url).hostname);
      } catch (e) { /* tab gone */ }
    }
    if (domain) {
      await touchSite(store, domain, { trackersBlocked: (store.sites[domain]?.trackersBlocked || 0) + 1 });
    }
    await setStore({ stats: store.stats, sites: store.sites });
  });
}

/* ============ content-script messages: M2 phishing, M3, M5 ============= */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === 'FORM_SCAN') {
      await handleFormScan(msg, sender);
    } else if (msg.type === 'FINGERPRINT') {
      const domain = registrableDomain(new URL(sender.tab.url).hostname);
      const store = await getStore();
      await touchSite(store, domain, { fingerprinting: true });
      await setStore({ sites: store.sites });
      await addAlert({
        severity: 2, confidence: 'medium', module: 'M5',
        title: `Possible browser fingerprinting on ${domain}`,
        detail: msg.detail || 'Canvas read-back after text rendering detected — a common fingerprinting pattern.',
        url: sender.tab.url, domain,
      });
    } else if (msg.type === 'PERMISSION_STATE') {
      const domain = registrableDomain(new URL(sender.tab.url).hostname);
      await addEvent('PERM', `Notification permission: ${msg.state}`, { domain });
    } else if (msg.type === 'TRIAGE_ALERT') {
      await triageAlert(msg.id, msg.status);
    } else if (msg.type === 'GET_SCORE') {
      const store = await getStore();
      sendResponse(computeScore(store));
      return;
    }
    sendResponse({ ok: true });
  })();
  return true; // async response
});

async function handleFormScan(msg, sender) {
  const tabUrl = sender.tab?.url || '';
  if (!isHttpUrl(tabUrl)) return;
  const url = new URL(tabUrl);
  const domain = registrableDomain(url.hostname);
  const store = await getStore();

  if (msg.hasPassword) {
    await addEvent('FORM', `Login form detected (${msg.passwordCount} password field${msg.passwordCount > 1 ? 's' : ''})`, { domain, url: tabUrl });

    // M3: password field over plain HTTP -> severity 3
    if (url.protocol === 'http:' && !store.whitelist.includes(domain)) {
      await addAlert({
        severity: 3, confidence: 'high', module: 'M3',
        title: `Password field on unencrypted HTTP page: ${domain}`,
        detail: 'Credentials entered here travel in cleartext. Do not log in on this page.',
        url: tabUrl, domain,
      });
    }

    // M2: brand impersonation — page claims a brand on login form but domain isn't the brand's
    if (store.settings.phishingDetection) {
      const data = await loadData();
      const title = (msg.title || '').toLowerCase();
      const hasAuthKeywords = /\b(log ?in|sign ?in|account|portal|verify|verification|password|auth|billing|secure)\b/i.test(title);

      for (const [brand, brandDomains] of Object.entries(data.brands)) {
        const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
        const isOfficial = brandDomains.some(bd => domain === bd || domain.endsWith('.' + bd));
        if (brandRegex.test(title) && !isOfficial && (hasAuthKeywords || msg.passwordCount >= 1)) {
          await addAlert({
            severity: 3, confidence: hasAuthKeywords ? 'high' : 'medium', module: 'M2',
            title: `Possible ${brand} phishing page: ${domain}`,
            detail: `This login page references "${brand}" but lives on ${domain}, which is not an official ${brand} domain.`,
            url: tabUrl, domain,
          });
          break;
        }
      }
    }
  }
}

async function triageAlert(id, status) {
  const store = await getStore();
  const alert = store.alerts.find(a => a.id === id);
  if (!alert) return;
  alert.status = status;
  alert.history.push({ ts: now(), by: 'analyst', action: `status -> ${status}` });
  await setStore({ alerts: store.alerts });
  await addEvent('TRIAGE', `Alert ${status}: ${alert.title}`, { domain: alert.domain, severity: alert.severity });
}

/* ============================ security score =========================== */

function computeScore(store) {
  let score = 100;
  const deductions = [];
  const open = store.alerts.filter(a => OPEN_STATUSES.includes(a.status));
  const sev4 = open.filter(a => a.severity === 4).length;
  const sev3 = open.filter(a => a.severity === 3).length;
  const sev2 = open.filter(a => a.severity === 2).length;
  if (sev4) { const d = Math.min(45, sev4 * 15); score -= d; deductions.push(`${sev4} critical alert${sev4 > 1 ? 's' : ''} open (−${d})`); }
  if (sev3) { const d = Math.min(32, sev3 * 8); score -= d; deductions.push(`${sev3} high alert${sev3 > 1 ? 's' : ''} open (−${d})`); }
  if (sev2) { const d = Math.min(15, sev2 * 3); score -= d; deductions.push(`${sev2} medium alert${sev2 > 1 ? 's' : ''} open (−${d})`); }

  const domains = Object.values(store.sites);
  const visits = domains.reduce((n, s) => n + (s.visits || 0), 0);
  const httpsVisits = domains.reduce((n, s) => n + (s.httpsVisits || 0), 0);
  if (visits >= 10) {
    const share = httpsVisits / visits;
    if (share < 0.9) {
      const d = Math.min(15, Math.round((0.9 - share) * 100 * 0.5));
      score -= d;
      deductions.push(`Only ${Math.round(share * 100)}% of browsing over HTTPS (−${d})`);
    }
  }
  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, deductions, openAlerts: open.length, visits, trackersBlocked: store.stats.trackersBlockedTotal || 0 };
}

/* ================================ alarms =============================== */

chrome.alarms.create('sentinel-daily', { periodInMinutes: 60 * 24 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'sentinel-daily') return;
  const store = await getStore();
  const { score } = computeScore(store);
  store.scoreHistory.push({ ts: now(), score });
  if (store.scoreHistory.length > 90) store.scoreHistory.shift();
  // prune events older than 30 days
  const cutoff = now() - 30 * 24 * 60 * 60 * 1000;
  store.events = store.events.filter(e => e.ts > cutoff);
  await setStore({ scoreHistory: store.scoreHistory, events: store.events });
  await addEvent('SYS', `Daily snapshot: security score ${score}`, {});
});

/* ============================ install / boot =========================== */

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    const store = await getStore();
    if (!store.stats.installedAt) store.stats.installedAt = now();
    await setStore({ stats: store.stats });
    await addEvent('SYS', 'Sentinel SOC v0.1.0 installed — monitoring started', {});
    // ensure tracker ruleset matches settings
    try {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: store.settings.trackerBlocking ? ['sentinel_trackers'] : [],
        disableRulesetIds: store.settings.trackerBlocking ? [] : ['sentinel_trackers'],
      });
    } catch (e) { /* DNR feedback permission quirk; non-fatal */ }
  }
  // warm the data cache
  loadData().catch(() => {});
});

// Warm cache whenever the worker wakes
loadData().catch(() => {});
