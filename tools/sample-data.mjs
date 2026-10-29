/* Sentinel SOC · DEV-ONLY sample data — NOT shipped in the store package.
 * Seeded into a real, freshly loaded copy of the extension by
 * tools/screenshots.mjs so store screenshots show the actual UI with
 * realistic (demo-domain) activity.
 */
export function sampleStore(MOCK_TIME = Date.now()) {
  return {
    onboarded: true,
    blocklist: [],
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
  };
}
