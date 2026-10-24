/* Sentinel SOC · warning interstitial logic */
'use strict';

const params = new URLSearchParams(location.search);
const target = params.get('target') || 'https://paypal-secure-login.test/account/signin';
const reason = params.get('reason') || 'Matched the Sentinel threat-intel list (severity 4 known malicious domain).';
const domain = params.get('domain') || 'paypal-secure-login.test';

document.getElementById('target').textContent = target;
document.getElementById('reason').textContent =
  reason + (domain ? ` (domain: ${domain})` : '');

document.getElementById('back').addEventListener('click', () => {
  if (history.length > 1) history.back();
  else chrome.tabs.getCurrent().then(t => t && chrome.tabs.remove(t.id)).catch(() => {});
});

document.getElementById('proceed').addEventListener('click', async () => {
  if (!domain || !target) return;
  const store = await chrome.storage.local.get(null);
  const whitelist = store.whitelist || [];
  if (!whitelist.includes(domain)) whitelist.push(domain);
  const events = store.events || [];
  events.unshift({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    ts: Date.now(), type: 'RESPONSE',
    detail: `Analyst overrode block — whitelisted ${domain}`,
    domain, severity: 4,
  });
  await chrome.storage.local.set({ whitelist, events: events.slice(0, 300) });
  location.href = target;
});
