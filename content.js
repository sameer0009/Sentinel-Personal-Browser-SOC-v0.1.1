/* Sentinel SOC · content script (isolated world)
 * - Injects the page-world sensor for canvas-fingerprinting detection
 * - Scans the DOM for login/password forms (M2/M3 sensors)
 * - Reports notification-permission state per site
 */
'use strict';

(function () {
  if (window.top !== window.self) return; // main frame only

  // ---- page-world sensor messages (injected via manifest with world: "MAIN")


  window.addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.source !== 'sentinel-inject') return;
    chrome.runtime.sendMessage({ type: 'FINGERPRINT', detail: ev.data.detail }).catch(() => {});
  });

  function scanForms() {
    const pwInputs = [...document.querySelectorAll('input[type="password"]')];
    if (!pwInputs.length) return;
    const formActions = [...document.querySelectorAll('form')]
      .map(f => f.action || '')
      .filter(Boolean)
      .slice(0, 5);
    chrome.runtime.sendMessage({
      type: 'FORM_SCAN',
      title: document.title || '',
      hasPassword: true,
      passwordCount: pwInputs.length,
      formActions,
    }).catch(() => {});
  }

  // Scan now and again shortly after load (SPAs render late)
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    scanForms();
  } else {
    document.addEventListener('DOMContentLoaded', scanForms);
  }
  setTimeout(scanForms, 2500);

  // Watch for dynamically injected login forms
  let observed = 0;
  const mo = new MutationObserver(() => {
    if (observed++ > 4) { mo.disconnect(); return; }
    if (document.querySelector('input[type="password"]')) { scanForms(); mo.disconnect(); }
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => mo.disconnect(), 15000);

  // Notification permission state (M7 feed)
  try {
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query({ name: 'notifications' }).then((st) => {
        chrome.runtime.sendMessage({ type: 'PERMISSION_STATE', state: st.state }).catch(() => {});
      }).catch(() => {});
    }
  } catch (e) { /* non-fatal */ }
})();
