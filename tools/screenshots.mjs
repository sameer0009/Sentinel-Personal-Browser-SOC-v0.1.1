/* Sentinel SOC · DEV-ONLY store-asset generator — NOT shipped in the store package.
 *
 * Loads the real extension in Chrome for Testing, seeds its storage with
 * tools/sample-data.mjs, and captures the actual UI at Chrome Web Store sizes:
 *   store/assets/screenshot-*.jpg   1280x800
 *   store/assets/promo-small.jpg    440x280
 *   store/assets/promo-marquee.jpg  1400x560
 *
 * Usage (branded Chrome ignores --load-extension, so use Chrome for Testing):
 *   npm i --no-save puppeteer-core@24
 *   npx @puppeteer/browsers install chrome@stable
 *   CHROME="/path/to/Google Chrome for Testing" [EXT=/unzipped/build] node tools/screenshots.mjs
 */
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sampleStore } from './sample-data.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'store', 'assets');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME, headless: true, pipe: true, enableExtensions: true,
  defaultViewport: { width: 1280, height: 800 },
});
// EXT: an unpacked copy of the build (e.g. unzipped dist/*.zip); defaults to the repo root
const id = await browser.installExtension(process.env.EXT || ROOT);
const base = `chrome-extension://${id}/`;
await sleep(2000); // let onInstalled finish before replacing storage

const sw = await (await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith(base))).worker();
const now = Date.now();
const seed = sampleStore(now);
// Spread routine navigation events across the last 24h so the activity chart has shape
for (let i = 0; i < 160; i++) {
  const domain = ['github.com', 'google.com', 'tracker-network.example'][i % 3];
  seed.events.push({ id: 'nav-' + i, ts: now - ((i * i * 37 + i * 113) % 1440) * 60000, type: 'NAV', detail: 'HTTPS visit', domain });
}
seed.events.sort((a, b) => b.ts - a.ts);
await sw.evaluate(async (s) => { await chrome.storage.local.clear(); await chrome.storage.local.set(s); }, seed);

const page = await browser.newPage();
const shot = (name) => page.screenshot({ path: join(OUT, name), type: 'jpeg', quality: 95 });

async function tab(name) {
  await page.goto(base + 'dashboard.html'); await sleep(500);
  await page.click(`[data-tab=${name}]`); await sleep(400);
}

await tab('overview'); await shot('screenshot-1-overview.jpg');
await tab('alerts'); await shot('screenshot-2-alerts.jpg');
await tab('intel');
await page.type('#intelInput', 'paypa1.com'); await page.click('#intelGo'); await sleep(300);
await shot('screenshot-4-intel-lookup.jpg');

// Popup: capture it at its natural size, then present it on a 1280x800 canvas
const pop = await browser.newPage();
await pop.setViewport({ width: 320, height: 600 });
await pop.goto(base + 'popup.html'); await sleep(800);
const popH = await pop.evaluate(() => document.body.scrollHeight);
await pop.setViewport({ width: 320, height: popH, deviceScaleFactor: 1.25 });
const popPng = (await pop.screenshot({ encoding: 'base64' }));
await pop.close();
await page.setContent(`<!doctype html><html><body style="margin:0;width:1280px;height:800px;display:flex;align-items:center;justify-content:center;gap:72px;
  background:radial-gradient(circle at 70% 40%,#16233d,#0b1220 70%);font-family:-apple-system,'Segoe UI',Roboto,sans-serif;color:#e2e8f0">
  <div style="max-width:420px"><div style="font-size:14px;letter-spacing:2px;color:#38bdf8;margin-bottom:12px">TOOLBAR POPUP</div>
    <div style="font-size:38px;font-weight:700;line-height:1.2;margin-bottom:18px">Your security posture at a glance</div>
    <div style="font-size:18px;color:#94a3b8;line-height:1.6">Live score, open alerts, trackers blocked and the latest detections — one click from any tab.</div></div>
  <img src="data:image/png;base64,${popPng}" style="width:400px;border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,.6);border:1px solid #1e293b">
</body></html>`);
await sleep(300); await shot('screenshot-5-popup.jpg');

// Warning interstitial via the real flow: navigate to a threat-listed demo domain
await sw.evaluate(() => chrome.storage.local.set({ whitelist: [] }));
try { await page.goto('https://paypal-secure-login.test/account/signin', { timeout: 8000 }); } catch (e) { /* replaced by interstitial */ }
await sleep(1500);
if (!page.url().startsWith(base + 'warning.html')) throw new Error('interstitial not shown: ' + page.url());
await shot('screenshot-3-threat-blocked.jpg');

// Promotional tiles
const icon = readFileSync(join(ROOT, 'icons', 'icon128.png')).toString('base64');
const tile = (w, h, iconPx, titlePx, subPx) => `<!doctype html><html><body style="margin:0;width:${w}px;height:${h}px;display:flex;align-items:center;justify-content:center;gap:${Math.round(w / 28)}px;
  background:radial-gradient(circle at 30% 30%,#1b2a4a,#0b1220 75%);font-family:-apple-system,'Segoe UI',Roboto,sans-serif;color:#e2e8f0">
  <img src="data:image/png;base64,${icon}" style="width:${iconPx}px;height:${iconPx}px">
  <div><div style="font-size:${titlePx}px;font-weight:800;letter-spacing:1px">SENTINEL <span style="color:#38bdf8">SOC</span></div>
  <div style="font-size:${subPx}px;color:#94a3b8;margin-top:6px">Personal browser security monitor</div></div></body></html>`;
await page.setViewport({ width: 440, height: 280 });
await page.setContent(tile(440, 280, 96, 34, 15)); await sleep(200);
await shot('promo-small.jpg');
await page.setViewport({ width: 1400, height: 560 });
await page.setContent(tile(1400, 560, 200, 84, 32)); await sleep(200);
await shot('promo-marquee.jpg');

await browser.close();
console.log('assets written to', OUT);
