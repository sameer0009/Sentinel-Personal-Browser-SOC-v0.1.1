# Chrome Web Store submission pack — Sentinel SOC v0.1.2

Everything needed to publish, in the order the Developer Dashboard asks for it.
Every block below is ready to paste.

- Package to upload: `dist/sentinel-soc-v0.1.2.zip` (build with `./scripts/build.sh`)
- Assets: `store/assets/`
- Privacy policy: https://sentinel-personal-browser.blogspot.com/2026/10/privacy-policy.html (source: `PRIVACY.md` — keep both in sync)

---

## 0. One-time setup (before the first upload)

1. Use a Google account you'll keep long-term. Turn on **2-Step Verification**; the dashboard requires it.
2. Register at <https://chrome.google.com/webstore/devconsole> and pay the **one-time US$5** fee.
3. **Account** tab:
   - Publisher name: `dev-hunters studio`
   - Contact email: add and **verify** it. You can't publish until it's verified.
   - **Trader / non-trader declaration** (EU Digital Services Act). If dev-hunters studio is a business that earns money from software, choose *Trader*. You'll need to publish an address, phone and email, and verify them.
4. **Privacy policy** — ✅ hosted at https://sentinel-personal-browser.blogspot.com/2026/10/privacy-policy.html
   Use `team@devhunters.dev` as the dashboard contact email so it matches the policy.

---

## 1. Package tab

Upload `dist/sentinel-soc-v0.1.2.zip`. `manifest.json` sits at the zip root, and every path uses forward slashes.

> For later updates, bump `"version"` in `manifest.json` (the store rejects re-uploading the same version), rebuild, and upload under **Package → Upload new package**.

---

## 2. Store listing tab

**Name** (from manifest): `Sentinel — Personal Browser SOC`

**Summary** (from manifest description, max 132 chars):
`Local-only browser security monitor: flags phishing, typosquats and insecure logins, blocks trackers, and scores your posture.`

**Category:** `Privacy & Security`  (in the current dashboard: *Productivity → Privacy & Security* if grouped)
**Language:** `English`

**Description** (paste as-is):

```
Sentinel turns your browser into a personal Security Operations Center. It watches your own browsing for common threats, raises alerts you can triage, and gives you a live security score. Everything runs locally on your device. There is no account, no server and no telemetry.

WHAT IT DETECTS
• Look-alike domains: typosquats (paypa1.com), brand names on the wrong TLD (paypal.xyz), and punycode homograph domains (xn--…).
• Phishing login pages: a page with a password field whose title claims a well-known brand while the site is not that brand's domain.
• Insecure logins: password fields on unencrypted HTTP pages.
• Threat-listed domains: domains on the built-in sample list or on your personal blocklist trigger a full-page warning before the site loads. You can go back, or proceed and whitelist it.
• Trackers: 44 common advertising and analytics networks are blocked with Chrome's built-in declarativeNetRequest engine.
• Browser fingerprinting: flags pages that read back canvas pixels after drawing text, a classic fingerprinting pattern.
• Connection hygiene: HSTS presence, mixed content and long redirect chains are logged.

THE SOC CONSOLE
• Overview: a 0–100 security score with grade, a breakdown of deductions, a trend line and a 24-hour activity chart.
• Alerts: triage each alert as Acknowledge, Investigating, Resolve or False positive.
• Live feed and per-site dossiers (visits, HTTPS share, trackers, HSTS, fingerprinting).
• Intel lookup: check any URL or domain against the local checks without visiting it.
• Reports: export your data as JSON, or your alerts as CSV.
• Settings: turn each module on or off, manage your whitelist and blocklist, or erase all data.

PRIVACY
Sentinel needs to see the addresses of the pages you visit in order to protect you. It stores what it finds only in your browser's local extension storage and never sends it anywhere. It never reads what you type into forms. Uninstalling it removes all of its data.

Sentinel is an independent project by dev-hunters studio. It is not affiliated with any brand it helps you recognise.
```

**Graphic assets** (`store/assets/`):

| Slot | File | Size |
|---|---|---|
| Store icon (required) | `icons/icon128.png` | 128×128 PNG |
| Screenshot 1 (required) | `screenshot-1-overview.jpg` | 1280×800 |
| Screenshot 2 | `screenshot-2-alerts.jpg` | 1280×800 |
| Screenshot 3 | `screenshot-3-threat-blocked.jpg` | 1280×800 |
| Screenshot 4 | `screenshot-4-intel-lookup.jpg` | 1280×800 |
| Screenshot 5 | `screenshot-5-popup.jpg` | 1280×800 |
| Small promo tile (strongly recommended: listings without one rank lower) | `promo-small.jpg` | 440×280 |
| Marquee (optional) | `promo-marquee.jpg` | 1400×560 |

All screenshots are captures of the real extension UI, seeded with sample activity on reserved demo domains. To regenerate them, run `tools/screenshots.mjs`.

**Official URL / Homepage URL:** your site or the public GitHub repo (optional).
**Support URL:** GitHub Issues page or a support email page (optional but recommended).

---

## 3. Privacy practices tab

### Single purpose

```
Sentinel is a personal browser security monitor: it detects threats to the user while they browse (phishing and look-alike domains, insecure login pages, threat-listed sites, trackers and fingerprinting), blocks or warns about them, and shows the results in a local security dashboard.
```

### Permission justifications

| Permission | Justification (paste) |
|---|---|
| `webNavigation` | `Used to see the address of each top-level page navigation so Sentinel can check it against the threat list and the user's blocklist before it loads (showing a warning page on a match), detect typosquat and punycode look-alike domains, and record redirect chains.` |
| `webRequest` | `Used in observe-only (non-blocking) mode to read the Strict-Transport-Security response header of visited pages, detect insecure HTTP sub-resources on HTTPS pages (mixed content), and count requests to known tracker domains per site. No requests are modified.` |
| `declarativeNetRequest` | `Blocks requests to 44 known advertising/analytics tracker domains using a static ruleset bundled with the extension (rules/trackers.json). The user can switch this off in Settings.` |
| `declarativeNetRequestFeedback` | `Used only to call declarativeNetRequest.getMatchedRules() so the dashboard can show how many trackers were blocked overall and on each site.` |
| `storage` | `Stores the user's alerts, event log, per-site security profiles, settings, whitelist and blocklist locally in chrome.storage.local. Nothing is synced or transmitted.` |
| `alarms` | `A daily alarm records a security-score snapshot and prunes events older than 30 days; a one-minute alarm collects blocked-tracker counts within getMatchedRules rate limits.` |
| `notifications` | `Shows a desktop notification when a high or critical severity threat is detected (e.g. a phishing page). The user can disable this in Settings.` |
| Host permissions `http://*/*`, `https://*/*` | `Sentinel protects the user on every website they visit, so it must run on all http/https pages: the content script detects password fields on insecure or brand-impersonating login pages and canvas fingerprinting, and webRequest/webNavigation checks need host access to observe those pages. All processing is local; no page data leaves the device.` |

### Remote code

Select **"No, I am not using remote code."**
(All JavaScript ships inside the package. There is no `eval`, no remote `<script>`, no `new Function`.)

### Data usage

Tick these categories. Local-only handling still counts as handling under Google's User Data FAQ:

- ☑ **Web history**: addresses of visited pages and domains.
- ☑ **Website content**: page title and whether a page has password fields.

Leave everything else unticked: personally identifiable info, health, financial, authentication info, personal communications, location and user activity. Sentinel never reads keystrokes or form values.

Tick all three certifications:
- ☑ I do not sell or transfer user data to third parties, outside of the approved use cases
- ☑ I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- ☑ I do not use or transfer user data to determine creditworthiness or for lending purposes

**Privacy policy URL:** `https://sentinel-personal-browser.blogspot.com/2026/10/privacy-policy.html`

---

## 4. Distribution tab

- Payments: **Free**
- Visibility: **Public**. Use **Unlisted** for a soft launch where only people with the link can install.
- Regions: **All regions**

---

## 5. Test instructions (paste into "Additional notes for the reviewer" / Test instructions)

```
No account or login is required. Sentinel works entirely offline/locally.

On install the SOC Console opens and shows a data-handling disclosure (click "Got it").

Quick verification (about 2 minutes):
1. Threat-list warning: visit https://paypal-secure-login.test/ . The domain is a reserved .test sample on the built-in demo list (it does not resolve). Sentinel shows its "THREAT BLOCKED" warning page before any request is made. "Go back to safety" returns; "Proceed anyway" whitelists the domain.
2. Personal blocklist: Console → Settings → Threat intel → add "example.com" → visit https://example.com → the same warning page appears. Remove it afterwards with the ✕.
3. Look-alike domain check without visiting anything: Console → Intel Lookup → enter "paypa1.com" (typosquat), "paypal.xyz" (TLD swap) or "xn--pypal-4ve.com" (punycode) → Analyze.
4. Tracker blocking: open any news site; within about a minute the popup's "Trackers blocked" counter rises (counts are collected once per minute via declarativeNetRequest.getMatchedRules).
5. Alerts: open Console → Alerts and use Acknowledge / Investigating / Resolve / False positive; the security score on Overview updates.
6. Insecure login: any plain-HTTP page that contains a password field raises a severity-3 "Password field on unencrypted HTTP page" alert (and a desktop notification).

Data: everything is stored in chrome.storage.local only; the extension makes no network requests of its own. Settings → "Erase all Sentinel data" wipes it.
```

---

## 6. Submit

Click **Submit for review**. Optionally untick *"Publish automatically after approval"* to publish manually (deferred publishing).

- Expect a longer **in-depth review**: broad host permissions plus `webRequest` always get one. Most reviews finish within a few days; allow up to ~3 weeks.
- Status changes arrive by email. A rejection quotes a violation ID; see the table below.
- After approval, each update goes through review again. Changing permissions can disable the extension for existing users until they accept the new warning, so avoid adding permissions casually.

---

## 7. Rejection-risk checklist (what was fixed, what to watch)

| Violation ID | Risk in the original v0.1.1 | Status |
|---|---|---|
| **Yellow Zinc** (misleading screenshots/metadata) | All 4 screenshots were AI-generated, with garbled text and UI that doesn't exist. They were also the wrong size (1376×768) and were JPEGs named `.png` | ✅ Replaced with real captures at 1280×800 |
| **Yellow Magnesium** (doesn't work / packaging errors) | Zip had Windows `\` paths; popup crashed (`CIRC` undefined); "Trackers blocked" was always 0 in a store install; the threat-list demo could never fire | ✅ All fixed and verified end-to-end on the packaged zip |
| **Red Nickel** (functionality differs from listing) | Listing claimed threat-intel blocking, but only an unreachable demo list shipped | ✅ Fires before DNS; added a personal blocklist; the description is honest that the built-in list is a sample |
| **Purple Potassium** (unused permissions) | `tabs` was unused; `web_accessible_resources` was exposed to all sites; `declarativeNetRequestFeedback` was used only for an unpacked-only debug API | ✅ Removed `tabs` and WAR; feedback permission now backs `getMatchedRules` |
| **Purple Lithium** (no privacy policy) | None existed | ✅ Hosted at the Blogger URL above |
| **Purple Nickel** (no prominent disclosure) | Browsing monitored with no in-product notice | ✅ First-run disclosure panel in the console |
| **Purple Magnesium** (collects unneeded browsing data) | Form-action URLs were collected and never used | ✅ Removed |
| **Red Potassium** (undisclosed behavior) | Canvas API wrapping in the page world isn't obvious | ✅ Disclosed in the description and privacy policy |
| **Blue Argon / Red Titanium** (remote / obfuscated code) | None | ✅ Clean: plain readable source, no remote code |
| Scareware perception | Hard-coded fake "threat" alerts sat in shipped JS (preview mocks) | ✅ Moved to dev-only `tools/sample-data.mjs` (not in the zip) |
| **Red Silicon / trademark** | ⚠️ **"Sentinel" is also the name of Microsoft Sentinel, a commercial SIEM/SOC product.** A store review won't usually flag this, but a trademark complaint can get a listing taken down | ⚠️ **Your call**: consider a more distinctive name (e.g. "DevHunters Browser SOC") before launch |
| **Yellow Argon** (keyword spam) | — | ✅ Description lists features in prose, with no keyword lists |

### Known non-blocking follow-ups

- The built-in threat list is demo-only. A real feed (e.g. the Google Safe Browsing Update API) would strengthen the product. It would add network traffic, so the privacy policy and data disclosure would need updating first.
- The dashboard and warning page write alerts and the whitelist directly to storage. They rarely race with the background, but routing those writes through background messages would make all storage writes serial.
