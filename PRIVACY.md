# Privacy Policy — Sentinel — Personal Browser SOC

**Publisher:** dev-hunters studio
**Effective date:** 2026-10-29
**Contact:** Abdul Mateen · team@devhunters.dev
**Published at:** https://sentinel-personal-browser.blogspot.com/2026/10/privacy-policy.html

Sentinel is a browser extension that monitors your own browsing for security
threats. This policy explains what it accesses, where that data goes, and how
you control it.

## Summary

- Everything Sentinel records stays **on your device**, in the extension's
  local storage (`chrome.storage.local`).
- Sentinel makes **no network requests** of its own. It has no server, no
  analytics, no telemetry, no advertising, and no account.
- We (dev-hunters studio) **never receive, see, sell, or share** your data.

## What Sentinel accesses, and why

| Data | Why it's needed | Kept where / how long |
|---|---|---|
| Addresses (URLs and domains) of pages you visit, and redirect chains | Detect threat-listed domains, typosquats, homograph (punycode) domains and plain-HTTP pages | On your device. Event log is pruned after 30 days; per-domain profiles and alerts stay until you erase them |
| Whether a page has password fields, plus the page title | Warn about passwords on unencrypted pages and pages impersonating a brand's login | On your device. **Never** what you type into any field |
| Security response headers (e.g. HSTS) for pages you visit | Connection-hygiene checks | On your device |
| Requests to known tracker domains, and counts of blocked trackers | Tracker blocking and per-site tracker statistics | On your device (counts only) |
| Whether a page reads back canvas pixels after drawing text | Detect canvas fingerprinting | On your device (yes/no flag per site) |
| A site's notification-permission state | Show it in your activity feed | On your device |
| Your settings, whitelist and blocklist | Remember your choices | On your device |

Sentinel does not read cookies, form contents, passwords, page text other
than the title, or anything else on the page.

## Sharing

Sentinel does not transfer data to dev-hunters studio or any third party. Data
leaves your device only if **you** use **Reports → Export**, which saves a
JSON or CSV file to your computer.

## Your control

- **Settings** lets you turn each detection module, notifications and tracker
  blocking on or off.
- **Settings → Danger zone → Erase all Sentinel data** deletes everything.
- Uninstalling the extension deletes all of its stored data.

## Chrome Web Store User Data Policy

The use of information received from Chrome APIs adheres to the
[Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/policies),
including the Limited Use requirements. Data is used only to provide the
extension's single purpose, browser security monitoring for the user.

## Changes

If this policy changes, the updated version will be published at this address
with a new effective date. A change that sends any data off your device would
require a new extension version and your consent first.
