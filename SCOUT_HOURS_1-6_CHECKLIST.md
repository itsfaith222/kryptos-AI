# Scout Agent – Hours 1–6 Requirements Checklist

## 1. Content Script (Broad Scanning) – `extension/content.js`

| Requirement | Status | Notes |
|-------------|--------|--------|
| Phishing/urgency keywords (urgent, action required, suspended, etc.) | ✅ | `PHISHING_KEYWORDS` + scam + malware |
| Login detection: `input type="password"` or forms with login/sign-in IDs | ✅ | `isLoginPage()` |
| Privacy policy detection: links with privacy, terms, T&C | ✅ | `hasPrivacyPolicyLinks()` |
| Send SCOUT_SIGNAL to background: url, isLogin, hasPrivacyPolicy, detectedKeywords | ✅ | Plus detectedScam, detectedMalware |

**Note:** Spec referenced `extension/src/content.js`; this repo uses `extension/content.js` (no `src/`). Functionality is in `content.js`.

---

## 2. Background Script (Orchestrator) – `extension/background.js`

| Requirement | Status | Notes |
|-------------|--------|--------|
| Listen for SCOUT_SIGNAL | ✅ | `chrome.runtime.onMessage` → `handleScoutSignal` |
| POST payload to `http://localhost:8000/api/scout/scan` | ✅ | `postScoutScan(payload)` |
| Badge default: `...` (Scanning) | ✅ | `setBadgeScanning()` |
| Risk > 70: `!` Red #FF0000 | ✅ | `setBadgeFromResult()` |
| Privacy detected: `i` Blue #0000FF | ✅ | Same |
| Safe: `✓` Green #00FF00 | ✅ | Same |

---

## 3. Backend – Scout + API + DB

| Requirement | Status | Notes |
|-------------|--------|--------|
| POST `/api/scout/scan` endpoint | ✅ | `main.py` – `api_scout_scan()` |
| Risk score from combination of factors (e.g. login on unknown domain = high risk) | ✅ | `scout.compute_risk_from_signal()` in `scout.py` |
| MongoDB connection + scans collection | ✅ | `database.py` – `get_db()`, `scans` |
| Save every scan: timestamp, url, score, metadata (isLogin, etc.) | ✅ | `db_save_scan()` from `main.py` |

---

## 4. Popup (Manual Tools) – `extension/popup.js` + `popup.html`

| Requirement | Status | Notes |
|-------------|--------|--------|
| Paste Analysis works for any text (email, SMS, privacy paragraph) | ✅ | Sends to background → backend with phishing/scam/malware keywords |
| Display “Privacy Policy Found” when content script detected one on current tab | ✅ | `privacyNotice` + `getTabState` |
| Handle async DB writes | ✅ | Backend calls `db_save_scan()`; extension doesn’t block on DB |
| Clear console for Hour 6 demo | ✅ | No noisy logs; only background `console.error` on failures |

---

## 5. Hours 1–6 Milestone (Person A – Scout)

| Milestone | Status |
|-----------|--------|
| Extension UI (popup, badge) | ✅ |
| Content script (DOM analysis) | ✅ |
| Email paste detection | ✅ (and any text) |
| Scout backend | ✅ (real risk logic, not just mock) |

---

## Summary

**Yes – the implementation meets the stated requirements and covers the Scout Hours 1–6 tasks.**

- Extension: multi-vector scan (phishing, scam, malware, login, privacy) → SCOUT_SIGNAL → background → POST to backend; badge state machine; popup Paste Analysis + Privacy Policy Found.
- Backend: `/api/scout/scan` with risk logic in Scout, MongoDB save when available, in-memory fallback when MongoDB is not running.

**Hour 6 demo:** Run backend (`uvicorn main:app` from `backend/`), load extension, browse; badge and popup behave as above. MongoDB optional.
