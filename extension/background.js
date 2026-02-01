/**
 * Guardian AI Scout - Background (Orchestrator)
 * Listens for SCOUT_SIGNAL, POSTs to backend, manages badge state machine
 */

const BACKEND_URL = 'http://localhost:8000';

// Per-tab state for popup (e.g. "Privacy Policy Found")
const tabState = new Map();

/**
 * Badge state machine:
 * - Default: '...' (Scanning)
 * - Risk > 70: '!' Red #FF0000 (Phishing/Dangerous)
 * - Privacy detected: 'i' Blue #0000FF (Privacy review available)
 * - Safe: '✓' Green #00FF00
 */
function setBadgeFromResult(result, tabId) {
  const risk = result.riskScore != null ? result.riskScore : 0;
  const hasPrivacy = result.hasPrivacyPolicy === true;

  let text = '✓';
  let color = '#00FF00'; // Green - Safe

  if (risk > 70) {
    text = '!';
    color = '#FF0000'; // Red - Phishing/Dangerous
  } else if (hasPrivacy) {
    text = 'i';
    color = '#0000FF'; // Blue - Privacy review available
  }

  chrome.action.setBadgeText({ text, tabId: tabId || null });
  chrome.action.setBadgeBackgroundColor({ color, tabId: tabId || null });
}

/**
 * Set badge to "Scanning" state
 */
function setBadgeScanning(tabId) {
  chrome.action.setBadgeText({ text: '...', tabId: tabId || null });
  chrome.action.setBadgeBackgroundColor({ color: '#666666', tabId: tabId || null });
}

/**
 * POST SCOUT_SIGNAL payload to backend (quick Scout-only; badge / lightweight risk).
 */
async function postScoutScan(payload) {
  const res = await fetch(`${BACKEND_URL}/api/scout/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error(`Backend error: ${res.status}`);
  }
  return res.json();
}

/**
 * Full pipeline: POST /scan (Scout → Analyst → Educator → DB → client).
 * Payload: { url, scanType, content?, image_data? } per ScanInput.
 */
async function postFullScan(payload) {
  const res = await fetch(`${BACKEND_URL}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data.error || data.message || `Backend error: ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

/**
 * Handle SCOUT_SIGNAL from content script — full pipeline (Scout → Analyst → Educator) per guide.
 * Everything scanned by Scout goes automatically to Analyzer; no extra button.
 */
async function handleScoutSignal(signal, sender, sendResponse) {
  const tabId = sender.tab && sender.tab.id;

  console.log('[Guardian AI Background] 🔍 Received Scout signal from tab', tabId, {
    url: signal.url,
    isLogin: signal.isLogin,
    hasPrivacyPolicy: signal.hasPrivacyPolicy,
    keywords: signal.detectedKeywords?.length || 0
  });

  // ===== Skip localhost URLs =====
  try {
    const url = new URL(signal.url);
    const isLocalhost = url.hostname === 'localhost' ||
      url.hostname === '127.0.0.1' ||
      url.hostname.endsWith('.local');

    if (isLocalhost) {
      console.log('[Guardian AI Background] ⏭️ Skipping localhost URL:', signal.url);
      // Set safe badge for localhost
      chrome.action.setBadgeText({ text: '✓', tabId: tabId || null });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId: tabId || null });

      // Store minimal state for popup
      if (tabId != null) {
        tabState.set(tabId, {
          url: signal.url,
          riskScore: 0,
          hasPrivacyPolicy: false,
          skippedReason: 'localhost'
        });
      }

      return; // Exit early, don't scan
    }
  } catch (e) {
    // Invalid URL, continue with scan anyway
    console.log('[Guardian AI Background] ⚠️ Could not parse URL, scanning anyway:', signal.url);
  }
  // ===== END localhost check =====

  setBadgeScanning(tabId);

  try {
    const result = await postFullScan({
      url: signal.url || '',
      scanType: 'page',
      content: ''
    });

    console.log('[Guardian AI Background] ✅ Full scan complete for tab', tabId, {
      riskScore: result.riskScore,
      threatType: result.threatType
    });

    if (tabId != null) {
      tabState.set(tabId, {
        hasPrivacyPolicy: signal.hasPrivacyPolicy,
        riskScore: result.riskScore,
        url: signal.url,
        fullResult: result
      });
    }

    setBadgeFromResult({
      riskScore: result.riskScore,
      hasPrivacyPolicy: signal.hasPrivacyPolicy
    }, tabId);

    sendResponse(result);
  } catch (err) {
    console.error('[Guardian AI Background] ❌ Full scan failed for tab', tabId, err);
    setBadgeFromResult({ riskScore: 0, hasPrivacyPolicy: signal.hasPrivacyPolicy }, tabId);
    if (tabId != null) {
      tabState.set(tabId, { hasPrivacyPolicy: signal.hasPrivacyPolicy, riskScore: 0, url: signal.url });
    }
    sendResponse({ error: err.message, riskScore: 0, hasPrivacyPolicy: signal.hasPrivacyPolicy });
  }
}

const PHISHING_KEYWORDS = [
  'urgent', 'immediate', 'action required', 'verify', 'confirm', 'suspended', 'locked',
  'expires', 'limited time', 'act now', 'click here', 'update required', 'security alert', 'unusual activity'
];
const SCAM_KEYWORDS = [
  'claim prize', 'you won', 'congratulations', 'inheritance', 'inherited', 'tech support',
  'microsoft support', 'apple support', 'refund', 'wire transfer', 'send money', 'bitcoin',
  'crypto', 'investment opportunity', 'act now or lose', 'limited offer', 'free gift', 'claim now'
];
const MALWARE_KEYWORDS = [
  'download now', 'install update', '.exe', 'run this file', 'enable macros',
  'click to install', 'security update required', 'flash player update'
];

/**
 * Handle paste / manual text analysis — quick Scout-only (no Analyst/Educator).
 * Popup now uses fullScan for "Analyze" so full pipeline runs; this is legacy/optional.
 */
async function handleAnalyzeText(text, sendResponse) {
  try {
    const textLower = (text || '').toLowerCase();
    const detectedKeywords = PHISHING_KEYWORDS.filter((kw) => textLower.includes(kw));
    const detectedScam = SCAM_KEYWORDS.filter((kw) => textLower.includes(kw));
    const detectedMalware = MALWARE_KEYWORDS.filter((kw) => textLower.includes(kw));
    const all = [...detectedKeywords, ...detectedScam, ...detectedMalware];

    const result = await postScoutScan({
      url: '',
      isLogin: false,
      hasPrivacyPolicy: /privacy|terms|t&c|terms and conditions/i.test(text || ''),
      detectedKeywords: all,
      detectedScam,
      detectedMalware
    });
    sendResponse(result);
  } catch (err) {
    console.error('[Guardian AI] Text analysis failed:', err);
    sendResponse({ error: err.message, riskScore: 0 });
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'SCOUT_SIGNAL') {
    handleScoutSignal(request, sender, sendResponse);
    return true; // async response
  }
  if (request.action === 'scanPage') {
    // Legacy: treat as SCOUT_SIGNAL-style payload if possible
    const signal = {
      url: request.signals?.url || (sender.tab && sender.tab.url) || '',
      isLogin: request.signals?.hasLoginForm === true,
      hasPrivacyPolicy: false,
      detectedKeywords: request.signals?.urgencySignals || request.signals?.urgencySignals || []
    };
    handleScoutSignal(signal, sender, sendResponse);
    return true;
  }
  if (request.action === 'analyzeText' || request.action === 'pasteAnalysis') {
    handleAnalyzeText(request.text, sendResponse);
    return true;
  }
  if (request.action === 'getTabState') {
    const tabId = request.tabId;
    sendResponse(tabId != null ? (tabState.get(tabId) || null) : null);
    return false;
  }
  if (request.action === 'fullScan') {
    postFullScan({
      url: request.url || '',
      scanType: request.scanType || 'message',
      content: request.content || null,
      image_data: request.image_data || null
    }).then(sendResponse).catch((err) => {
      console.error('[Guardian AI] Full scan failed:', err);
      sendResponse({ error: err.message });
    });
    return true;
  }
  if (request.action === 'checkLinkSafety') {
    // Quick link safety check for hover tooltips
    checkLinkSafety(request.url).then(sendResponse).catch((err) => {
      console.error('[Guardian AI] Link safety check failed:', err);
      sendResponse({ risk: 0, reason: 'Check failed' });
    });
    return true;
  }
  return false;
});

// Link safety cache (5-minute TTL)
const linkSafetyCache = new Map();

/**
 * Quick link safety check for hover tooltips
 */
async function checkLinkSafety(url) {
  // Check cache first
  const cached = linkSafetyCache.get(url);
  if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) {
    return { ...cached.result, cached: true };
  }

  try {
    // Use the existing Scout scan endpoint for quick check
    const result = await postScoutScan({
      url: url,
      isLogin: false,
      hasPrivacyPolicy: false,
      detectedKeywords: [],
      detectedScam: [],
      detectedMalware: []
    });

    const riskScore = result.riskScore || 0;
    let status = 'safe';

    if (riskScore > 70) {
      status = 'dangerous';
    } else if (riskScore >= 40) {
      status = 'suspicious';
    }

    const response = {
      riskScore,
      status,
      reason: result.explanation || (status === 'safe' ? 'Domain appears safe' : 'Suspicious indicators detected')
    };

    // Cache result
    linkSafetyCache.set(url, {
      result: response,
      timestamp: Date.now()
    });

    return response;
  } catch (error) {
    return { riskScore: 0, status: 'unknown', reason: 'Unable to check link' };
  }
}

// Clean up link safety cache periodically
setInterval(() => {
  const now = Date.now();
  for (const [url, data] of linkSafetyCache.entries()) {
    if (now - data.timestamp > 5 * 60 * 1000) {
      linkSafetyCache.delete(url);
    }
  }
}, 60 * 1000); // Clean every minute

// Default badge on load: Scanning
setBadgeScanning();
