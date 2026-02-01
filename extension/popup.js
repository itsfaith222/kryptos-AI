/**
 * Kryptos-AI Scout - Popup (Manual Tools)
 * Full pipeline: Scout → Analyst → Educator → display (paste + current page).
 * Shows "Privacy Policy Found" when content script detected one on current tab.
 */

const BACKEND_URL = 'http://localhost:8000';
const WEBAPP_URL = 'http://localhost:5173';

const pasteInput = document.getElementById('paste-input');
const analyzeBtn = document.getElementById('analyze-btn');
const pasteResult = document.getElementById('paste-result');
const pageResult = document.getElementById('page-result');
const currentPageEl = document.getElementById('current-page');
const statusMessage = document.getElementById('status-message');
const privacyNotice = document.getElementById('privacy-notice');
const fullScanBtn = document.getElementById('full-scan-btn');

/** Full pipeline: POST /scan (Scout → Analyst → Educator → DB → client) */
async function fullScanToBackend(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({
      action: 'fullScan',
      url: payload.url || '',
      scanType: payload.scanType || 'message',
      content: payload.content ?? null,
      image_data: payload.image_data ?? null
    }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || 'Extension error'));
        return;
      }
      if (response && response.error) {
        reject(new Error(response.error));
        return;
      }
      resolve(response || {});
    });
  });
}

/** Display full ScanResult (explanation, nextSteps, evidence, mitreAttackTechniques) */
function displayFullResult(container, result) {
  const risk = result.riskScore != null ? result.riskScore : 0;
  let riskColor = 'green';
  let riskEmoji = '✅';
  if (risk > 70) {
    riskColor = 'red';
    riskEmoji = '🚨';
  } else if (risk >= 40) {
    riskColor = 'yellow';
    riskEmoji = '⚠️';
  }
  const explanation = result.explanation || '';
  const nextSteps = result.nextSteps || [];
  const evidence = result.evidence || [];
  const mitre = result.mitreAttackTechniques || [];
  const threatType = result.threatType || 'unknown';

  container.innerHTML = `
    <div class="result-content full-result">
      <div class="risk-score ${riskColor}">
        <span class="emoji">${riskEmoji}</span>
        <span class="score">${risk}/100</span>
      </div>
      <div class="risk-label">Risk Score · ${threatType}</div>
      ${explanation ? `<div class="explanation">${escapeHtml(explanation)}</div>` : ''}
      ${nextSteps.length ? `<div class="next-steps"><strong>Next steps:</strong><ul>${nextSteps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ul></div>` : ''}
      ${evidence.length ? `<div class="evidence"><strong>Evidence:</strong><ul>${evidence.slice(0, 5).map(e => `<li>${escapeHtml(e.finding || JSON.stringify(e))}</li>`).join('')}</ul></div>` : ''}
      ${mitre.length ? `<div class="mitre">MITRE: ${escapeHtml(mitre.join(', '))}</div>` : ''}
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/** Play voice alert in popup when we have high-risk result with voiceAlert. Plays immediately. */
function playVoiceAlertIfHighRisk(result) {
  if (!result || (result.riskScore ?? 0) < 70) return
  const voiceAlert = result.voiceAlert || result.voice_alert
  if (!voiceAlert) return
  const audioSrc = voiceAlert.startsWith('audio/mpeg;base64,')
    ? voiceAlert
    : `${BACKEND_URL}/audio/${voiceAlert}`
  try {
    const audio = new Audio(audioSrc)
    audio.volume = 1
    audio.play().catch(() => {})
  } catch (_) {}
}

/** Simple risk-only display (used for quick /api/scout/scan on page load) */
function displayResult(container, result) {
  const risk = result.riskScore != null ? result.riskScore : 0;
  let riskColor = 'green';
  let riskEmoji = '✅';
  if (risk > 70) {
    riskColor = 'red';
    riskEmoji = '🚨';
  } else if (risk >= 40) {
    riskColor = 'yellow';
    riskEmoji = '⚠️';
  }
  container.innerHTML = `
    <div class="result-content">
      <div class="risk-score ${riskColor}">
        <span class="emoji">${riskEmoji}</span>
        <span class="score">${risk}/100</span>
      </div>
      <div class="risk-label">Risk Score</div>
      <div class="recommendation">
        ${risk > 70 ? '🚨 High Risk - Do not proceed' :
      risk >= 40 ? '⚠️ Medium Risk - Be cautious' :
        '✅ Low Risk - Appears safe'}
      </div>
    </div>
  `;
}

analyzeBtn.addEventListener('click', async () => {
  const text = pasteInput.value.trim();
  if (!text || text.length < 10) {
    showStatus('Please paste at least 10 characters', 'error');
    return;
  }
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  pasteResult.innerHTML = '<div class="loading"></div> Full pipeline (Scout → Analyst → Educator)...';

  try {
    const result = await fullScanToBackend({ url: '', scanType: 'message', content: text });
    displayFullResult(pasteResult, result);
    playVoiceAlertIfHighRisk(result);
    showStatus('Analysis complete (saved to DB)', 'success');
  } catch (error) {
    showStatus(`Error: ${error.message}`, 'error');
    pasteResult.innerHTML = `<div class="error">❌ ${error.message}</div>`;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});


if (fullScanBtn) {
  fullScanBtn.addEventListener('click', async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        showStatus('No active tab', 'error');
        return;
      }

      // Use already-stored scan for this tab (no new scan). Open dashboard immediately.
      const tabState = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getTabState', tabId: tab.id }, (r) => resolve(r != null ? r : null));
      });
      const scanId = tabState?.fullResult?.scanId;
      const url = scanId
        ? `${WEBAPP_URL}/scan/${scanId}`
        : WEBAPP_URL;

      chrome.tabs.create({ url, active: true });
      showStatus('Opening dashboard…', 'success');
    } catch (error) {
      showStatus(`Error: ${error.message}`, 'error');
    }
  });
}


function showStatus(message, type = 'info') {
  statusMessage.textContent = message;
  statusMessage.className = `status-message ${type}`;

  if (type !== 'error') {
    setTimeout(() => {
      statusMessage.textContent = '';
      statusMessage.className = 'status-message';
    }, 3000);
  }
}

// ===== Screenshot Upload Functionality =====
const screenshotBtn = document.getElementById('screenshot-btn');
const screenshotInput = document.getElementById('screenshot-input');
const screenshotPreview = document.getElementById('screenshot-preview');
const previewImage = document.getElementById('preview-image');
const removeScreenshotBtn = document.getElementById('remove-screenshot');
const analyzeScreenshotBtn = document.getElementById('analyze-screenshot-btn');
const screenshotResult = document.getElementById('screenshot-result');

let currentImageData = null;

// Trigger file input when button clicked
screenshotBtn.addEventListener('click', () => {
  screenshotInput.click();
});

// Handle file selection
screenshotInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  // Validate file type
  const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
  if (!validTypes.includes(file.type)) {
    showStatus('Please select a valid image file (PNG, JPG, WEBP)', 'error');
    return;
  }

  // Validate file size (5MB max)
  const maxSize = 5 * 1024 * 1024; // 5MB
  if (file.size > maxSize) {
    showStatus('Image too large. Please select an image under 5MB', 'error');
    return;
  }

  try {
    // Read file and convert to base64
    const reader = new FileReader();
    reader.onload = (event) => {
      const base64Data = event.target.result;
      currentImageData = base64Data;

      // Show preview
      previewImage.src = base64Data;
      screenshotPreview.style.display = 'block';
      analyzeScreenshotBtn.style.display = 'block';
      screenshotResult.innerHTML = '';

      showStatus('Screenshot loaded. Click "Analyze Screenshot" to scan.', 'success');
    };

    reader.onerror = () => {
      showStatus('Failed to read image file', 'error');
    };

    reader.readAsDataURL(file);
  } catch (error) {
    showStatus(`Error loading image: ${error.message}`, 'error');
  }
});

// Remove screenshot
removeScreenshotBtn.addEventListener('click', () => {
  currentImageData = null;
  screenshotPreview.style.display = 'none';
  analyzeScreenshotBtn.style.display = 'none';
  screenshotInput.value = '';
  screenshotResult.innerHTML = '';
  showStatus('Screenshot removed', 'info');
});

// Analyze screenshot – runs entirely in extension (no dashboard open). Backend saves to alert history.
analyzeScreenshotBtn.addEventListener('click', async () => {
  if (!currentImageData) {
    showStatus('No screenshot selected', 'error');
    return;
  }

  analyzeScreenshotBtn.disabled = true;
  analyzeScreenshotBtn.textContent = 'Analyzing...';
  screenshotResult.innerHTML = '<div class="loading"></div> Analyzing screenshot...';

  try {
    const result = await fullScanToBackend({
      url: '',
      scanType: 'image',
      content: '',
      image_data: currentImageData
    });

    displayFullResult(screenshotResult, result);
    showStatus('Report saved to alert history', 'success');
    const scanId = result && (result.scanId || result.scan_id);
    if (scanId) {
      const link = document.createElement('p');
      link.className = 'screenshot-view-dashboard';
      link.innerHTML = `<a href="${WEBAPP_URL}/scan/${scanId}" target="_blank" rel="noopener">View in dashboard →</a>`;
      link.style.marginTop = '8px';
      link.style.fontSize = '12px';
      screenshotResult.appendChild(link);
    }
  } catch (error) {
    showStatus(`Error: ${error.message}`, 'error');
    screenshotResult.innerHTML = `<div class="error">❌ ${error.message}</div>`;
  } finally {
    analyzeScreenshotBtn.disabled = false;
    analyzeScreenshotBtn.textContent = 'Analyze Screenshot';
  }
});

/** On popup open: show last scan for this tab (from background cache). Scan runs on page load and every 5 min; we do not re-scan here. */
async function loadCurrentPageStatus() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      currentPageEl.textContent = 'No active tab';
      privacyNotice.style.display = 'none';
      pageResult.innerHTML = '';
      return;
    }

    const hostname = tab.url ? new URL(tab.url).hostname : 'Unknown';
    currentPageEl.textContent = `Current page: ${hostname}`;

    // ===== Skip localhost URLs =====
    if (tab.url) {
      try {
        const url = new URL(tab.url);
        const isLocalhost = url.hostname === 'localhost' ||
          url.hostname === '127.0.0.1' ||
          url.hostname.endsWith('.local');

        if (isLocalhost) {
          pageResult.innerHTML = '<div style="color: #10b981; font-size: 13px;">✅ Localhost URL - No scan needed</div>';
          privacyNotice.style.display = 'none';
          return; // Exit early
        }
      } catch (e) {
        // Invalid URL, continue
      }
    }
    // ===== END localhost check =====

    const tabState = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'getTabState', tabId: tab.id }, (r) => {
        resolve(r != null ? r : null);
      });
    });

    if (tabState && tabState.hasPrivacyPolicy) {
      privacyNotice.style.display = 'block';
    } else {
      privacyNotice.style.display = 'none';
    }

    // Show last scan result (scan runs on page load + every 5 min in background; we don't re-scan on popup open)
    if (tab.url && tab.url.startsWith('http')) {
      if (tabState && tabState.fullResult && !tabState.fullResult.error) {
        displayFullResult(pageResult, tabState.fullResult);
        // Voice for page scan is played by background when scan completes; don't replay every time popup opens
      } else if (tabState && tabState.skippedReason === 'localhost') {
        pageResult.innerHTML = '<div style="color: #10b981; font-size: 13px;">✅ Localhost - No scan needed</div>';
      } else {
        pageResult.innerHTML = '<div style="color: #94a3b8; font-size: 13px;">Scan runs when the page loads. If you just opened this tab, wait a moment and open the extension again.</div>';
      }
    } else {
      pageResult.innerHTML = '';
    }
  } catch (err) {
    currentPageEl.textContent = 'Unable to analyze current page';
    pageResult.innerHTML = `<div class="error">❌ ${err.message || 'Backend unavailable'}</div>`;
    privacyNotice.style.display = 'none';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const logo = document.getElementById('popup-logo');
  if (logo) logo.src = chrome.runtime.getURL('icons/logo.png');
  loadCurrentPageStatus();
});
