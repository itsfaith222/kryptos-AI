/**
 * Guardian AI Scout - Popup (Manual Tools)
 * Paste Analysis for any text (email, SMS, privacy paragraph).
 * Shows "Privacy Policy Found" when content script detected one on current tab.
 */

const BACKEND_URL = 'http://localhost:8000';

const pasteInput = document.getElementById('paste-input');
const analyzeBtn = document.getElementById('analyze-btn');
const pasteResult = document.getElementById('paste-result');
const pageResult = document.getElementById('page-result');
const currentPageEl = document.getElementById('current-page');
const statusMessage = document.getElementById('status-message');
const privacyNotice = document.getElementById('privacy-notice');

analyzeBtn.addEventListener('click', async () => {
  const text = pasteInput.value.trim();

  if (!text || text.length < 10) {
    showStatus('Please paste at least 10 characters', 'error');
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  pasteResult.innerHTML = '<div class="loading"></div> Analyzing...';

  try {
    const result = await sendPasteToBackend(text);
    displayResult(pasteResult, result);
    showStatus('Analysis complete', 'success');
  } catch (error) {
    showStatus(`Error: ${error.message}`, 'error');
    pasteResult.innerHTML = `<div class="error">❌ ${error.message}</div>`;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});

/** Send pasted text via background so backend gets same SCOUT_SIGNAL-style payload */
async function sendPasteToBackend(text) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: 'pasteAnalysis', text }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || 'Extension error'));
        return;
      }
      if (response && response.error) {
        reject(new Error(response.error));
        return;
      }
      resolve(response || { riskScore: 0 });
    });
  });
}

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

/** Load current tab status and show Privacy Policy Found if content script detected one */
async function loadCurrentPageStatus() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      currentPageEl.textContent = 'No active tab';
      privacyNotice.style.display = 'none';
      return;
    }

    const hostname = tab.url ? new URL(tab.url).hostname : 'Unknown';
    currentPageEl.textContent = `Current page: ${hostname}`;

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

    if (tab.url && tab.url.startsWith('http')) {
      const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: tab.url,
          isLogin: false,
          hasPrivacyPolicy: tabState ? !!tabState.hasPrivacyPolicy : false,
          detectedKeywords: []
        })
      });
      if (response.ok) {
        const result = await response.json();
        displayResult(pageResult, result);
      } else {
        pageResult.innerHTML = '<div class="error">Backend unavailable</div>';
      }
    } else {
      pageResult.innerHTML = '';
    }
  } catch (_) {
    currentPageEl.textContent = 'Unable to analyze current page';
    pageResult.innerHTML = '<div class="error">Backend unavailable</div>';
    privacyNotice.style.display = 'none';
  }
}

document.addEventListener('DOMContentLoaded', loadCurrentPageStatus);
