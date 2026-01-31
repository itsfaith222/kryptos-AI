/**
 * Guardian AI Scout - Content Script
 * Runs on every web page to detect threats
 * - Scans DOM for urgency signals
 * - Listens for copy/paste events
 * - Sends data to background script
 */

console.log('Guardian AI Scout initialized on page:', window.location.href);

// Urgency keywords to detect
const URGENCY_KEYWORDS = [
  'action required',
  'urgent',
  'immediate',
  'verify',
  'confirm',
  'suspended',
  'locked',
  'expires',
  'limited time',
  'act now',
  'click here',
  'update required',
  'security alert',
  'unusual activity'
];

/**
 * Scan DOM for urgency signals
 */
function scanPageForSignals() {
  const signals = {
    url: window.location.href,
    urgencySignals: [],
    hasLoginForm: false,
    timestamp: new Date().toISOString()
  };
  
  // Check for login forms
  const loginForms = document.querySelectorAll('form[action*="login"], form[action*="signin"], input[type="password"]');
  signals.hasLoginForm = loginForms.length > 0;
  
  // Scan page text for urgency keywords
  const pageText = document.body.innerText.toLowerCase();
  URGENCY_KEYWORDS.forEach(keyword => {
    if (pageText.includes(keyword)) {
      signals.urgencySignals.push(keyword);
    }
  });
  
  return signals;
}

/**
 * Send signals to background script
 */
function sendSignalsToBackground(signals) {
  chrome.runtime.sendMessage(
    { action: 'scanPage', signals: signals },
    response => {
      if (chrome.runtime.lastError) {
        console.warn('Background script not responding:', chrome.runtime.lastError);
      } else if (response && response.riskScore > 70) {
        showWarningBanner(response);
      }
    }
  );
}

/**
 * Scan page on load
 */
const pageSignals = scanPageForSignals();
sendSignalsToBackground(pageSignals);

/**
 * Listen for copy/paste events
 */
document.addEventListener('paste', (event) => {
  const pastedText = event.clipboardData?.getData('text') || '';
  if (pastedText.length > 10) {
    console.log('Paste detected, sending to background:', pastedText.substring(0, 50));
    chrome.runtime.sendMessage(
      { action: 'analyzeText', text: pastedText },
      response => {
        if (chrome.runtime.lastError) {
          console.warn('Background script not responding');
        }
      }
    );
  }
});

/**
 * Show warning banner for dangerous pages
 */
function showWarningBanner(result) {
  const banner = document.createElement('div');
  banner.id = 'guardian-warning-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: #ef4444;
    color: white;
    padding: 16px;
    text-align: center;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 16px;
    z-index: 2147483647;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    animation: slideDown 0.3s ease-out;
  `;
  
  banner.innerHTML = `
    <div style="max-width: 1200px; margin: 0 auto;">
      <strong>🚨 Guardian AI Warning</strong>
      <span style="font-size: 14px; margin-left: 8px;">
        Risk Score: ${result.riskScore}/100
      </span>
      <button id="guardian-dismiss" style="
        margin-left: 16px;
        padding: 8px 16px;
        background: white;
        color: #ef4444;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-weight: 600;
        font-size: 13px;
      ">
        Dismiss
      </button>
    </div>
  `;
  
  document.body.prepend(banner);
  document.getElementById('guardian-dismiss').addEventListener('click', () => {
    banner.remove();
  });
}
