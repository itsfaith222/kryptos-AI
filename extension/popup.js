/**
 * Scout - Popup Logic
 * Handles user interactions and result display
 */

const BACKEND_URL = 'http://localhost:8000';

console.log('[Scout] Popup script loaded');

// DOM Elements
const pasteInput = document.getElementById('paste-input');
const analyzeBtn = document.getElementById('analyze-btn');
const pasteResult = document.getElementById('paste-result');
const imageInput = document.getElementById('image-input');
const uploadBtn = document.getElementById('upload-btn');
const imageResult = document.getElementById('image-result');
const pageResult = document.getElementById('page-result');
const currentPageEl = document.getElementById('current-page');
const statusMessage = document.getElementById('status-message');

// ============= PASTE ANALYSIS =============

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
    const result = await analyzePastedText(text);
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

// ============= IMAGE UPLOAD =============

uploadBtn.addEventListener('click', async () => {
  const file = imageInput.files[0];
  
  if (!file) {
    showStatus('Please select an image file', 'error');
    return;
  }
  
  if (!file.type.startsWith('image/')) {
    showStatus('Please select a valid image file', 'error');
    return;
  }
  
  uploadBtn.disabled = true;
  uploadBtn.textContent = 'Analyzing...';
  imageResult.innerHTML = '<div class="loading"></div> Analyzing screenshot...';
  
  try {
    const base64 = await fileToBase64(file);
    const result = await analyzeScreenshot(base64);
    displayResult(imageResult, result);
    showStatus('Screenshot analysis complete', 'success');
  } catch (error) {
    showStatus(`Error: ${error.message}`, 'error');
    imageResult.innerHTML = `<div class="error">❌ ${error.message}</div>`;
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = 'Analyze Screenshot';
  }
});

// ============= FUNCTIONS =============

/**
 * Analyze pasted text
 */
async function analyzePastedText(text) {
  console.log('[Scout] Analyzing pasted text');
  
  const payload = {
    url: '',
    is_login_page: false,
    detected_keywords: extractPhishingKeywords(text),
    pasted_text: text
  };
  
  console.log('[Scout] Payload:', payload);
  
  const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  if (!response.ok) {
    throw new Error(`Backend error: ${response.status}`);
  }
  
  return await response.json();
}

/**
 * Analyze screenshot (placeholder - would use Gemini Vision in full implementation)
 */
async function analyzeScreenshot(base64) {
  console.log('[Scout] Analyzing screenshot');
  
  // For now, treat screenshot like text analysis
  // In full implementation, would send to Gemini Vision API
  const payload = {
    url: '',
    is_login_page: false,
    detected_keywords: ['screenshot-uploaded'],
    pasted_text: null
  };
  
  const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  if (!response.ok) {
    throw new Error(`Backend error: ${response.status}`);
  }
  
  return await response.json();
}

/**
 * Extract phishing keywords from text
 */
function extractPhishingKeywords(text) {
  const phishingKeywords = [
    'urgent', 'action required', 'suspended', 'verify', 'security alert',
    'confirm', 'update', 'immediate', 'click here', 'limited time'
  ];
  
  const textLower = text.toLowerCase();
  return phishingKeywords.filter(keyword => textLower.includes(keyword));
}

/**
 * Convert file to base64
 */
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

/**
 * Display result
 */
function displayResult(container, result) {
  const risk = result.risk_score || 0;
  let riskColor = 'green';
  let riskEmoji = '✅';
  
  if (risk > 70) {
    riskColor = 'red';
    riskEmoji = '🚨';
  } else if (risk >= 40) {
    riskColor = 'yellow';
    riskEmoji = '⚠️';
  }
  
  const html = `
    <div class="result-content">
      <div class="risk-score ${riskColor}">
        <span class="emoji">${riskEmoji}</span>
        <span class="score">${risk}/100</span>
      </div>
      <div class="risk-label">Risk Score</div>
      <div class="warning-message">
        ${result.warning_message || 'Analysis complete'}
      </div>
    </div>
  `;
  
  container.innerHTML = html;
}

/**
 * Show status message
 */
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

/**
 * Load current page status
 */
async function loadCurrentPageStatus() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentPageEl.textContent = `Current page: ${new URL(tab.url).hostname}`;
    
    const hasLogin = tab.url.toLowerCase().includes('login');
    
    const payload = {
      url: tab.url,
      is_login_page: hasLogin,
      detected_keywords: [],
      pasted_text: null
    };
    
    const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const result = await response.json();
      displayResult(pageResult, result);
    }
  } catch (error) {
    console.error('[Scout] Error loading page status:', error);
    currentPageEl.textContent = 'Unable to analyze current page';
    pageResult.innerHTML = `<div class="error">Backend unavailable</div>`;
  }
}

// Load on popup open
document.addEventListener('DOMContentLoaded', loadCurrentPageStatus);
