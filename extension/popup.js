/**
 * Scout - Popup Logic
 */

const BACKEND_URL = 'http://localhost:8000';

// DOM Elements
const pasteInput = document.getElementById('paste-input');
const analyzeBtn = document.getElementById('analyze-btn');
const pasteResult = document.getElementById('paste-result');
const pageResult = document.getElementById('page-result');
const currentPageEl = document.getElementById('current-page');
const statusMessage = document.getElementById('status-message');

// Analyze button handler
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
    const result = await sendToBackend(text);
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

// Send text to backend
async function sendToBackend(text) {
  const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: '',
      signals: extractSignals(text),
      hasLoginForm: false
    })
  });
  
  if (!response.ok) {
    throw new Error(`Backend error: ${response.status}`);
  }
  
  return await response.json();
}

// Extract urgency signals
function extractSignals(text) {
  const urgencyKeywords = [
    'urgent', 'immediate', 'action required', 'verify', 'confirm',
    'suspended', 'locked', 'expires', 'limited time', 'act now',
    'click here', 'update required', 'security alert', 'unusual activity'
  ];
  
  const textLower = text.toLowerCase();
  return urgencyKeywords.filter(keyword => textLower.includes(keyword));
}

// Display result
function displayResult(container, result) {
  const risk = result.riskScore || 0;
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
      <div class="recommendation">
        ${risk > 70 ? '🚨 High Risk - Do not proceed' : 
          risk >= 40 ? '⚠️ Medium Risk - Be cautious' : 
          '✅ Low Risk - Appears safe'}
      </div>
    </div>
  `;
  
  container.innerHTML = html;
}

// Show status message
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

// Load current page status
async function loadCurrentPageStatus() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentPageEl.textContent = `Current page: ${new URL(tab.url).hostname}`;
    
    const hasLogin = tab.url.toLowerCase().includes('login');
    
    const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: tab.url,
        signals: [],
        hasLoginForm: hasLogin
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      displayResult(pageResult, result);
    }
  } catch (error) {
    currentPageEl.textContent = 'Unable to analyze current page';
    pageResult.innerHTML = `<div class="error">Backend unavailable</div>`;
  }
}

// Load on popup open
document.addEventListener('DOMContentLoaded', loadCurrentPageStatus);
