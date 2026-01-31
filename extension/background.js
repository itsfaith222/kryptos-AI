/**
 * Guardian AI Scout - Background Service Worker
 * Handles message passing, API communication, and badge updates
 */

const BACKEND_URL = 'http://localhost:8000';
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

// Cache for storing recent analysis results
const analysisCache = new Map();

/**
 * Listen for messages from content script and popup
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received:', request.action);
  
  if (request.action === 'scanPage') {
    handlePageScan(request.signals).then(sendResponse);
    return true;
  }
  
  if (request.action === 'analyzeText') {
    handleTextAnalysis(request.text).then(sendResponse);
    return true;
  }
  
  if (request.action === 'pasteAnalysis') {
    handlePasteAnalysis(request.text).then(sendResponse);
    return true;
  }
});

/**
 * Handle page scan from content script
 */
async function handlePageScan(signals) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: signals.url,
        signals: signals.urgencySignals,
        hasLoginForm: signals.hasLoginForm
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    const result = await response.json();
    updateBadge(result.riskScore);
    return result;
  } catch (error) {
    console.error('Error scanning page:', error);
    updateBadge(0); // Default to safe
    return { error: error.message, riskScore: 0 };
  }
}

/**
 * Handle text analysis from paste events
 */
async function handleTextAnalysis(text) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/scout/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: '',
        signals: extractSignalsFromText(text),
        hasLoginForm: false
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    const result = await response.json();
    updateBadge(result.riskScore);
    return result;
  } catch (error) {
    console.error('Error analyzing text:', error);
    return { error: error.message, riskScore: 0 };
  }
}

/**
 * Handle paste analysis from popup
 */
async function handlePasteAnalysis(text) {
  return handleTextAnalysis(text);
}

/**
 * Extract urgency signals from text
 */
function extractSignalsFromText(text) {
  const urgencyKeywords = [
    'urgent', 'immediate', 'action required', 'verify', 'confirm',
    'suspended', 'locked', 'expires', 'limited time', 'act now',
    'click here', 'update required', 'security alert', 'unusual activity'
  ];
  
  const textLower = text.toLowerCase();
  return urgencyKeywords.filter(keyword => textLower.includes(keyword));
}

/**
 * Update extension badge based on risk score
 * Red (>70), Yellow (40-70), Green (<40)
 */
function updateBadge(riskScore) {
  let badgeText = '✅';
  let badgeColor = '#10b981'; // Green
  
  if (riskScore > 70) {
    badgeText = '🚨';
    badgeColor = '#ef4444'; // Red
  } else if (riskScore >= 40) {
    badgeText = '⚠️';
    badgeColor = '#f59e0b'; // Yellow
  }
  
  chrome.action.setBadgeText({ text: badgeText });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor });
}

// Initialize with safe badge on load
updateBadge(0);
