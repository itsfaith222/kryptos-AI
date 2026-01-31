/**
 * Guardian AI Scout - Background Service Worker
 * Handles message passing and API communication
 */

const BACKEND_URL = 'http://localhost:8000';

// Cache for storing recent analysis results
const analysisCache = new Map();

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request.action);
  
  if (request.action === 'analyzeMessage') {
    analyzeMessage(request.message).then(sendResponse);
    return true;  // Will respond asynchronously
  }
  
  if (request.action === 'analyzeImage') {
    analyzeImage(request.imageData).then(sendResponse);
    return true;
  }
  
  if (request.action === 'analyzePage') {
    analyzePage(request.url, request.pageData).then(sendResponse);
    return true;
  }
  
  if (request.action === 'updateBadge') {
    updateBadge(request.riskScore);
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'privacyPolicyDetected') {
    analyzePrivacyPolicy(request.text).then(sendResponse);
    return true;
  }
});

/**
 * Analyze pasted message text
 */
async function analyzeMessage(message) {
  try {
    // Check cache first
    const cacheKey = `msg:${message.substring(0, 100)}`;
    if (analysisCache.has(cacheKey)) {
      console.log('Returning cached message analysis');
      return analysisCache.get(cacheKey);
    }
    
    // Call backend API
    const response = await fetch(`${BACKEND_URL}/scout/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: '',
        scanType: 'message',
        content: message
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    const result = await response.json();
    
    // Cache the result for 1 hour
    analysisCache.set(cacheKey, result);
    setTimeout(() => analysisCache.delete(cacheKey), 60 * 60 * 1000);
    
    return result;
  } catch (error) {
    console.error('Error analyzing message:', error);
    return {
      error: error.message,
      initialRisk: 0
    };
  }
}

/**
 * Analyze uploaded image
 */
async function analyzeImage(imageData) {
  try {
    const cacheKey = `img:${imageData.substring(0, 50)}`;
    if (analysisCache.has(cacheKey)) {
      console.log('Returning cached image analysis');
      return analysisCache.get(cacheKey);
    }
    
    const response = await fetch(`${BACKEND_URL}/scout/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: '',
        scanType: 'image',
        image_data: imageData
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    const result = await response.json();
    analysisCache.set(cacheKey, result);
    setTimeout(() => analysisCache.delete(cacheKey), 60 * 60 * 1000);
    
    return result;
  } catch (error) {
    console.error('Error analyzing image:', error);
    return {
      error: error.message,
      initialRisk: 0
    };
  }
}

/**
 * Analyze web page
 */
async function analyzePage(url, pageData) {
  try {
    const cacheKey = `page:${url}`;
    if (analysisCache.has(cacheKey)) {
      console.log('Returning cached page analysis');
      return analysisCache.get(cacheKey);
    }
    
    const response = await fetch(`${BACKEND_URL}/scout/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        scanType: 'page',
        page_data: pageData
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    const result = await response.json();
    analysisCache.set(cacheKey, result);
    setTimeout(() => analysisCache.delete(cacheKey), 10 * 60 * 1000);  // Cache pages for 10 min
    
    return result;
  } catch (error) {
    console.error('Error analyzing page:', error);
    return {
      error: error.message,
      initialRisk: 0
    };
  }
}

/**
 * Analyze privacy policy
 */
async function analyzePrivacyPolicy(text) {
  try {
    const response = await fetch(`${BACKEND_URL}/analyst/analyze-privacy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policyText: text })
    });
    
    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error analyzing privacy policy:', error);
    return { error: error.message };
  }
}

/**
 * Update extension badge based on risk score
 */
function updateBadge(riskScore) {
  if (riskScore > 70) {
    chrome.action.setBadgeText({ text: '🚨' });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  } else if (riskScore > 30) {
    chrome.action.setBadgeText({ text: '⚠️' });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
  } else {
    chrome.action.setBadgeText({ text: '✅' });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
  }
}

// Initialize with safe badge on load
chrome.action.setBadgeText({ text: '✅' });
chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
