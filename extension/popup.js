/**
 * Guardian AI Scout - Popup Logic
 * Handles tab switching, user interactions, and result display
 */

const BACKEND_URL = 'http://localhost:8000';

// ============= TAB SWITCHING =============
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    // Remove active class from all tabs and content
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    // Add active class to clicked tab and corresponding content
    tab.classList.add('active');
    const tabName = tab.dataset.tab;
    document.getElementById(`${tabName}-tab`).classList.add('active');
  });
});

// ============= MESSAGE ANALYSIS =============
document.getElementById('analyze-btn').addEventListener('click', async () => {
  const message = document.getElementById('message-input').value;
  const btn = document.getElementById('analyze-btn');
  const resultsDiv = document.getElementById('paste-results');
  
  // Validate input
  if (!message || message.trim().length < 10) {
    showError(resultsDiv, 'Please paste at least 10 characters');
    return;
  }
  
  if (message.length > 10000) {
    showError(resultsDiv, 'Message too long (max 10,000 characters)');
    return;
  }
  
  // Show loading state
  btn.disabled = true;
  btn.textContent = 'Analyzing...';
  resultsDiv.innerHTML = '<div class="loading"></div><span class="loading-text">Analyzing message...</span>';
  
  try {
    const result = await analyzeMessage(message);
    if (result.error) {
      showError(resultsDiv, result.error);
    } else {
      displayResults(resultsDiv, result);
      updateBadge(result.initialRisk);
    }
  } catch (error) {
    showError(resultsDiv, `Error: ${error.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Message';
  }
});

// ============= IMAGE UPLOAD =============
document.getElementById('upload-btn').addEventListener('click', async () => {
  const fileInput = document.getElementById('image-input');
  const file = fileInput.files[0];
  const btn = document.getElementById('upload-btn');
  const resultsDiv = document.getElementById('upload-results');
  
  if (!file) {
    showError(resultsDiv, 'Please select an image file');
    return;
  }
  
  // Validate file type
  if (!file.type.startsWith('image/')) {
    showError(resultsDiv, 'Please select a valid image file');
    return;
  }
  
  // Show loading state
  btn.disabled = true;
  btn.textContent = 'Analyzing...';
  resultsDiv.innerHTML = '<div class="loading"></div><span class="loading-text">Analyzing screenshot...</span>';
  
  try {
    const base64 = await fileToBase64(file);
    const result = await analyzeImage(base64);
    if (result.error) {
      showError(resultsDiv, result.error);
    } else {
      displayResults(resultsDiv, result);
      updateBadge(result.initialRisk);
    }
  } catch (error) {
    showError(resultsDiv, `Error: ${error.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Screenshot';
  }
});

// ============= HELPERS =============

/**
 * Convert file to base64 string
 */
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      // Remove "data:image/png;base64," prefix
      const base64 = reader.result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

/**
 * Display analysis results
 */
function displayResults(container, result) {
  const risk = result.initialRisk;
  const riskColor = risk > 70 ? 'high' : risk > 30 ? 'medium' : 'low';
  const riskBadge = risk > 70 ? 'badge-red' : risk > 30 ? 'badge-yellow' : 'badge-green';
  
  let recommendation = 'Safe to proceed';
  let recommendationClass = 'safe';
  
  if (result.recommendation === 'ESCALATE_TO_ANALYST') {
    recommendation = 'This needs human review';
    recommendationClass = risk > 50 ? 'danger' : 'caution';
  } else if (result.recommendation === 'BLOCK_IMMEDIATELY') {
    recommendation = 'Do not proceed with this';
    recommendationClass = 'danger';
  }
  
  let signalsHtml = '';
  if (result.signals) {
    const signals = result.signals;
    const signalsList = [];
    
    // Message signals
    if (signals.urgencyWords && signals.urgencyWords.length > 0) {
      signalsList.push(`Urgency words: ${signals.urgencyWords.join(', ')}`);
    }
    if (signals.hasPassword) {
      signalsList.push('Contains password requests');
    }
    if (signals.hasEmail) {
      signalsList.push('Contains email addresses');
    }
    if (signals.suspiciousPatterns && signals.suspiciousPatterns.length > 0) {
      signalsList.push(`Suspicious patterns: ${signals.suspiciousPatterns.join(', ')}`);
    }
    
    // Image signals
    if (signals.suspiciousImages) {
      signalsList.push('Suspicious visual elements detected');
    }
    if (signals.logoQuality === 'low') {
      signalsList.push('Low-quality logo detected');
    }
    if (signals.extractedText) {
      signalsList.push(`Text extracted: "${signals.extractedText.substring(0, 50)}..."`);
    }
    
    // Page signals
    if (signals.domain && !signals.hasHTTPS) {
      signalsList.push(`Domain uses HTTP (not secure): ${signals.domain}`);
    }
    
    if (signalsList.length > 0) {
      signalsHtml = `
        <div style="margin-top: 12px;">
          <strong style="font-size: 12px; color: #6b7280;">Detected Signals:</strong>
          <ul class="signals-list">
            ${signalsList.map(s => `<li>${s}</li>`).join('')}
          </ul>
        </div>
      `;
    }
  }
  
  const warningHtml = result.predictiveWarning ? `
    <div style="margin-top: 12px; padding: 12px; background: #fef3c7; border-radius: 8px; border-left: 4px solid #f59e0b;">
      <strong style="font-size: 12px; color: #b45309;">⚠️ Predictive Warning:</strong>
      <p style="margin: 4px 0 0 0; font-size: 12px; color: #78350f;">${result.predictiveWarning}</p>
    </div>
  ` : '';
  
  container.innerHTML = `
    <div class="risk-score-container">
      <div class="risk-score ${riskColor}">${risk}</div>
      <div class="risk-label">Risk Score</div>
    </div>
    <div class="recommendation-box ${recommendationClass}">
      <strong>${result.recommendation === 'BLOCK_IMMEDIATELY' ? '🚨' : recommendation === 'Safe to proceed' ? '✅' : '⚠️'} ${recommendation}</strong>
      <p>Based on: ${result.scanType} analysis</p>
    </div>
    ${signalsHtml}
    ${warningHtml}
  `;
}

/**
 * Display error message
 */
function showError(container, message) {
  container.innerHTML = `<div class="error-message">❌ ${message}</div>`;
}

/**
 * Update extension badge based on risk score
 */
function updateBadge(riskScore) {
  // This will be sent to background script later
  chrome.runtime.sendMessage({
    action: 'updateBadge',
    riskScore: riskScore
  }).catch(() => {
    // Silently fail if background script not ready
  });
}

// ============= API CALLS =============

/**
 * Send message to backend for analysis
 */
async function analyzeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: 'analyzeMessage', message: message },
      response => {
        if (chrome.runtime.lastError) {
          resolve({
            error: 'Background script not responding',
            initialRisk: 0
          });
        } else if (response && response.error) {
          resolve(response);
        } else {
          resolve(response);
        }
      }
    );
  });
}

/**
 * Send image to backend for analysis
 */
async function analyzeImage(base64) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: 'analyzeImage', imageData: base64 },
      response => {
        if (chrome.runtime.lastError) {
          resolve({
            error: 'Background script not responding',
            initialRisk: 0
          });
        } else if (response && response.error) {
          resolve(response);
        } else {
          resolve(response);
        }
      }
    );
  });
}

// ============= LOAD PREDICTIVE WARNINGS =============

/**
 * Load and display predictive warnings on popup open
 */
async function loadPredictiveWarnings() {
  const warningsList = document.getElementById('warnings-list');
  
  try {
    const response = await fetch(`${BACKEND_URL}/scout/warnings`);
    if (!response.ok) throw new Error('Failed to fetch warnings');
    
    const warnings = await response.json();
    
    if (!warnings || warnings.length === 0) {
      warningsList.innerHTML = '<div class="no-warnings">✅ No active threats in your area</div>';
    } else {
      warningsList.innerHTML = warnings
        .slice(0, 3) // Show top 3
        .map(w => `
          <div class="warning-item">
            <strong>⚠️ ${w.threatType || 'Unknown Threat'}</strong>
            <p>${w.description || 'Check your vigilance settings'}</p>
          </div>
        `)
        .join('');
    }
  } catch (error) {
    warningsList.innerHTML = '<div class="no-warnings">Unable to load warnings</div>';
  }
}

// Load warnings when popup opens
document.addEventListener('DOMContentLoaded', loadPredictiveWarnings);
