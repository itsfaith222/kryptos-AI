/**
 * Guardian AI Scout - Content Script
 * Runs on every web page to detect threats
 */

console.log('Guardian AI Scout initialized on page:', window.location.href);

// Extract page signals
function extractPageSignals() {
  const signals = {
    url: window.location.href,
    domain: window.location.hostname,
    hasHTTPS: window.location.protocol === 'https:',
    hasPassword: false,
    hasEmail: false,
    formCount: 0,
    externalLinks: 0,
    isPrivacyPolicy: false
  };
  
  // Check for password fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  signals.hasPassword = passwordFields.length > 0;
  
  // Check for email fields
  const emailFields = document.querySelectorAll('input[type="email"]');
  signals.hasEmail = emailFields.length > 0;
  
  // Count forms
  signals.formCount = document.querySelectorAll('form').length;
  
  // Count external links
  const links = document.querySelectorAll('a[href]');
  links.forEach(link => {
    try {
      if (link.hostname && link.hostname !== window.location.hostname) {
        signals.externalLinks++;
      }
    } catch (e) {
      // Skip invalid URLs
    }
  });
  
  // Check if privacy policy page
  const url = window.location.href.toLowerCase();
  const title = document.title.toLowerCase();
  const h1 = document.querySelector('h1')?.textContent.toLowerCase() || '';
  
  const privacyKeywords = ['privacy', 'terms', 'policy', 'conditions', 'legal'];
  signals.isPrivacyPolicy = privacyKeywords.some(kw => 
    url.includes(kw) || title.includes(kw) || h1.includes(kw)
  );
  
  return signals;
}

// Send signals to background script on page load
const pageSignals = extractPageSignals();

chrome.runtime.sendMessage(
  { action: 'analyzePage', url: window.location.href, pageData: pageSignals },
  response => {
    if (response && response.initialRisk > 70) {
      showWarningBanner(response);
    }
  }
);

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
      <br style="display: none;" />
      <span style="font-size: 14px; margin-left: 8px;">
        This site may be dangerous. Risk score: ${result.initialRisk}/100
      </span>
      <br style="display: block; margin: 8px 0;" />
      <button id="guardian-dismiss" style="
        margin-top: 8px;
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
  
  // Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideDown {
      from {
        transform: translateY(-100%);
      }
      to {
        transform: translateY(0);
      }
    }
  `;
  document.head.appendChild(style);
  
  document.body.prepend(banner);
  
  document.getElementById('guardian-dismiss').addEventListener('click', () => {
    banner.remove();
  });
}

/**
 * Inject link hover tooltips
 */
document.addEventListener('mouseover', async (event) => {
  if (event.target.tagName === 'A' && event.target.href) {
    const url = event.target.href;
    
    // Skip javascript: and mailto: links
    if (url.startsWith('javascript:') || url.startsWith('mailto:')) {
      return;
    }
    
    // Don't create multiple tooltips
    if (document.getElementById('guardian-tooltip')) {
      return;
    }
    
    // Create tooltip
    const tooltip = document.createElement('div');
    tooltip.id = 'guardian-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      background: rgba(0, 0, 0, 0.95);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 11px;
      z-index: 2147483646;
      pointer-events: none;
      max-width: 300px;
      word-wrap: break-word;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    `;
    tooltip.textContent = 'Checking safety...';
    document.body.appendChild(tooltip);
    
    // Position tooltip near cursor
    const rect = event.target.getBoundingClientRect();
    tooltip.style.left = (rect.left + 10) + 'px';
    tooltip.style.top = (rect.top + 30) + 'px';
  }
});

document.addEventListener('mousemove', (event) => {
  const tooltip = document.getElementById('guardian-tooltip');
  if (tooltip) {
    tooltip.style.left = (event.clientX + 10) + 'px';
    tooltip.style.top = (event.clientY + 10) + 'px';
  }
});

document.addEventListener('mouseout', (event) => {
  if (event.target.tagName === 'A') {
    const tooltip = document.getElementById('guardian-tooltip');
    if (tooltip) {
      tooltip.remove();
    }
  }
});

// Privacy policy text extraction (for future deep analysis)
if (pageSignals.isPrivacyPolicy) {
  const paragraphs = Array.from(document.querySelectorAll('p, li, div'))
    .map(el => el.textContent.trim())
    .filter(text => text.length > 20);
  
  if (paragraphs.length > 0) {
    chrome.runtime.sendMessage({
      action: 'privacyPolicyDetected',
      text: paragraphs.join('\n\n').substring(0, 5000)  // Limit to 5000 chars
    });
  }
}
