/**
 * Kryptos-AI Scout - Content Script (Broad Scanning)
 * Multi-vector scanner: phishing, scams, malware cues, login detection, privacy policy
 * Sends structured SCOUT_SIGNAL to background script
 */

(function () {
  'use strict';

  // Phishing / urgency
  const PHISHING_KEYWORDS = [
    'urgent', 'action required', 'suspended', 'immediate', 'verify', 'confirm',
    'expires', 'limited time', 'act now', 'click here', 'update required',
    'security alert', 'unusual activity', 're-confirm'
  ];

  // Scam patterns (prize, inheritance, tech support, refund, crypto, romance)
  const SCAM_KEYWORDS = [
    'claim prize', 'you won', 'congratulations', 'inheritance', 'inherited',
    'tech support', 'microsoft support', 'apple support', 'refund', 'wire transfer',
    'send money', 'bitcoin', 'crypto', 'investment opportunity', 'act now or lose',
    'limited offer', 'free gift', 'claim now', 'urgent reply', 'verify your account'
  ];

  // Malware / suspicious download cues
  const MALWARE_KEYWORDS = [
    'download now', 'install update', '.exe', 'run this file', 'enable macros',
    'click to install', 'security update required', 'flash player update'
  ];

  const PRIVACY_LINK_PATTERNS = ['privacy', 'terms', 't&c', 'terms and conditions', 'privacy policy'];

  /**
   * Scan page for threat keywords (phishing + scam + malware) in visible text
   */
  function getDetectedKeywords() {
    const text = (document.body && document.body.innerText) ? document.body.innerText.toLowerCase() : '';
    const phishing = PHISHING_KEYWORDS.filter((kw) => text.includes(kw));
    const scam = SCAM_KEYWORDS.filter((kw) => text.includes(kw));
    const malware = MALWARE_KEYWORDS.filter((kw) => text.includes(kw));
    return { phishing, scam, malware, all: [...phishing, ...scam, ...malware] };
  }

  /**
   * Detect login page: password input or forms with login/sign-in IDs or classes
   */
  function isLoginPage() {
    const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
    const loginFormSelectors = [
      'form[action*="login"]',
      'form[action*="signin"]',
      'form[action*="sign-in"]',
      'form#login',
      'form#signin',
      'form#sign-in',
      'form[id*="login"]',
      'form[id*="signin"]',
      'form[class*="login"]',
      'form[class*="sign-in"]'
    ];
    const hasLoginForm = loginFormSelectors.some((sel) => {
      try {
        return document.querySelector(sel) !== null;
      } catch (_) {
        return false;
      }
    });
    return hasPasswordInput || hasLoginForm;
  }

  /**
   * Detect links to privacy policy / terms (privacy, terms, T&C)
   */
  function hasPrivacyPolicyLinks() {
    const links = document.querySelectorAll('a[href]');
    for (const a of links) {
      const href = (a.getAttribute('href') || '').toLowerCase();
      const text = (a.textContent || '').toLowerCase();
      const combined = `${href} ${text}`;
      const matches = PRIVACY_LINK_PATTERNS.some((p) => combined.includes(p));
      if (matches) return true;
    }
    return false;
  }

  /**
   * Build and send SCOUT_SIGNAL to background
   */
  function sendScoutSignal() {
    const keywords = getDetectedKeywords();

    // ===== Skip localhost URLs =====
    try {
      const url = new URL(window.location.href);
      const isLocalhost = url.hostname === 'localhost' ||
        url.hostname === '127.0.0.1' ||
        url.hostname.endsWith('.local');

      if (isLocalhost) {
        console.log('[Guardian AI Content] ⏭️ Skipping localhost URL scan');
        return; // Don't send signal for localhost
      }
    } catch (e) {
      // Invalid URL, continue with scan
    }
    // ===== END localhost check =====

    const payload = {
      action: 'SCOUT_SIGNAL',
      url: window.location.href,
      isLogin: isLoginPage(),
      hasPrivacyPolicy: hasPrivacyPolicyLinks(),
      detectedKeywords: keywords.all,
      detectedPhishing: keywords.phishing,
      detectedScam: keywords.scam,
      detectedMalware: keywords.malware
    };

    console.log('[Guardian AI Content] 🔍 Sending Scout signal to background:', {
      url: payload.url,
      isLogin: payload.isLogin,
      hasPrivacyPolicy: payload.hasPrivacyPolicy,
      keywordCount: keywords.all.length,
      phishing: keywords.phishing.length,
      scam: keywords.scam.length,
      malware: keywords.malware.length
    });

    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        console.warn('[Guardian AI Content] ⚠️ Background not ready:', chrome.runtime.lastError.message);
      } else {
        console.log('[Guardian AI Content] ✅ Scout signal acknowledged by background');
      }
    });
  }

  // Run scan on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sendScoutSignal);
  } else {
    sendScoutSignal();
  }

  // Listen for paste: send text to background for analysis (any text, not just email)
  document.addEventListener('paste', (e) => {
    const pastedText = (e.clipboardData && e.clipboardData.getData('text')) || '';
    if (pastedText.length > 10) {
      chrome.runtime.sendMessage(
        { action: 'analyzeText', text: pastedText },
        () => { if (chrome.runtime.lastError) { /* ignore */ } }
      );
    }
  });

  // ===== Link Hover Tooltips =====
  let currentTooltip = null;
  let hoverTimeout = null;
  const linkCache = new Map(); // Cache link safety results

  /**
   * Create and show tooltip for a link
   */
  function showLinkTooltip(link, result) {
    // Remove any existing tooltip
    removeTooltip();

    const tooltip = document.createElement('div');
    tooltip.className = 'kryptos-ai-tooltip';
    tooltip.id = 'kryptos-ai-tooltip';

    const risk = result.risk || 0;
    let riskClass = 'safe';
    let riskLabel = 'Safe';
    let riskEmoji = '✅';

    if (risk > 70) {
      riskClass = 'danger';
      riskLabel = 'High Risk';
      riskEmoji = '🚨';
    } else if (risk >= 40) {
      riskClass = 'warning';
      riskLabel = 'Medium Risk';
      riskEmoji = '⚠️';
    }

    tooltip.innerHTML = `
      <div class="tooltip-header ${riskClass}">
        <span class="tooltip-emoji">${riskEmoji}</span>
        <span class="tooltip-label">${riskLabel} (${risk}/100)</span>
      </div>
      <div class="tooltip-body">
        ${result.reason || 'Link safety check'}
      </div>
    `;

    document.body.appendChild(tooltip);
    currentTooltip = tooltip;

    // Position tooltip above the link
    positionTooltip(tooltip, link);

    // Fade in
    setTimeout(() => {
      tooltip.style.opacity = '1';
    }, 10);
  }

  /**
   * Position tooltip above link, avoiding viewport edges
   */
  function positionTooltip(tooltip, link) {
    const linkRect = link.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();

    let top = linkRect.top + window.scrollY - tooltipRect.height - 8;
    let left = linkRect.left + window.scrollX + (linkRect.width / 2) - (tooltipRect.width / 2);

    // Avoid going off top of viewport
    if (top < window.scrollY) {
      top = linkRect.bottom + window.scrollY + 8;
    }

    // Avoid going off left edge
    if (left < window.scrollX) {
      left = window.scrollX + 8;
    }

    // Avoid going off right edge
    if (left + tooltipRect.width > window.scrollX + window.innerWidth) {
      left = window.scrollX + window.innerWidth - tooltipRect.width - 8;
    }

    tooltip.style.top = `${top}px`;
    tooltip.style.left = `${left}px`;
  }

  /**
   * Remove current tooltip
   */
  function removeTooltip() {
    if (currentTooltip) {
      currentTooltip.style.opacity = '0';
      setTimeout(() => {
        if (currentTooltip && currentTooltip.parentNode) {
          currentTooltip.parentNode.removeChild(currentTooltip);
        }
        currentTooltip = null;
      }, 200);
    }
  }

  /**
   * Handle link hover
   */
  function handleLinkHover(e) {
    const link = e.target.closest('a[href]');
    if (!link) return;

    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;

    // ===== Skip localhost URLs =====
    try {
      const absoluteUrl = new URL(href, window.location.href).href;
      const url = new URL(absoluteUrl);
      const isLocalhost = url.hostname === 'localhost' ||
        url.hostname === '127.0.0.1' ||
        url.hostname.endsWith('.local');

      if (isLocalhost) return; // Don't show tooltip for localhost
    } catch (e) {
      // Invalid URL, ignore
    }
    // ===== END localhost check =====

    // Clear any pending hover timeout
    if (hoverTimeout) {
      clearTimeout(hoverTimeout);
    }

    // Debounce: wait 500ms before showing tooltip
    hoverTimeout = setTimeout(() => {
      // Perform lightweight client-side checks first
      const quickCheck = performQuickLinkCheck(href);

      if (quickCheck.suspicious) {
        // Show immediate warning for obviously suspicious links
        console.log('[Guardian AI Content] 🔗 Suspicious link detected:', href, quickCheck.reason);
        showLinkTooltip(link, {
          risk: quickCheck.risk,
          reason: `⚠️ Security Tip: ${quickCheck.reason}`
        });
        return;
      }

      // Check cache first
      if (linkCache.has(href)) {
        showLinkTooltip(link, linkCache.get(href));
        return;
      }

      // Request safety check from background
      console.log('[Guardian AI Content] 🔗 Requesting link safety check:', href);
      chrome.runtime.sendMessage(
        { action: 'checkLinkSafety', url: href },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            console.warn('[Guardian AI Content] ⚠️ Link check failed:', chrome.runtime.lastError?.message);
            return;
          }

          console.log('[Guardian AI Content] ✅ Link check complete:', response);

          // Cache result
          linkCache.set(href, response);

          // Show tooltip if still hovering
          if (link.matches(':hover')) {
            showLinkTooltip(link, response);
          }
        }
      );
    }, 500);
  }

  /**
   * Perform quick client-side link check for obvious threats
   */
  function performQuickLinkCheck(url) {
    const urlLower = url.toLowerCase();

    // Suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link'];
    for (const tld of suspiciousTLDs) {
      if (urlLower.includes(tld)) {
        return {
          suspicious: true,
          risk: 75,
          reason: `Suspicious domain extension (${tld}) - often used in scams`
        };
      }
    }

    // Urgency keywords in URL
    const urgencyKeywords = ['urgent', 'verify', 'suspended', 'expires', 'confirm', 'update', 'security-alert'];
    for (const keyword of urgencyKeywords) {
      if (urlLower.includes(keyword)) {
        return {
          suspicious: true,
          risk: 60,
          reason: `Urgency trigger in URL ("${keyword}") - common phishing tactic`
        };
      }
    }

    // IP address instead of domain
    const ipPattern = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipPattern.test(url)) {
      return {
        suspicious: true,
        risk: 70,
        reason: 'Link uses IP address instead of domain - suspicious'
      };
    }

    // Excessive subdomains (potential typosquatting)
    try {
      const urlObj = new URL(url);
      const parts = urlObj.hostname.split('.');
      if (parts.length > 4) {
        return {
          suspicious: true,
          risk: 55,
          reason: 'Unusual number of subdomains - verify legitimacy'
        };
      }
    } catch (e) {
      // Invalid URL
    }

    return { suspicious: false };
  }

  /**
   * Handle link mouseout
   */
  function handleLinkMouseout(e) {
    const link = e.target.closest('a[href]');
    if (!link) return;

    // Clear pending hover timeout
    if (hoverTimeout) {
      clearTimeout(hoverTimeout);
      hoverTimeout = null;
    }

    // Remove tooltip
    removeTooltip();
  }

  // Attach hover listeners to document
  document.addEventListener('mouseover', handleLinkHover);
  document.addEventListener('mouseout', handleLinkMouseout);

  // Clean up cache periodically (every 5 minutes)
  setInterval(() => {
    linkCache.clear();
  }, 5 * 60 * 1000);
})();
