/**
 * Guardian AI Scout - Content Script (Broad Scanning)
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

    chrome.runtime.sendMessage(payload, () => {
      if (chrome.runtime.lastError) { /* background not ready yet */ }
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
})();
