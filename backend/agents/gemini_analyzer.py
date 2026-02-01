"""
gemini_analyzer.py
GUARDIAN AI - Gemini AI Analyzer (Hour 6-12 Enhanced)
Optimized prompts, privacy policy analysis
"""

import os
import json
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class GeminiAnalyzer:
    """Enhanced Gemini analyzer with privacy policy support"""

    OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
    MODEL_ID = "google/gemini-2.0-flash-001"

    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.available = bool(self.api_key)

        if self.available:
            print(f"[GEMINI/OR] ✓ Ready — OpenRouter → {self.MODEL_ID}")
        else:
            print("[GEMINI/OR] ✗ OPENROUTER_API_KEY missing")

    def analyze_threat(self, content: str, url: str = "") -> Dict:
        """HOUR 6-12: Enhanced threat analysis with optimized prompts"""
        if not self.available:
            return self._fallback_analysis(content)

        prompt = f"""You are an expert cybersecurity analyst. Analyze this content for threats:

URL: {url}
Content (first 2000 chars):
{content[:2000]}

Look for:
1. Phishing indicators (fake login, credential theft)
2. Scam patterns (prize scams, inheritance, tech support)
3. Psychological manipulation (urgency, fear, authority)
4. Brand impersonation
5. Suspicious links/domains

Return ONLY valid JSON:
{{
  "threatType": "phishing" | "scam" | "social_engineering" | "malware" | "benign",
  "riskScore": 0-100,
  "confidence": 0.0-1.0,
  "manipulationTactics": [
    {{
      "type": "urgency" | "fear" | "authority" | "credential_request" | "financial_request",
      "example": "exact quote showing this tactic",
      "severity": "critical" | "high" | "medium" | "low"
    }}
  ],
  "evidence": [
    {{
      "type": "content" | "domain" | "form" | "linguistic",
      "finding": "specific indicator found",
      "severity": "critical" | "high" | "medium" | "low"
    }}
  ],
  "explanation": "2-3 sentence summary"
}}

SCORING: 80-100=clear threat, 60-79=suspicious, 40-59=some concerns, 0-39=likely safe"""

        return self._make_request(prompt)

    def analyze_privacy_policy(self, policy_text: str) -> Dict:
        """HOUR 6-12: Privacy policy deep analysis"""
        if not self.available:
            return self._fallback_privacy()

        prompt = f"""Analyze this privacy policy for privacy concerns:

Policy (first 4000 chars):
{policy_text[:4000]}

Extract:
1. What data is collected (location, contacts, browsing, biometrics, etc.)
2. Who data is shared with (advertisers, data brokers, third parties)
3. Can users delete their data?
4. Red flags and concerning practices

Return ONLY valid JSON:
{{
  "dataCollected": ["list specific data types like: location, contacts, browsing history, camera, microphone"],
  "thirdPartySharing": ["list who receives data like: advertisers, data brokers, partners"],
  "canDelete": true | false,
  "canOptOut": true | false,
  "retentionPeriod": "how long data is kept",
  "redFlags": ["list concerning practices"],
  "privacyScore": 0-100,
  "reasoning": "brief summary"
}}

PRIVACY SCORE (higher = worse): 80-100=severe violations, 60-79=significant concerns, 40-59=moderate, 0-39=acceptable"""

        result = self._make_request(prompt)
        
        # Ensure required fields
        result.setdefault('privacyScore', 50)
        result.setdefault('dataCollected', [])
        result.setdefault('thirdPartySharing', [])
        result.setdefault('canDelete', True)
        result.setdefault('redFlags', [])
        
        return result

    def _make_request(self, prompt: str) -> Dict:
        """Make request to OpenRouter API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.MODEL_ID,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.3,
        }

        try:
            resp = requests.post(self.OPENROUTER_URL, headers=headers, json=body, timeout=45)
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            print(f"[GEMINI/OR] ✓ Got response ({len(raw)} chars)")
            return self._parse_json(raw)
        except Exception as e:
            print(f"[GEMINI/OR] ✗ {e}")
            return self._fallback_analysis("")

    def _parse_json(self, text: str) -> Dict:
        """Parse JSON, handling markdown code blocks"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            clean = text.strip()
            if clean.startswith("```"):
                lines = clean.split("\n")
                clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
                if clean.startswith("json"):
                    clean = clean[4:]
            try:
                return json.loads(clean.strip())
            except:
                return self._fallback_analysis("")

    def _fallback_analysis(self, content: str) -> Dict:
        """Fallback when API unavailable"""
        content_lower = (content or "").lower()
        urgency_words = ['urgent', 'immediate', 'act now', 'expires', 'suspended', 'verify']
        credential_words = ['password', 'login', 'credentials', 'verify account']
        
        urgency_count = sum(1 for w in urgency_words if w in content_lower)
        credential_count = sum(1 for w in credential_words if w in content_lower)
        risk_score = min(100, (urgency_count * 15) + (credential_count * 20))
        
        tactics = []
        if urgency_count > 0:
            tactics.append({"type": "urgency", "example": "urgency language", "severity": "high"})
        if credential_count > 0:
            tactics.append({"type": "credential_request", "example": "credential request", "severity": "critical"})

        return {
            "threatType": "phishing" if risk_score >= 60 else "benign",
            "riskScore": risk_score,
            "confidence": 0.4,
            "manipulationTactics": tactics,
            "evidence": [],
            "explanation": "Heuristic analysis (AI unavailable)"
        }

    def _fallback_privacy(self) -> Dict:
        """Fallback for privacy analysis"""
        return {
            "privacyScore": 50,
            "dataCollected": [],
            "thirdPartySharing": [],
            "canDelete": True,
            "redFlags": [],
            "reasoning": "AI analysis unavailable"
        }
        
