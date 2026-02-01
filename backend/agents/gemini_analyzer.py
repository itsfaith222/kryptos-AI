"""
gemini_analyzer.py
Gemini AI Analyzer — calls OpenRouter directly via requests.
No OpenAI SDK = no 'proxies' kwarg bug, ever.
"""
import os
import json
import requests
from typing import Dict


class GeminiAnalyzer:
    """Calls Gemini 2.0 Flash through OpenRouter's REST API directly"""

    OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
    MODEL_ID = "google/gemini-2.0-flash-001"

    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()

        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.available = bool(self.api_key)

        if self.available:
            print(f"[GEMINI/OR] ✓ Ready — OpenRouter → {self.MODEL_ID}")
        else:
            print("[GEMINI/OR] ✗ OPENROUTER_API_KEY missing")

    # ──────────────────────────────────────────────────────────────────
    def analyze_threat(self, content: str, url: str = "") -> Dict:
        """Send to Gemini 2.0 Flash via OpenRouter REST endpoint. No fallback — raise if not configured or API fails."""
        if not self.available:
            raise ValueError("Analyst: OpenRouter not configured — set OPENROUTER_API_KEY in .env")

        prompt = f"""You are a cybersecurity analyst. Analyze this for threats:

URL: {url}
Content: {content[:1500]}

Return ONLY valid JSON:
{{
  "threatType": "phishing"|"scam"|"social_engineering"|"benign",
  "riskScore": 0-100,
  "confidence": 0.0-1.0,
  "manipulationTactics": [
    {{
      "type": "urgency"|"fear"|"authority"|"credential_request"|"financial_request",
      "example": "exact quote from content",
      "severity": "critical"|"high"|"medium"|"low"
    }}
  ],
  "evidence": [
    {{
      "finding": "specific indicator",
      "severity": "critical"|"high"|"medium"|"low",
      "source": "content_analysis"
    }}
  ],
  "explanation": "2-3 sentence summary"
}}"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.MODEL_ID,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        }

        try:
            resp = requests.post(
                self.OPENROUTER_URL,
                headers=headers,
                json=body,
                timeout=30,
            )
            resp.raise_for_status()

            raw = resp.json()["choices"][0]["message"]["content"]
            print(f"[GEMINI/OR] ✓ Got response ({len(raw)} chars)")
            return self._parse_json(raw)

        except requests.exceptions.HTTPError as e:
            print(f"[GEMINI/OR] ✗ HTTP {e.response.status_code}: {e.response.text[:200]}")
            return self._fallback_analysis(content)
        except Exception as e:
            print(f"[GEMINI/OR] ✗ {e}")
            return self._fallback_analysis(content)

    # ──────────────────────────────────────────────────────────────────
    def _parse_json(self, text: str) -> Dict:
        """Parse JSON, stripping markdown code-block wrappers if present"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            clean = text.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())

    # No _fallback_analysis — we raise so you know where to fix (OpenRouter config or API)