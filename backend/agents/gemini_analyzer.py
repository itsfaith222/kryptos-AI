"""
Gemini AI Analyzer Helper - UPDATED FOR HOUR 6 (google-genai 1.0+)
"""
from typing import Dict
import os
import json

try:
    # UPDATED: The new library name
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class GeminiAnalyzer:
    """Uses the new Gemini 2.0 AI for threat analysis"""
    
    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = os.getenv('GEMINI_API_KEY')
        self.available = False
        
        if GEMINI_AVAILABLE and api_key:
            try:
                # UPDATED: New Client-based initialization
                self.client = genai.Client(api_key=api_key)
                # We use 2.0-flash as it is the fastest/most current for this library
                self.model_id = "gemini-2.0-flash" 
                self.available = True
                print(f"[GEMINI] ✓ Connected to {self.model_id}")
            except Exception as e:
                print(f"[GEMINI] ✗ Init failed: {e}")
        else:
            reason = "API key missing" if not api_key else "Library not installed"
            print(f"[GEMINI] ✗ Unavailable ({reason})")
    
    def analyze_threat(self, content: str, url: str = "") -> Dict:
        if not self.available:
            return self._fallback_analysis(content)
        
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
      "example": "exact quote",
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
        
        try:
            # UPDATED: New generation method
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt
            )
            return self._parse_json(response.text)
        except Exception as e:
            print(f"[GEMINI] Error: {e}")
            return self._fallback_analysis(content)
    
    def _parse_json(self, text: str) -> Dict:
        clean = text.strip()
        if clean.startswith('```json'):
            clean = clean.replace('```json', '').replace('```', '').strip()
        elif clean.startswith('```'):
            clean = clean.replace('```', '').strip()
        
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "riskScore": 50, "explanation": "AI returned invalid JSON"}

    def _fallback_analysis(self, content: str) -> Dict:
        # (Keep your existing fallback logic here)
        return {
            "threatType": "unknown",
            "riskScore": 40,
            "confidence": 0.6,
            "manipulationTactics": [],
            "evidence": [{"finding": "Fallback analysis (AI offline)", "severity": "medium", "source": "fallback"}],
            "explanation": "Gemini library is not yet connected correctly."
        }