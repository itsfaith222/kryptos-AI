"""
Scout Agent - Guardian AI's First Line of Defense
Provides real-time analysis of emails, screenshots, and web pages.
Covers all threat types: phishing, scams, malware indicators, and privacy.
"""

import os
import re
import json
import sys
from typing import Optional, Dict, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contracts import ScanInput, ScoutOutput

# OpenRouter only (same key as Analyst/Educator) — used for image analysis
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "google/gemini-2.0-flash-001"


class ScoutAgent:
    """Scout agent for analyzing potential threats"""
    
    def __init__(self):
        self.phishing_keywords = {
            "urgency": ["urgent", "immediate", "verify", "suspended", "expires", "limited time", "act now", "confirm", "update", "click here", "re-confirm"],
            "credentials": ["password", "login", "credentials", "verify account", "confirm identity", "authenticate"],
            "financial": ["wire transfer", "credit card", "bank account", "payment", "refund", "billing"],
            "company_spoofing": ["amazon", "apple", "google", "microsoft", "paypal", "bank of america", "wells fargo"]
        }
        
        # Only detect actual executable file types, not .com domains
        self.suspicious_file_types = [".exe", ".scr", ".vbs", ".bat", ".pif", ".zip", ".rar"]
    
    async def analyze(self, input_data: ScanInput) -> ScoutOutput:
        """
        Main entry point for Scout analysis
        
        Args:
            input_data: ScanInput with url, scanType, and content
            
        Returns:
            ScoutOutput with risk score and recommendations
        """
        
        signals = {}
        
        # Route to appropriate analysis based on scan type
        if input_data.scanType == "message":
            signals = await self.analyze_message_text(input_data.content)
        elif input_data.scanType == "image":
            signals = await self.analyze_image(input_data.image_data)
        elif input_data.scanType == "page":
            signals = await self.extract_page_signals(input_data.url)
        
        # Calculate initial risk score
        initial_risk = self.calculate_initial_risk(signals)
        
        # Determine recommendation
        recommendation = self.get_recommendation(initial_risk, signals)
        
        # Get predictive warning (mock for now)
        predictive_warning = await self.get_predictive_warnings({})
        
        # Pass url/content in signals so Analyst can use them (integration contract)
        signals["_url"] = input_data.url or ""
        signals["_content"] = input_data.content or ""
        
        return ScoutOutput(
            scanType=input_data.scanType,
            initialRisk=initial_risk,
            signals=signals,
            recommendation=recommendation,
            predictiveWarning=predictive_warning
        )
    
    async def analyze_message_text(self, text: str) -> Dict:
        """
        Analyze pasted message text for scam indicators
        
        Args:
            text: The message text to analyze
            
        Returns:
            Signals dict with detected patterns
        """
        signals = {
            "urgencyWords": [],
            "hasPassword": False,
            "hasEmail": False,
            "suspiciousPatterns": [],
            "source": "message"
        }
        
        if not text:
            return signals
        
        text_lower = text.lower()
        
        # Detect urgency words
        signals["urgencyWords"] = [
            word for word in self.phishing_keywords["urgency"]
            if word in text_lower
        ]
        
        # Detect credential requests
        for cred_word in self.phishing_keywords["credentials"]:
            if cred_word in text_lower:
                signals["hasPassword"] = True
                break
        
        # Detect email patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        signals["hasEmail"] = bool(re.search(email_pattern, text))
        
        # Detect company spoofing attempts
        for company in self.phishing_keywords["company_spoofing"]:
            if company in text_lower:
                # Check if it's slightly misspelled
                if self._is_typosquatted(text_lower, company):
                    signals["suspiciousPatterns"].append(f"Possible {company} spoofing")
        
        # Detect too-good-to-be-true offers
        if any(phrase in text_lower for phrase in ["claim prize", "won", "congratulations", "inherited"]):
            signals["suspiciousPatterns"].append("Too-good-to-be-true offer detected")
        
        # Detect fake attachments mentioned
        for file_ext in self.suspicious_file_types:
            if file_ext in text_lower:
                signals["suspiciousPatterns"].append(f"Suspicious file type: {file_ext}")
        
        return signals
    
    async def analyze_image(self, image_data: str) -> Dict:
        """
        Analyze screenshot using OpenRouter (vision-capable model). No fallback — raise if not configured or API fails.
        """
        import base64
        import requests as req

        signals = {
            "hasLogo": False,
            "logoQuality": "high",
            "suspiciousImages": False,
            "extractedText": "",
            "suspiciousPatterns": [],
            "source": "image"
        }

        if not image_data:
            return signals

        if not OPENROUTER_API_KEY:
            raise ValueError("Scout image: OpenRouter not configured — set OPENROUTER_API_KEY in .env")

        prompt = """Analyze this image for potential scams or phishing attempts.
Look for: company logos (legitimate or fake), urgency language, requests for personal info, suspicious URLs/phone numbers, poor quality or spelling errors.
Extract any visible text. Respond with JSON only:
{"hasLogo": true/false, "logoQuality": "high/medium/low", "suspiciousElements": [], "extractedText": "up to 500 chars", "overallAssessment": "legitimate/suspicious/scam"}"""

        # OpenRouter vision: image in content as image_url (data URL)
        url = f"data:image/png;base64,{image_data}" if "base64," not in image_data[:20] else image_data
        content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": image_url}}
        ]

        try:
            resp = req.post(
                OPENROUTER_URL,
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"},
                json={"model": OPENROUTER_MODEL, "messages": [{"role": "user", "content": content}]},
                timeout=45,
            )
            resp.raise_for_status()
            raw = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
            if not raw:
                raise RuntimeError("Scout image: not generating — OpenRouter returned empty")
            result = json.loads(raw.strip())
            signals["hasLogo"] = result.get("hasLogo", False)
            signals["logoQuality"] = result.get("logoQuality", "high")
            signals["suspiciousImages"] = result.get("overallAssessment") != "legitimate"
            signals["extractedText"] = (result.get("extractedText") or "")[:500]
            signals["suspiciousPatterns"] = result.get("suspiciousElements", [])
        except req.exceptions.RequestException as e:
            print(f"Scout image: OpenRouter request failed: {e}")
            raise RuntimeError("Scout image: not generating — OpenRouter request failed") from e
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Scout image: parse error: {e}")
            raise RuntimeError("Scout image: not generating — invalid response format") from e

        return signals
    
    async def extract_page_signals(self, url: str) -> Dict:
        """
        Extract signals from web page
        
        Args:
            url: The page URL
            
        Returns:
            Signals dict from page analysis
        """
        signals = {
            "domain": None,
            "hasHTTPS": False,
            "suspiciousPatterns": [],
            "source": "page"
        }
        
        if not url:
            return signals
        
        # Parse domain
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            signals["domain"] = parsed.netloc
            signals["hasHTTPS"] = parsed.scheme == 'https'
        except:
            signals["domain"] = url.split('/')[2] if '/' in url else url
            signals["hasHTTPS"] = url.startswith('https')
        
        # Check for domain spoofing (typosquatting)
        for company in self.phishing_keywords["company_spoofing"]:
            if company in signals["domain"].lower():
                if self._is_typosquatted(signals["domain"].lower(), company):
                    signals["suspiciousPatterns"].append(f"Possible {company} domain spoofing")
        
        return signals
    
    def calculate_initial_risk(self, signals: Dict) -> int:
        """
        Calculate 0-100 risk score from signals
        
        Args:
            signals: Signals dict extracted from input
            
        Returns:
            Risk score 0-100
        """
        risk = 0
        
        # Message signals
        risk += len(signals.get("urgencyWords", [])) * 10  # Each urgency word adds 10 points
        
        if signals.get("hasPassword"):
            risk += 25  # Credential request is suspicious
        
        if signals.get("hasEmail"):
            risk += 10  # Email in suspicious message
        
        risk += len(signals.get("suspiciousPatterns", [])) * 15  # Each suspicious pattern
        
        # Image signals
        if signals.get("suspiciousImages"):
            risk += 40  # Visual scam indicators are strong signal
        
        logo_quality = signals.get("logoQuality", "high")
        if logo_quality == "low":
            risk += 20
        elif logo_quality == "medium":
            risk += 10
        
        # Cap at 100
        return min(risk, 100)
    
    def get_recommendation(self, risk_score: int, signals: Dict) -> str:
        """
        Determine recommendation based on risk score and signals
        
        Args:
            risk_score: Calculated risk score 0-100
            signals: Detected signals
            
        Returns:
            Recommendation string
        """
        if risk_score > 70:
            return "BLOCK"
        elif risk_score > 30:
            return "ESCALATE_TO_ANALYST"
        else:
            return "SAFE"
    
    async def get_predictive_warnings(self, user_context: Dict) -> Optional[str]:
        """
        Get predictive warnings based on trending threats
        
        Args:
            user_context: User location/context (for future MongoDB integration)
            
        Returns:
            Predictive warning message or None
        """
        # This will query MongoDB in the final implementation
        # For now, return mock warning
        try:
            # Mock trending threats
            import random
            threats = [
                "Fake Netflix billing scams trending this week",
                "Amazon package delivery scams up 150%",
                "Tax refund phishing campaigns detected",
                "Tech support scams targeting your OS",
                "Fake PayPal invoice scams spreading"
            ]
            
            return random.choice(threats) if random.random() > 0.3 else None
        except:
            return None
    
    def _is_typosquatted(self, text: str, company: str) -> bool:
        """
        Detect if company name is slightly misspelled (typosquatting)
        
        Args:
            text: Text to check
            company: Company name to look for
            
        Returns:
            True if likely typosquatted version found
        """
        # Common typosquatting patterns
        typo_patterns = [
            company.replace('a', '4').replace('e', '3').replace('o', '0'),
            company.replace('l', '1'),
            company.replace('i', '1'),
            company[:-1],  # Missing last letter
            company + 's',  # Extra s
        ]
        
        for pattern in typo_patterns:
            if pattern in text and pattern != company:
                return True
        
        return False


def compute_risk_from_signal(
    url: str,
    is_login: bool,
    has_privacy_policy: bool,
    detected_keywords: List[str],
    detected_scam: Optional[List[str]] = None,
    detected_malware: Optional[List[str]] = None,
) -> Dict:
    """
    Compute risk_score from extension SCOUT_SIGNAL payload.
    Covers phishing, scams, malware indicators, and privacy. Used by POST /api/scout/scan.
    Login on unknown/suspicious domain = high risk.
    """
    risk = 0
    detected_scam = detected_scam or []
    detected_malware = detected_malware or []
    metadata = {
        "isLogin": is_login,
        "hasPrivacyPolicy": has_privacy_policy,
        "detectedKeywords": detected_keywords or [],
        "detectedScam": detected_scam,
        "detectedMalware": detected_malware,
    }

    # Phishing/urgency keywords
    risk += min(len(detected_keywords or []) * 10, 45)
    # Scam keywords (prize, inheritance, tech support, refund, crypto, etc.)
    risk += min(len(detected_scam) * 14, 45)
    # Malware / suspicious download cues
    risk += min(len(detected_malware) * 18, 50)

    # Login page: high risk if URL looks non-trusted (no https or odd domain)
    if is_login:
        url_lower = (url or "").lower()
        has_https = url_lower.startswith("https://")
        # Known high-trust patterns (simplified)
        trusted = any(
            x in url_lower
            for x in [
                "google.com",
                "apple.com",
                "microsoft.com",
                "github.com",
                "paypal.com",
                "amazon.com",
                "facebook.com",
                "twitter.com",
                "linkedin.com",
            ]
        )
        if not has_https:
            risk += 50
        elif not trusted:
            risk += 35
        else:
            risk += 10

    # Privacy policy present: informational only (blue badge), small risk bump
    if has_privacy_policy:
        risk += 5

    risk_score = min(risk, 100)
    return {"risk_score": risk_score, "metadata": metadata}


# Create singleton instance
scout = ScoutAgent()


# ============= ORCHESTRATOR API (main.py calls this) =============
async def analyze(input_data: ScanInput) -> ScoutOutput:
    """Entry point for orchestrator: Scout analyzes input and returns ScoutOutput."""
    return await scout.analyze(input_data)


# ============= ASYNC WRAPPER FOR TESTING =============

async def main():
    """Test the scout agent with sample inputs"""
    
    # Test 1: Phishing message
    print("Test 1: Phishing Message Analysis")
    print("=" * 50)
    
    phishing_msg = "URGENT: Your PayPal account has been suspended! Click here immediately to verify your account or it will be closed. Confirm your password now!"
    
    input1 = ScanInput(
        url="",
        scanType="message",
        content=phishing_msg
    )
    
    result1 = await scout.analyze(input1)
    print(f"Risk Score: {result1.initialRisk}/100")
    print(f"Recommendation: {result1.recommendation}")
    print(f"Signals: {result1.signals}")
    print(f"Predictive Warning: {result1.predictiveWarning}")
    print()
    
    # Test 2: Legitimate page
    print("Test 2: Legitimate Page Analysis")
    print("=" * 50)
    
    input2 = ScanInput(
        url="https://www.paypal.com/login",
        scanType="page"
    )
    
    result2 = await scout.analyze(input2)
    print(f"Risk Score: {result2.initialRisk}/100")
    print(f"Recommendation: {result2.recommendation}")
    print()
    
    # Test 3: Typosquatting domain
    print("Test 3: Typosquatting Domain Analysis")
    print("=" * 50)
    
    input3 = ScanInput(
        url="https://paypa1-security.com/verify",
        scanType="page"
    )
    
    result3 = await scout.analyze(input3)
    print(f"Risk Score: {result3.initialRisk}/100")
    print(f"Recommendation: {result3.recommendation}")
    print(f"Signals: {result3.signals}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
