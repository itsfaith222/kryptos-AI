"""
Scout Agent - Guardian AI's First Line of Defense
Provides real-time analysis of emails, screenshots, and web pages
"""

import os
import re
import json
import sys
from typing import Optional, Dict, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contracts import ScanInput, ScoutOutput, ScoutSignals, ScanType

# Initialize Gemini (if available)
try:
    import google.generativeai as genai
    genai.configure(api_key=os.getenv('GEMINI_API_KEY', ''))
    GEMINI_AVAILABLE = True
except Exception as e:
    print(f"Warning: Gemini API not configured: {e}")
    GEMINI_AVAILABLE = False


class ScoutAgent:
    """Scout agent for analyzing potential threats"""
    
    def __init__(self):
        self.phishing_keywords = {
            "urgency": ["urgent", "immediate", "verify", "suspended", "expires", "limited time", "act now", "confirm", "update", "click here", "re-confirm"],
            "credentials": ["password", "login", "credentials", "verify account", "confirm identity", "authenticate"],
            "financial": ["wire transfer", "credit card", "bank account", "payment", "refund", "billing"],
            "company_spoofing": ["amazon", "apple", "google", "microsoft", "paypal", "bank of america", "wells fargo"]
        }
        
        self.suspicious_file_types = [".exe", ".scr", ".vbs", ".bat", ".com", ".pif", ".zip", ".rar"]
    
    async def analyze(self, input_data: ScanInput) -> ScoutOutput:
        """
        Main entry point for Scout analysis
        
        Args:
            input_data: ScanInput with url, scanType, and content
            
        Returns:
            ScoutOutput with risk score and recommendations
        """
        
        signals = ScoutSignals()
        
        # Route to appropriate analysis based on scan type
        if input_data.scanType == ScanType.MESSAGE:
            signals = await self.analyze_message_text(input_data.content)
        elif input_data.scanType == ScanType.IMAGE:
            signals = await self.analyze_image(input_data.image_data)
        elif input_data.scanType == ScanType.PAGE:
            signals = await self.extract_page_signals(input_data.url, input_data.page_data)
        
        # Calculate initial risk score
        initial_risk = self.calculate_initial_risk(signals)
        
        # Determine recommendation
        recommendation = self.get_recommendation(initial_risk, signals)
        
        # Get predictive warning (mock for now)
        predictive_warning = await self.get_predictive_warnings({})
        
        return ScoutOutput(
            scanType=input_data.scanType,
            initialRisk=initial_risk,
            signals=signals,
            recommendation=recommendation,
            predictiveWarning=predictive_warning
        )
    
    async def analyze_message_text(self, text: str) -> ScoutSignals:
        """
        Analyze pasted message text for scam indicators
        
        Args:
            text: The message text to analyze
            
        Returns:
            ScoutSignals with detected patterns
        """
        signals = ScoutSignals()
        
        if not text:
            return signals
        
        text_lower = text.lower()
        
        # Detect urgency words
        signals.urgencyWords = [
            word for word in self.phishing_keywords["urgency"]
            if word in text_lower
        ]
        
        # Detect credential requests
        for cred_word in self.phishing_keywords["credentials"]:
            if cred_word in text_lower:
                signals.hasPassword = True
                break
        
        # Detect email patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        signals.hasEmail = bool(re.search(email_pattern, text))
        
        # Detect company spoofing attempts
        for company in self.phishing_keywords["company_spoofing"]:
            if company in text_lower:
                # Check if it's slightly misspelled
                if self._is_typosquatted(text_lower, company):
                    signals.suspiciousPatterns.append(f"Possible {company} spoofing")
        
        # Detect too-good-to-be-true offers
        if any(phrase in text_lower for phrase in ["claim prize", "won", "congratulations", "inherited"]):
            signals.suspiciousPatterns.append("Too-good-to-be-true offer detected")
        
        # Detect fake attachments mentioned
        for file_ext in self.suspicious_file_types:
            if file_ext in text_lower:
                signals.suspiciousPatterns.append(f"Suspicious file type: {file_ext}")
        
        return signals
    
    async def analyze_image(self, image_data: str) -> ScoutSignals:
        """
        Analyze screenshot using Gemini Vision API
        
        Args:
            image_data: Base64 encoded image data
            
        Returns:
            ScoutSignals with detected visual elements
        """
        signals = ScoutSignals()
        
        if not image_data or not GEMINI_AVAILABLE:
            return signals
        
        try:
            import base64
            
            # Initialize Gemini Vision model
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            # Decode base64
            image_bytes = base64.b64decode(image_data)
            
            # Create prompt for scam detection
            prompt = """
            Analyze this image for potential scams or phishing attempts.
            
            Look for:
            1. Company logos (check if they look legitimate or fake)
            2. Urgency language or threats
            3. Requests for personal information (SSN, credit card, etc)
            4. Suspicious URLs or phone numbers
            5. Poor quality graphics, spelling errors, or misaligned elements
            
            Extract any visible text from the image.
            
            Respond with JSON:
            {
              "hasLogo": true/false,
              "logoQuality": "high/medium/low",
              "suspiciousElements": ["list", "of", "red", "flags"],
              "extractedText": "up to 500 chars of text from image",
              "overallAssessment": "legitimate/suspicious/scam"
            }
            """
            
            # Generate analysis
            response = model.generate_content(
                [prompt, {"mime_type": "image/png", "data": image_bytes}]
            )
            
            # Parse response
            result = json.loads(response.text)
            
            signals.hasLogo = result.get("hasLogo", False)
            signals.logoQuality = result.get("logoQuality", "high")
            signals.suspiciousImages = result.get("overallAssessment") != "legitimate"
            signals.extractedText = result.get("extractedText", "")[:500]
            signals.suspiciousPatterns = result.get("suspiciousElements", [])
            
        except Exception as e:
            print(f"Error analyzing image with Gemini: {e}")
            # Return conservative signals on error
            signals.suspiciousImages = True
            signals.logoQuality = "low"
        
        return signals
    
    async def extract_page_signals(self, url: str, page_data: Optional[Dict] = None) -> ScoutSignals:
        """
        Extract signals from web page
        
        Args:
            url: The page URL
            page_data: DOM signals from content script
            
        Returns:
            ScoutSignals from page analysis
        """
        signals = ScoutSignals()
        
        if not url:
            return signals
        
        # Parse domain
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            signals.domain = parsed.netloc
            signals.hasHTTPS = parsed.scheme == 'https'
        except:
            signals.domain = url.split('/')[2] if '/' in url else url
            signals.hasHTTPS = url.startswith('https')
        
        # Use page_data if provided (from content script)
        if page_data:
            signals.hasPassword = page_data.get("hasPassword", False)
            signals.hasEmail = page_data.get("hasEmail", False)
            signals.formCount = page_data.get("formCount", 0)
            signals.externalLinks = page_data.get("externalLinks", 0)
            signals.isPrivacyPolicy = page_data.get("isPrivacyPolicy", False)
        
        # Check for domain spoofing (typosquatting)
        for company in self.phishing_keywords["company_spoofing"]:
            if company in signals.domain.lower():
                if self._is_typosquatted(signals.domain.lower(), company):
                    signals.suspiciousPatterns.append(f"Possible {company} domain spoofing")
        
        return signals
    
    def calculate_initial_risk(self, signals: ScoutSignals) -> int:
        """
        Calculate 0-100 risk score from signals
        
        Args:
            signals: ScoutSignals extracted from input
            
        Returns:
            Risk score 0-100
        """
        risk = 0
        
        # Message signals
        risk += len(signals.urgencyWords) * 10  # Each urgency word adds 10 points
        
        if signals.hasPassword:
            risk += 25  # Credential request is suspicious
        
        if signals.hasEmail:
            risk += 10  # Email in suspicious message
        
        risk += len(signals.suspiciousPatterns) * 15  # Each suspicious pattern
        
        # Image signals
        if signals.suspiciousImages:
            risk += 40  # Visual scam indicators are strong signal
        
        if signals.logoQuality == "low":
            risk += 20
        elif signals.logoQuality == "medium":
            risk += 10
        
        # Page signals
        if signals.hasPassword and not signals.hasHTTPS:
            risk += 30  # Password field on non-HTTPS is very dangerous
        
        if signals.formCount > 3 and not signals.hasHTTPS:
            risk += 20  # Many forms on non-HTTPS site
        
        if signals.isPrivacyPolicy:
            risk -= 10  # Privacy policy pages are generally safe
            risk = max(0, risk)  # Don't go negative
        
        # Cap at 100
        return min(risk, 100)
    
    def get_recommendation(self, risk_score: int, signals: ScoutSignals) -> str:
        """
        Determine recommendation based on risk score and signals
        
        Args:
            risk_score: Calculated risk score 0-100
            signals: Detected signals
            
        Returns:
            Recommendation string
        """
        if risk_score > 70:
            return "BLOCK_IMMEDIATELY"
        elif risk_score > 40:
            return "ESCALATE_TO_ANALYST"
        elif risk_score > 20:
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


# Create singleton instance
scout = ScoutAgent()


# ============= ASYNC WRAPPER FOR TESTING =============

async def main():
    """Test the scout agent with sample inputs"""
    
    # Test 1: Phishing message
    print("Test 1: Phishing Message Analysis")
    print("=" * 50)
    
    phishing_msg = "URGENT: Your PayPal account has been suspended! Click here immediately to verify your account or it will be closed. Confirm your password now!"
    
    input1 = ScanInput(
        url="",
        scanType=ScanType.MESSAGE,
        content=phishing_msg
    )
    
    result1 = await scout.analyze(input1)
    print(f"Risk Score: {result1.initialRisk}/100")
    print(f"Recommendation: {result1.recommendation}")
    print(f"Signals: {result1.signals.dict()}")
    print(f"Predictive Warning: {result1.predictiveWarning}")
    print()
    
    # Test 2: Legitimate page
    print("Test 2: Legitimate Page Analysis")
    print("=" * 50)
    
    input2 = ScanInput(
        url="https://www.paypal.com/login",
        scanType=ScanType.PAGE,
        page_data={
            "hasPassword": True,
            "hasEmail": True,
            "formCount": 1,
            "externalLinks": 5,
            "isPrivacyPolicy": False
        }
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
        scanType=ScanType.PAGE,
        page_data={
            "hasPassword": True,
            "hasEmail": True,
            "formCount": 1,
            "externalLinks": 20,
            "isPrivacyPolicy": False
        }
    )
    
    result3 = await scout.analyze(input3)
    print(f"Risk Score: {result3.initialRisk}/100")
    print(f"Recommendation: {result3.recommendation}")
    print(f"Signals: {result3.signals.dict()}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
