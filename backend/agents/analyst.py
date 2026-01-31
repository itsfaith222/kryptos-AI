"""
GUARDIAN AI - ANALYST AGENT
Person B's Main Hub

HOUR 2-4: With Gemini AI
"""

import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

try:
    from .gemini_analyzer import GeminiAnalyzer
except ImportError:
    from gemini_analyzer import GeminiAnalyzer


class AnalystAgent:
    """The Analyst Agent - Guardian AI's Deep Investigator"""
    
    def __init__(self, db=None):
        """Initialize Analyst Agent"""
        self.db = db
        self.gemini = GeminiAnalyzer()  # MUST HAVE THIS LINE
        print("[ANALYST] 🔍 Hour 2-4: Analyst with Gemini AI")
        print(f"[ANALYST] Gemini: {'✓' if self.gemini.available else '✗'}")
        print(f"[ANALYST] MongoDB: {'✓' if db else '✗ (standalone mode)'}")
        
    async def analyze_threat(self, scout_data: Dict) -> Dict:
        analysis_id = str(uuid.uuid4())
        
        print(f"\n[ANALYST] ========================================")
        print(f"[ANALYST] 🔍 Analysis {analysis_id[:8]}")
        print(f"[ANALYST] ========================================")
        
        url = scout_data.get('url', '')
        content = scout_data.get('content', '')
        scan_type = scout_data.get('scanType', 'webpage')
        signals = scout_data.get('signals', {})
        
        print(f"[ANALYST] URL: {url}")
        print(f"[ANALYST] Using Gemini: {self.gemini.available}")
        
        # HOUR 2-4: Use Gemini AI
        gemini_result = self.gemini.analyze_threat(content, url)
        
        base_risk = gemini_result.get('riskScore', 50)
        
        # Add Scout signals to risk
        if signals.get('hasPassword'):
            base_risk += 10
        if not signals.get('sslValid', True):
            base_risk += 10
        
        final_risk = min(base_risk, 100)
        
        print(f"[ANALYST] Risk: {final_risk}/100")
        print(f"[ANALYST] Tactics: {len(gemini_result.get('manipulationTactics', []))}")
        print(f"[ANALYST] ========================================\n")
        
        return {
            "analysisId": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "threatType": gemini_result.get('threatType', 'unknown'),
            "riskScore": final_risk,
            "confidence": gemini_result.get('confidence', 0.5),
            "manipulationTactics": gemini_result.get('manipulationTactics', []),
            "evidence": gemini_result.get('evidence', []),
            "explanation": gemini_result.get('explanation', ''),
            "nextSteps": self._generate_next_steps(final_risk),
            "scanType": scan_type
        }
    
    def _calculate_basic_risk(self, content: str, signals: Dict) -> int:
        """Calculate risk score from Scout signals"""
        risk = 30  # Base risk
        
        # Check urgency words
        if signals.get('urgencyWords'):
            risk += 20
        
        # Check for password fields
        if signals.get('hasPassword'):
            risk += 25
        
        # Check SSL
        if not signals.get('sslValid', True):
            risk += 15
        
        return min(risk, 100)
    
    def _extract_basic_evidence(self, signals: Dict) -> List[Dict]:
        """Extract evidence from Scout signals"""
        evidence = []
        
        urgency_words = signals.get('urgencyWords', [])
        if urgency_words:
            evidence.append({
                "finding": f"Urgency language: {', '.join(urgency_words)}",
                "severity": "high",
                "weight": 0.7,
                "source": "scout"
            })
        
        if signals.get('hasPassword'):
            evidence.append({
                "finding": "Password field present",
                "severity": "critical",
                "weight": 0.9,
                "source": "scout"
            })
        
        if not signals.get('sslValid', True):
            evidence.append({
                "finding": "No valid SSL certificate",
                "severity": "high",
                "weight": 0.8,
                "source": "scout"
            })
        
        return evidence
    
    def _generate_next_steps(self, risk_score: int) -> List[str]:
        """Generate actionable recommendations"""
        if risk_score >= 70:
            return [
                "🛑 DO NOT enter any information",
                "Close this page immediately",
                "Report to phishing@antiphishing.org"
            ]
        elif risk_score >= 40:
            return [
                "⚠️ Proceed with caution",
                "Verify sender through official channels",
                "Do not enter sensitive information"
            ]
        else:
            return [
                "✅ Low risk detected",
                "Stay vigilant"
            ]


# ==========================================
# STANDALONE TESTING
# ==========================================

async def test_hour_2_4():
    """Test Hour 2-4: Gemini AI integration"""
    print("="*60)
    print("🧪 TESTING HOUR 2-4: Gemini AI")
    print("="*60)
    
    scout_data = {
        "url": "https://paypa1-security.com/verify",
        "content": """
        URGENT: Your PayPal Account Has Been Suspended
        
        We detected unusual activity. Click here within 24 hours
        or your account will be permanently closed.
        
        Enter your password to verify.
        """,
        "scanType": "email",
        "signals": {
            "hasPassword": True,
            "urgencyWords": ["urgent", "suspended"],
            "sslValid": False
        }
    }
    
    analyst = AnalystAgent(db=None)
    result = await analyst.analyze_threat(scout_data)
    
    print("\n" + "="*60)
    print("📊 RESULTS")
    print("="*60)
    print(f"Threat: {result['threatType']}")
    print(f"Risk: {result['riskScore']}/100")
    print(f"Confidence: {result['confidence']:.0%}")
    print(f"\nManipulation Tactics:")
    for tactic in result['manipulationTactics']:
        print(f"  • {tactic['type']}: {tactic['example']}")
    print("="*60)
    print("✅ HOUR 2-4 COMPLETE!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_hour_2_4())