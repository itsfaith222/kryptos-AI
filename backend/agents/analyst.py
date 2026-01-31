"""
Analyst Agent
MILESTONE 1: Basic rule-based analysis
"""

import uuid
from datetime import datetime
from typing import Dict, List


class AnalystAgent:
    """Basic analyst with rule-based threat detection"""
    
    def __init__(self, db=None):
        self.db = db
        print("[ANALYST] 🔍 Milestone 1: Basic Analyst initialized")
    
    async def analyze_threat(self, scout_data: Dict) -> Dict:
        analysis_id = str(uuid.uuid4())
        
        # Extract data
        url = scout_data.get('url', '')
        content = scout_data.get('content', '')
        signals = scout_data.get('signals', {})
        
        print(f"[ANALYST] Analyzing: {url}")
        
        # Rule-based scoring
        risk_score = 30  # Base risk
        evidence = []
        tactics = []
        
        # Check for urgency words
        urgency_words = signals.get('urgencyWords', [])
        if urgency_words:
            risk_score += 20
            tactics.append({
                "type": "urgency",
                "example": f"Detected words: {', '.join(urgency_words)}",
                "severity": "high"
            })
            evidence.append({
                "finding": f"Urgency language detected: {', '.join(urgency_words)}",
                "severity": "high",
                "source": "scout_signals"
            })
        
        # Check for password fields
        if signals.get('hasPassword'):
            risk_score += 25
            tactics.append({
                "type": "credential_request",
                "example": "Password field detected",
                "severity": "critical"
            })
            evidence.append({
                "finding": "Password field present on page",
                "severity": "critical",
                "source": "scout_signals"
            })
        
        # Check for SSL
        if not signals.get('sslValid', True):
            risk_score += 15
            evidence.append({
                "finding": "No valid SSL certificate",
                "severity": "high",
                "source": "scout_signals"
            })
        
        # Determine threat type
        if risk_score >= 70:
            threat_type = "phishing"
        elif risk_score >= 40:
            threat_type = "scam"
        else:
            threat_type = "benign"
        
        # Generate next steps
        next_steps = self._generate_next_steps(risk_score)
        
        print(f"[ANALYST] Risk: {risk_score}/100 | Type: {threat_type}")
        
        return {
            "analysisId": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "threatType": threat_type,
            "riskScore": risk_score,
            "confidence": 0.7,
            "manipulationTactics": tactics,
            "evidence": evidence,
            "explanation": f"Detected as {threat_type} using rule-based analysis.",
            "nextSteps": next_steps,
            "scanType": scout_data.get('scanType', 'webpage')
        }
    
    def _generate_next_steps(self, risk_score: int) -> List[str]:
        """Generate recommendations based on risk"""
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
                "Stay vigilant with any requests"
            ]


# Test function
async def test_milestone_1():
    """Test Milestone 1"""
    print("="*60)
    print("🧪 TESTING MILESTONE 1: Basic Analyst")
    print("="*60)
    
    # Mock scout data
    scout_data = {
        "url": "https://paypa1-security.com/verify",
        "content": "URGENT: Your account has been suspended!",
        "scanType": "webpage",
        "signals": {
            "hasPassword": True,
            "urgencyWords": ["urgent", "suspended"],
            "sslValid": False
        }
    }
    
    # Create analyst
    analyst = AnalystAgent(db=None)
    
    # Run analysis
    result = await analyst.analyze_threat(scout_data)
    
    # Display
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"Analysis ID: {result['analysisId'][:8]}...")
    print(f"Threat Type: {result['threatType']}")
    print(f"Risk Score: {result['riskScore']}/100")
    print(f"\nEvidence ({len(result['evidence'])} items):")
    for e in result['evidence']:
        print(f"  • [{e['severity']}] {e['finding']}")
    print(f"\nNext Steps:")
    for i, step in enumerate(result['nextSteps'], 1):
        print(f"  {i}. {step}")
    print("="*60)
    print("✅ MILESTONE 1 COMPLETE!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_milestone_1())