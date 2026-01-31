"""
GUARDIAN AI - ANALYST AGENT
Person B's Main Hub

HOUR 1-2: Basic structure with mock data
"""

import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional


class AnalystAgent:
    """
    The Analyst Agent - Guardian AI's Deep Investigator
    
    ORCHESTRATOR CALLS:
        analyst = AnalystAgent(db)
        result = await analyst.analyze_threat(scout_data)
    """
    
    def __init__(self, db=None):
        """
        Initialize Analyst Agent
        
        Args:
            db: MongoDB database instance (provided by Orchestrator)
        """
        self.db = db
        print("[ANALYST] 🔍 Hour 1-2: Basic Analyst initialized")
        print(f"[ANALYST] MongoDB: {'✓' if db else '✗ (standalone mode)'}")
    
    async def analyze_threat(self, scout_data: Dict) -> Dict:
        """
        MAIN ENTRY POINT - Orchestrator calls this
        
        Input (from Scout via Orchestrator):
        {
            "url": "https://suspicious-site.com",
            "content": "page text",
            "scanType": "webpage",
            "signals": {
                "hasPassword": true,
                "urgencyWords": ["urgent"],
                "sslValid": false
            }
        }
        
        Output (to Orchestrator/Educator):
        {
            "analysisId": "uuid",
            "threatType": "phishing",
            "riskScore": 87,
            "confidence": 0.92,
            "evidence": [...],
            "explanation": "...",
            "nextSteps": [...]
        }
        """
        analysis_id = str(uuid.uuid4())
        
        print(f"\n[ANALYST] ========================================")
        print(f"[ANALYST] 🔍 Analysis {analysis_id[:8]}")
        print(f"[ANALYST] ========================================")
        
        # Extract Scout data
        url = scout_data.get('url', '')
        content = scout_data.get('content', '')
        scan_type = scout_data.get('scanType', 'webpage')
        signals = scout_data.get('signals', {})
        
        print(f"[ANALYST] URL: {url}")
        print(f"[ANALYST] Type: {scan_type}")
        
        # HOUR 1-2: Simple rule-based scoring
        risk_score = self._calculate_basic_risk(content, signals)
        evidence = self._extract_basic_evidence(signals)
        next_steps = self._generate_next_steps(risk_score)
        
        # Determine threat type
        if risk_score >= 70:
            threat_type = "phishing"
        elif risk_score >= 40:
            threat_type = "scam"
        else:
            threat_type = "benign"
        
        print(f"[ANALYST] Risk: {risk_score}/100")
        print(f"[ANALYST] Type: {threat_type}")
        print(f"[ANALYST] ========================================\n")
        
        return {
            "analysisId": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "threatType": threat_type,
            "riskScore": risk_score,
            "confidence": 0.7,
            "evidence": evidence,
            "explanation": f"Detected as {threat_type} using rule-based analysis.",
            "nextSteps": next_steps,
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

async def test_hour_1_2():
    """Test Hour 1-2: Basic analyst"""
    print("="*60)
    print("🧪 TESTING HOUR 1-2: Basic Analyst")
    print("="*60)
    
    # Mock scout data
    scout_data = {
        "url": "https://paypa1-security.com/verify",
        "content": "URGENT: Verify your account!",
        "scanType": "webpage",
        "signals": {
            "hasPassword": True,
            "urgencyWords": ["urgent", "verify"],
            "sslValid": False
        }
    }
    
    # Create analyst (no DB yet)
    analyst = AnalystAgent(db=None)
    
    # Run analysis
    result = await analyst.analyze_threat(scout_data)
    
    # Display
    print("\n" + "="*60)
    print("📊 RESULTS")
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
    print("✅ HOUR 1-2 COMPLETE!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_hour_1_2())