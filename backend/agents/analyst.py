"""
analyst.py
GUARDIAN AI - ANALYST AGENT
Person B's Main Hub
HOUR 4-6: MITRE + WHOIS + OPENROUTER → Gemini
"""

import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

# Handle imports for both direct script execution and package import
try:
    from .gemini_analyzer import GeminiAnalyzer
    from .mitre_mapper import MITREMapper
    from .whois_checker import WHOISChecker
except (ImportError, ValueError):
    from gemini_analyzer import GeminiAnalyzer
    from mitre_mapper import MITREMapper
    from whois_checker import WHOISChecker


class AnalystAgent:
    """The Analyst Agent - Guardian AI's Deep Investigator"""

    def __init__(self, db=None):
        """Initialize Analyst Agent"""
        self.db = db

        # GeminiAnalyzer now routes exclusively through OpenRouter
        self.gemini = GeminiAnalyzer()
        self.whois = WHOISChecker()
        self.mitre_mapper = MITREMapper()

        print("[ANALYST] 🔍 Hour 4-6: Analyst with MITRE + WHOIS")
        print(f"[ANALYST] OpenRouter → Gemini: {'✓' if self.gemini.available else '✗'}")
        print(f"[ANALYST] MongoDB: {'✓' if db else '✗ (standalone mode)'}")

    async def analyze_threat(self, scout_data: Dict) -> Dict:
        """HOUR 4-6: Fuses OpenRouter AI with MITRE & WHOIS heuristics"""
        analysis_id = str(uuid.uuid4())

        print(f"\n[ANALYST] ========================================")
        print(f"[ANALYST] 🔍 Analysis {analysis_id[:8]}")
        print(f"[ANALYST] ========================================")

        url = scout_data.get('url', '')
        content = scout_data.get('content', '')
        print(f"[ANALYST] URL: {url}")

        # 1. Domain Heuristics (Local)
        domain = url.replace('http://', '').replace('https://', '').split('/')[0].replace('www.', '')
        whois_data = self.whois.check_domain(domain)
        print(f"[ANALYST] Domain age: {whois_data.get('domainAgeDays')} days")

        # 2. AI Analysis via OpenRouter → Gemini 2.0 Flash
        gemini_result = self.gemini.analyze_threat(content, url)

        # 3. MITRE Mapping
        tactics = gemini_result.get('manipulationTactics', [])
        mitre_techniques = self.mitre_mapper.map_tactics_to_mitre(tactics)
        print(f"[ANALYST] MITRE techniques: {len(mitre_techniques)}")

        # 4. Hybrid Risk Scoring
        base_risk = gemini_result.get('riskScore', 40)
        whois_suspicion = whois_data.get('suspicionScore', 0)

        # Weighted: 70% AI, 30% WHOIS
        combined_risk = int((base_risk * 0.7) + (whois_suspicion * 0.3))

        # 5. Scout Signal Penalties
        signals = scout_data.get('signals', {})
        if not signals.get('sslValid', True):
            combined_risk += 10
        if signals.get('hasPassword'):
            combined_risk += 5

        final_risk = min(combined_risk, 100)
        print(f"[ANALYST] Final risk: {final_risk}/100")
        print(f"[ANALYST] ========================================\n")

        return {
            "analysisId": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "domain": domain,
            "threatType": gemini_result.get('threatType', 'unknown'),
            "riskScore": final_risk,
            "confidence": gemini_result.get('confidence', 0.5),
            "mitreAttackTechniques": mitre_techniques,
            "manipulationTactics": tactics,
            "whoisData": whois_data,
            "explanation": gemini_result.get('explanation', ''),
            "nextSteps": self._generate_next_steps(final_risk),
        }

    def _generate_next_steps(self, risk_score: int) -> List[str]:
        if risk_score >= 70:
            return ["🛑 DO NOT enter any info", "Close page immediately"]
        elif risk_score >= 40:
            return ["⚠️ Proceed with caution", "Verify official channels"]
        return ["✅ Low risk detected"]
