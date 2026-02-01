"""
analyst.py
Kryptos-AI - ANALYST AGENT (Hour 6-12 Enhanced)
Person B's Main Hub
"""

import os
import uuid
from datetime import datetime
from typing import Dict, List

# Handle imports for both direct script execution and package import
try:
    from .gemini_analyzer import GeminiAnalyzer
    from .mitre_mapper import MITREMapper
    from .whois_checker import WHOISChecker
except ImportError:
    from gemini_analyzer import GeminiAnalyzer
    from mitre_mapper import MITREMapper
    from whois_checker import WHOISChecker

try:
    from ..contracts import ScoutOutput, AnalystOutput
except ImportError:
    from contracts import ScoutOutput, AnalystOutput


class AnalystAgent:
    """The Analyst Agent - Kryptos-AI's Deep Investigator"""

    def __init__(self, db=None):
        """Initialize Analyst Agent with all sub-modules"""
        self.db = db
        self.gemini = GeminiAnalyzer()
        self.whois = WHOISChecker()
        self.mitre_mapper = MITREMapper()

        print("[ANALYST] 🔍 Hour 6-12: Enhanced Analyst Agent")
        print(f"[ANALYST] OpenRouter → Gemini: {'✓' if self.gemini.available else '✗'}")
        print(f"[ANALYST] WHOIS Checker: ✓")
        print(f"[ANALYST] MITRE Mapper: ✓ ({len(MITREMapper.TECHNIQUE_DB)} techniques)")

    async def analyze_threat(self, scout_data: Dict) -> Dict:
        """
        HOUR 6-12: Enhanced threat analysis
        Returns dict that investigate() converts to AnalystOutput
        """
        analysis_id = str(uuid.uuid4())

        print(f"\n[ANALYST] ========================================")
        print(f"[ANALYST] 🔍 Analysis {analysis_id[:8]}")
        print(f"[ANALYST] ========================================")

        url = scout_data.get('url', '')
        content = scout_data.get('content', '')
        scan_type = scout_data.get('scanType', 'page')
        signals = scout_data.get('signals', {})

        print(f"[ANALYST] URL: {url}")
        print(f"[ANALYST] Scan Type: {scan_type}")

        # Extract domain
        domain = self._extract_domain(url)

        # 1. WHOIS Domain Investigation
        whois_data = self.whois.check_domain(domain)
        print(f"[ANALYST] Domain: {domain}")
        print(f"[ANALYST] Domain age: {whois_data.get('domainAgeDays', -1)} days")

        # 2. Check if this is a privacy policy
        is_privacy_policy = self._detect_privacy_policy(content, url, scan_type)
        privacy_analysis = None
        
        if is_privacy_policy:
            print(f"[ANALYST] 📜 Privacy policy detected - analyzing...")
            privacy_analysis = self.gemini.analyze_privacy_policy(content)
            print(f"[ANALYST] Privacy score: {privacy_analysis.get('privacyScore', 50)}/100")

        # 3. AI Threat Analysis
        gemini_result = self.gemini.analyze_threat(content, url)
        print(f"[ANALYST] AI threat type: {gemini_result.get('threatType', 'unknown')}")

        # 4. Enhanced MITRE Mapping
        tactics = gemini_result.get('manipulationTactics', [])
        mitre_techniques = self.mitre_mapper.map_tactics_to_mitre(tactics)
        content_mitre = self.mitre_mapper.analyze_content_patterns(content)
        mitre_techniques = self._merge_mitre_techniques(mitre_techniques, content_mitre)
        print(f"[ANALYST] MITRE techniques: {len(mitre_techniques)}")

        # 5. Calculate Final Risk Score with Evidence Weighting
        final_risk, confidence = self._calculate_weighted_risk(
            base_risk=gemini_result.get('riskScore', 40),
            whois_data=whois_data,
            signals=signals,
            privacy_analysis=privacy_analysis
        )

        # 6. Determine threat type
        threat_type = self._determine_threat_type(
            gemini_result.get('threatType', 'unknown'),
            privacy_analysis,
            final_risk
        )

        print(f"[ANALYST] Final risk: {final_risk}/100 (confidence: {confidence:.2f})")
        print(f"[ANALYST] Threat type: {threat_type}")
        print(f"[ANALYST] ========================================\n")

        return {
            "analysisId": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "domain": domain,
            "threatType": threat_type,
            "riskScore": final_risk,
            "confidence": confidence,
            "mitreAttackTechniques": mitre_techniques,
            "manipulationTactics": tactics,
            "whoisData": whois_data,
            "privacyAnalysis": privacy_analysis,
            "geminiEvidence": gemini_result.get('evidence', []),
            "explanation": gemini_result.get('explanation', ''),
        }

    def _extract_domain(self, url: str) -> str:
        """Extract clean domain from URL"""
        if not url:
            return ""
        domain = url.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0].replace('www.', '')
        return domain.lower()

    def _detect_privacy_policy(self, content: str, url: str, scan_type: str) -> bool:
        """Detect if content is a privacy policy"""
        if scan_type == "privacy_policy":
            return True
        
        url_lower = (url or "").lower()
        content_lower = (content or "").lower()[:2000]
        
        privacy_url_patterns = ['/privacy', '/terms', '/tos', '/legal', '/policy']
        privacy_content_patterns = [
            'privacy policy', 'terms of service', 'data collection',
            'personal information', 'we collect', 'third party', 'cookies'
        ]
        
        url_match = any(p in url_lower for p in privacy_url_patterns)
        content_matches = sum(1 for p in privacy_content_patterns if p in content_lower)
        
        return url_match or content_matches >= 3

    def _merge_mitre_techniques(self, list1: List[Dict], list2: List[Dict]) -> List[Dict]:
        """Merge MITRE technique lists, avoiding duplicates"""
        seen_ids = set()
        merged = []
        for tech in list1 + list2:
            tech_id = tech.get('id', '')
            if tech_id and tech_id not in seen_ids:
                seen_ids.add(tech_id)
                merged.append(tech)
        return merged

    def _calculate_weighted_risk(
        self, base_risk: int, whois_data: Dict, signals: Dict, privacy_analysis
    ) -> tuple:
        """Calculate final risk using evidence weighting"""
        
        # Base: 70% AI, 30% WHOIS
        whois_suspicion = whois_data.get('suspicionScore', 0)
        weighted_risk = (base_risk * 0.7) + (whois_suspicion * 0.3)

        # Signal penalties
        if not signals.get('sslValid', True):
            weighted_risk += 10
        if signals.get('hasPassword'):
            weighted_risk += 5
        if len(signals.get('urgencyWords', [])) > 2:
            weighted_risk += 5

        # Privacy policy penalty
        if privacy_analysis:
            privacy_score = privacy_analysis.get('privacyScore', 50)
            if privacy_score > 70:
                weighted_risk += 10

        final_risk = min(int(weighted_risk), 100)

        # Calculate confidence
        confidence = 0.6
        if whois_data.get('domainAgeDays', -1) >= 0:
            confidence += 0.15
        if privacy_analysis:
            confidence += 0.1
        confidence = min(round(confidence, 2), 0.95)

        return final_risk, confidence

    def _determine_threat_type(self, ai_threat_type: str, privacy_analysis, risk_score: int) -> str:
        """Determine final threat type. Returns only contract-allowed: phishing | scam | malware | privacy_violation."""
        if privacy_analysis and privacy_analysis.get('privacyScore', 0) > 70:
            return "privacy_violation"
        if ai_threat_type in ['phishing', 'scam', 'malware']:
            return ai_threat_type
        if ai_threat_type in ['social_engineering', 'suspicious']:
            return 'phishing'
        if risk_score > 70:
            return 'phishing'
        elif risk_score > 40:
            return 'phishing'  # suspicious band; riskScore differentiates severity
        return 'phishing'  # benign; low riskScore indicates low threat


# ==========================================
# ORCHESTRATOR API - DO NOT CHANGE SIGNATURE
# ==========================================
async def investigate(scout_result: ScoutOutput) -> AnalystOutput:
    """
    Entry point for orchestrator.
    DO NOT CHANGE THIS SIGNATURE - main.py depends on it.
    """
    # Build scout_data from ScoutOutput (same as before)
    scout_data = {
        "url": scout_result.signals.get("_url", ""),
        "content": scout_result.signals.get("_content", ""),
        "scanType": scout_result.scanType,
        "signals": scout_result.signals,
    }

    # Run analysis
    agent = AnalystAgent(db=None)
    result = await agent.analyze_threat(scout_data)

    # Build evidence list for AnalystOutput
    # CRITICAL: Evidence must have type, finding, severity
    # CRITICAL: finding text must contain keywords Educator looks for
    evidence: List[Dict] = []

    # WHOIS Evidence
    whois_data = result.get("whoisData") or {}
    if whois_data:
        age = whois_data.get("domainAgeDays", -1)
        domain_name = whois_data.get('domainName', '')
        
        if age >= 0 and age < 30:
            evidence.append({
                "type": "domain",
                "finding": f"Domain {domain_name} registered only {age} days ago - suspicious",
                "weight": 0.8,
                "severity": "high" if age < 7 else "medium",
            })
        elif age >= 0:
            evidence.append({
                "type": "domain",
                "finding": f"Domain {domain_name} is {age} days old",
                "weight": 0.3,
                "severity": "low",
            })
        
        if whois_data.get('privacyProtected'):
            evidence.append({
                "type": "domain",
                "finding": "Domain owner identity hidden behind privacy protection",
                "weight": 0.5,
                "severity": "medium",
            })

    # Manipulation Tactics Evidence
    for tactic in result.get("manipulationTactics", []):
        evidence.append({
            "type": "tactic",
            "finding": tactic.get("example", tactic.get("type", "manipulation")),
            "weight": 0.7,
            "severity": tactic.get("severity", "medium"),
        })

    # Gemini AI Evidence
    for item in result.get("geminiEvidence", []):
        evidence.append({
            "type": item.get('type', 'ai_analysis'),
            "finding": item.get('finding', ''),
            "weight": 0.6,
            "severity": item.get('severity', 'medium'),
        })

    # Privacy Analysis Evidence - FORMATTED FOR EDUCATOR
    # These keywords are what Educator's _bucket_privacy_evidence looks for
    privacy_analysis = result.get("privacyAnalysis")
    if privacy_analysis:
        # Data collected - use "collect" keyword
        data_collected = privacy_analysis.get('dataCollected', [])
        if data_collected:
            # Include keywords: location, contacts, browsing, history, track, camera, microphone
            finding = f"Collects sensitive data: {', '.join(data_collected[:5])}"
            evidence.append({
                "type": "privacy",
                "finding": finding,
                "weight": 0.8,
                "severity": "high",
            })

        # Third party sharing - use "share", "third", "advertis" keywords
        third_parties = privacy_analysis.get('thirdPartySharing', [])
        if third_parties:
            finding = f"Shares data with third parties: {', '.join(third_parties[:3])}"
            evidence.append({
                "type": "sharing",
                "finding": finding,
                "weight": 0.8,
                "severity": "high",
            })

        # Data deletion - use "cannot delete", "retain indefinitely" keywords
        if not privacy_analysis.get('canDelete', True):
            evidence.append({
                "type": "retention",
                "finding": "Cannot delete your data - retained indefinitely",
                "weight": 0.9,
                "severity": "critical",
            })

        # Red flags
        for flag in privacy_analysis.get('redFlags', [])[:3]:
            evidence.append({
                "type": "privacy",
                "finding": f"Privacy red flag: {flag}",
                "weight": 0.7,
                "severity": "high",
            })

    # MITRE techniques - convert to List[str] of IDs as contract requires
    mitre_list = result.get("mitreAttackTechniques", [])
    mitre_ids = [t.get("id", t) if isinstance(t, dict) else str(t) for t in mitre_list]

    # Return AnalystOutput - DO NOT CHANGE STRUCTURE
    return AnalystOutput(
        analysisId=result.get("analysisId", str(uuid.uuid4())),
        threatType=result.get("threatType", "phishing"),  # contract: phishing | scam | malware | privacy_violation
        riskScore=result.get("riskScore", 0),
        confidence=result.get("confidence", 0.5),
        evidence=evidence,
        mitreAttackTechniques=mitre_ids,
    )