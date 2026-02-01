"""
mitre_mapper.py
Kryptos-AI - MITRE ATT&CK Framework Mapper (Hour 6-12 Enhanced)
Expanded technique database
"""

from typing import Dict, List
import re


class MITREMapper:
    """Enhanced MITRE ATT&CK mapper"""

    # Expanded MITRE ATT&CK Technique Database
    TECHNIQUE_DB = {
        "T1566": {"name": "Phishing", "severity": "critical"},
        "T1566.001": {"name": "Phishing: Spearphishing Attachment", "severity": "critical"},
        "T1566.002": {"name": "Phishing: Spearphishing Link", "severity": "critical"},
        "T1566.003": {"name": "Phishing: Spearphishing via Service", "severity": "high"},
        "T1056.003": {"name": "Input Capture: Web Portal Capture", "severity": "critical"},
        "T1598": {"name": "Phishing for Information", "severity": "critical"},
        "T1598.003": {"name": "Phishing for Information: Spearphishing Link", "severity": "critical"},
        "T1534": {"name": "Internal Spearphishing", "severity": "critical"},
        "T1204.001": {"name": "User Execution: Malicious Link", "severity": "high"},
        "T1204.002": {"name": "User Execution: Malicious File", "severity": "critical"},
        "T1657": {"name": "Financial Theft", "severity": "critical"},
        "T1589.001": {"name": "Gather Victim Identity: Credentials", "severity": "critical"},
    }

    # Tactic to MITRE mapping
    TACTIC_TO_MITRE = {
        "urgency": ["T1566.002", "T1534", "T1598.003"],
        "fear": ["T1534", "T1566.002", "T1598"],
        "authority": ["T1598.003", "T1534", "T1566.003"],
        "scarcity": ["T1566.001", "T1204.001"],
        "social_proof": ["T1204.002", "T1566.002"],
        "credential_request": ["T1056.003", "T1598.003", "T1589.001"],
        "financial_request": ["T1657", "T1566.002"],
    }

    # Content patterns for automatic detection
    CONTENT_PATTERNS = {
        r"(password|credential|login|sign.?in)": ["T1056.003", "T1598.003"],
        r"(wire.?transfer|payment|bitcoin|crypto)": ["T1657"],
        r"(urgent|immediate|act.?now|expires)": ["T1566.002", "T1534"],
        r"(suspended|locked|disabled)": ["T1566.002", "T1598"],
        r"(click.?here|download|\.exe|\.zip)": ["T1204.001", "T1204.002"],
        r"(verify|confirm).*(account|identity)": ["T1598.003", "T1056.003"],
    }

    @classmethod
    def map_tactics_to_mitre(cls, tactics: List[Dict]) -> List[Dict]:
        """Convert manipulation tactics to MITRE techniques"""
        detected = {}

        for tactic in tactics:
            tactic_type = tactic.get('type', '').lower().replace(' ', '_')
            
            if tactic_type in cls.TACTIC_TO_MITRE:
                for mitre_id in cls.TACTIC_TO_MITRE[tactic_type]:
                    if mitre_id not in detected:
                        tech_info = cls.TECHNIQUE_DB.get(mitre_id, {})
                        detected[mitre_id] = {
                            "id": mitre_id,
                            "name": tech_info.get('name', 'Unknown'),
                            "severity": tech_info.get('severity', 'medium'),
                            "confidence": 0.85,
                        }

        return list(detected.values())

    @classmethod
    def analyze_content_patterns(cls, content: str) -> List[Dict]:
        """Analyze content for MITRE techniques"""
        if not content:
            return []

        content_lower = content.lower()
        detected = {}

        for pattern, mitre_ids in cls.CONTENT_PATTERNS.items():
            if re.search(pattern, content_lower, re.IGNORECASE):
                for mitre_id in mitre_ids:
                    if mitre_id not in detected:
                        tech_info = cls.TECHNIQUE_DB.get(mitre_id, {})
                        detected[mitre_id] = {
                            "id": mitre_id,
                            "name": tech_info.get('name', 'Unknown'),
                            "severity": tech_info.get('severity', 'medium'),
                            "confidence": 0.7,
                        }

        return list(detected.values())

    @classmethod
    def get_technique_info(cls, mitre_id: str) -> Dict:
        """Get info about a MITRE technique"""
        tech = cls.TECHNIQUE_DB.get(mitre_id, {})
        return {
            "id": mitre_id,
            "name": tech.get('name', 'Unknown'),
            "severity": tech.get('severity', 'medium'),
        }


def get_mitre_info(technique_id: str) -> Dict:
    """Helper for Educator"""
    return MITREMapper.get_technique_info(technique_id)