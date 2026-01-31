"""
mitre_mapper.py
MITRE ATT&CK Framework Mapper
HOUR 4-6: Industry-standard threat categorization
"""

from typing import Dict, List


class MITREMapper:
    """Maps psychological tactics to MITRE ATT&CK techniques"""
    
    # Database of techniques we detect
    TECHNIQUE_DB = {
        "T1566.002": {
            "name": "Phishing: Spearphishing Link",
            "severity": "critical"
        },
        "T1534": {
            "name": "Internal Spearphishing",
            "severity": "critical"
        },
        "T1598.003": {
            "name": "Phishing for Information",
            "severity": "critical"
        },
        "T1566.001": {
            "name": "Phishing: Spearphishing Attachment",
            "severity": "high"
        },
        "T1204.002": {
            "name": "User Execution: Malicious File",
            "severity": "critical"
        },
        "T1056.003": {
            "name": "Input Capture: Web Portal",
            "severity": "critical"
        },
        "T1657": {
            "name": "Financial Theft",
            "severity": "critical"
        }
    }
    
    TACTIC_TO_MITRE = {
        "urgency": ["T1566.002", "T1534"],
        "fear": ["T1534", "T1566.002"],
        "authority": ["T1598.003", "T1534"],
        "scarcity": ["T1566.001"],
        "social_proof": ["T1204.002"],
        "credential_request": ["T1056.003", "T1598.003"],
        "financial_request": ["T1657"]
    }
    
    @classmethod
    def map_tactics_to_mitre(cls, tactics: List[Dict]) -> List[Dict]:
        """Convert Gemini tactics to MITRE techniques"""
        detected = {}
        
        for tactic in tactics:
            tactic_type = tactic.get('type', '').lower()
            if tactic_type in cls.TACTIC_TO_MITRE:
                for mitre_id in cls.TACTIC_TO_MITRE[tactic_type]:
                    if mitre_id not in detected:
                        tech_info = cls.TECHNIQUE_DB.get(mitre_id, {})
                        detected[mitre_id] = {
                            "id": mitre_id,
                            "name": tech_info.get('name', 'Unknown'),
                            "severity": tech_info.get('severity', 'medium'),
                            "confidence": 0.85,
                            "linkedTactic": tactic.get('example', '')
                        }
        
        return list(detected.values())
    
    @classmethod
    def get_technique_info(cls, mitre_id: str) -> Dict:
        """Get info about a MITRE technique (for Educator)"""
        tech = cls.TECHNIQUE_DB.get(mitre_id, {})
        return {
            "id": mitre_id,
            "name": tech.get('name', 'Unknown'),
            "severity": tech.get('severity', 'medium'),
            "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
        }


# Helper function for Educator
def get_mitre_info(technique_id: str) -> Dict:
    """Educator imports this"""
    return MITREMapper.get_technique_info(technique_id)