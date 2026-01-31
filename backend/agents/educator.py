from typing import Optional, List, Dict
from pydantic import BaseModel

class ScanInput(BaseModel):
    url: str
    scanType: str  # "page" | "email" | "message" | "image"
    content: Optional[str] = None
    image_data: Optional[str] = None  # base64

class ScoutOutput(BaseModel):
    scanType: str
    initialRisk: int  # 0-100
    signals: Dict
    recommendation: str  # "ESCALATE_TO_ANALYST" | "SAFE" | "BLOCK"
    predictiveWarning: Optional[str] = None

class AnalystOutput(BaseModel):
    analysisId: str
    threatType: str  # "phishing" | "scam" | "malware" | "privacy_violation"
    riskScore: int  # 0-100
    confidence: float  # 0.0-1.0
    evidence: List[Dict]
    mitreAttackTechniques: List[str]

class EducatorOutput(BaseModel):
    explanation: str
    nextSteps: List[str]
    learningPoints: List[str]
    voiceAlert: Optional[str] = None
