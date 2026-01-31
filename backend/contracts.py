"""
Data contracts for Guardian AI agents.
Defines the standardized input/output formats for inter-agent communication.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from enum import Enum


class ScanType(str, Enum):
    """Types of scans the Scout can perform."""
    MESSAGE = "message"
    IMAGE = "image"
    PAGE = "page"


class ScanInput(BaseModel):
    """Input format for Scout agent."""
    url: Optional[str] = Field(None, description="URL of the page being scanned")
    scanType: ScanType = Field(..., description="Type of scan: message, image, or page")
    content: Optional[str] = Field(None, description="Text content to analyze (for message scans)")
    image_data: Optional[str] = Field(None, description="Base64 encoded image data (for image scans)")
    page_data: Optional[Dict[str, Any]] = Field(None, description="DOM signals extracted from page")

    class Config:
        use_enum_values = True


class ScoutSignals(BaseModel):
    """Signals extracted by Scout agent."""
    # Message signals
    urgencyWords: List[str] = Field(default_factory=list, description="Detected urgency/pressure words")
    hasPassword: bool = Field(False, description="Message contains password requests")
    hasEmail: bool = Field(False, description="Message contains email addresses")
    suspiciousPatterns: List[str] = Field(default_factory=list, description="Detected suspicious patterns")
    
    # Image signals
    hasLogo: bool = Field(False, description="Image contains logos")
    logoQuality: Optional[str] = Field(None, description="Logo quality: high/medium/low")
    suspiciousImages: bool = Field(False, description="Detected suspicious visual elements")
    extractedText: str = Field("", description="Text extracted from image")
    
    # Page signals
    domain: Optional[str] = Field(None, description="Domain of the page")
    hasHTTPS: bool = Field(True, description="Page uses HTTPS")
    formCount: int = Field(0, description="Number of forms on page")
    externalLinks: int = Field(0, description="Number of external links")
    isPrivacyPolicy: bool = Field(False, description="Page is a privacy policy")
    
    class Config:
        use_enum_values = True


class ScoutOutput(BaseModel):
    """Output format for Scout agent."""
    scanType: ScanType = Field(..., description="Type of scan performed")
    initialRisk: int = Field(..., description="Risk score 0-100")
    signals: ScoutSignals = Field(..., description="Extracted signals")
    recommendation: str = Field(..., description="Scout recommendation: SAFE/ESCALATE_TO_ANALYST/BLOCK_IMMEDIATELY")
    predictiveWarning: Optional[str] = Field(None, description="Predictive warning message")

    class Config:
        use_enum_values = True


class AnalystInput(BaseModel):
    """Input format for Analyst agent."""
    scoutOutput: ScoutOutput = Field(..., description="Output from Scout")
    deepAnalysis: bool = Field(False, description="Perform deep analysis")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")


class AnalystOutput(BaseModel):
    """Output format for Analyst agent."""
    riskScore: int = Field(..., description="Final risk score 0-100")
    recommendation: str = Field(..., description="Analyst recommendation")
    explanation: str = Field(..., description="Detailed explanation")
    threats: List[Dict[str, Any]] = Field(default_factory=list, description="Identified threats")


class EducatorOutput(BaseModel):
    """Output format for Educator agent."""
    lesson: str = Field(..., description="Educational content")
    tips: List[str] = Field(default_factory=list, description="Safety tips")
    resources: List[Dict[str, str]] = Field(default_factory=list, description="External resources")
