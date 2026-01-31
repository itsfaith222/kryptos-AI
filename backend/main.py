"""
Guardian AI Backend Server
FastAPI server that orchestrates Scout, Analyst, and Educator agents
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
from datetime import datetime
import sys
import os

# Add agents to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contracts import ScanInput, ScoutOutput, AnalystOutput, EducatorOutput, ScanResult
from agents.scout import scout

# Initialize FastAPI app
app = FastAPI(
    title="Guardian AI",
    description="Real-time protection from scams and privacy violations",
    version="1.0.0"
)

# Enable CORS for Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for extension
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (replace with MongoDB later)
scan_history: Dict[str, ScanResult] = {}


# ============= SCOUT ENDPOINTS =============

@app.post("/scout/analyze")
async def scout_analyze(input_data: ScanInput) -> ScoutOutput:
    """
    Analyze input with Scout agent
    
    Args:
        input_data: ScanInput with url, scanType, and content
        
    Returns:
        ScoutOutput with risk score and signals
    """
    try:
        result = await scout.analyze(input_data)
        return result
    except Exception as e:
        print(f"Error in scout analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scout/warnings")
async def scout_warnings() -> List[Dict]:
    """
    Get predictive warnings about trending threats
    
    Returns:
        List of threat warnings
    """
    try:
        # Mock warnings - will integrate with MongoDB later
        warnings = [
            {
                "threatType": "Phishing",
                "description": "PayPal phishing emails up 300% this week",
                "severity": "high"
            },
            {
                "threatType": "Scam",
                "description": "Amazon package delivery scams trending",
                "severity": "medium"
            },
            {
                "threatType": "Malware",
                "description": "Fake Chrome extension downloads detected",
                "severity": "high"
            }
        ]
        return warnings
    except Exception as e:
        print(f"Error fetching warnings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============= ANALYST ENDPOINTS =============

@app.post("/analyst/analyze")
async def analyst_analyze(scout_output: ScoutOutput) -> AnalystOutput:
    """
    Deep analysis by Analyst agent
    
    Args:
        scout_output: Output from Scout agent
        
    Returns:
        AnalystOutput with detailed threat analysis
    """
    try:
        # Determine threat type based on signals and risk
        threat_type = "unknown"
        signals = scout_output.signals
        
        # Check for phishing indicators
        if signals.get("urgencyWords") or signals.get("hasPassword"):
            threat_type = "phishing"
        # Check for scam indicators
        elif signals.get("suspiciousPatterns"):
            threat_type = "scam"
        # Check for privacy violations
        elif signals.get("isPrivacyPolicy"):
            threat_type = "privacy_violation"
        # Fallback to risk-based classification
        elif scout_output.initialRisk > 70:
            threat_type = "phishing"
        elif scout_output.initialRisk > 40:
            threat_type = "scam"
        elif scout_output.initialRisk > 20:
            threat_type = "privacy_violation"
        
        result = AnalystOutput(
            analysisId=str(uuid.uuid4()),
            threatType=threat_type,
            riskScore=scout_output.initialRisk,
            confidence=0.85,
            evidence=[
                {"type": "signal", "value": signal}
                for signal in scout_output.signals.get("suspiciousPatterns", [])
            ],
            mitreAttackTechniques=["T1566.002", "T1598.003"]  # Phishing techniques
        )
        return result
    except Exception as e:
        print(f"Error in analyst analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyst/analyze-privacy")
async def analyze_privacy_policy(policy_text: str) -> Dict:
    """
    Analyze privacy policy text
    
    Args:
        policy_text: Full privacy policy text
        
    Returns:
        Analysis results
    """
    try:
        # Mock privacy analysis - will implement real agent later
        return {
            "riskScore": 45,
            "dataCollected": ["email", "location", "browsing_history"],
            "thirdPartySharing": True,
            "recommendation": "Review before using"
        }
    except Exception as e:
        print(f"Error analyzing privacy policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============= EDUCATOR ENDPOINTS =============

@app.post("/educator/explain")
async def educator_explain(analyst_output: AnalystOutput) -> EducatorOutput:
    """
    Generate educational content about the threat
    
    Args:
        analyst_output: Output from Analyst agent
        
    Returns:
        EducatorOutput with explanation and tips
    """
    try:
        # Mock educator response - will implement real agent later
        explanations = {
            "phishing": "This appears to be a phishing attempt trying to steal your credentials.",
            "scam": "This looks like a scam trying to trick you into sending money or personal info.",
            "malware": "This may contain malware that could harm your device.",
            "privacy_violation": "This site may be collecting more data than necessary."
        }
        
        tips = {
            "phishing": [
                "Never click links in suspicious emails",
                "Verify the sender's email address carefully",
                "Check for spelling errors and poor formatting",
                "Hover over links to see the real URL"
            ],
            "scam": [
                "Be skeptical of urgent requests",
                "Verify requests through official channels",
                "Never send money to unknown sources",
                "Check for too-good-to-be-true offers"
            ],
            "malware": [
                "Keep your antivirus software updated",
                "Don't download from untrusted sources",
                "Be careful with email attachments",
                "Use strong, unique passwords"
            ]
        }
        
        threat_type = analyst_output.threatType
        result = EducatorOutput(
            explanation=explanations.get(threat_type, "Unknown threat type"),
            nextSteps=[
                "Report this to the platform",
                "Block the sender",
                "Delete the message"
            ],
            learningPoints=tips.get(threat_type, []),
            voiceAlert=None  # Will implement voice alerts later
        )
        return result
    except Exception as e:
        print(f"Error in educator explanation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============= ORCHESTRATION ENDPOINTS =============

@app.post("/scan")
async def full_scan(input_data: ScanInput) -> ScanResult:
    """
    Full scan pipeline: Scout → Analyst → Educator
    
    Args:
        input_data: ScanInput with url, scanType, and content
        
    Returns:
        Complete ScanResult with all analysis
    """
    try:
        # Step 1: Scout analysis
        scout_result = await scout_analyze(input_data)
        
        # Step 2: Analyst deep dive
        analyst_result = await analyst_analyze(scout_result)
        
        # Step 3: Educator explanation
        educator_result = await educator_explain(analyst_result)
        
        # Step 4: Assemble final result
        scan_id = str(uuid.uuid4())
        final_result = ScanResult(
            scanId=scan_id,
            timestamp=datetime.now().isoformat(),
            url=input_data.url or "unknown",
            scanType=input_data.scanType,
            riskScore=analyst_result.riskScore,
            threatType=analyst_result.threatType,
            confidence=analyst_result.confidence,
            evidence=analyst_result.evidence,
            explanation=educator_result.explanation,
            nextSteps=educator_result.nextSteps,
            mitreAttackTechniques=analyst_result.mitreAttackTechniques
        )
        
        # Store in history
        scan_history[scan_id] = final_result
        
        return final_result
    except Exception as e:
        print(f"Error in full scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str) -> ScanResult:
    """
    Retrieve a previous scan result
    
    Args:
        scan_id: ID of the scan to retrieve
        
    Returns:
        ScanResult from history
    """
    if scan_id not in scan_history:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_history[scan_id]


@app.get("/scan/history")
async def get_scan_history() -> List[ScanResult]:
    """
    Get all scan history
    
    Returns:
        List of all ScanResults
    """
    return list(scan_history.values())


# ============= HEALTH CHECK =============

@app.get("/health")
async def health_check() -> Dict:
    """
    Health check endpoint
    
    Returns:
        Status information
    """
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


# ============= ROOT =============

@app.get("/")
async def root() -> Dict:
    """
    Root endpoint with API info
    
    Returns:
        API information
    """
    return {
        "name": "Guardian AI",
        "version": "1.0.0",
        "description": "Real-time protection from scams and privacy violations",
        "endpoints": {
            "scout": "/scout/analyze",
            "warnings": "/scout/warnings",
            "full_scan": "/scan",
            "health": "/health"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
