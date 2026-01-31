"""
Orchestrator - Person D: FastAPI server, /scan endpoint, agent coordination
"""
import logging
import os
from datetime import datetime
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import APP_NAME
from contracts import ScanInput, ScanResult

logger = logging.getLogger(__name__)

app = FastAPI(title=APP_NAME or "Guardian AI")

# CORS: use CORS_ORIGINS env (comma-separated) or default dashboard origin
_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173")
CORS_ORIGINS = [o.strip() for o in _cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _is_high_risk(input_data: ScanInput) -> bool:
    """Deterministic risk: high if content contains urgency triggers."""
    content = (input_data.content or "").lower()
    return "urgent" in content or "verify" in content


def get_mock_scan_result(input_data: ScanInput) -> ScanResult:
    """Return mock ScanResult matching contracts. Deterministic based on input."""
    high_risk = _is_high_risk(input_data)
    risk_score = 80 if high_risk else 20
    threat_type = "phishing" if high_risk else "safe"
    confidence = 0.85 if high_risk else 0.60
    evidence = []
    if high_risk:
        evidence.append({"type": "mock", "finding": "Urgency triggers detected in content", "weight": 0.8, "severity": "high"})
    explanation = (
        "Potential phishing indicators detected. Avoid clicking links." if high_risk
        else "Content appears safe. No urgent or verify triggers found."
    )
    next_steps = (
        ["Do not click links", "Verify sender identity", "Report if suspicious"] if high_risk
        else ["Proceed with caution", "Verify sender if unsure", "Report suspicious activity"]
    )
    mitre = ["T1566.002"] if high_risk else []

    return ScanResult(
        scanId=str(uuid4()),
        timestamp=datetime.utcnow().isoformat(),
        url=input_data.url,
        scanType=input_data.scanType,
        riskScore=risk_score,
        threatType=threat_type,
        confidence=confidence,
        evidence=evidence,
        explanation=explanation,
        nextSteps=next_steps,
        mitreAttackTechniques=mitre,
    )


@app.get("/health")
async def health():
    return {"ok": True, "service": APP_NAME or "Guardian AI"}


@app.post("/scan")
async def scan_endpoint(input_data: ScanInput):
    """Scan endpoint. Returns mock ScanResult matching contracts."""
    result = get_mock_scan_result(input_data)
    try:
        from database import save_scan
        await save_scan(result.model_dump())
    except Exception as e:
        logger.warning("Could not save scan to database: %s", e)
    return result.model_dump()
