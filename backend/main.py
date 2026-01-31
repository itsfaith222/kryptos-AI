"""
Orchestrator - Person D: FastAPI server, /scan endpoint, agent coordination
"""
import logging
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import APP_NAME
from contracts import (
    ScanInput,
    ScanResult,
    ScoutOutput,
    AnalystOutput,
    EducatorOutput,
)

logger = logging.getLogger(__name__)

app = FastAPI(title=APP_NAME or "Guardian AI")


@app.on_event("startup")
async def startup():
    """Log MongoDB config on startup so you can verify in terminal."""
    uri = os.getenv("MONGODB_URI", "")
    has_uri = bool(uri and uri != "mongodb://localhost:27017")
    print(f"\n[Guardian AI] Backend ready | MongoDB: {'configured' if has_uri else 'using localhost (set MONGODB_URI in .env for Atlas)'}\n")

# CORS: allow dashboard + Chrome extension (chrome-extension://)
_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,chrome-extension://")
CORS_ORIGINS = [o.strip() for o in _cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Extension ID varies when unpacked; * allows all for dev
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Mock agent outputs (used until Person A/B/C implement real agents) ---

def _is_high_risk(input_data: ScanInput) -> bool:
    content = (input_data.content or "").lower()
    return "urgent" in content or "verify" in content


def _mock_scout(input_data: ScanInput) -> ScoutOutput:
    high_risk = _is_high_risk(input_data)
    return ScoutOutput(
        scanType=input_data.scanType,
        initialRisk=80 if high_risk else 20,
        signals={"hasPassword": high_risk, "urgencyWords": ["urgent", "verify"] if high_risk else []},
        recommendation="ESCALATE_TO_ANALYST" if high_risk else "SAFE",
        predictiveWarning="Fake phishing scams trending" if high_risk else None,
    )


def _mock_analyst(scout_result: ScoutOutput) -> AnalystOutput:
    high_risk = scout_result.recommendation == "ESCALATE_TO_ANALYST"
    return AnalystOutput(
        analysisId=str(uuid4()),
        threatType="phishing" if high_risk else "safe",
        riskScore=scout_result.initialRisk,
        confidence=0.92 if high_risk else 0.60,
        evidence=[
            {"type": "mock", "finding": "Urgency triggers detected", "weight": 0.8, "severity": "high"}
        ] if high_risk else [],
        mitreAttackTechniques=["T1566.002"] if high_risk else [],
    )


def _mock_educator(analyst_result: AnalystOutput) -> EducatorOutput:
    high_risk = analyst_result.threatType != "safe"
    return EducatorOutput(
        explanation=(
            "Potential phishing indicators detected. Avoid clicking links."
            if high_risk
            else "Content appears safe. No urgent or verify triggers found."
        ),
        nextSteps=(
            ["Do not click links", "Verify sender identity", "Report if suspicious"]
            if high_risk
            else ["Proceed with caution", "Verify sender if unsure"]
        ),
        learningPoints=["Watch for urgency words", "Check sender address"] if high_risk else [],
        voiceAlert=None,
    )


# --- Pipeline: Scout → Analyst → Educator → ScanResult ---

async def _run_scout(input_data: ScanInput) -> ScoutOutput:
    try:
        from agents.scout import analyze
        return await analyze(input_data)
    except (ImportError, AttributeError) as e:
        logger.debug("Using mock Scout: %s", e)
        return _mock_scout(input_data)


async def _run_analyst(scout_result: ScoutOutput) -> AnalystOutput:
    try:
        from agents.analyst import investigate
        return await investigate(scout_result)
    except (ImportError, AttributeError) as e:
        logger.debug("Using mock Analyst: %s", e)
        return _mock_analyst(scout_result)


async def _run_educator(analyst_result: AnalystOutput) -> EducatorOutput:
    try:
        from agents.educator import explain
        return await explain(analyst_result)
    except (ImportError, AttributeError) as e:
        logger.debug("Using mock Educator: %s", e)
        return _mock_educator(analyst_result)


def _assemble_scan_result(
    input_data: ScanInput,
    analyst_result: AnalystOutput,
    educator_result: EducatorOutput,
) -> ScanResult:
    return ScanResult(
        scanId=str(uuid4()),
        timestamp=datetime.utcnow().isoformat(),
        url=input_data.url,
        scanType=input_data.scanType,
        riskScore=analyst_result.riskScore,
        threatType=analyst_result.threatType,
        confidence=analyst_result.confidence,
        evidence=analyst_result.evidence,
        explanation=educator_result.explanation,
        nextSteps=educator_result.nextSteps,
        mitreAttackTechniques=analyst_result.mitreAttackTechniques,
    )


@app.get("/health")
async def health():
    return {"ok": True, "service": APP_NAME or "Guardian AI"}


@app.post("/api/scout/scan")
async def api_scout_scan(request: dict):
    """
    Extension endpoint: accepts SCOUT_SIGNAL payload (url, isLogin, hasPrivacyPolicy,
    detectedKeywords, detectedScam, detectedMalware) and returns riskScore, hasPrivacyPolicy.
    """
    try:
        from agents.scout import compute_risk_from_signal
        result = compute_risk_from_signal(
            url=request.get("url", ""),
            is_login=request.get("isLogin", False),
            has_privacy_policy=request.get("hasPrivacyPolicy", False),
            detected_keywords=request.get("detectedKeywords", []),
            detected_scam=request.get("detectedScam"),
            detected_malware=request.get("detectedMalware"),
        )
        risk_score = result["risk_score"]
        metadata = result.get("metadata", {})
        metadata["scanId"] = str(uuid4())
        metadata["timestamp"] = datetime.utcnow().isoformat()
        return {
            "riskScore": risk_score,
            "url": request.get("url", ""),
            "hasPrivacyPolicy": request.get("hasPrivacyPolicy", False),
            "detectedKeywords": request.get("detectedKeywords", []),
            "timestamp": metadata["timestamp"],
            "metadata": metadata,
        }
    except (ImportError, AttributeError) as e:
        logger.debug("compute_risk_from_signal not available: %s", e)
        # Fallback: simple risk from keywords
        kw = request.get("detectedKeywords", [])
        scam = request.get("detectedScam", [])
        malware = request.get("detectedMalware", [])
        risk = min(100, len(kw) * 10 + len(scam) * 14 + len(malware) * 18)
        if request.get("isLogin"):
            risk = min(100, risk + 35)
        if request.get("hasPrivacyPolicy"):
            risk = min(100, risk + 5)
        return {
            "riskScore": min(risk, 100),
            "url": request.get("url", ""),
            "hasPrivacyPolicy": request.get("hasPrivacyPolicy", False),
            "detectedKeywords": kw,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"isLogin": request.get("isLogin"), "hasPrivacyPolicy": request.get("hasPrivacyPolicy")},
        }


@app.post("/scan")
async def scan_endpoint(input_data: ScanInput):
    """Full pipeline: Scout → Analyst → Educator → ScanResult. Uses mocks until agents exist."""
    scout_result = await _run_scout(input_data)

    if scout_result.recommendation == "SAFE":
        analyst_result = _mock_analyst(scout_result)
        educator_result = _mock_educator(analyst_result)
    else:
        analyst_result = await _run_analyst(scout_result)
        educator_result = await _run_educator(analyst_result)

    result = _assemble_scan_result(input_data, analyst_result, educator_result)

    try:
        from database import save_scan
        await save_scan(result.model_dump())
    except Exception as e:
        logger.exception("Could not save scan to database")
        print(f"\n[DB ERROR] {e}\n  Check MONGODB_URI in backend/.env and Atlas Network Access.\n")

    return result.model_dump()
