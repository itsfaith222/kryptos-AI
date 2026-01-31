"""
Orchestrator - Person D: FastAPI server, /scan endpoint, agent coordination
"""
import os
from datetime import datetime
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import APP_NAME
from contracts import ScanInput, ScanResult

# Use mocks until real agents are integrated
USE_MOCKS = os.getenv("USE_MOCKS", "true").lower() == "true"

app = FastAPI(title=APP_NAME)

# CORS for extension (chrome-extension://) and dashboard (localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Dev: allow extension + dashboard; tighten for production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_mock_scan_result(input_data: ScanInput) -> ScanResult:
    """Return mock ScanResult for development/demo. Matches contracts."""
    risk = 75 if input_data.scanType in ("email", "message") else 60
    return ScanResult(
        scanId=str(uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        url=input_data.url,
        scanType=input_data.scanType,
        riskScore=risk,
        threatType="phishing",
        confidence=0.85,
        evidence=[
            {"type": "mock", "finding": "Mock analysis - replace with Scout/Analyst", "weight": 0.8, "severity": "high"},
        ],
        explanation=f"{APP_NAME} detected potential threats. This is a mock response until real agents are wired.",
        nextSteps=["Do not click links", "Verify sender identity", "Report if suspicious"],
        mitreAttackTechniques=["T1566.002"],
    )


@app.get("/health")
async def health():
    return {"status": "ok", "mocks": USE_MOCKS}


@app.post("/scan")
async def scan_endpoint(input_data: ScanInput):
    """Scan endpoint. Returns mock JSON when USE_MOCKS=true."""
    if USE_MOCKS:
        result = get_mock_scan_result(input_data)
        return result.model_dump()
    # TODO: Wire Scout -> Analyst -> Educator when USE_MOCKS=false
    result = get_mock_scan_result(input_data)
    return result.model_dump()
