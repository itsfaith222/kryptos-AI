"""
Orchestrator - Person D: FastAPI server, /scan endpoint, agent coordination
Hour 6-12: WebSocket real-time alerts, rate limiting (POST /scan unchanged).
"""
import asyncio
import logging
import os
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

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

# --- WebSocket: broadcast new scans to dashboard clients ---
_ws_connections: set[WebSocket] = set()


async def broadcast_scan_result(result_dict: dict) -> None:
    """Send new scan result to all connected WebSocket clients (dashboard)."""
    if not _ws_connections:
        return
    msg = {"type": "new_scan", "payload": result_dict}
    dead = set()
    for ws in _ws_connections:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    for ws in dead:
        _ws_connections.discard(ws)


# --- Rate limiting: per-IP, same 503/error shape for extension ---
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def _rate_limit_check(client_key: str) -> bool:
    """True if allowed, False if rate limited."""
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_SEC
    times = _rate_limit_store[client_key]
    times[:] = [t for t in times if t > window_start]
    if len(times) >= RATE_LIMIT_REQUESTS:
        return False
    times.append(now)
    return True


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


# --- Fallback mocks when agents fail to import; remove later if we want to fail instead ---
# def _is_high_risk(input_data: ScanInput) -> bool:
#     content = (input_data.content or "").lower()
#     return "urgent" in content or "verify" in content
#
# def _mock_scout(...): ...
# def _mock_analyst(...): ...
# def _mock_educator(...): ...
# (Kept below for fallback in _run_scout/_run_analyst/_run_educator on ImportError/AttributeError)

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
    """Assemble full ScanResult (Scout → Analyst → Educator) for client and DB."""
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
        mitreAttackTechniques=analyst_result.mitreAttackTechniques or [],
        voiceAlert=educator_result.voiceAlert,
    )


@app.get("/health")
async def health():
    return {"ok": True, "service": APP_NAME or "Guardian AI"}


@app.post("/educator/chat")
async def educator_chat(request: dict):
    """Chat with the Educator LLM — wired to educator.chat_reply (age + last_scan_result for Person C)."""
    msg = (request.get("message") or "").strip()
    if not msg or len(msg) > 2000:
        raise HTTPException(status_code=400, detail="Message required (max 2000 chars)")

    age = request.get("age")
    if age is not None and (not isinstance(age, int) or age < 0 or age > 120):
        age = None
    last_scan_result = request.get("last_scan_result") or request.get("lastScanResult")

    try:
        from agents.educator import chat_reply
        reply = await asyncio.to_thread(chat_reply, msg, age=age, last_scan_result=last_scan_result)
        return {"reply": reply}
    except (ImportError, AttributeError):
        # Person C (Educator) will add chat_reply; until then use fallback
        logger.warning("Educator chat_reply not available, using fallback")
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise HTTPException(status_code=503, detail="Educator not configured (OPENROUTER_API_KEY)")
        import requests as req
        system = (
            "You are the Guardian AI Educator: a concise security and privacy expert. "
            "Answer user questions about phishing, scams, malware, and privacy in 2-5 sentences. "
            "Be direct and helpful. No fluff."
        )
        try:
            r = req.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001"),
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": msg},
                    ],
                },
                timeout=30,
            )
            r.raise_for_status()
            reply = (r.json().get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            return {"reply": reply}
        except req.exceptions.RequestException as e:
            logger.warning("Educator chat failed: %s", e)
            raise HTTPException(status_code=503, detail="Educator unavailable") from e
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.warning("Educator chat_reply failed: %s", e)
        raise HTTPException(status_code=503, detail="Educator unavailable") from e


@app.get("/history")
async def get_history(limit: int = 50):
    """Get recent scan history from DB (for dashboard)."""
    try:
        from database import get_recent_scans
        scans = await get_recent_scans(limit=limit)
        # Convert ObjectId etc for JSON
        out = []
        from bson import ObjectId

        def _serialize(obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            if isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_serialize(x) for x in obj]
            return obj

        for s in scans:
            s.pop("_id", None)
            out.append(_serialize(s))
        return out
    except Exception as e:
        logger.exception("Failed to fetch history")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/audio/{file_id}")
async def get_audio(file_id: str):
    """Stream educator voice MP3 from GridFS (Person D)."""
    from bson import ObjectId
    from database import get_audio as db_get_audio

    try:
        f = db_get_audio(file_id)
        return StreamingResponse(
            iter([f.read()]),
            media_type="audio/mpeg",
        )
    except Exception as e:
        logger.debug("Audio fetch failed: %s", e)
        raise HTTPException(status_code=404, detail="Audio not found") from e


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time alerts: dashboard clients connect here; new scans are broadcast."""
    await websocket.accept()
    _ws_connections.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Optional: ping/pong or commands; for now just keep connection alive
            if data.strip().lower() == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        _ws_connections.discard(websocket)


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


def _is_localhost_url(url: str) -> bool:
    """True if URL is localhost or 127.0.0.1 (we do not record these in history)."""
    if not url or not isinstance(url, str):
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = (parsed.hostname or parsed.netloc or "").lower().split(":")[0]
        return host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
    except Exception:
        return False


@app.post("/scan")
async def scan_endpoint(request: Request, input_data: ScanInput):
    """Full pipeline: Scout → Analyst → Educator → ScanResult → DB → client (extension/dashboard)."""
    # Rate limiting: same 503/error shape for extension
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_check(client_ip):
        logger.warning("Rate limit exceeded for %s", client_ip)
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={"error": "Rate limit exceeded"})
    try:
        scout_result = await _run_scout(input_data)
        analyst_result = await _run_analyst(scout_result)
        educator_result = await _run_educator(analyst_result)
        result = _assemble_scan_result(input_data, analyst_result, educator_result)
        result_dict = result.model_dump()
        url = result_dict.get("url") or getattr(input_data, "url", "") or ""
        if not _is_localhost_url(url):
            try:
                from database import save_scan
                await save_scan(result_dict)
            except Exception as e:
                logger.exception("Could not save scan to database")
                print(f"\n[DB ERROR] {e}\n  Check MONGODB_URI in backend/.env and Atlas Network Access.\n")
            await broadcast_scan_result(result_dict)
        else:
            logger.info("Skipping save/broadcast for localhost URL: %s", url[:80] if url else "")
        return result_dict
    except (ValueError, RuntimeError) as e:
        msg = str(e)
        logger.warning("Scan pipeline error: %s", msg)
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={"error": msg})
