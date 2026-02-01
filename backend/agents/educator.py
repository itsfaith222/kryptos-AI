from __future__ import annotations

import hashlib
import json
import os
import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load .env for local runs (safe in prod too; it won't override real env vars)
load_dotenv()

from contracts import AnalystOutput, EducatorOutput


# =============================
# Config — OpenRouter only (no GEMINI_API_KEY)
# =============================
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "google/gemini-2.0-flash-001"

# Mongo is OPTIONAL — educator must work without it
MONGODB_URI = os.getenv("MONGODB_URI", "")
MONGODB_DB = os.getenv("MONGODB_DB", "M0") or "M0"

# ElevenLabs (optional) — when enabled, voice MP3 stored in GridFS
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY", "")
ELEVENLABS_VOICE_ID = os.getenv("ELEVENLABS_VOICE_ID", "")
EDUCATOR_VOICE_ENABLED = os.getenv("EDUCATOR_VOICE_ENABLED", "false").lower() == "true"

EDUCATOR_DEFAULT_LANG = os.getenv("EDUCATOR_DEFAULT_LANG", "en")

# Toggle this to True when you want prints
EDUCATOR_DEBUG = os.getenv("EDUCATOR_DEBUG", "false").lower() == "true"


# =============================
# Clients (lazy init)
# =============================
_mongo_client = None
_learning_col = None
_gridfs = None


def _get_learning_collection():
    """
    MongoDB is OPTIONAL.
    If MONGODB_URI is missing/empty, this returns None and Educator continues normally.
    """
    global _mongo_client, _learning_col

    # Hard bypass when Mongo is not configured
    if not MONGODB_URI:
        return None

    # Already initialized
    if _learning_col is not None:
        return _learning_col

    # Import pymongo ONLY if Mongo is actually configured
    try:
        from pymongo import MongoClient  # local import avoids dependency if unused
    except Exception:
        return None

    try:
        _mongo_client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
        )
        db = _mongo_client[MONGODB_DB]
        _learning_col = db["learning_history"]
        return _learning_col
    except Exception:
        # Silent fail — logging is optional
        return None


def _get_gridfs():
    """
    MongoDB GridFS is OPTIONAL.
    If MONGODB_URI is missing/empty, this returns None and Educator continues normally.
    """
    global _mongo_client, _gridfs

    if not MONGODB_URI:
        return None

    if _gridfs is not None:
        return _gridfs

    # Import pymongo/gridfs only when needed
    try:
        from pymongo import MongoClient  # local import avoids dependency if unused
        import gridfs
    except Exception as e:
        if EDUCATOR_DEBUG:
            print("DEBUG GridFS import failed:", repr(e))
        return None

    try:
        # Reuse existing mongo client if already created
        if _mongo_client is None:
            _mongo_client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000,
            )

        # Force a quick connection check so failures aren't silent
        _mongo_client.admin.command("ping")

        db = _mongo_client[MONGODB_DB]
        _gridfs = gridfs.GridFS(db)
        return _gridfs

    except Exception as e:
        if EDUCATOR_DEBUG:
            print("DEBUG GridFS init failed:", repr(e))
        return None


# =============================
# Helpers
# =============================
def _hash_user_id(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bucket_privacy_evidence(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    what, who = [], []
    can_delete = "unclear"

    for e in evidence or []:
        finding = (e.get("finding") or "").strip()
        text = f"{e.get('type','')} {finding}".lower()

        # WHAT THEY TAKE
        if any(k in text for k in [
            "collect", "location", "contacts", "call", "text",
            "browsing", "history", "track", "microphone", "camera"
        ]):
            if finding:
                what.append(finding)

        # WHO SEES IT
        if any(k in text for k in ["share", "third", "advertis", "broker", "sell", "partners", "vendors"]):
            if finding:
                who.append(finding)

        # CAN YOU DELETE IT
        if any(k in text for k in ["no delete", "cannot delete", "retain indefinitely", "keep forever", "no deletion"]):
            can_delete = "no"
        elif any(k in text for k in ["right to delete", "data deletion", "erasure", "delete"]) and can_delete != "no":
            can_delete = "yes"

    # de-dupe preserving order
    what = list(dict.fromkeys(what))
    who = list(dict.fromkeys(who))

    return {"what": what, "who": who, "can_delete": can_delete}


def _openrouter_explanation(analyst: AnalystOutput, privacy: Dict[str, Any], lang: str) -> str:
    """Call OpenRouter (same key as Analyst) for plain-English explanation. No fallback — raise if not generating."""
    if not OPENROUTER_API_KEY:
        raise ValueError("Educator: OpenRouter not configured — set OPENROUTER_API_KEY in .env")

    evidence_lines = "\n".join(
        f"- {e.get('finding','')}" for e in (analyst.evidence or [])[:8] if e.get("finding")
    )

    prompt = f"""
Write a short security warning in {lang}.
Rules:
- Security & privacy risk only
- Direct and serious tone
- 3–5 sentences max
- No empowerment or accessibility language

Threat type: {analyst.threatType}
Risk score: {analyst.riskScore}/100
Confidence: {analyst.confidence}

Evidence:
{evidence_lines if evidence_lines else "- (no evidence provided)"}

If this is a privacy violation, include:
- WHAT data they take
- WHO it may be shared with
- whether you can delete it

Privacy:
WHAT: {privacy['what'][:5]}
WHO: {privacy['who'][:5]}
DELETE: {privacy['can_delete']}
""".strip()

    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENROUTER_MODEL,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        raw = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        txt = (raw or "").strip()
        if not txt:
            raise RuntimeError("Educator: not generating — OpenRouter returned empty explanation")
        if EDUCATOR_DEBUG:
            print("DEBUG OpenRouter Educator: generated =", bool(txt))
        return txt
    except requests.exceptions.RequestException as e:
        if EDUCATOR_DEBUG:
            print("DEBUG OpenRouter Educator exception:", repr(e))
        raise RuntimeError("Educator: not generating — OpenRouter request failed") from e


def _next_steps(threat_type: str, privacy: Dict[str, Any]) -> List[str]:
    if threat_type == "privacy_violation":
        steps = [
            "Do not accept these terms",
            "Look for an alternative app or service with safer data practices",
            "Disable high-risk permissions (location, contacts, microphone) if you must proceed"
        ]
        if privacy["can_delete"] == "no":
            steps.append("Assume collected/shared data cannot be recovered once exposed")
        return steps[:5]

    return [
        "Do not click links or download attachments",
        "Verify the sender using official channels",
        "Report and delete the message"
    ]


def _learning_points(threat_type: str, privacy: Dict[str, Any]) -> List[str]:
    if threat_type == "privacy_violation":
        pts = []
        if privacy["what"]:
            pts.append("Continuous collection of sensitive data increases surveillance and profiling risk")
        if privacy["who"]:
            pts.append("Third-party sharing can amplify exposure through vendor networks")
        if privacy["can_delete"] == "no":
            pts.append("No-deletion policies increase long-term exposure if data is leaked or misused")
        return (pts or ["This policy increases privacy risk and long-term exposure."])[:3]

    return [
        "Urgency and threats are common manipulation techniques used in scams",
        "Impersonation and lookalike senders are frequent indicators of phishing"
    ]


def _log_learning(user_id: str, analyst: AnalystOutput, tags: List[str]) -> None:
    """
    Optional learning-history logging.
    If Mongo isn't configured, this does nothing.
    """
    col = _get_learning_collection()
    if col is None:
        return  # Mongo intentionally bypassed

    try:
        col.insert_one({
            "userId": _hash_user_id(user_id),
            "timestamp": _now_iso(),
            "threatType": analyst.threatType,
            "riskScore": analyst.riskScore,
            "tags": tags[:10],
        })
        if EDUCATOR_DEBUG:
            print("DEBUG Mongo: inserted learning event")
    except Exception as ex:
        if EDUCATOR_DEBUG:
            print("DEBUG Mongo exception:", repr(ex))
        return


def _voice_alert(text: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Generate voice via ElevenLabs; store in GridFS if Mongo configured; return file_id or None."""
    if not EDUCATOR_VOICE_ENABLED or not ELEVENLABS_API_KEY or not ELEVENLABS_VOICE_ID:
        return None
    short = (text.split(".")[0] or text).strip()
    if len(short) > 240:
        short = short[:240] + "…"
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{ELEVENLABS_VOICE_ID}"
    headers = {"xi-api-key": ELEVENLABS_API_KEY, "Content-Type": "application/json", "Accept": "audio/mpeg"}
    payload = {"text": short, "model_id": "eleven_multilingual_v2"}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code != 200:
            return None
        mp3_bytes = r.content
        # Store in GridFS when Mongo is configured (Person D / dashboard can play via /audio/{file_id})
        try:
            from database import save_audio
            file_id = save_audio(
                mp3_bytes,
                filename="educator_voice.mp3",
                metadata=metadata or {"source": "educator", "text_preview": short[:80]},
            )
            return file_id
        except Exception:
            # Fallback: base64 when GridFS/Mongo not available (e.g. local dev without Mongo)
            import base64
            return "audio/mpeg;base64," + base64.b64encode(mp3_bytes).decode("utf-8")
    except Exception:
        return None


# =============================
# Public API (function + class)
# =============================
async def explain(
    analyst_output: AnalystOutput,
    user_id: str = "anonymous",
    lang: Optional[str] = None
) -> EducatorOutput:
    lang = lang or EDUCATOR_DEFAULT_LANG

    if EDUCATOR_DEBUG:
        print("DEBUG: riskScore =", analyst_output.riskScore, "voice enabled =", EDUCATOR_VOICE_ENABLED)
        print("DEBUG: Mongo enabled =", bool(MONGODB_URI))

    privacy = _bucket_privacy_evidence(analyst_output.evidence)
    explanation = _openrouter_explanation(analyst_output, privacy, lang)

    next_steps = _next_steps(analyst_output.threatType, privacy)
    learning_points = _learning_points(analyst_output.threatType, privacy)

    tags = []
    if privacy["what"]:
        tags.append("data_collection")
    if privacy["who"]:
        tags.append("third_party_sharing")
    if privacy["can_delete"] == "no":
        tags.append("no_deletion")

    _log_learning(user_id, analyst_output, tags)

    voice = None
    if analyst_output.riskScore >= 70:
        voice = _voice_alert(explanation, metadata={"riskScore": analyst_output.riskScore, "threatType": analyst_output.threatType})

    return EducatorOutput(
        explanation=explanation,
        nextSteps=next_steps,
        learningPoints=learning_points,
        voiceAlert=voice,
    )


class EducatorAgent:
    async def explain(
        self,
        analyst_output: AnalystOutput,
        user_id: Optional[str] = None,
        lang: Optional[str] = None,
    ) -> EducatorOutput:
        return await explain(analyst_output, user_id=user_id or "anonymous", lang=lang)


# ==================================================================================
# PERSON D DID THIS — for the web chatbox. Educator's code above was NOT changed.
# ==================================================================================
# - Chat UI (input, send button, message list) lives in the webapp (Person D).
# - POST /educator/chat lives in main.py (Person D). It reads message, age,
#   last_scan_result from the request and will call a chat function from this
#   file when you (Person C) add it — e.g. chat_reply(message, age=..., last_scan_result=...)
#   returning {"reply": str}. Until then, main.py uses a fallback so the chatbox works.
# - Webapp sends { message, age?, last_scan_result? } so your chat logic can use
#   age and last_scan_result for age-aware, alert-aware replies.
# - Do not change explain() or EducatorAgent above; add your new chat entry point
#   in this file when you implement the plan (ask for age, tailor by age, use last_scan_result).
