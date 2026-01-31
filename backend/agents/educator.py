
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import requests
from dotenv import load_dotenv

# Load .env for local runs (safe in prod too; it won't override real env vars)
load_dotenv()

# New Gemini SDK (non-deprecated)
from google import genai

from contracts import AnalystOutput, EducatorOutput


# =============================
# Config
# =============================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Mongo is OPTIONAL — educator must work without it
MONGODB_URI = os.getenv("MONGODB_URI", "")
MONGODB_DB = os.getenv("MONGODB_DB", "guardian_ai")

ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
ELEVENLABS_VOICE_ID = os.getenv("ELEVENLABS_VOICE_ID")

EDUCATOR_DEFAULT_LANG = os.getenv("EDUCATOR_DEFAULT_LANG", "en")
EDUCATOR_VOICE_ENABLED = os.getenv("EDUCATOR_VOICE_ENABLED", "true").lower() == "true"

# Toggle this to True when you want prints
EDUCATOR_DEBUG = os.getenv("EDUCATOR_DEBUG", "false").lower() == "true"


# =============================
# Clients (lazy init)
# =============================
_mongo_client = None
_learning_col = None

_gemini_client = None
if GEMINI_API_KEY:
    _gemini_client = genai.Client(api_key=GEMINI_API_KEY)


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


def _gemini_explanation(analyst: AnalystOutput, privacy: Dict[str, Any], lang: str) -> str:
    # Fallback explanation for demo stability + when Gemini is down/rate-limited
    fallback = (
        f"🚨 High-risk security issue detected ({analyst.threatType}). "
        f"Risk score {analyst.riskScore}/100. "
        f"This item shows indicators of unsafe behavior. Do not proceed until verified."
    )

    if not _gemini_client:
        if EDUCATOR_DEBUG:
            print("DEBUG Gemini: no client (missing GEMINI_API_KEY)")
        return fallback

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
        resp = _gemini_client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        txt = (getattr(resp, "text", "") or "").strip()
        if EDUCATOR_DEBUG:
            print("DEBUG Gemini: generated =", bool(txt))
        return txt if txt else fallback

    except Exception as ex:
        # handle quota/rate-limit errors gracefully (no crash)
        if EDUCATOR_DEBUG:
            print("DEBUG Gemini exception:", repr(ex))

        msg = repr(ex)
        if ("RESOURCE_EXHAUSTED" in msg) or ("429" in msg) or ("Quota exceeded" in msg):
            return fallback

        return fallback


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


def _voice_alert(text: str) -> Optional[str]:
    # If any of these are missing, voice should be None — we print WHY (only if debug)
    if not EDUCATOR_VOICE_ENABLED:
        if EDUCATOR_DEBUG:
            print("DEBUG ElevenLabs: voice disabled (EDUCATOR_VOICE_ENABLED=false)")
        return None
    if not ELEVENLABS_API_KEY:
        if EDUCATOR_DEBUG:
            print("DEBUG ElevenLabs: missing ELEVENLABS_API_KEY")
        return None
    if not ELEVENLABS_VOICE_ID:
        if EDUCATOR_DEBUG:
            print("DEBUG ElevenLabs: missing ELEVENLABS_VOICE_ID")
        return None

    short = (text.split(".")[0] or text).strip()
    if len(short) > 240:
        short = short[:240] + "…"

    url = f"https://api.elevenlabs.io/v1/text-to-speech/{ELEVENLABS_VOICE_ID}"
    headers = {
        "xi-api-key": ELEVENLABS_API_KEY,
        "Content-Type": "application/json",
        "Accept": "audio/mpeg"
    }

    # Try multilingual model (usually safest across accounts)
    payload = {"text": short, "model_id": "eleven_multilingual_v2"}

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)

        if EDUCATOR_DEBUG:
            print("DEBUG ElevenLabs status:", r.status_code)
            print("DEBUG ElevenLabs content-type:", r.headers.get("content-type"))
            try:
                print("DEBUG ElevenLabs body:", (r.text or "")[:300])
            except Exception:
                print("DEBUG ElevenLabs body: <unavailable>")

        if r.status_code != 200:
            return None

        import base64
        return "audio/mpeg;base64," + base64.b64encode(r.content).decode("utf-8")
    except Exception as ex:
        if EDUCATOR_DEBUG:
            print("DEBUG ElevenLabs exception:", repr(ex))
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
        print("DEBUG: Eleven key loaded =", bool(ELEVENLABS_API_KEY), "voice id =", ELEVENLABS_VOICE_ID)
        print("DEBUG: Mongo enabled =", bool(MONGODB_URI))

    privacy = _bucket_privacy_evidence(analyst_output.evidence)
    explanation = _gemini_explanation(analyst_output, privacy, lang)

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
        if EDUCATOR_DEBUG:
            print("DEBUG: calling _voice_alert() now")
        voice = _voice_alert(explanation)

    return EducatorOutput(
        explanation=explanation,
        nextSteps=next_steps,
        learningPoints=learning_points,
        voiceAlert=voice
    )


class EducatorAgent:
    async def explain(
        self,
        analyst_output: AnalystOutput,
        user_id: str = "anonymous",
        lang: Optional[str] = None
    ) -> EducatorOutput:
        return await explain(analyst_output, user_id=user_id, lang=lang)

