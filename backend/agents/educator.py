from __future__ import annotations

import json
import os
import requests
from typing import List, Dict, Any, Optional

from contracts import AnalystOutput, EducatorOutput
from utils.env import load_env, env_bool, env_str, env_int
from utils.storage import ensure_dirs, safe_base_dir, audio_path

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _summarize_evidence(evidence: List[Dict[str, Any]], limit: int = 6) -> str:
    if not evidence:
        return "- No detailed evidence provided."

    lines = []
    for e in evidence[:limit]:
        finding = str(e.get("finding", "")).strip()
        etype = str(e.get("type", "")).strip()
        sev = str(e.get("severity", "")).strip()
        if not finding:
            continue
        tag = "/".join([x for x in [sev, etype] if x]) or "evidence"
        lines.append(f"- [{tag}] {finding}")

    return "\n".join(lines) if lines else "- No detailed evidence provided."


def _risk_tone(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _template_explain(a: AnalystOutput) -> EducatorOutput:
    score = int(a.riskScore or 0)
    tone = _risk_tone(score)

    if a.threatType == "privacy_violation":
        explanation = (
            f"{tone.upper()} privacy risk detected (score {score}/100). "
            f"Based on the evidence provided, this service may increase tracking, sharing, "
            f"or long-term retention of sensitive data. "
            f"Treat the data practices as unsafe unless you can verify stricter limits."
        )
        next_steps = [
            "Avoid accepting these terms unless you absolutely must.",
            "Deny or revoke high-risk permissions (especially background location).",
            "Check privacy settings for ad tracking, sharing, and data sale options.",
            "Minimize profile data and disable unnecessary integrations.",
            "Prefer alternatives with clear deletion controls.",
        ]
        learning = [
            "Continuous data collection increases surveillance risk.",
            "Third-party sharing expands exposure across vendor networks.",
            "Unclear retention policies increase long-term impact after breaches.",
        ]
    else:
        explanation = (
            f"{tone.upper()} security risk detected (score {score}/100). "
            f"Based on the evidence provided, this content should be treated as untrusted. "
            f"Protective action is recommended before interacting further."
        )
        next_steps = [
            "Do not click links or open attachments.",
            "Verify the sender using official channels.",
            "Change affected passwords and enable MFA if interaction occurred.",
            "Report and block the sender or domain.",
        ]
        learning = [
            "Urgency and pressure are common scam indicators.",
            "Unknown links are common malware delivery paths.",
            "Verification through trusted channels reduces risk.",
        ]

    return EducatorOutput(
        explanation=explanation.strip(),
        nextSteps=[x.strip() for x in next_steps],
        learningPoints=[x.strip() for x in learning],
        voiceAlert=None,
    )


def _openrouter_chat(system: str, user: str) -> str:
    api_key = env_str("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("Missing OPENROUTER_API_KEY")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": env_str("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
    }

    r = requests.post(
        OPENROUTER_URL,
        headers=headers,
        json=payload,
        timeout=env_int("EDUCATOR_HTTP_TIMEOUT", 45),
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        return json.loads(t)
    except Exception:
        return None


def _llm_explain_openrouter(a: AnalystOutput) -> EducatorOutput:
    system = (
        "You are Guardian AI - Educator agent. SECURITY PILLAR ONLY. "
        "Explain risk and give protective steps. No empowerment framing."
    )

    user = f"""
threatType: {a.threatType}
riskScore: {a.riskScore}
confidence: {a.confidence}

evidence:
{_summarize_evidence(a.evidence)}

Return JSON with keys:
explanation, nextSteps, learningPoints
""".strip()

    try:
        raw = _openrouter_chat(system, user)
        data = _parse_json(raw)
    except Exception:
        return _template_explain(a)

    if not data:
        return _template_explain(a)

    return EducatorOutput(
        explanation=str(data.get("explanation", "")).strip(),
        nextSteps=[str(x).strip() for x in data.get("nextSteps", [])],
        learningPoints=[str(x).strip() for x in data.get("learningPoints", [])],
        voiceAlert=None,
    )


def _elevenlabs_tts(text: str, out_path: str) -> Optional[str]:
    api_key = env_str("ELEVENLABS_API_KEY", "")
    voice_id = env_str("ELEVENLABS_VOICE_ID", "")
    if not api_key or not voice_id:
        return None

    r = requests.post(
        f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}",
        headers={
            "xi-api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "audio/mpeg",
        },
        json={"text": text},
        timeout=45,
    )

    if r.status_code != 200:
        return None

    with open(out_path, "wb") as f:
        f.write(r.content)

    return out_path.strip()


def explain(analyst: AnalystOutput) -> EducatorOutput:
    load_env()
    base_dir = safe_base_dir()
    ensure_dirs(base_dir)

    use_llm = env_bool("ENABLE_LLM", True)
    use_voice = env_bool("ENABLE_ELEVENLABS", False)
    reuse_voice = env_bool("EDUCATOR_VOICE_SKIP_IF_EXISTS", True)

    if use_llm and not env_str("OPENROUTER_API_KEY", ""):
        use_llm = False

    edu = _llm_explain_openrouter(analyst) if use_llm else _template_explain(analyst)

    if use_voice:
        mp3 = audio_path(base_dir, f"educator_alert_{analyst.analysisId}.mp3")
        if reuse_voice and os.path.exists(mp3):
            edu.voiceAlert = mp3.strip()
        else:
            edu.voiceAlert = _elevenlabs_tts(
                f"Security alert. Privacy risk detected. {edu.nextSteps[0]}",
                mp3,
            )

    if edu.voiceAlert:
        edu.voiceAlert = str(edu.voiceAlert).strip()

    return edu


class EducatorAgent:
    async def explain(
        self,
        analyst: AnalystOutput,
        user_id: Optional[str] = None,
        lang: str = "en",
    ) -> EducatorOutput:
        return explain(analyst)
