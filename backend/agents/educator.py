from typing import List, Optional

# Adjust these imports to match your repo
# Example:
# from backend.contracts import AnalystOutput, EducatorOutput
# If your contracts are elsewhere, update accordingly.

class EducatorAgent:
    def explain(self, analyst_output, language: str = "en", voice: bool = False):
        """
        Input: AnalystOutput
        Output: EducatorOutput
        Security pillar: threat detection + user protection + next steps.
        """

        risk = int(getattr(analyst_output, "riskScore", 0))
        threat = getattr(analyst_output, "threatType", "unknown")

        severity = self._severity_label(risk)
        explanation = self._build_explanation(threat, risk, severity, getattr(analyst_output, "evidence", []))
        next_steps = self._build_next_steps(threat)
        learning_points = self._build_learning_points(threat)

        voice_alert = self._build_voice_alert(threat, risk, severity) if voice else None

        # Return a dict if your project doesn’t use Pydantic models here.
        # If you DO have EducatorOutput as a model, return EducatorOutput(...)
        return {
            "explanation": explanation,
            "nextSteps": next_steps,
            "learningPoints": learning_points,
            "voiceAlert": voice_alert
        }

    def _severity_label(self, risk: int) -> str:
        if risk >= 70:
            return "HIGH"
        if risk >= 40:
            return "MEDIUM"
        return "LOW"

    def _build_explanation(self, threat: str, risk: int, severity: str, evidence: list) -> str:
        # Use only top 2 evidence points, don’t paste full user content
        ev = evidence[:2] if evidence else []
        bullets = []
        for e in ev:
            finding = (e.get("finding") if isinstance(e, dict) else None) or "Suspicious indicator detected"
            sev = (e.get("severity") if isinstance(e, dict) else None) or "unknown"
            bullets.append(f"- {finding} (severity: {sev})")

        why = "\n".join(bullets) if bullets else "- Multiple risk indicators were detected."

        return (
            f"🚨 SECURITY ALERT — {severity} RISK ({risk}/100)\n"
            f"Threat type: {threat.replace('_',' ').upper()}\n\n"
            f"Why this looks dangerous:\n{why}\n\n"
            "Recommendation: avoid interacting with the content until you verify the source through official channels."
        )

    def _build_next_steps(self, threat: str) -> List[str]:
        if threat in ["phishing", "scam"]:
            return [
                "Do not click links or open attachments from this message.",
                "Verify the sender using an official website or known phone number (not the message).",
                "Report it as phishing/scam in the platform you received it on.",
                "If you entered credentials, change your password immediately and enable MFA."
            ]
        if threat == "malware":
            return [
                "Do not run downloaded files or enable macros.",
                "Disconnect from the internet if something may have executed.",
                "Run a trusted antivirus scan and review recent downloads.",
                "Change passwords from a clean device if compromise is likely."
            ]
        if threat == "privacy_violation":
            return [
                "Avoid accepting terms until you review data collection and sharing details.",
                "Look for opt-outs (ads/analytics toggles, 'Do Not Sell/Share', privacy settings).",
                "Deny non-essential permissions (location/contacts) unless required for core features.",
                "Consider an alternative service with clearer retention and deletion rules."
            ]
        return [
            "Avoid interacting with the content until verified.",
            "Confirm legitimacy via official channels.",
            "Report suspicious activity if it repeats."
        ]

    def _build_learning_points(self, threat: str) -> List[str]:
        if threat in ["phishing", "scam"]:
            return [
                "Urgency and threats are common pressure tactics used in scams.",
                "Legitimate orgs rarely ask for passwords or codes through random links.",
                "Verify using official channels, not information inside the message."
            ]
        if threat == "privacy_violation":
            return [
                "Broad data sharing increases exposure to tracking and profiling risks.",
                "Unclear retention/deletion terms can mean data stays stored long-term.",
                "Extra permissions beyond the feature need are a risk signal."
            ]
        return [
            "High-risk content often combines multiple red flags at once.",
            "When unsure, verify first—don’t interact."
        ]

    def _build_voice_alert(self, threat: str, risk: int, severity: str) -> str:
        # Short, TTS-friendly
        return f"Warning. {severity} risk {threat.replace('_',' ')} detected. Do not click links. Verify the source."
