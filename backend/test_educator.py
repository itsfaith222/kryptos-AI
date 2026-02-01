import asyncio
from agents.educator import explain
from contracts import AnalystOutput

from contracts import AnalystOutput

async def main():
    # Make sure riskScore >= 70 so voice triggers
    analyst = AnalystOutput(
        analysisId="test123",
        threatType="phishing",
        riskScore=92,
        confidence=0.93,
        evidence=[
            {"type": "domain", "finding": "Domain created 2 days ago", "weight": 0.8, "severity": "high"},
            {"type": "content", "finding": "Urgent language asking to verify account immediately", "weight": 0.6, "severity": "medium"},
        ],
        mitreAttackTechniques=["T1566.002"]
    )

    out = await explain(analyst, user_id="nada", lang="en")
    print("\n=== EducatorOutput ===")
    print("explanation:", out.explanation)
    print("nextSteps:", out.nextSteps)
    print("learningPoints:", out.learningPoints)
    print("voiceAlert:", out.voiceAlert)

asyncio.run(main())
