import asyncio
import json
from agents.educator import EducatorAgent
from contracts import AnalystOutput


def _to_dict(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return obj


def pretty_print(out):
    d = _to_dict(out)

    border = "=" * 30
    print("\n" + border)
    print(" Guardian AI • Educator Output ")
    print(border + "\n")

    print("🧠 Explanation\n" + "-" * 28)
    print(d["explanation"].strip(), "\n")

    print("✅ Next Steps\n" + "-" * 28)
    for i, s in enumerate(d["nextSteps"], 1):
        print(f"{i}. {s.strip()}")
    print()

    print("📌 Learning Points\n" + "-" * 28)
    for i, s in enumerate(d["learningPoints"], 1):
        print(f"{i}. {s.strip()}")
    print()

    print("🔊 Voice Alert\n" + "-" * 28)
    print(d["voiceAlert"] if d["voiceAlert"] else "(disabled)")
    print()

    print("🧾 Raw JSON\n" + "-" * 28)
    print(json.dumps(d, indent=2, ensure_ascii=False))
    print()


async def main():
    agent = EducatorAgent()
    mock = AnalystOutput(
        analysisId="test123",
        threatType="privacy_violation",
        riskScore=87,
        confidence=0.92,
        evidence=[
            {"type": "privacy", "finding": "Collects your exact location 24/7", "severity": "high"},
            {"type": "sharing", "finding": "Shares data with advertisers", "severity": "high"},
            {"type": "retention", "finding": "No deletion option; data retained indefinitely", "severity": "high"},
        ],
        mitreAttackTechniques=[],
    )

    out = await agent.explain(mock)
    pretty_print(out)


if __name__ == "__main__":
    asyncio.run(main())
