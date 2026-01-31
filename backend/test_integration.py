"""
HOUR 6: First Integration Test
Mock Orchestrator calling Analyst
"""

import asyncio
import sys
import os

# Ensure 'backend/' is on the path so 'from agents.analyst' resolves
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def test_integration():
    print("=" * 60)
    print("🧪 HOUR 6: FIRST INTEGRATION TEST")
    print("🎯 Testing: Orchestrator → Analyst")
    print("=" * 60)

    # Import here so any ImportError is visible
    from agents.analyst import AnalystAgent

    # Mock Scout data (would come from extension in real system)
    scout_data = {
        "url": "https://amaz0n-delivery.tk/track",
        "content": """
        Dear Customer,

        Your package delivery failed. Click here immediately to reschedule.
        Failure to respond within 24 hours will result in package return.

        Verify your address and payment details.
        """,
        "scanType": "email",
        "signals": {
            "hasPassword": False,
            "hasEmail": True,
            "urgencyWords": ["immediately", "24 hours", "failure"],
            "sslValid": False,
            "externalLinks": 3,
        },
    }

    # Create Analyst (no DB yet - will add in Hour 12)
    print("\n[ORCHESTRATOR] Creating Analyst...")
    analyst = AnalystAgent(db=None)

    # Call Analyst
    print("[ORCHESTRATOR] Sending scout data to Analyst...")
    result = await analyst.analyze_threat(scout_data)

    # ── Display what Orchestrator receives ──────────────────────────
    # Keys match what analyst.py actually returns:
    #   mitreAttackTechniques  (list of dicts with 'id', 'name', etc.)
    #   manipulationTactics    (list of dicts with 'type', 'example', etc.)
    #   nextSteps              (list of strings)

    mitre_ids = [t["id"] for t in result.get("mitreAttackTechniques", [])]
    mitre_names = [t["name"] for t in result.get("mitreAttackTechniques", [])]
    tactic_types = [t["type"] for t in result.get("manipulationTactics", [])]

    print("\n" + "=" * 60)
    print("📊 ORCHESTRATOR RECEIVED:")
    print("=" * 60)
    print(f"Analysis ID:  {result['analysisId'][:8]}...")
    print(f"Threat Type:  {result['threatType']}")
    print(f"Risk Score:   {result['riskScore']}/100")
    print(f"Confidence:   {result['confidence']:.0%}")
    print(f"Explanation:  {result.get('explanation', 'N/A')}")
    print(f"\nMITRE IDs:    {', '.join(mitre_ids) if mitre_ids else 'None'}")
    print(f"MITRE Names:  {', '.join(mitre_names) if mitre_names else 'None'}")
    print(f"Tactics:      {', '.join(tactic_types) if tactic_types else 'None'}")
    print(f"Next Steps:   {result.get('nextSteps', [])}")
    print(f"\nWHOIS Domain Age: {result.get('whoisData', {}).get('domainAgeDays')} days")
    print(f"WHOIS Suspicion:  {result.get('whoisData', {}).get('suspicionScore')}/100")

    print("\n" + "=" * 60)
    print("✅ FIRST INTEGRATION SUCCESS!")
    print("   Orchestrator can call Analyst ✓")
    print("   Contract format matches       ✓")
    print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(test_integration())
    except Exception as e:
        # This is why it was silent before — errors were swallowed
        print(f"\n❌ CRASHED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()