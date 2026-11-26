"""Quick test: send the malware alert to Groq alone, see if Llama 3.3 70B
correctly identifies it as MALICIOUS (which the small local model missed).
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.llm.groq_provider import GroqProvider


async def main():
    alert_path = (
        Path(__file__).parent.parent / "examples" / "malware_detected.json"
    )
    with open(alert_path) as f:
        alert = json.load(f)

    print(f"\n{'=' * 70}")
    print("Testing Groq (Llama 3.3 70B) on CryptoLocker alert")
    print(f"{'=' * 70}\n")

    print(f"Rule:       {alert['rule_description']}")
    print(f"Agent:      {alert['agent_name']}")
    print(f"Severity:   {alert['severity']}/15\n")

    print("Sending to Groq...\n")

    provider = GroqProvider()
    decision = await provider.analyze_alert(alert)

    print(f"{'-' * 70}")
    print(f"VERDICT:    {decision.verdict.upper()}")
    print(f"CONFIDENCE: {decision.confidence:.0%}")
    print(f"REASONING:  {decision.reasoning}")
    print(f"ACTION:     {decision.recommended_action}")
    print(f"{'-' * 70}\n")

    if decision.verdict == "malicious":
        print("✓ Groq correctly identified the ransomware as MALICIOUS")
        print("  (vs. local Ollama which incorrectly said BENIGN)")
    else:
        print(f"⚠ Groq said {decision.verdict.upper()} — larger model also missed this one")


if __name__ == "__main__":
    asyncio.run(main())