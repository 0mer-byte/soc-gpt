"""End-to-end test: load a sample alert, send to Ollama, print the triage decision."""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path so we can import from src/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.llm.ollama_provider import OllamaProvider


async def main():
    alert_path = Path(__file__).parent.parent / "examples" / "sample_alert.json"
    with open(alert_path) as f:
        alert = json.load(f)

    print(f"\n{'=' * 70}")
    print("SOC-GPT 2.0 — Alert Triage Test")
    print(f"{'=' * 70}\n")

    print(f"Alert ID:       {alert['alert_id']}")
    print(f"Rule:           {alert['rule_description']}")
    print(f"Agent:          {alert['agent_name']} ({alert['agent_ip']})")
    print(f"Source IP:      {alert.get('source_ip', 'N/A')}")
    print(f"Severity:       {alert['severity']}/15")
    print(f"Notes:          {alert.get('notes', 'N/A')}\n")

    print("Sending to Llama 3.2 for analysis (may take 10-30s on first run)...\n")

    provider = OllamaProvider()
    decision = await provider.analyze_alert(alert)

    print(f"{'-' * 70}")
    print(f"VERDICT:        {decision.verdict.upper()}")
    print(f"CONFIDENCE:     {decision.confidence:.0%}")
    print(f"REASONING:      {decision.reasoning}")
    print(f"ACTION:         {decision.recommended_action}")
    print(f"{'-' * 70}\n")


if __name__ == "__main__":
    asyncio.run(main())