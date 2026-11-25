"""Batch triage — fire every sample alert at the live webhook and summarize."""

import json
from pathlib import Path

import httpx

WEBHOOK_URL = "http://localhost:8000/webhook/alert"
EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def main():
    alert_files = sorted(EXAMPLES_DIR.glob("*.json"))

    print(f"\n{'=' * 95}")
    print(f"SOC-GPT 2.0 — Batch Triage of {len(alert_files)} Alerts")
    print(f"{'=' * 95}\n")

    results = []

    for i, alert_file in enumerate(alert_files, 1):
        with open(alert_file) as f:
            alert = json.load(f)

        print(f"[{i}/{len(alert_files)}] {alert_file.name}")
        print(f"    Rule: {alert['rule_description']}")
        print(f"    Sending to webhook...", end=" ", flush=True)

        try:
            r = httpx.post(WEBHOOK_URL, json=alert, timeout=180.0)
            r.raise_for_status()
            decision = r.json()
            print("done.")
            print(f"    Verdict: {decision['verdict'].upper()} ({decision['confidence']:.0%})")
            print(f"    Action:  {decision['action_taken']}")
            print()
            results.append(
                {
                    "file": alert_file.name,
                    "verdict": decision["verdict"],
                    "confidence": decision["confidence"],
                    "action": decision["action_taken"],
                }
            )
        except Exception as e:
            print(f"ERROR: {e}\n")
            results.append({"file": alert_file.name, "error": str(e)[:60]})

    # Summary table
    print(f"\n{'=' * 95}")
    print("SUMMARY")
    print(f"{'=' * 95}")
    print(f"{'ALERT FILE':<35} {'VERDICT':<13} {'CONF':<8} {'ACTION'}")
    print(f"{'-' * 95}")
    for r in results:
        if "error" in r:
            print(f"{r['file']:<35} ERROR: {r['error']}")
        else:
            conf = f"{r['confidence']:.0%}"
            action_short = r["action"].split(" (")[0]
            print(f"{r['file']:<35} {r['verdict'].upper():<13} {conf:<8} {action_short}")
    print(f"{'=' * 95}\n")


if __name__ == "__main__":
    main()