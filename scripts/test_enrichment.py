"""Quick test: look up a known Tor exit node and a benign IP via AbuseIPDB."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.enrichment import EnrichmentService


async def main():
    service = EnrichmentService()

    print("\nTesting AbuseIPDB enrichment:\n")

    # Known Tor exit node (from sample_alert.json)
    print("1. 185.220.101.34 (known Tor exit node):")
    result = await service.enrich({"source_ip": "185.220.101.34"})
    print(f"   {result.summary()}\n")

    # Google DNS (benign)
    print("2. 8.8.8.8 (Google DNS):")
    result = await service.enrich({"source_ip": "8.8.8.8"})
    print(f"   {result.summary()}\n")

    # Private IP (should skip)
    print("3. 10.0.1.42 (private IP):")
    result = await service.enrich({"source_ip": "10.0.1.42"})
    print(f"   {result.summary()}\n")


if __name__ == "__main__":
    asyncio.run(main())