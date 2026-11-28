"""Enrichment service — adds external threat intel to alerts before LLM triage.

Right now we enrich with AbuseIPDB (IP reputation). Future providers (VirusTotal,
GeoIP, MISP, Shodan) plug into the same interface.
"""

import logging
import os
from dataclasses import dataclass, field

import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


@dataclass
class EnrichmentData:
    """Threat intel attached to an alert before triage."""

    abuse_score: int | None = None          # 0-100 confidence
    country: str | None = None
    isp: str | None = None
    usage_type: str | None = None           # "Data Center", "Fixed Line ISP", "Tor" etc.
    total_reports: int = 0
    last_reported_at: str | None = None
    is_tor: bool = False
    is_whitelisted: bool = False
    raw: dict = field(default_factory=dict)
    source: str = "none"                    # "abuseipdb" or "none"

    def summary(self) -> str:
        """Human-readable summary — the LLM sees this in its prompt."""
        if self.source == "none":
            return "No external enrichment data available."

        parts = []
        if self.abuse_score is not None:
            parts.append(f"abuse_confidence_score={self.abuse_score}/100")
        if self.country:
            parts.append(f"country={self.country}")
        if self.usage_type:
            parts.append(f"usage_type={self.usage_type}")
        if self.isp:
            parts.append(f"isp={self.isp}")
        if self.total_reports:
            parts.append(f"reports_in_last_90_days={self.total_reports}")
        if self.is_tor:
            parts.append("tor_exit_node=YES")
        if self.is_whitelisted:
            parts.append("whitelisted=YES")
        return " | ".join(parts) if parts else "No data returned."


class EnrichmentService:
    """Pulls threat intel for alerts before LLM triage."""

    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        if not self.abuseipdb_key:
            logger.warning(
                "ABUSEIPDB_API_KEY not set — IP enrichment will be skipped"
            )

    async def enrich(self, alert_json: dict) -> EnrichmentData:
        """Return enrichment data for the alert's source IP, if available."""
        source_ip = alert_json.get("source_ip")

        if not source_ip:
            return EnrichmentData()

        if not self.abuseipdb_key:
            return EnrichmentData()

        if self._is_private_ip(source_ip):
            logger.info("Skipping enrichment for private IP %s", source_ip)
            return EnrichmentData()

        try:
            return await self._query_abuseipdb(source_ip)
        except Exception as e:
            logger.error("AbuseIPDB enrichment failed for %s: %s", source_ip, e)
            return EnrichmentData()

    async def _query_abuseipdb(self, ip: str) -> EnrichmentData:
        """Query AbuseIPDB for an IP's reputation."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json",
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()["data"]

        logger.info(
            "AbuseIPDB enrichment for %s: score=%s, country=%s, reports=%s",
            ip, data.get("abuseConfidenceScore"), data.get("countryCode"),
            data.get("totalReports"),
        )

        return EnrichmentData(
            abuse_score=data.get("abuseConfidenceScore"),
            country=data.get("countryCode"),
            isp=data.get("isp"),
            usage_type=data.get("usageType") or None,
            total_reports=data.get("totalReports", 0),
            last_reported_at=data.get("lastReportedAt"),
            is_tor=bool(data.get("isTor", False)),
            is_whitelisted=bool(data.get("isWhitelisted", False)),
            raw=data,
            source="abuseipdb",
        )

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """RFC 1918 private, loopback, or link-local — skip enrichment for these."""
        private_prefixes = [
            "10.", "127.", "169.254.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
        ]
        return any(ip.startswith(p) for p in private_prefixes)