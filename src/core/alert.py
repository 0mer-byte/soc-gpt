"""Alert data model — represents a single SIEM alert."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Alert:
    """Normalized SIEM alert from any source (Wazuh, Elastic, Splunk)."""

    alert_id: str
    timestamp: datetime
    source: str              # e.g. "wazuh"
    rule_id: str
    rule_description: str
    severity: int            # 0-15 (Wazuh scale)
    agent_name: str
    agent_ip: str
    raw_log: str
    enriched_data: dict = field(default_factory=dict)

    @property
    def severity_score(self) -> int:
        """Convert 0-15 Wazuh severity to 0-100 scale."""
        return min(int(self.severity * 100 / 15), 100)

    def __str__(self) -> str:
        return f"[{self.severity_score}] {self.rule_description} on {self.agent_name}"