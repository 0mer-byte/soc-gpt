"""Base interface for LLM providers.

Every LLM backend (Ollama, Claude, OpenAI) implements this interface
so the rest of the codebase can treat them interchangeably.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class TriageDecision:
    """An LLM's verdict on an alert."""
    verdict: str          # "benign" | "suspicious" | "malicious"
    confidence: float     # 0.0-1.0
    reasoning: str
    recommended_action: str

    def __str__(self) -> str:
        return f"{self.verdict.upper()} ({self.confidence:.0%}) — {self.recommended_action}"


class LLMProvider(ABC):
    """Abstract base — every LLM backend implements this."""

    @abstractmethod
    async def analyze_alert(self, alert_json: dict) -> TriageDecision:
        """Analyze a single alert and return a triage decision."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the provider (e.g. 'ollama', 'claude')."""
        pass