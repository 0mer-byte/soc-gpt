"""Tests for the multi-LLM consensus engine using mock providers."""

import pytest

from src.core.consensus import ConsensusEngine
from src.llm.base import LLMProvider, TriageDecision


class MockProvider(LLMProvider):
    def __init__(self, name: str, verdict: str, confidence: float = 0.8):
        self._name = name
        self._verdict = verdict
        self._confidence = confidence

    @property
    def name(self) -> str:
        return self._name

    async def analyze_alert(self, alert_json: dict) -> TriageDecision:
        return TriageDecision(
            verdict=self._verdict,
            confidence=self._confidence,
            reasoning=f"Mock {self._name} reasoning",
            recommended_action="Mock action",
        )
            

@pytest.mark.asyncio
async def test_unanimous_vote():
    engine = ConsensusEngine([
        MockProvider("llm-a", "malicious", 0.9),
        MockProvider("llm-b", "malicious", 0.8),
    ])
    decision = await engine.analyze_alert({"test": "data"})
    assert decision.verdict == "malicious"
    assert "UNANIMOUS" in decision.reasoning


@pytest.mark.asyncio
async def test_split_vote_picks_conservative():
    """When votes tie, more severe verdict wins (safer to over-alert)."""
    engine = ConsensusEngine([
        MockProvider("llm-a", "benign", 0.9),
        MockProvider("llm-b", "malicious", 0.9),
    ])
    decision = await engine.analyze_alert({"test": "data"})
    assert decision.verdict == "malicious"
    assert "SPLIT" in decision.reasoning


@pytest.mark.asyncio
async def test_majority_vote():
    engine = ConsensusEngine([
        MockProvider("llm-a", "benign", 0.9),
        MockProvider("llm-b", "malicious", 0.9),
        MockProvider("llm-c", "malicious", 0.9),
    ])
    decision = await engine.analyze_alert({"test": "data"})
    assert decision.verdict == "malicious"
    assert "MAJORITY" in decision.reasoning