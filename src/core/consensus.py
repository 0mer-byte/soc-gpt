"""Consensus engine — runs an alert through multiple LLMs and takes majority vote.

Why: A single LLM (especially a small one) can misclassify. Running the same alert
through multiple models and voting catches cases where one model is confidently wrong.
Ties break conservatively — if votes split evenly between benign and malicious,
malicious wins, because it's safer to over-alert than to silently miss a threat.
"""

import asyncio
import logging
from collections import Counter

from src.llm.base import LLMProvider, TriageDecision

logger = logging.getLogger(__name__)

# On ties, prefer more conservative verdicts (higher = more severe)
VERDICT_SEVERITY = {"benign": 0, "suspicious": 1, "malicious": 2}


class ConsensusEngine:
    """Runs an alert through multiple LLM providers in parallel and votes."""

    def __init__(self, providers: list[LLMProvider]):
        if not providers:
            raise ValueError("ConsensusEngine requires at least one provider")
        self.providers = providers

    @property
    def name(self) -> str:
        short_names = [p.name.split("/")[-1] for p in self.providers]
        return "consensus(" + "+".join(short_names) + ")"

    async def analyze_alert(self, alert_json: dict) -> TriageDecision:
        """Run all providers in parallel, aggregate by majority vote."""

        results = await asyncio.gather(
            *[p.analyze_alert(alert_json) for p in self.providers],
            return_exceptions=True,
        )

        decisions = []
        vote_details = []

        for provider, result in zip(self.providers, results):
            short = provider.name.split("/")[-1]
            if isinstance(result, Exception):
                logger.error("Provider %s failed: %s", provider.name, result)
                vote_details.append(f"{short}=ERROR")
                continue
            decisions.append((provider, result))
            vote_details.append(
                f"{short}={result.verdict}({int(result.confidence*100)}%)"
            )

        if not decisions:
            return TriageDecision(
                verdict="suspicious",
                confidence=0.0,
                reasoning=f"All LLM providers failed. Votes: {' | '.join(vote_details)}",
                recommended_action="Manual review — all AI providers unavailable",
            )

        # Count verdicts
        counts = Counter(d.verdict for _, d in decisions)
        top = counts.most_common()

        # Agreement classification
        if len(top) == 1 and top[0][1] == len(decisions):
            agreement = "UNANIMOUS"
            winner = top[0][0]
        elif len(top) >= 2 and top[0][1] > top[1][1]:
            agreement = "MAJORITY"
            winner = top[0][0]
        else:
            # Tie — pick more conservative
            agreement = "SPLIT"
            tied = [v for v, c in top if c == top[0][1]]
            winner = max(tied, key=lambda v: VERDICT_SEVERITY.get(v, 0))

        agreeing = [d for _, d in decisions if d.verdict == winner]
        avg_conf = sum(d.confidence for d in agreeing) / len(agreeing)

        # Combined reasoning from agreeing providers
        reasoning_parts = [
            f"[{p.name.split('/')[-1]}] {d.reasoning}"
            for p, d in decisions
            if d.verdict == winner
        ]
        combined = f"[{agreement}] {' | '.join(reasoning_parts)}"

        # Action from highest-confidence agreeing provider
        best = max(agreeing, key=lambda d: d.confidence)

        logger.info(
            "Consensus: %s (%s) | votes: %s",
            winner.upper(), agreement, " | ".join(vote_details),
        )

        return TriageDecision(
            verdict=winner,
            confidence=avg_conf,
            reasoning=combined,
            recommended_action=best.recommended_action,
        )