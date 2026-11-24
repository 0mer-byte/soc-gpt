"""Ollama provider — runs local Llama models for alert triage."""

import json
import logging

import ollama

from src.llm.base import LLMProvider, TriageDecision

logger = logging.getLogger(__name__)


TRIAGE_SYSTEM_PROMPT = """You are a Tier-1 SOC (Security Operations Center) analyst.
Your job is to triage SIEM alerts from Wazuh and decide whether each one is benign,
suspicious, or malicious. You must respond with valid JSON only — no markdown, no prose."""


TRIAGE_USER_PROMPT = """Analyze this security alert and return your verdict.

Alert:
{alert_json}

Respond with ONLY a JSON object in this exact format:
{{
  "verdict": "benign" | "suspicious" | "malicious",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<2-3 sentences explaining your decision>",
  "recommended_action": "<1 sentence: what should the SOC team do?>"
}}"""


class OllamaProvider(LLMProvider):
    """LLM provider backed by a local Ollama server."""

    def __init__(self, model: str = "llama3.2:3b", host: str = "http://localhost:11434"):
        self.model = model
        self.client = ollama.Client(host=host)

    @property
    def name(self) -> str:
        return f"ollama/{self.model}"

    async def analyze_alert(self, alert_json: dict) -> TriageDecision:
        prompt = TRIAGE_USER_PROMPT.format(
            alert_json=json.dumps(alert_json, indent=2)
        )

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                format="json",
                options={"temperature": 0.2},
            )

            content = response["message"]["content"]
            data = json.loads(content)

            return TriageDecision(
                verdict=data.get("verdict", "suspicious"),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", "No reasoning provided"),
                recommended_action=data.get(
                    "recommended_action", "Manual review required"
                ),
            )

        except json.JSONDecodeError as e:
            logger.error(f"Llama returned invalid JSON: {content[:200]}")
            return TriageDecision(
                verdict="suspicious",
                confidence=0.0,
                reasoning=f"LLM returned malformed JSON: {e}",
                recommended_action="Manual review — AI could not parse",
            )
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            return TriageDecision(
                verdict="suspicious",
                confidence=0.0,
                reasoning=f"LLM call failed: {e}",
                recommended_action="Manual review — AI unavailable",
            )