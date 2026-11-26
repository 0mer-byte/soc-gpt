"""Groq provider — runs gpt-oss-120b via Groq's free cloud API.

Groq is ~20x faster than local Ollama and uses a much larger model,
so verdicts are sharper. Used in consensus with the local Ollama provider.
"""

import json
import logging
import os

from dotenv import load_dotenv
from groq import Groq

from src.llm.base import LLMProvider, TriageDecision

load_dotenv()
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


class GroqProvider(LLMProvider):
    """LLM provider backed by Groq's cloud API (free tier)."""

    def __init__(self, model: str = "openai/gpt-oss-120b"):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY not found in environment. "
                "Check that .env exists at the project root and contains GROQ_API_KEY=..."
            )
        self.model = model
        self.client = Groq(api_key=api_key)

    @property
    def name(self) -> str:
        return f"groq/{self.model}"

    async def analyze_alert(self, alert_json: dict) -> TriageDecision:
        prompt = TRIAGE_USER_PROMPT.format(
            alert_json=json.dumps(alert_json, indent=2)
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
            )

            content = response.choices[0].message.content
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
            logger.error("Groq returned invalid JSON")
            return TriageDecision(
                verdict="suspicious",
                confidence=0.0,
                reasoning=f"LLM returned malformed JSON: {e}",
                recommended_action="Manual review — AI could not parse",
            )
        except Exception as e:
            logger.error("Groq call failed: %s", e)
            return TriageDecision(
                verdict="suspicious",
                confidence=0.0,
                reasoning=f"LLM call failed: {e}",
                recommended_action="Manual review — AI unavailable",
            )