"""Decision router — maps triage decisions to concrete actions.

Defense-in-depth design:
1. Critical keyword guard — rules matching known-dangerous patterns can
   NEVER auto-close, regardless of LLM verdict. The LLM is overridden.
2. LLM verdict + confidence thresholds decide between escalate and auto-respond.

In production, auto-response would EXECUTE: UFW firewall rules, Wazuh Active
Response, Slack webhooks, PagerDuty escalations. For now, actions are simulated
and logged.
"""

import logging

from src.llm.base import TriageDecision

logger = logging.getLogger(__name__)

AUTO_RESPONSE_CONFIDENCE = 0.80
ESCALATION_CONFIDENCE = 0.60

# Keywords that force escalation regardless of LLM verdict.
# If any of these appear in the rule description, the alert is NEVER auto-closed.
CRITICAL_KEYWORDS = {
    "malware", "trojan", "ransomware", "rootkit", "backdoor",
    "exploit", "cve-", "rce", "reverse shell",
    "privilege escalation", "sudo to root",
    "data exfiltration", "credential dump", "mimikatz",
    "lateral movement", "c2", "command and control",
}


def _has_critical_keyword(rule_description: str) -> str | None:
    """Return the matching keyword if one is found in the rule, else None."""
    rule_lower = rule_description.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in rule_lower:
            return kw
    return None


def route_decision(decision: TriageDecision, rule_description: str = "") -> str:
    """Pick an action based on verdict + confidence + safety rails.

    Returns the action label.
    """
    verdict = decision.verdict.lower()
    confidence = decision.confidence

    # SAFETY RAIL: critical keywords cannot be auto-closed
    critical_match = _has_critical_keyword(rule_description)
    if critical_match and verdict == "benign":
        action = f"ESCALATE [OVERRIDE: '{critical_match}' detected despite LLM benign verdict]"
        logger.error(
            "[SAFETY OVERRIDE] LLM said BENIGN but rule contains '%s' — escalating instead",
            critical_match,
        )
        return action

    # High-confidence malicious → auto-block
    if verdict == "malicious" and confidence >= AUTO_RESPONSE_CONFIDENCE:
        action = "AUTO-BLOCK (simulated firewall rule)"
        logger.warning("[AUTO-RESPONSE] %s | confidence=%.0f%%", action, confidence * 100)
        return action

    # Lower-confidence malicious or mid+ suspicious → escalate
    if verdict == "malicious" or (verdict == "suspicious" and confidence >= ESCALATION_CONFIDENCE):
        action = "ESCALATE (simulated Slack alert to SOC team)"
        logger.info("[ESCALATION] %s | confidence=%.0f%%", action, confidence * 100)
        return action

    # Benign or weak suspicious → auto-close
    action = "AUTO-CLOSE (logged for review, no action)"
    logger.info("[AUTO-CLOSE] %s | confidence=%.0f%%", action, confidence * 100)
    return action