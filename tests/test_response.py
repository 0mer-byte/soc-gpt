"""Tests for decision router and critical keyword safety rail."""

from src.core.response import route_decision, _has_critical_keyword
from src.llm.base import TriageDecision


def test_critical_keyword_detected():
    assert _has_critical_keyword("ClamAV detected malware") == "malware"
    assert _has_critical_keyword("Trojan.CryptoLocker found") == "trojan"
    assert _has_critical_keyword("sudo to root detected") == "sudo to root"
    assert _has_critical_keyword("Normal web traffic") is None


def test_safety_rail_overrides_wrong_benign():
    """A benign verdict on a malware rule should be escalated by the safety rail."""
    decision = TriageDecision(
        verdict="benign", confidence=0.95,
        reasoning="Looks fine", recommended_action="Close",
    )
    action = route_decision(decision, rule_description="ClamAV detected malware")
    assert "OVERRIDE" in action
    assert "ESCALATE" in action


def test_high_confidence_malicious_auto_blocks():
    decision = TriageDecision(
        verdict="malicious", confidence=0.9,
        reasoning="Clear attack", recommended_action="Block",
    )
    action = route_decision(decision, rule_description="Some rule")
    assert "AUTO-BLOCK" in action


def test_benign_auto_closes():
    decision = TriageDecision(
        verdict="benign", confidence=0.9,
        reasoning="Normal", recommended_action="Close",
    )
    action = route_decision(decision, rule_description="Normal operation")
    assert "AUTO-CLOSE" in action


def test_low_confidence_malicious_escalates_instead_of_blocking():
    decision = TriageDecision(
        verdict="malicious", confidence=0.5,
        reasoning="Maybe", recommended_action="Investigate",
    )
    action = route_decision(decision, rule_description="Some rule")
    assert "ESCALATE" in action
    