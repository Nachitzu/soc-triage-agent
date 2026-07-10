"""The output schema is the safety boundary; these tests pin its guarantees."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.schemas.normalized_alert import NormalizedAlert, is_internal_ip
from src.schemas.triage_output import TriageOutput

BASE_OUTPUT = {
    "alert_id": "a-1",
    "severity": "HIGH",
    "false_positive_probability": 0.1,
    "confidence": 0.9,
    "mitre_techniques": ["T1110 - Brute Force"],
    "key_evidence": ["47 failed logins"],
    "summary": "Brute force against an internal host.",
    "recommended_action": "escalate_tier2",
}


def _output(**overrides: object) -> TriageOutput:
    return TriageOutput.model_validate({**BASE_OUTPUT, **overrides})


class TestTriageOutputEscalationRules:
    """The two rules a triage agent must never break."""

    def test_low_confidence_cannot_close_an_alert(self) -> None:
        with pytest.raises(ValidationError, match="Low-confidence triage cannot close"):
            _output(confidence=0.59, recommended_action="close_false_positive")

    def test_confident_close_is_allowed(self) -> None:
        assert _output(confidence=0.6, recommended_action="close_false_positive")

    def test_low_confidence_may_still_escalate(self) -> None:
        assert _output(confidence=0.2, recommended_action="escalate_tier2")
        assert _output(confidence=0.2, recommended_action="needs_more_data")

    def test_block_requires_critical_severity(self) -> None:
        with pytest.raises(ValidationError, match="block_and_escalate requires"):
            _output(
                severity="HIGH", confidence=0.95, recommended_action="block_and_escalate"
            )

    def test_block_requires_high_confidence(self) -> None:
        with pytest.raises(ValidationError, match="block_and_escalate requires"):
            _output(
                severity="CRITICAL",
                confidence=0.79,
                recommended_action="block_and_escalate",
            )

    def test_block_at_the_confidence_boundary(self) -> None:
        assert _output(
            severity="CRITICAL", confidence=0.8, recommended_action="block_and_escalate"
        )


class TestTriageOutputFieldConstraints:
    def test_key_evidence_must_not_be_empty(self) -> None:
        with pytest.raises(ValidationError):
            _output(key_evidence=[])

    def test_key_evidence_caps_at_five_items(self) -> None:
        assert _output(key_evidence=["a", "b", "c", "d", "e"])
        with pytest.raises(ValidationError):
            _output(key_evidence=["a", "b", "c", "d", "e", "f"])

    def test_mitre_techniques_may_be_empty(self) -> None:
        """The prompt forbids forcing a mapping, so an empty list must validate."""
        assert _output(mitre_techniques=[]).mitre_techniques == []

    @pytest.mark.parametrize("value", [-0.01, 1.01])
    def test_probabilities_are_bounded(self, value: float) -> None:
        with pytest.raises(ValidationError):
            _output(false_positive_probability=value)
        with pytest.raises(ValidationError):
            _output(confidence=value)

    def test_severity_is_a_closed_set(self) -> None:
        with pytest.raises(ValidationError):
            _output(severity="SEVERE")

    def test_recommended_action_is_a_closed_set(self) -> None:
        with pytest.raises(ValidationError):
            _output(recommended_action="ignore")

    def test_summary_must_not_be_empty(self) -> None:
        with pytest.raises(ValidationError):
            _output(summary="")


class TestNormalizedAlert:
    def test_naive_timestamp_is_interpreted_as_utc(self) -> None:
        alert = NormalizedAlert(
            alert_id="a-1",
            timestamp=datetime(2026, 7, 8, 3, 12, 44),
            rule_id="R",
            alert_type="t",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            raw_log="x",
        )
        assert alert.timestamp is not None
        assert alert.timestamp.tzinfo is timezone.utc

    def test_aware_timestamp_is_preserved(self) -> None:
        alert = NormalizedAlert(
            alert_id="a-1",
            timestamp="2026-07-08T03:12:44Z",
            rule_id="R",
            alert_type="t",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            raw_log="x",
        )
        assert alert.timestamp == datetime(2026, 7, 8, 3, 12, 44, tzinfo=timezone.utc)

    def test_malformed_ip_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not a valid IP address"):
            NormalizedAlert(
                alert_id="a-1",
                rule_id="R",
                alert_type="t",
                source_ip="10.0.0.999",
                dest_ip="10.0.0.2",
                raw_log="x",
            )

    def test_port_range_is_enforced(self) -> None:
        with pytest.raises(ValidationError):
            NormalizedAlert(
                alert_id="a-1", rule_id="R", alert_type="t", raw_log="x", port=65536
            )

    def test_degraded_alert_reports_its_missing_fields(
        self, degraded_alert: NormalizedAlert
    ) -> None:
        assert degraded_alert.has_network_context is False
        assert degraded_alert.missing_fields == [
            "timestamp",
            "source_ip",
            "dest_ip",
            "protocol",
        ]

    def test_complete_alert_has_network_context(self, alert: NormalizedAlert) -> None:
        assert alert.has_network_context is True
        assert alert.missing_fields == []
        assert alert.source_is_internal is False
        assert alert.dest_is_internal is True


class TestIsInternalIp:
    @pytest.mark.parametrize("ip", ["10.0.1.12", "172.16.0.1", "192.168.10.50"])
    def test_rfc1918_ranges_are_internal(self, ip: str) -> None:
        assert is_internal_ip(ip) is True

    @pytest.mark.parametrize("ip", ["185.220.101.34", "8.8.8.8"])
    def test_public_addresses_are_not_internal(self, ip: str) -> None:
        assert is_internal_ip(ip) is False

    @pytest.mark.parametrize("value", [None, "not-an-ip", ""])
    def test_missing_or_malformed_is_not_internal(self, value: str | None) -> None:
        assert is_internal_ip(value) is False
