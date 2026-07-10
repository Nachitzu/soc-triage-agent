"""Shared fixtures. No test in this suite is allowed to reach the network."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from src.schemas.normalized_alert import NormalizedAlert

VALID_TRIAGE = {
    "alert_id": "a-2941",
    "severity": "CRITICAL",
    "false_positive_probability": 0.05,
    "confidence": 0.92,
    "mitre_techniques": ["T1110 - Brute Force"],
    "key_evidence": ["47 failed SSH logins followed by a successful login"],
    "summary": "Probable compromise of a domain controller via SSH brute force.",
    "recommended_action": "block_and_escalate",
}


class _FakeMessages:
    def __init__(self, parent: "FakeClient") -> None:
        self._parent = parent

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self._parent.calls.append(kwargs)
        if not self._parent.responses:
            raise AssertionError("FakeClient ran out of scripted responses")
        text = self._parent.responses.pop(0)
        # Mirror the real shape: adaptive thinking puts a thinking block first.
        blocks: list[SimpleNamespace] = []
        if self._parent.with_thinking:
            blocks.append(SimpleNamespace(type="thinking", thinking="..."))
        blocks.append(SimpleNamespace(type="text", text=text))
        return SimpleNamespace(content=blocks, stop_reason="end_turn")


@dataclass
class FakeClient:
    """Stands in for `anthropic.Anthropic`, replaying scripted responses."""

    responses: list[str]
    with_thinking: bool = False
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.messages = _FakeMessages(self)


@pytest.fixture
def valid_triage_json() -> str:
    return json.dumps(VALID_TRIAGE)


@pytest.fixture
def alert() -> NormalizedAlert:
    """A complete alert: brute force against a domain controller."""
    return NormalizedAlert(
        alert_id="a-2941",
        timestamp="2026-07-08T03:12:44Z",
        rule_id="SSH-BRUTE-01",
        alert_type="authentication_failure_burst",
        source_ip="185.220.101.34",
        dest_ip="10.0.1.12",
        raw_log="47 failed SSH logins for user 'admin' in 120s, followed by 1 successful login",
        asset_tag="domain_controller",
        protocol="TCP",
        port=22,
    )


@pytest.fixture
def degraded_alert() -> NormalizedAlert:
    """An alert from a source that records no network context (MachineLearningCVE)."""
    return NormalizedAlert(
        alert_id="a-0000000001",
        rule_id="SSH-BRUTE-01",
        alert_type="authentication_failure_burst",
        raw_log="SSH-BRUTE-01 matched flow to destination port 22: 47 forward packets.",
        port=22,
    )


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure a stray real key in the environment can never be used by a test."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("TRIAGE_MODEL", raising=False)
    monkeypatch.delenv("TRIAGE_THINKING", raising=False)
