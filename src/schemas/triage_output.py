"""Output schema: the strict contract every agent response must satisfy.

Validation is the safety boundary of this project. The model is instructed to
emit this JSON, but nothing downstream trusts it until it has passed through
`TriageOutput`. The `enforce_confidence_rules` validator encodes the two
non-negotiable escalation rules from the system prompt, so a model that ignores
them produces a hard failure rather than a silently closed alert.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

RecommendedAction = Literal[
    "escalate_tier2",
    "monitor",
    "close_false_positive",
    "block_and_escalate",
    "needs_more_data",
]


class TriageOutput(BaseModel):
    alert_id: str = Field(min_length=1)
    severity: Severity
    false_positive_probability: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str]
    key_evidence: list[str] = Field(min_length=1, max_length=5)
    summary: str = Field(min_length=1)
    recommended_action: RecommendedAction

    @model_validator(mode="after")
    def enforce_confidence_rules(self) -> "TriageOutput":
        if self.confidence < 0.6 and self.recommended_action == "close_false_positive":
            raise ValueError("Low-confidence triage cannot close alerts")
        if self.recommended_action == "block_and_escalate":
            if self.severity != "CRITICAL" or self.confidence < 0.8:
                raise ValueError(
                    "block_and_escalate requires CRITICAL + confidence >= 0.8"
                )
        return self
