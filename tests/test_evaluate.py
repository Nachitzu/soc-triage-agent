"""Evaluation tests. The scoring is a pure function, so no API is involved."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.evaluation.evaluate import (
    evaluate,
    format_report,
    load_failed,
    load_results,
    severity_distance,
)
from src.schemas.triage_output import TriageOutput


def _output(
    alert_id: str, severity: str, action: str, **overrides: Any
) -> TriageOutput:
    base = {
        "alert_id": alert_id,
        "severity": severity,
        "false_positive_probability": 0.1,
        "confidence": 0.9,
        "mitre_techniques": [],
        "key_evidence": ["evidence"],
        "summary": "summary",
        "recommended_action": action,
    }
    return TriageOutput.model_validate({**base, **overrides})


def _labels(**alerts: dict[str, Any]) -> dict[str, Any]:
    return {"alerts": alerts}


class TestSeverityDistance:
    def test_same_severity(self) -> None:
        assert severity_distance("HIGH", "HIGH") == 0

    def test_adjacent(self) -> None:
        assert severity_distance("HIGH", "CRITICAL") == 1

    def test_far(self) -> None:
        assert severity_distance("LOW", "CRITICAL") == 3


class TestSeverityAccuracy:
    def test_exact_and_adjacent(self) -> None:
        results = {
            "a-1": _output("a-1", "CRITICAL", "block_and_escalate", confidence=0.9),
            "a-2": _output("a-2", "MEDIUM", "escalate_tier2"),  # expected HIGH → adjacent
            "a-3": _output("a-3", "LOW", "monitor"),  # expected CRITICAL → far miss
        }
        labels = _labels(
            **{
                "a-1": {"ground_truth": "attack", "expected_severity": "CRITICAL"},
                "a-2": {"ground_truth": "attack", "expected_severity": "HIGH"},
                "a-3": {"ground_truth": "attack", "expected_severity": "CRITICAL"},
            }
        )

        report = evaluate(results, labels)

        assert report.severity_scored == 3
        assert report.severity_exact == 1
        assert report.severity_adjacent == 2  # a-1 exact, a-2 within one level
        assert report.severity_exact_rate == 1 / 3

    def test_alerts_without_expected_severity_are_not_scored(self) -> None:
        results = {"a-1": _output("a-1", "LOW", "needs_more_data")}
        labels = _labels(
            **{"a-1": {"ground_truth": "unknown", "expected_severity": None}}
        )

        report = evaluate(results, labels)

        assert report.severity_scored == 0
        assert report.severity_exact_rate is None


class TestEscalationSafety:
    def test_a_closed_attack_is_flagged(self) -> None:
        results = {
            "a-1": _output("a-1", "LOW", "close_false_positive", confidence=0.9),
            "a-2": _output("a-2", "HIGH", "escalate_tier2"),
        }
        labels = _labels(
            **{
                "a-1": {"ground_truth": "attack", "expected_severity": "HIGH"},
                "a-2": {"ground_truth": "attack", "expected_severity": "HIGH"},
            }
        )

        report = evaluate(results, labels)

        assert report.unsafely_closed == ["a-1"]
        assert report.escalation_safety == 0.5

    def test_no_closed_attacks_is_full_safety(self) -> None:
        results = {"a-1": _output("a-1", "HIGH", "escalate_tier2")}
        labels = _labels(
            **{"a-1": {"ground_truth": "attack", "expected_severity": "HIGH"}}
        )

        report = evaluate(results, labels)

        assert report.unsafely_closed == []
        assert report.escalation_safety == 1.0


class TestFalsePositiveMetrics:
    def test_precision_and_recall(self) -> None:
        results = {
            # benign correctly closed → true positive
            "a-1": _output("a-1", "LOW", "close_false_positive", confidence=0.9),
            # benign not closed → false negative (missed an FP)
            "a-2": _output("a-2", "MEDIUM", "monitor"),
            # attack closed → false positive (the dangerous error)
            "a-3": _output("a-3", "LOW", "close_false_positive", confidence=0.9),
        }
        labels = _labels(
            **{
                "a-1": {"ground_truth": "benign", "expected_severity": "LOW"},
                "a-2": {"ground_truth": "benign", "expected_severity": "LOW"},
                "a-3": {"ground_truth": "attack", "expected_severity": "HIGH"},
            }
        )

        report = evaluate(results, labels)

        assert report.fp_true_positives == 1
        assert report.fp_false_positives == 1
        assert report.fp_false_negatives == 1
        assert report.fp_precision == 0.5
        assert report.fp_recall == 0.5


class TestValidationPassRate:
    def test_failed_alert_lowers_the_rate(self) -> None:
        results = {"a-1": _output("a-1", "HIGH", "escalate_tier2")}
        labels = _labels(
            **{
                "a-1": {"ground_truth": "attack", "expected_severity": "HIGH"},
                "a-2": {"ground_truth": "attack", "expected_severity": "HIGH"},
            }
        )

        report = evaluate(results, labels, failed=["a-2"])

        assert report.validated == 1
        assert report.total_labeled == 2
        assert report.validation_pass_rate == 0.5
        assert report.failed == ["a-2"]


class TestAdversarial:
    def test_resisted_injection(self) -> None:
        results = {"a-1": _output("a-1", "HIGH", "escalate_tier2")}
        labels = _labels(
            **{
                "a-1": {
                    "ground_truth": "attack",
                    "expected_severity": "HIGH",
                    "adversarial": True,
                }
            }
        )

        report = evaluate(results, labels)

        assert report.adversarial_total == 1
        assert report.adversarial_resisted == 1

    def test_fell_for_injection(self) -> None:
        results = {"a-1": _output("a-1", "LOW", "close_false_positive", confidence=0.9)}
        labels = _labels(
            **{
                "a-1": {
                    "ground_truth": "attack",
                    "expected_severity": "HIGH",
                    "adversarial": True,
                }
            }
        )

        report = evaluate(results, labels)

        assert report.adversarial_resisted == 0
        assert "a-1" in report.unsafely_closed


class TestFormatReport:
    def test_breach_is_shouted(self) -> None:
        results = {"a-1": _output("a-1", "LOW", "close_false_positive", confidence=0.9)}
        labels = _labels(
            **{"a-1": {"ground_truth": "attack", "expected_severity": "HIGH"}}
        )

        text = format_report(evaluate(results, labels))

        assert "ESCALATION SAFETY BREACH" in text
        assert "a-1" in text

    def test_clean_run_reports_safety(self) -> None:
        results = {"a-1": _output("a-1", "HIGH", "escalate_tier2")}
        labels = _labels(
            **{"a-1": {"ground_truth": "attack", "expected_severity": "HIGH"}}
        )

        text = format_report(evaluate(results, labels))

        assert "no real attack was closed" in text


class TestLoading:
    def test_load_results_and_failed_from_disk(self, tmp_path: Path) -> None:
        (tmp_path / "a-1.json").write_text(
            _output("a-1", "HIGH", "escalate_tier2").model_dump_json()
        )
        (tmp_path / "a-2.error.json").write_text(
            json.dumps({"alert_id": "a-2", "error": "boom"})
        )

        results = load_results(tmp_path)
        failed = load_failed(tmp_path)

        assert set(results) == {"a-1"}
        assert results["a-1"].severity == "HIGH"
        assert failed == ["a-2"]

    def test_error_files_are_not_loaded_as_results(self, tmp_path: Path) -> None:
        (tmp_path / "a-2.error.json").write_text(
            json.dumps({"alert_id": "a-2", "error": "boom"})
        )

        assert load_results(tmp_path) == {}


class TestEndToEndScoringOnDisk:
    def test_score_a_directory_of_results(self, tmp_path: Path) -> None:
        (tmp_path / "a-1.json").write_text(
            _output(
                "a-1", "CRITICAL", "block_and_escalate", confidence=0.9
            ).model_dump_json()
        )
        labels = _labels(
            **{"a-1": {"ground_truth": "attack", "expected_severity": "CRITICAL"}}
        )

        report = evaluate(load_results(tmp_path), labels, failed=load_failed(tmp_path))

        assert report.severity_exact == 1
        assert report.escalation_safety == 1.0
