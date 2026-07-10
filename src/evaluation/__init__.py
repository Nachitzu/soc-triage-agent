"""Evaluation: score agent triage against CICIDS2017 ground truth (Phase 4)."""

from src.evaluation.evaluate import (
    EvaluationReport,
    evaluate,
    format_report,
    load_labels,
    load_results,
    severity_distance,
)

__all__ = [
    "EvaluationReport",
    "evaluate",
    "format_report",
    "load_labels",
    "load_results",
    "severity_distance",
]
