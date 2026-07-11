"""Report tests: the HTML is generated from disk, ordered, and escape-safe."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from src.reporting.html_report import load_results, render_report, write_report

TRIAGE_HIGH = {
    "alert_id": "a-0001",
    "severity": "HIGH",
    "false_positive_probability": 0.12,
    "confidence": 0.65,
    "mitre_techniques": ["T1110 - Brute Force"],
    "key_evidence": ["47 failed SSH logins followed by a success"],
    "summary": "Probable brute force against the VPN gateway.",
    "recommended_action": "escalate_tier2",
}

TRIAGE_LOW = {
    "alert_id": "a-0002",
    "severity": "LOW",
    "false_positive_probability": 0.9,
    "confidence": 0.8,
    "mitre_techniques": [],
    "key_evidence": ["Nightly scanner traffic inside its window"],
    "summary": "Documented benign scanner activity.",
    "recommended_action": "close_false_positive",
}


def _write_run(directory: Path) -> None:
    (directory / "a-0001.json").write_text(json.dumps(TRIAGE_HIGH))
    (directory / "a-0002.json").write_text(json.dumps(TRIAGE_LOW))
    (directory / "a-0003.error.json").write_text(
        json.dumps({"alert_id": "a-0003", "error": "no valid TriageOutput"})
    )


class TestLoadResults:
    def test_results_and_errors_are_separated(self, tmp_path: Path) -> None:
        _write_run(tmp_path)

        results, errors = load_results(tmp_path)

        assert {r["alert_id"] for r in results} == {"a-0001", "a-0002"}
        assert errors == [{"alert_id": "a-0003", "error": "no valid TriageOutput"}]

    def test_a_corrupt_file_becomes_an_error(self, tmp_path: Path) -> None:
        (tmp_path / "a-9.json").write_text("{not json")

        results, errors = load_results(tmp_path)

        assert results == []
        assert errors[0]["alert_id"] == "a-9"
        assert "unreadable" in errors[0]["error"]


class TestRenderReport:
    def test_default_language_is_english(self) -> None:
        document = render_report([TRIAGE_HIGH], [])

        assert '<html lang="en">' in document
        assert "Escalate to Tier 2" in document
        assert "Prioritized Queue" in document
        assert "Alert Detail" in document
        # The Spanish label only ever appears as an attribute value
        # (data-es="...") — never as visible element text content. It shows
        # up twice: once for the queue-table badge, once for the detail card.
        assert document.count('data-es="Escalar a Tier 2"') == 2
        assert ">Escalar a Tier 2<" not in document

    def test_spanish_translations_are_attached(self) -> None:
        document = render_report([TRIAGE_HIGH], [])

        assert 'data-en="Escalate to Tier 2"' in document
        assert 'data-es="Escalar a Tier 2"' in document
        assert 'data-en="Prioritized Queue"' in document
        assert 'data-es="Cola priorizada"' in document

    def test_language_toggle_button_is_present(self) -> None:
        document = render_report([TRIAGE_HIGH], [])

        assert 'data-set-lang="en"' in document
        assert 'data-set-lang="es"' in document
        assert "lang-btn active" in document  # EN starts selected
        assert "soc-triage-report-lang" in document  # persistence key in the script

    def test_queue_is_ordered_by_priority(self, tmp_path: Path) -> None:
        _write_run(tmp_path)
        results, errors = load_results(tmp_path)

        document = render_report(results, errors)

        # The escalation must appear before the closed false positive.
        assert document.index("a-0001") < document.index("a-0002")
        assert "Escalate to Tier 2" in document
        assert "Close (false positive)" in document

    def test_errors_are_listed(self, tmp_path: Path) -> None:
        _write_run(tmp_path)
        results, errors = load_results(tmp_path)

        document = render_report(results, errors)

        assert "Unresolved Alerts" in document
        assert "no valid TriageOutput" in document

    def test_model_text_is_escaped(self) -> None:
        """A summary containing markup must render as text, never as HTML."""
        hostile = {
            **TRIAGE_HIGH,
            "summary": '<script>alert("x")</script>',
            "key_evidence": ["<img src=x onerror=alert(1)>"],
        }

        document = render_report([hostile], [])

        assert "<script>alert" not in document
        assert "&lt;script&gt;" in document
        assert "<img src=x" not in document

    def test_document_is_self_contained(self) -> None:
        document = render_report([TRIAGE_HIGH], [])

        assert "<style>" in document
        assert "<script>" in document
        assert "http://" not in document and "https://" not in document


class TestWriteReport:
    def test_filename_carries_the_timestamp(self, tmp_path: Path) -> None:
        _write_run(tmp_path)
        stamp = datetime(2026, 7, 10, 18, 30, 45)

        path = write_report(tmp_path, tmp_path / "reports", now=stamp)

        assert path.name == "triage_report_20260710_183045.html"
        assert path.exists()
        assert "a-0001" in path.read_text(encoding="utf-8")

    def test_successive_sessions_do_not_overwrite(self, tmp_path: Path) -> None:
        _write_run(tmp_path)
        out = tmp_path / "reports"

        first = write_report(tmp_path, out, now=datetime(2026, 7, 10, 10, 0, 0))
        second = write_report(tmp_path, out, now=datetime(2026, 7, 10, 11, 0, 0))

        assert first != second
        assert first.exists() and second.exists()
