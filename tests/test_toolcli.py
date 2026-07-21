"""Tests for `soc-tool`, the deterministic plumbing behind the console (no-API) mode.

Validation (pass and fail), the enrichment tools in their offline degraded mode, and
the session report — all without touching the network or needing an API key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.toolcli import main


@pytest.fixture(autouse=True)
def _offline_toolbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # No AbuseIPDB key => reputation tool degrades offline; isolate the SQLite store.
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("TRIAGE_DB", str(tmp_path / "triage.db"))


def _out(capsys: pytest.CaptureFixture[str]) -> dict:
    text = capsys.readouterr().out.strip()
    return json.loads(text) if text else {}


# --- validate ----------------------------------------------------------------
def test_validate_ok(valid_triage_json: str, tmp_path: Path, capsys) -> None:
    p = tmp_path / "triage.json"
    p.write_text(valid_triage_json, encoding="utf-8")
    rc = main(["validate", "--in", str(p)])
    assert rc == 0
    assert _out(capsys)["status"] == "ok"


def test_validate_rejects_confidence_rule(
    valid_triage_json: str, tmp_path: Path, capsys
) -> None:
    bad = json.loads(valid_triage_json)
    bad["confidence"] = 0.3
    bad["recommended_action"] = "close_false_positive"
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    rc = main(["validate", "--in", str(p)])
    assert rc == 1
    assert "confidence" in capsys.readouterr().err.lower()


# --- tools (offline) ---------------------------------------------------------
def test_tool_lookup_ip_reputation_offline(capsys) -> None:
    rc = main(["tool", "lookup_ip_reputation", "--input", '{"ip": "45.133.1.77"}'])
    assert rc == 0
    payload = _out(capsys)
    # No API key configured -> the tool reports why it could not score, offline.
    assert payload["status"] in {"unavailable", "skipped", "error"}


def test_tool_check_alert_history(capsys) -> None:
    rc = main(
        [
            "tool",
            "check_alert_history",
            "--input",
            '{"rule_id": "SSH-BRUTE-01", "source_ip": "185.220.101.34"}',
        ]
    )
    assert rc == 0
    # Empty store: a well-formed history result, not an error.
    assert "error" not in _out(capsys)


def test_tool_bad_input_json(capsys) -> None:
    rc = main(["tool", "lookup_ip_reputation", "--input", "not json"])
    assert rc == 2
    assert "not valid JSON" in capsys.readouterr().err


# --- report ------------------------------------------------------------------
def test_report_renders_html(tmp_path: Path, capsys) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    rc = main(
        ["report", "--results", str(results_dir), "--out", str(tmp_path / "reports")]
    )
    assert rc == 0
    report_path = Path(_out(capsys)["report"])
    assert report_path.exists()
    assert report_path.suffix == ".html"
