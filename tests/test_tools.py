"""Tool tests. In-memory SQLite and a fake HTTP client — never a real network call."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from src.agent.tools import (
    TOOL_DEFINITIONS,
    Toolbox,
    TriageStore,
    check_ip_reputation,
    is_public_ip,
)

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)

ABUSEIPDB_PAYLOAD = {
    "data": {
        "ipAddress": "185.220.101.34",
        "abuseConfidenceScore": 100,
        "countryCode": "RU",
        "isp": "Example Hosting Ltd",
        "domain": "example-host.ru",
        "totalReports": 42,
        "lastReportedAt": "2026-07-09T22:14:00+00:00",
        "isPublic": True,
        "isWhitelisted": False,
    }
}


@dataclass
class FakeResponse:
    _json: dict[str, Any]
    status_code: int = 200

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "error", request=None, response=None  # type: ignore[arg-type]
            )

    def json(self) -> dict[str, Any]:
        return self._json


@dataclass
class FakeHttpClient:
    """Records requests and returns scripted responses."""

    response: Any = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def get(self, url: str, *, params: dict, headers: dict) -> Any:
        self.calls.append({"url": url, "params": params, "headers": headers})
        if self.error is not None:
            raise self.error
        return self.response


@pytest.fixture
def store() -> TriageStore:
    s = TriageStore(":memory:")
    yield s
    s.close()


class TestIsPublicIp:
    @pytest.mark.parametrize("ip", ["185.220.101.34", "8.8.8.8", "1.1.1.1"])
    def test_public_addresses(self, ip: str) -> None:
        assert is_public_ip(ip) is True

    @pytest.mark.parametrize(
        "ip", ["10.0.1.12", "172.16.0.1", "192.168.1.1", "127.0.0.1", "not-an-ip"]
    )
    def test_non_public_addresses(self, ip: str) -> None:
        assert is_public_ip(ip) is False


class TestAlertHistory:
    def test_empty_history(self, store: TriageStore) -> None:
        history = store.query_history("SSH-BRUTE-01", "185.220.101.34", now=NOW)
        assert history.total_firings == 0
        assert history.escalated_firings == 0
        assert history.to_dict()["note"] == "no prior firings in the window"

    def test_counts_firings_and_escalations(self, store: TriageStore) -> None:
        store.record_firing(
            "SSH-BRUTE-01", "185.220.101.34", NOW - timedelta(days=1), escalated=False
        )
        store.record_firing(
            "SSH-BRUTE-01", "185.220.101.34", NOW - timedelta(hours=2), escalated=True
        )
        store.record_firing(
            "SSH-BRUTE-01", "185.220.101.34", NOW - timedelta(minutes=5), escalated=False
        )

        history = store.query_history("SSH-BRUTE-01", "185.220.101.34", now=NOW)

        assert history.total_firings == 3
        assert history.escalated_firings == 1
        assert history.first_seen is not None and history.last_seen is not None

    def test_window_excludes_old_firings(self, store: TriageStore) -> None:
        store.record_firing(
            "SCAN-01", "45.83.64.7", NOW - timedelta(days=30), escalated=False
        )
        store.record_firing(
            "SCAN-01", "45.83.64.7", NOW - timedelta(days=1), escalated=False
        )

        history = store.query_history("SCAN-01", "45.83.64.7", now=NOW, window_days=7)

        assert history.total_firings == 1

    def test_history_is_keyed_by_rule_and_source(self, store: TriageStore) -> None:
        store.record_firing("SSH-BRUTE-01", "185.220.101.34", NOW, escalated=False)

        other_rule = store.query_history("FTP-BRUTE-01", "185.220.101.34", now=NOW)
        other_source = store.query_history("SSH-BRUTE-01", "1.2.3.4", now=NOW)

        assert other_rule.total_firings == 0
        assert other_source.total_firings == 0

    def test_firing_without_source_is_not_recorded(self, store: TriageStore) -> None:
        store.record_firing("SSH-BRUTE-01", None, NOW, escalated=True)

        assert store.query_history("SSH-BRUTE-01", "", now=NOW).total_firings == 0


class TestReputationCache:
    def test_miss_then_hit_within_ttl(self, store: TriageStore) -> None:
        store.cache_reputation("8.8.8.8", {"status": "ok", "score": 0}, now=NOW)

        cached = store.get_cached_reputation("8.8.8.8", now=NOW + timedelta(hours=1))

        assert cached == {"status": "ok", "score": 0}

    def test_expired_entry_is_a_miss(self, store: TriageStore) -> None:
        store.cache_reputation("8.8.8.8", {"status": "ok"}, now=NOW)

        assert (
            store.get_cached_reputation("8.8.8.8", now=NOW + timedelta(hours=48))
            is None
        )

    def test_unknown_ip_is_a_miss(self, store: TriageStore) -> None:
        assert store.get_cached_reputation("8.8.8.8", now=NOW) is None


class TestCheckIpReputation:
    def test_private_ip_is_skipped_without_a_call(self, store: TriageStore) -> None:
        http = FakeHttpClient()

        result = check_ip_reputation(
            "10.0.1.12", store=store, api_key="k", http_client=http, now=NOW
        )

        assert result["status"] == "skipped"
        assert http.calls == []

    def test_missing_api_key_is_unavailable(self, store: TriageStore) -> None:
        http = FakeHttpClient()

        result = check_ip_reputation(
            "185.220.101.34", store=store, api_key=None, http_client=http, now=NOW
        )

        assert result["status"] == "unavailable"
        assert http.calls == []

    def test_successful_lookup_parses_and_caches(self, store: TriageStore) -> None:
        http = FakeHttpClient(response=FakeResponse(ABUSEIPDB_PAYLOAD))

        result = check_ip_reputation(
            "185.220.101.34", store=store, api_key="k", http_client=http, now=NOW
        )

        assert result["status"] == "ok"
        assert result["abuse_confidence_score"] == 100
        assert result["country_code"] == "RU"
        assert result["total_reports"] == 42
        assert result["cache"] == "miss"
        assert http.calls[0]["headers"]["Key"] == "k"
        assert http.calls[0]["params"]["ipAddress"] == "185.220.101.34"

    def test_second_lookup_is_served_from_cache(self, store: TriageStore) -> None:
        http = FakeHttpClient(response=FakeResponse(ABUSEIPDB_PAYLOAD))

        check_ip_reputation(
            "185.220.101.34", store=store, api_key="k", http_client=http, now=NOW
        )
        second = check_ip_reputation(
            "185.220.101.34", store=store, api_key="k", http_client=http, now=NOW
        )

        assert second["cache"] == "hit"
        assert len(http.calls) == 1  # the network was hit exactly once

    def test_http_error_returns_a_status_not_an_exception(
        self, store: TriageStore
    ) -> None:
        http = FakeHttpClient(error=httpx.ConnectError("boom"))

        result = check_ip_reputation(
            "185.220.101.34", store=store, api_key="k", http_client=http, now=NOW
        )

        assert result["status"] == "error"
        assert "boom" in result["reason"]


class TestToolbox:
    def test_definitions_cover_both_tools(self, store: TriageStore) -> None:
        names = {d["name"] for d in Toolbox(store=store).definitions}
        assert names == {"lookup_ip_reputation", "check_alert_history"}

    def test_definitions_match_the_module_constant(self) -> None:
        assert [d["name"] for d in TOOL_DEFINITIONS] == [
            "lookup_ip_reputation",
            "check_alert_history",
        ]

    def test_dispatch_routes_history(self, store: TriageStore) -> None:
        store.record_firing("SSH-BRUTE-01", "185.220.101.34", NOW, escalated=True)
        toolbox = Toolbox(store=store, now_fn=lambda: NOW)

        content, is_error = toolbox.dispatch(
            "check_alert_history",
            {"rule_id": "SSH-BRUTE-01", "source_ip": "185.220.101.34"},
        )

        assert is_error is False
        assert json.loads(content)["total_firings"] == 1

    def test_dispatch_routes_reputation(self, store: TriageStore) -> None:
        http = FakeHttpClient(response=FakeResponse(ABUSEIPDB_PAYLOAD))
        toolbox = Toolbox(store=store, api_key="k", http_client=http, now_fn=lambda: NOW)

        content, is_error = toolbox.dispatch(
            "lookup_ip_reputation", {"ip": "185.220.101.34"}
        )

        assert is_error is False
        assert json.loads(content)["abuse_confidence_score"] == 100

    def test_unknown_tool_is_an_error(self, store: TriageStore) -> None:
        content, is_error = Toolbox(store=store).dispatch("rm_rf", {})

        assert is_error is True
        assert "unknown tool" in json.loads(content)["error"]

    def test_missing_arguments_are_reported(self, store: TriageStore) -> None:
        content, is_error = Toolbox(store=store).dispatch("check_alert_history", {})

        assert is_error is False  # a usable message, not a crash
        assert "requires" in json.loads(content)["error"]

    def test_record_triage_marks_escalating_actions(self, store: TriageStore) -> None:
        toolbox = Toolbox(store=store, now_fn=lambda: NOW)

        toolbox.record_triage(
            "SSH-BRUTE-01", "185.220.101.34", NOW, "block_and_escalate"
        )
        toolbox.record_triage("SCAN-01", "45.83.64.7", NOW, "monitor")

        assert (
            store.query_history(
                "SSH-BRUTE-01", "185.220.101.34", now=NOW
            ).escalated_firings
            == 1
        )
        assert (
            store.query_history("SCAN-01", "45.83.64.7", now=NOW).escalated_firings == 0
        )
