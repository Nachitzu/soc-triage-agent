"""Enrichment tools the agent may call while triaging (Phase 3).

Two tools, matching the names the system prompt already advertises:

- `lookup_ip_reputation(ip)` — AbuseIPDB reputation for a *public* IP, cached
  locally so a batch run stays inside the free tier's daily quota.
- `check_alert_history(rule_id, source_ip)` — how often this rule has fired for
  this source recently, and how many of those firings were escalated. Backed by
  a local SQLite store the agent writes to as it triages.

BOUNDARIES
==========
- The tools are pure data providers. They never block an IP, disable an account,
  or take any action — that belongs to a future SOAR layer with human approval.
- Every tool degrades gracefully. A missing API key, a private IP, or an HTTP
  failure returns a structured status the model can reason about, rather than an
  exception that aborts the triage. The agent can always fall back to triaging
  from the alert data alone.
- Nothing here reaches the network in tests: the HTTP client and the clock are
  injected, and the store runs in-memory.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_DB_PATH = Path("data/triage.db")
DEFAULT_HISTORY_WINDOW_DAYS = 7
DEFAULT_CACHE_TTL_HOURS = 24
DEFAULT_MAX_AGE_DAYS = 90

# Tool schemas sent to the model. The names and signatures mirror the TOOLS
# section of SYSTEM_PROMPT.md — the prompt and these definitions must agree.
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "lookup_ip_reputation",
        "description": (
            "Look up the abuse reputation of a PUBLIC IP address via AbuseIPDB: "
            "abuse confidence score (0-100), country, ISP, and recent report "
            "count. Do NOT call this for internal / RFC 1918 addresses — it will "
            "return a 'skipped' status. Call only when reputation would "
            "materially change your assessment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "The public IP to check"}
            },
            "required": ["ip"],
        },
    },
    {
        "name": "check_alert_history",
        "description": (
            "Return how many times this SIEM rule has fired for this source IP in "
            "the last 7 days, and how many of those firings were escalated. Use it "
            "to spot noisy rules (many firings, none escalated) and repeat "
            "offenders."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "The firing rule id"},
                "source_ip": {"type": "string", "description": "The source IP"},
            },
            "required": ["rule_id", "source_ip"],
        },
    },
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_public_ip(ip: str) -> bool:
    """True only for globally routable addresses.

    AbuseIPDB is meaningless for anything else, and the system prompt forbids
    looking up internal addresses.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_reserved
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


# --------------------------------------------------------------------------
# Local store: alert history + reputation cache
# --------------------------------------------------------------------------


@dataclass
class AlertHistory:
    """The answer to `check_alert_history`."""

    rule_id: str
    source_ip: str
    window_days: int
    total_firings: int
    escalated_firings: int
    first_seen: str | None
    last_seen: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "window_days": self.window_days,
            "total_firings": self.total_firings,
            "escalated_firings": self.escalated_firings,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "note": (
                "no prior firings in the window"
                if self.total_firings == 0
                else None
            ),
        }


class TriageStore:
    """SQLite-backed alert history and IP-reputation cache.

    Pass `":memory:"` in tests. The default on-disk path is git-ignored.
    """

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alert_firings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id   TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                fired_at  TEXT NOT NULL,
                escalated INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_firings_lookup
                ON alert_firings (rule_id, source_ip, fired_at);

            CREATE TABLE IF NOT EXISTS ip_reputation_cache (
                ip         TEXT PRIMARY KEY,
                payload    TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    # -- alert history ----------------------------------------------------

    def record_firing(
        self,
        rule_id: str,
        source_ip: str | None,
        fired_at: datetime,
        *,
        escalated: bool,
    ) -> None:
        """Record one rule firing. Firings without a source IP are not stored.

        History is keyed by rule + source; a firing with no source cannot be
        looked up later, so recording it would only bloat the table.
        """
        if not source_ip:
            return
        self._conn.execute(
            "INSERT INTO alert_firings (rule_id, source_ip, fired_at, escalated) "
            "VALUES (?, ?, ?, ?)",
            (rule_id, source_ip, _iso(fired_at), int(escalated)),
        )
        self._conn.commit()

    def query_history(
        self,
        rule_id: str,
        source_ip: str,
        *,
        now: datetime,
        window_days: int = DEFAULT_HISTORY_WINDOW_DAYS,
    ) -> AlertHistory:
        cutoff = _iso(now - timedelta(days=window_days))
        rows = self._conn.execute(
            "SELECT fired_at, escalated FROM alert_firings "
            "WHERE rule_id = ? AND source_ip = ? AND fired_at >= ? "
            "ORDER BY fired_at",
            (rule_id, source_ip, cutoff),
        ).fetchall()
        return AlertHistory(
            rule_id=rule_id,
            source_ip=source_ip,
            window_days=window_days,
            total_firings=len(rows),
            escalated_firings=sum(int(r["escalated"]) for r in rows),
            first_seen=rows[0]["fired_at"] if rows else None,
            last_seen=rows[-1]["fired_at"] if rows else None,
        )

    # -- reputation cache -------------------------------------------------

    def get_cached_reputation(
        self, ip: str, *, now: datetime, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload, fetched_at FROM ip_reputation_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if row is None:
            return None
        fetched_at = datetime.fromisoformat(row["fetched_at"])
        if now - fetched_at > timedelta(hours=ttl_hours):
            return None
        return json.loads(row["payload"])

    def cache_reputation(
        self, ip: str, payload: dict[str, Any], *, now: datetime
    ) -> None:
        self._conn.execute(
            "INSERT INTO ip_reputation_cache (ip, payload, fetched_at) VALUES (?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET payload = excluded.payload, "
            "fetched_at = excluded.fetched_at",
            (ip, json.dumps(payload), _iso(now)),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# lookup_ip_reputation
# --------------------------------------------------------------------------


def check_ip_reputation(
    ip: str,
    *,
    store: TriageStore,
    api_key: str | None,
    http_client: httpx.Client | None,
    now: datetime,
    ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> dict[str, Any]:
    """Return an AbuseIPDB reputation summary for `ip`, or a status explaining why not.

    The returned dict always carries a `status` of `ok`, `skipped`, `unavailable`
    or `error`, so the model can act on the outcome either way.
    """
    if not is_public_ip(ip):
        return {
            "ip": ip,
            "status": "skipped",
            "reason": "not a public IP; reputation lookup does not apply to internal addresses",
        }
    if not api_key:
        return {
            "ip": ip,
            "status": "unavailable",
            "reason": "ABUSEIPDB_API_KEY is not configured; triage without reputation data",
        }

    cached = store.get_cached_reputation(ip, now=now, ttl_hours=ttl_hours)
    if cached is not None:
        return {**cached, "cache": "hit"}

    if http_client is None:
        return {
            "ip": ip,
            "status": "unavailable",
            "reason": "no HTTP client available for the reputation lookup",
        }

    try:
        response = http_client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()["data"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return {
            "ip": ip,
            "status": "error",
            "reason": f"reputation lookup failed: {exc}",
        }

    payload = {
        "ip": ip,
        "status": "ok",
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "is_public": data.get("isPublic"),
        "is_whitelisted": data.get("isWhitelisted"),
    }
    store.cache_reputation(ip, payload, now=now)
    return {**payload, "cache": "miss"}


# --------------------------------------------------------------------------
# Toolbox: definitions + dispatch
# --------------------------------------------------------------------------


ESCALATING_ACTIONS = frozenset({"escalate_tier2", "block_and_escalate"})


@dataclass
class Toolbox:
    """Bundles the enrichment tools for the agent loop.

    `definitions` is handed to the model; `dispatch` runs the tool the model
    asked for and returns `(content, is_error)`, where `content` is the JSON the
    model reads back as a tool result.
    """

    store: TriageStore
    api_key: str | None = None
    http_client: httpx.Client | None = None
    now_fn: Callable[[], datetime] = _utcnow
    ttl_hours: int = DEFAULT_CACHE_TTL_HOURS
    history_window_days: int = DEFAULT_HISTORY_WINDOW_DAYS
    definitions: list[dict[str, Any]] = field(
        default_factory=lambda: [dict(d) for d in TOOL_DEFINITIONS]
    )

    def dispatch(self, name: str, tool_input: dict[str, Any]) -> tuple[str, bool]:
        try:
            if name == "lookup_ip_reputation":
                result = self._lookup_ip_reputation(tool_input)
            elif name == "check_alert_history":
                result = self._check_alert_history(tool_input)
            else:
                return json.dumps({"error": f"unknown tool {name!r}"}), True
        except Exception as exc:  # a tool bug must not crash the triage
            return json.dumps({"error": f"{name} failed: {exc}"}), True
        return json.dumps(result), False

    def _lookup_ip_reputation(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        ip = tool_input.get("ip")
        if not ip:
            return {"error": "lookup_ip_reputation requires an 'ip' argument"}
        return check_ip_reputation(
            str(ip),
            store=self.store,
            api_key=self.api_key,
            http_client=self._ensure_http_client(),
            now=self.now_fn(),
            ttl_hours=self.ttl_hours,
        )

    def _check_alert_history(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        rule_id = tool_input.get("rule_id")
        source_ip = tool_input.get("source_ip")
        if not rule_id or not source_ip:
            return {"error": "check_alert_history requires 'rule_id' and 'source_ip'"}
        return self.store.query_history(
            str(rule_id),
            str(source_ip),
            now=self.now_fn(),
            window_days=self.history_window_days,
        ).to_dict()

    def _ensure_http_client(self) -> httpx.Client | None:
        """Create a real HTTP client on first use, only when a key is present.

        Tests inject `http_client`, so this never fabricates a network client in
        the suite.
        """
        if self.http_client is None and self.api_key:
            self.http_client = httpx.Client(timeout=10.0)
        return self.http_client

    def record_triage(
        self, rule_id: str, source_ip: str | None, fired_at: datetime, action: str
    ) -> None:
        """Record a completed triage as a firing, so later alerts have history."""
        self.store.record_firing(
            rule_id, source_ip, fired_at, escalated=action in ESCALATING_ACTIONS
        )

    def close(self) -> None:
        if self.http_client is not None:
            self.http_client.close()
        self.store.close()


def build_toolbox(
    *, db_path: str | Path | None = None, api_key: str | None = None
) -> Toolbox:
    """Construct a Toolbox from the environment (CLI / batch entry point)."""
    import os

    resolved_path = db_path or os.environ.get("TRIAGE_DB") or DEFAULT_DB_PATH
    resolved_key = api_key or os.environ.get("ABUSEIPDB_API_KEY") or None
    return Toolbox(store=TriageStore(resolved_path), api_key=resolved_key)
