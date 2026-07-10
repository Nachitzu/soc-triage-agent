"""Generic normalization utilities shared by every alert source.

Nothing here knows about CICIDS2017 specifically. The CSV quirks live in
`cicids_parser`; this module holds the primitives any future source (syslog,
Wazuh, Splunk export) would also need.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from datetime import datetime, timezone
from typing import Any

# Critical asset ranges, mirroring the "ENVIRONMENT CONTEXT" section of the
# system prompt. Keeping them here means the agent learns an alert touches a
# critical asset from a field, not only from the prose in its prompt.
CRITICAL_ASSET_RANGES: dict[str, str] = {
    "10.0.1.0/24": "domain_controller",
    "10.0.2.0/24": "database_server",
}

# IANA protocol numbers that appear in flow records.
_PROTOCOL_NAMES: dict[int, str] = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

_DATETIME_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %I:%M %p",
    "%Y-%m-%d %H:%M:%S",
)


def normalize_column_name(name: str) -> str:
    """Fold a CSV header into a stable lookup key.

    CICIDS2017 headers carry leading spaces and inconsistent casing
    (`" Source IP"`, `"Flow Duration"`). Everything collapses to snake_case:
    `" Source IP"` -> `"source_ip"`.
    """
    return _NON_ALNUM.sub("_", name.strip().lower()).strip("_")


def normalize_label(label: str) -> str:
    """Fold a dataset label into a stable lookup key.

    CICIDS2017 web-attack labels contain a CP-1252 en dash (`\\x96`) that
    survives as mojibake through most readers, and spacing varies between
    files. `"Web Attack \\x96 Brute Force"` -> `"web_attack_brute_force"`.
    """
    cleaned = label.replace("\x96", " ").replace("–", " ").replace("‑", " ")
    return _NON_ALNUM.sub("_", cleaned.strip().lower()).strip("_")


def make_alert_id(*parts: Any) -> str:
    """Build a deterministic alert id from the fields that identify a flow.

    Deterministic rather than sequential so that re-parsing the same CSV
    produces the same ids, which keeps evaluation runs comparable across
    parser changes.
    """
    digest = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()
    return f"a-{digest[:10]}"


def coerce_timestamp(value: Any) -> datetime:
    """Parse a flow timestamp into a timezone-aware UTC datetime.

    CICIDS2017 writes day-first, naive local timestamps (`"5/7/2017 8:55"`).
    Naive values are interpreted as UTC — see `NormalizedAlert.timestamp`.
    """
    parsed = value if isinstance(value, datetime) else _parse_datetime_text(str(value).strip())
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_datetime_text(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"unrecognized timestamp format: {text!r}")


def protocol_name(value: Any) -> str | None:
    """Map an IANA protocol number to its name, passing names through."""
    if is_missing(value):
        return None
    if isinstance(value, str) and not value.strip().isdigit():
        return value.strip().upper() or None
    return _PROTOCOL_NAMES.get(int(float(value)))


def asset_tag_for_ip(ip: str) -> str | None:
    """Tag an IP that falls inside a documented critical-asset range."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr, tag in CRITICAL_ASSET_RANGES.items():
        if address in ipaddress.ip_network(cidr):
            return tag
    return None


def coerce_port(value: Any) -> int | None:
    """Parse a port, returning None for missing or out-of-range values."""
    if is_missing(value):
        return None
    try:
        port = int(float(value))
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def coerce_int(value: Any, default: int = 0) -> int:
    """Parse a flow counter, tolerating the NaN/inf that pandas leaves behind."""
    if is_missing(value):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def is_missing(value: Any) -> bool:
    """True for None, empty/blank strings, and pandas' NaN/inf floats."""
    if value is None:
        return True
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return True
    return isinstance(value, str) and not value.strip()
