"""CICIDS2017 labeled flow records -> synthetic SIEM-style `NormalizedAlert`s.

MAPPING STRATEGY
================
CICIDS2017 rows are *network flow records*, not SIEM alerts. A flow says "host A
sent 47 packets to host B:22 over 120ms and the ground-truth label is
SSH-Patator". A SIEM alert says "rule SSH-BRUTE-01 fired: 47 failed SSH logins
for one account in 120s". This parser bridges the two by treating the label as
the detection a hypothetical SIEM rule would have produced, and the flow
counters as the evidence that rule would have cited.

For every row:

  1. The ground-truth `Label` selects a (rule_id, alert_type) pair from
     `LABEL_MAP`. A labeled brute-force flow becomes an
     `authentication_failure_burst` alert from rule `SSH-BRUTE-01`.
  2. Flow counters (duration, packet and byte counts in each direction) are
     rendered into `raw_log` as the human-readable evidence line.
  3. `asset_tag` is derived from the destination IP when one is present and
     falls inside a documented critical-asset range.
  4. `alert_id` is a deterministic hash of the row's identifying fields plus its
     ordinal position, so re-parsing the same CSV yields the same ids.

TWO DATASET LAYOUTS
===================
CICIDS2017 circulates in two shapes, and this parser reads both. `detect_layout`
picks between them by inspecting the header.

`LABELLED_FLOWS` (85 columns, the "GeneratedLabelledFlows" archive)
    Carries `Flow ID`, `Source IP`, `Destination IP`, `Source Port`,
    `Destination Port`, `Protocol` and `Timestamp`. Produces complete alerts:
    `NormalizedAlert.has_network_context` is True, and the agent can reason
    about critical assets, business hours and IP reputation.

`FEATURES_ONLY` (79 columns, the "MachineLearningCVE" archive)
    Carries `Destination Port`, 77 flow features and `Label` — no identifiers.
    Produces degraded alerts with `timestamp`, `source_ip`, `dest_ip` and
    `protocol` set to None. The parser does not invent them; see the module
    docstring of `src.schemas.normalized_alert`. Triage still works from flow
    evidence, but the environment-baseline half of the system prompt is inert,
    and evaluation numbers from this layout are not comparable to a real SOC.

WHAT THIS IS NOT
================
The synthesized `raw_log` is not a real log line — it is a faithful rendering of
the flow features the dataset actually provides. Any semantic detail a real SIEM
would carry (usernames, HTTP paths, process names) is absent, and the parser does
not invent it.

BENIGN ROWS
===========
Benign flows outnumber attack flows by roughly an order of magnitude. They are
kept (a triage agent that never sees benign traffic cannot be scored on false
positives) but can be downsampled deterministically via `benign_sample_rate`.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import pandas as pd

from src.ingest.normalizer import (
    asset_tag_for_ip,
    coerce_int,
    coerce_port,
    coerce_timestamp,
    is_missing,
    make_alert_id,
    normalize_column_name,
    normalize_label,
    protocol_name,
)
from src.schemas.normalized_alert import NormalizedAlert


class UnknownLabelError(ValueError):
    """Raised when a row carries a label absent from `LABEL_MAP`."""


class Layout(str, Enum):
    """Which CICIDS2017 distribution a file follows."""

    LABELLED_FLOWS = "labelled_flows"
    FEATURES_ONLY = "features_only"


@dataclass(frozen=True)
class AlertMeta:
    """The SIEM-side identity a labeled flow is mapped onto."""

    rule_id: str
    alert_type: str
    is_attack: bool


# Ground-truth label (normalized) -> the alert a SIEM rule would have raised.
LABEL_MAP: dict[str, AlertMeta] = {
    "benign": AlertMeta("BASELINE-00", "benign_traffic_baseline", False),
    "ftp_patator": AlertMeta("FTP-BRUTE-01", "authentication_failure_burst", True),
    "ssh_patator": AlertMeta("SSH-BRUTE-01", "authentication_failure_burst", True),
    "dos_hulk": AlertMeta("DOS-HULK-01", "dos_traffic_flood", True),
    "dos_goldeneye": AlertMeta("DOS-GOLDENEYE-01", "dos_traffic_flood", True),
    "dos_slowloris": AlertMeta(
        "DOS-SLOWLORIS-01", "dos_slow_connection_exhaustion", True
    ),
    "dos_slowhttptest": AlertMeta(
        "DOS-SLOWHTTP-01", "dos_slow_connection_exhaustion", True
    ),
    "ddos": AlertMeta("DDOS-01", "distributed_dos_flood", True),
    "heartbleed": AlertMeta("HEARTBLEED-01", "vulnerability_exploit_attempt", True),
    "portscan": AlertMeta("SCAN-01", "port_scan_detected", True),
    "bot": AlertMeta("BOT-C2-01", "c2_beacon_suspected", True),
    "infiltration": AlertMeta("INFIL-01", "suspicious_internal_transfer", True),
    "web_attack_brute_force": AlertMeta("WEB-BRUTE-01", "web_login_brute_force", True),
    "web_attack_xss": AlertMeta("WEB-XSS-01", "web_attack_xss", True),
    "web_attack_sql_injection": AlertMeta(
        "WEB-SQLI-01", "web_attack_sql_injection", True
    ),
}

# Header aliases across the CICIDS2017 distributions. Keys are the normalized
# column names produced by `normalize_column_name`.
_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip": ("source_ip", "src_ip", "src_addr"),
    "dest_ip": ("destination_ip", "dst_ip", "dst_addr"),
    "port": ("destination_port", "dst_port"),
    "protocol": ("protocol",),
    "timestamp": ("timestamp",),
    "label": ("label",),
    "flow_duration": ("flow_duration",),
    "fwd_packets": ("total_fwd_packets", "tot_fwd_pkts"),
    "bwd_packets": ("total_backward_packets", "tot_bwd_pkts"),
    "fwd_bytes": ("total_length_of_fwd_packets", "totlen_fwd_pkts"),
    "bwd_bytes": ("total_length_of_bwd_packets", "totlen_bwd_pkts"),
}

# The web-attack labels are the only rows whose encoding varies between mirrors,
# so the CSVs are read as latin-1 and the label normalizer discards the offending
# bytes. Reading as utf-8 raises on some mirrors.
_CSV_ENCODING = "latin-1"

OnUnknownLabel = Literal["raise", "skip"]


def detect_layout(columns: Iterable[str]) -> Layout:
    """Decide which distribution a file follows from its header."""
    normalized = {normalize_column_name(str(c)) for c in columns}
    has_source = bool(normalized & set(_COLUMN_ALIASES["source_ip"]))
    has_dest = bool(normalized & set(_COLUMN_ALIASES["dest_ip"]))
    return Layout.LABELLED_FLOWS if has_source and has_dest else Layout.FEATURES_ONLY


def label_to_meta(label: str) -> AlertMeta:
    """Resolve a raw CICIDS2017 label to its SIEM-side alert identity."""
    key = normalize_label(label)
    try:
        return LABEL_MAP[key]
    except KeyError as exc:
        raise UnknownLabelError(
            f"no mapping for label {label!r} (normalized {key!r})"
        ) from exc


def flow_to_alert(row: Mapping[str, Any], *, row_index: int = 0) -> NormalizedAlert:
    """Convert one labeled flow record into a synthetic SIEM alert."""
    return _flow_to_alert_with_meta(row, row_index)[0]


def _flow_to_alert_with_meta(
    row: Mapping[str, Any], row_index: int
) -> tuple[NormalizedAlert, AlertMeta]:
    """Build the alert and hand back the meta the caller would otherwise re-derive."""
    fields = _resolve_fields(row)
    if is_missing(fields.get("label")):
        raise ValueError("flow record is missing the required 'Label' column")

    meta = label_to_meta(str(fields["label"]))
    timestamp = (
        None
        if is_missing(fields.get("timestamp"))
        else coerce_timestamp(fields["timestamp"])
    )
    source_ip = _clean_ip(fields.get("source_ip"))
    dest_ip = _clean_ip(fields.get("dest_ip"))
    port = coerce_port(fields.get("port"))
    proto = protocol_name(fields.get("protocol"))

    alert = NormalizedAlert(
        alert_id=make_alert_id(row_index, meta.rule_id, source_ip, dest_ip, port),
        timestamp=timestamp,
        rule_id=meta.rule_id,
        alert_type=meta.alert_type,
        source_ip=source_ip,
        dest_ip=dest_ip,
        raw_log=_build_raw_log(meta, fields, dest_ip, port, proto),
        asset_tag=asset_tag_for_ip(dest_ip) if dest_ip else None,
        protocol=proto,
        port=port,
    )
    return alert, meta


def parse_cicids_dataframe(
    frame: pd.DataFrame,
    *,
    include_benign: bool = True,
    benign_sample_rate: float = 1.0,
    on_unknown_label: OnUnknownLabel = "raise",
) -> list[NormalizedAlert]:
    """Convert an already-loaded CICIDS2017 frame into normalized alerts."""
    return list(
        _iter_alerts(
            (row for _, row in frame.iterrows()),
            start_index=0,
            include_benign=include_benign,
            benign_sample_rate=benign_sample_rate,
            on_unknown_label=on_unknown_label,
        )
    )


def parse_cicids_csv(
    path: str | Path,
    *,
    limit: int | None = None,
    include_benign: bool = True,
    benign_sample_rate: float = 1.0,
    on_unknown_label: OnUnknownLabel = "raise",
    chunksize: int = 100_000,
) -> list[NormalizedAlert]:
    """Stream a CICIDS2017 CSV and return normalized alerts.

    The full CSVs run to hundreds of thousands of rows each, so the file is read
    in chunks and `limit` short-circuits as soon as enough alerts exist.
    """
    alerts: list[NormalizedAlert] = []
    reader = pd.read_csv(
        path,
        chunksize=chunksize,
        skipinitialspace=True,
        low_memory=False,
        encoding=_CSV_ENCODING,
    )
    offset = 0
    for chunk in reader:
        rows = (row for _, row in chunk.iterrows())
        for alert in _iter_alerts(
            rows,
            start_index=offset,
            include_benign=include_benign,
            benign_sample_rate=benign_sample_rate,
            on_unknown_label=on_unknown_label,
        ):
            alerts.append(alert)
            if limit is not None and len(alerts) >= limit:
                return alerts
        offset += len(chunk)
    return alerts


def _iter_alerts(
    rows: Iterable[Mapping[str, Any]],
    *,
    start_index: int,
    include_benign: bool,
    benign_sample_rate: float,
    on_unknown_label: OnUnknownLabel,
) -> Iterator[NormalizedAlert]:
    for offset, row in enumerate(rows):
        try:
            alert, meta = _flow_to_alert_with_meta(row, start_index + offset)
        except UnknownLabelError:
            if on_unknown_label == "raise":
                raise
            continue

        if not meta.is_attack:
            if not include_benign or not _keep_benign(
                alert.alert_id, benign_sample_rate
            ):
                continue
        yield alert


def _keep_benign(alert_id: str, sample_rate: float) -> bool:
    """Deterministically decide whether a benign alert survives downsampling.

    Hash-based rather than random so that two runs over the same CSV select the
    same benign rows.
    """
    if sample_rate >= 1.0:
        return True
    if sample_rate <= 0.0:
        return False
    bucket = int(alert_id[-4:], 16) / 0xFFFF
    return bucket < sample_rate


def _clean_ip(value: Any) -> str | None:
    return None if is_missing(value) else str(value).strip()


def _resolve_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """Look up each logical field through its known header aliases."""
    normalized = {normalize_column_name(str(k)): v for k, v in row.items()}
    resolved: dict[str, Any] = {}
    for field, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                resolved[field] = normalized[alias]
                break
    return resolved


def _build_raw_log(
    meta: AlertMeta,
    fields: Mapping[str, Any],
    dest_ip: str | None,
    port: int | None,
    proto: str | None,
) -> str:
    """Render the flow counters into the evidence line the agent will read.

    Only states what the row actually contained: a file without IPs yields a line
    that names the destination port and nothing more.
    """
    duration_us = coerce_int(fields.get("flow_duration"))
    fwd_packets = coerce_int(fields.get("fwd_packets"))
    bwd_packets = coerce_int(fields.get("bwd_packets"))
    fwd_bytes = coerce_int(fields.get("fwd_bytes"))
    bwd_bytes = coerce_int(fields.get("bwd_bytes"))

    if dest_ip and port is not None:
        target = f"{dest_ip}:{port}"
    elif dest_ip:
        target = dest_ip
    elif port is not None:
        target = f"destination port {port}"
    else:
        target = "an unrecorded destination"

    transport = f" over {proto}" if proto else ""

    return (
        f"{meta.rule_id} matched flow to {target}{transport}: "
        f"{fwd_packets} forward packets ({fwd_bytes} bytes), "
        f"{bwd_packets} backward packets ({bwd_bytes} bytes), "
        f"flow duration {duration_us / 1_000_000:.3f}s."
    )
