"""Input schema: the common shape every alert source is normalized into.

Heterogeneous sources (CICIDS2017 flow records, raw syslog, a live SIEM) are all
converted into a `NormalizedAlert` before the triage agent ever sees them. The
agent's system prompt is written against these field names.

WHY THE NETWORK FIELDS ARE OPTIONAL
-----------------------------------
`timestamp`, `source_ip`, `dest_ip` and `protocol` are nullable because not every
alert source carries them. The widely mirrored *MachineLearningCVE* distribution
of CICIDS2017 ships 77 flow features, a destination port and a label — and no
identifiers at all. The alternative is to synthesize plausible IPs and
timestamps, which would fabricate exactly the evidence the agent is forbidden to
invent. An absent field is therefore represented as absent, and `raw_log` states
only what the source actually provided.

An alert that lacks network context cannot be reasoned about against the
environment baseline (internal ranges, business hours, critical assets). Use
`has_network_context` to tell the two populations apart.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


def is_internal_ip(ip: str | None) -> bool:
    """Return True if `ip` is in a private (RFC 1918) range.

    Mirrors the "internal ranges" section of the system prompt. Used to decide
    whether an IP reputation lookup is worth making (Phase 3) and to give the
    parser a cheap notion of traffic direction.
    """
    if ip is None:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class NormalizedAlert(BaseModel):
    """A single SIEM alert, normalized.

    `timestamp` is always stored timezone-aware. A naive datetime is interpreted
    as UTC rather than as the host's local time, so that parsing the same alert
    on two machines yields the same instant.
    """

    alert_id: str = Field(min_length=1)
    timestamp: datetime | None = None
    rule_id: str = Field(min_length=1)
    alert_type: str = Field(min_length=1)
    source_ip: str | None = None
    dest_ip: str | None = None
    raw_log: str
    asset_tag: str | None = None
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def _check_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {value!r}") from exc
        return value

    @field_validator("timestamp")
    @classmethod
    def _ensure_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @property
    def has_network_context(self) -> bool:
        """True when the source supplied both endpoints and a timestamp.

        Alerts without network context can still be triaged on flow evidence,
        but the environment-baseline reasoning in the system prompt does not
        apply to them.
        """
        return None not in (self.timestamp, self.source_ip, self.dest_ip)

    @property
    def missing_fields(self) -> list[str]:
        """Names of the network-context fields this source did not provide."""
        candidates = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
        }
        return [name for name, value in candidates.items() if value is None]

    @property
    def source_is_internal(self) -> bool:
        return is_internal_ip(self.source_ip)

    @property
    def dest_is_internal(self) -> bool:
        return is_internal_ip(self.dest_ip)
