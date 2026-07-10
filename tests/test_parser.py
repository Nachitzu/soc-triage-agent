"""Parser tests. Both CICIDS2017 layouts, from synthetic CSVs written to tmp_path."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from src.ingest.cicids_parser import (
    Layout,
    UnknownLabelError,
    detect_layout,
    flow_to_alert,
    label_to_meta,
    parse_cicids_csv,
    parse_cicids_dataframe,
)
from src.ingest.normalizer import (
    asset_tag_for_ip,
    coerce_port,
    coerce_timestamp,
    normalize_column_name,
    normalize_label,
    protocol_name,
)

# The "GeneratedLabelledFlows" shape: identifiers present.
LABELLED_FLOWS_CSV = (
    "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol,"
    " Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,"
    "Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
    "f1, 172.16.0.1, 56341, 10.0.1.12, 22, 6, 5/7/2017 8:55, 120043, 47, 12, 5120, 800, SSH-Patator\n"
    "f2, 192.168.10.5, 51000, 192.168.10.50, 443, 6, 5/7/2017 9:01, 2000, 4, 4, 300, 900, BENIGN\n"
)

# The "MachineLearningCVE" shape: destination port, features, label. Nothing else.
FEATURES_ONLY_CSV = (
    " Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,"
    "Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
    "22, 120043, 47, 12, 5120, 800, SSH-Patator\n"
    "443, 2000, 4, 4, 300, 900, BENIGN\n"
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class TestNormalizerPrimitives:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (" Source IP", "source_ip"),
            ("Total Length of Fwd Packets", "total_length_of_fwd_packets"),
            (" Label", "label"),
            ("Flow Bytes/s", "flow_bytes_s"),
        ],
    )
    def test_column_names_fold_to_snake_case(self, raw: str, expected: str) -> None:
        assert normalize_column_name(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("BENIGN", "benign"),
            ("SSH-Patator", "ssh_patator"),
            ("DoS slowloris", "dos_slowloris"),
            ("DoS Slowhttptest", "dos_slowhttptest"),
            ("PortScan", "portscan"),
            # The three encodings of the web-attack dash seen across mirrors.
            ("Web Attack \x96 Brute Force", "web_attack_brute_force"),
            ("Web Attack � XSS", "web_attack_xss"),
            ("Web Attack – Sql Injection", "web_attack_sql_injection"),
        ],
    )
    def test_labels_fold_across_encodings(self, raw: str, expected: str) -> None:
        assert normalize_label(raw) == expected

    def test_day_first_timestamps_become_utc(self) -> None:
        assert coerce_timestamp("5/7/2017 8:55") == datetime(
            2017, 7, 5, 8, 55, tzinfo=timezone.utc
        )

    def test_iso_timestamps_are_accepted(self) -> None:
        assert coerce_timestamp("2026-07-08T03:12:44Z") == datetime(
            2026, 7, 8, 3, 12, 44, tzinfo=timezone.utc
        )

    def test_unparseable_timestamp_raises(self) -> None:
        with pytest.raises(ValueError, match="unrecognized timestamp"):
            coerce_timestamp("not a date")

    @pytest.mark.parametrize(
        ("value", "expected"), [(6, "TCP"), (17, "UDP"), (1, "ICMP")]
    )
    def test_protocol_numbers_map_to_names(self, value: int, expected: str) -> None:
        assert protocol_name(value) == expected

    def test_missing_protocol_is_none(self) -> None:
        assert protocol_name(float("nan")) is None
        assert protocol_name(None) is None

    def test_unknown_protocol_number_is_none(self) -> None:
        assert protocol_name(253) is None

    @pytest.mark.parametrize(
        ("value", "expected"), [("22", 22), (443.0, 443), (99999, None)]
    )
    def test_port_coercion(self, value: object, expected: int | None) -> None:
        assert coerce_port(value) == expected

    def test_critical_asset_ranges_are_tagged(self) -> None:
        assert asset_tag_for_ip("10.0.1.12") == "domain_controller"
        assert asset_tag_for_ip("10.0.2.11") == "database_server"
        assert asset_tag_for_ip("10.0.5.40") is None
        assert asset_tag_for_ip("not-an-ip") is None


class TestLabelMapping:
    def test_known_label_resolves(self) -> None:
        meta = label_to_meta("SSH-Patator")
        assert meta.rule_id == "SSH-BRUTE-01"
        assert meta.alert_type == "authentication_failure_burst"
        assert meta.is_attack is True

    def test_benign_is_not_an_attack(self) -> None:
        assert label_to_meta("BENIGN").is_attack is False

    def test_unknown_label_raises(self) -> None:
        with pytest.raises(UnknownLabelError, match="no mapping for label"):
            label_to_meta("Cryptolocker")


class TestLayoutDetection:
    def test_labelled_flows_layout(self) -> None:
        columns = [" Source IP", " Destination IP", " Label"]
        assert detect_layout(columns) is Layout.LABELLED_FLOWS

    def test_features_only_layout(self) -> None:
        columns = [" Destination Port", " Flow Duration", " Label"]
        assert detect_layout(columns) is Layout.FEATURES_ONLY

    def test_source_without_destination_is_features_only(self) -> None:
        """Half the identifiers is not enough to reason about network context."""
        assert detect_layout([" Source IP", " Label"]) is Layout.FEATURES_ONLY


class TestFlowToAlert:
    def test_labelled_flow_produces_a_complete_alert(self) -> None:
        row = {
            " Source IP": "172.16.0.1",
            " Destination IP": "10.0.1.12",
            " Destination Port": 22,
            " Protocol": 6,
            " Timestamp": "5/7/2017 8:55",
            " Flow Duration": 120043,
            " Total Fwd Packets": 47,
            " Total Backward Packets": 12,
            "Total Length of Fwd Packets": 5120,
            " Total Length of Bwd Packets": 800,
            " Label": "SSH-Patator",
        }
        alert = flow_to_alert(row)

        assert alert.has_network_context is True
        assert alert.rule_id == "SSH-BRUTE-01"
        assert alert.alert_type == "authentication_failure_burst"
        assert alert.source_ip == "172.16.0.1"
        assert alert.dest_ip == "10.0.1.12"
        assert alert.port == 22
        assert alert.protocol == "TCP"
        assert alert.asset_tag == "domain_controller"
        assert alert.timestamp == datetime(2017, 7, 5, 8, 55, tzinfo=timezone.utc)
        assert "10.0.1.12:22" in alert.raw_log
        assert "47 forward packets (5120 bytes)" in alert.raw_log

    def test_features_only_flow_produces_a_degraded_alert(self) -> None:
        row = {
            " Destination Port": 22,
            " Flow Duration": 120043,
            " Total Fwd Packets": 47,
            " Total Backward Packets": 12,
            "Total Length of Fwd Packets": 5120,
            " Total Length of Bwd Packets": 800,
            " Label": "SSH-Patator",
        }
        alert = flow_to_alert(row)

        assert alert.has_network_context is False
        assert alert.source_ip is None
        assert alert.dest_ip is None
        assert alert.timestamp is None
        assert alert.protocol is None
        assert alert.asset_tag is None
        assert alert.port == 22
        assert alert.rule_id == "SSH-BRUTE-01"
        # The evidence line names only what the row actually contained.
        assert "destination port 22" in alert.raw_log
        assert "None" not in alert.raw_log

    def test_row_without_a_label_raises(self) -> None:
        with pytest.raises(ValueError, match="missing the required 'Label'"):
            flow_to_alert({" Destination Port": 22})

    def test_alert_ids_are_deterministic_and_positional(self) -> None:
        row = {" Destination Port": 22, " Label": "SSH-Patator"}
        assert (
            flow_to_alert(row, row_index=7).alert_id
            == flow_to_alert(row, row_index=7).alert_id
        )
        assert (
            flow_to_alert(row, row_index=7).alert_id
            != flow_to_alert(row, row_index=8).alert_id
        )


class TestParseCsv:
    def test_labelled_flows_csv(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "flows.csv", LABELLED_FLOWS_CSV)
        alerts = parse_cicids_csv(path)

        assert len(alerts) == 2
        attack, benign = alerts
        assert attack.rule_id == "SSH-BRUTE-01"
        assert attack.has_network_context is True
        assert benign.rule_id == "BASELINE-00"

    def test_features_only_csv(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "features.csv", FEATURES_ONLY_CSV)
        alerts = parse_cicids_csv(path)

        assert len(alerts) == 2
        assert all(a.has_network_context is False for a in alerts)
        assert alerts[0].port == 22

    def test_benign_rows_can_be_excluded(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "features.csv", FEATURES_ONLY_CSV)
        alerts = parse_cicids_csv(path, include_benign=False)

        assert [a.rule_id for a in alerts] == ["SSH-BRUTE-01"]

    def test_zero_sample_rate_drops_every_benign_row(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "features.csv", FEATURES_ONLY_CSV)
        alerts = parse_cicids_csv(path, benign_sample_rate=0.0)

        assert [a.rule_id for a in alerts] == ["SSH-BRUTE-01"]

    def test_limit_short_circuits(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "features.csv", FEATURES_ONLY_CSV)
        assert len(parse_cicids_csv(path, limit=1)) == 1

    def test_latin1_web_attack_label_round_trips(self, tmp_path: Path) -> None:
        """The real CSVs carry a non-UTF-8 byte inside the web-attack labels."""
        path = tmp_path / "web.csv"
        path.write_bytes(
            b" Destination Port, Flow Duration, Label\n"
            b"80, 1000, Web Attack \x96 Sql Injection\n"
        )
        alerts = parse_cicids_csv(path)

        assert [a.rule_id for a in alerts] == ["WEB-SQLI-01"]

    def test_unknown_label_raises_by_default(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "bad.csv", " Destination Port, Label\n80, Cryptolocker\n"
        )
        with pytest.raises(UnknownLabelError):
            parse_cicids_csv(path)

    def test_unknown_label_can_be_skipped(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "bad.csv",
            " Destination Port, Label\n80, Cryptolocker\n22, SSH-Patator\n",
        )
        alerts = parse_cicids_csv(path, on_unknown_label="skip")

        assert [a.rule_id for a in alerts] == ["SSH-BRUTE-01"]

    def test_chunk_boundaries_do_not_collide_alert_ids(self, tmp_path: Path) -> None:
        """Identical rows across chunks must still receive distinct ids."""
        rows = "".join("22, 100, SSH-Patator\n" for _ in range(6))
        path = _write(
            tmp_path / "dupes.csv", " Destination Port, Flow Duration, Label\n" + rows
        )
        alerts = parse_cicids_csv(path, chunksize=2)

        assert len({a.alert_id for a in alerts}) == 6


class TestParseDataframe:
    def test_dataframe_entrypoint(self) -> None:
        frame = pd.DataFrame(
            [
                {
                    " Destination Port": 22,
                    " Flow Duration": 100,
                    " Label": "SSH-Patator",
                },
                {" Destination Port": 443, " Flow Duration": 100, " Label": "BENIGN"},
            ]
        )
        alerts = parse_cicids_dataframe(frame, include_benign=False)

        assert [a.rule_id for a in alerts] == ["SSH-BRUTE-01"]
