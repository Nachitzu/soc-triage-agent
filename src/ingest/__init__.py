"""Alert ingestion: turn heterogeneous sources into `NormalizedAlert`."""

from src.ingest.cicids_parser import (
    LABEL_MAP,
    AlertMeta,
    Layout,
    UnknownLabelError,
    detect_layout,
    flow_to_alert,
    label_to_meta,
    parse_cicids_csv,
    parse_cicids_dataframe,
)

__all__ = [
    "LABEL_MAP",
    "AlertMeta",
    "Layout",
    "UnknownLabelError",
    "detect_layout",
    "flow_to_alert",
    "label_to_meta",
    "parse_cicids_csv",
    "parse_cicids_dataframe",
]
