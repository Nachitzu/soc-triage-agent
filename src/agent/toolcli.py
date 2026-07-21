"""`soc-tool`: deterministic plumbing for the Claude Code console mode (no API key).

The triage agent's reasoning normally runs against the Anthropic API. This module is
the other half — the parts that are pure code, not a language model — exposed as a CLI
so the live Claude Code session can drive a triage without any API call:

    soc-tool validate --in triage.json          # check a TriageOutput against the contract
    soc-tool tool lookup_ip_reputation --input '{"ip": "45.133.1.77"}'
    soc-tool tool check_alert_history --input '{"rule_id": "R1", "source_ip": "10.0.0.1"}'
    soc-tool report --results results/ --out reports/

It reuses the exact same primitives as API mode — `TriageOutput` for validation,
`Toolbox.dispatch` for enrichment, `write_report` for the session report — so the two
run modes can never drift. Offline by default: without `ABUSEIPDB_API_KEY` the
reputation tool returns a `status` explaining the skip rather than hitting the network.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import BaseModel, ValidationError

from src.agent.tools import build_toolbox
from src.schemas.normalized_alert import NormalizedAlert
from src.schemas.triage_output import TriageOutput

SCHEMAS: dict[str, type[BaseModel]] = {
    "triage-output": TriageOutput,
    "normalized-alert": NormalizedAlert,
}


def _read_input(spec: str) -> str:
    if spec == "-":
        return sys.stdin.read()
    return Path(spec).read_text(encoding="utf-8")


def cmd_validate(args: argparse.Namespace) -> int:
    model = SCHEMAS[args.schema]
    try:
        raw = json.loads(_read_input(args.in_))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read/parse input: {exc}", file=sys.stderr)
        return 1
    try:
        obj = model.model_validate(raw)
    except ValidationError as exc:
        # Verbatim error so the console session can correct itself and re-validate,
        # exactly like the API-mode parse-and-retry loop.
        print(f"validation failed for {args.schema}:\n{exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "schema": args.schema,
                "normalized": obj.model_dump(mode="json"),
            },
            indent=2,
            default=str,
        )
    )
    return 0


def cmd_tool(args: argparse.Namespace) -> int:
    try:
        tool_input = json.loads(args.input) if args.input else {}
    except json.JSONDecodeError as exc:
        print(f"--input is not valid JSON: {exc}", file=sys.stderr)
        return 2
    toolbox = build_toolbox()
    try:
        content, is_error = toolbox.dispatch(args.name, tool_input)
    finally:
        toolbox.close()
    print(content)
    return 1 if is_error else 0


def cmd_report(args: argparse.Namespace) -> int:
    from src.reporting.html_report import write_report

    path = write_report(args.results, args.out, model=args.model)
    print(json.dumps({"status": "ok", "report": str(path)}))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-tool",
        description="Deterministic, offline plumbing for the Claude Code console mode "
        "(validation, enrichment tools, session report). No API key needed.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="validate JSON against a triage contract")
    p_val.add_argument("--schema", default="triage-output", choices=sorted(SCHEMAS))
    p_val.add_argument(
        "--in", dest="in_", required=True, help="input JSON path, or '-' for stdin"
    )
    p_val.set_defaults(func=cmd_validate)

    p_tool = sub.add_parser(
        "tool", help="run an enrichment tool and print its JSON result"
    )
    p_tool.add_argument(
        "name", choices=["lookup_ip_reputation", "check_alert_history"]
    )
    p_tool.add_argument("--input", default="{}", help="tool input as a JSON object")
    p_tool.set_defaults(func=cmd_tool)

    p_rep = sub.add_parser(
        "report", help="render the HTML session report from a results dir"
    )
    p_rep.add_argument(
        "--results", required=True, help="directory of triage result JSON files"
    )
    p_rep.add_argument(
        "--out", default="reports", help="output directory (default: reports/)"
    )
    p_rep.add_argument("--model", help="model label to stamp on the report")
    p_rep.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
