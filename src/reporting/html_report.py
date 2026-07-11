"""Session report: one self-contained HTML file per batch run (Phase 5).

The JSON files the agent writes are a machine contract, not a reading surface —
a SOC specialist should never have to open twenty `.json` files to work a
queue. This module turns a results directory into a single timestamped HTML
report: a prioritized queue table on top, one detail card per alert below it,
and any failed triages listed explicitly so nothing disappears silently.

DESIGN RULES
============
- Self-contained: all CSS/JS inline, no external fonts, images, or network
  calls, so the file can be opened from a file share, attached to a ticket, or
  e-mailed.
- English is the normalized base language (the report always renders in
  English with no JS, and the model's own output — alert IDs, summaries,
  evidence, MITRE technique strings — is never translated, since translating
  it would mean inventing text the model didn't produce). A language toggle in
  the header switches the UI chrome to Spanish client-side, for analysts who
  prefer it; every translatable label carries `data-en`/`data-es` attributes.
- Everything the model produced is untrusted text and is HTML-escaped. An
  alert summary that contains markup must render as text, never execute.
- Severity/action colors never carry meaning alone — every colored badge also
  says its label in words, and the queue is *ordered* by priority.
"""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

# Ordering of the queue: what a Tier 2 analyst should look at first.
ACTION_PRIORITY = {
    "block_and_escalate": 0,
    "escalate_tier2": 1,
    "needs_more_data": 2,
    "monitor": 3,
    "close_false_positive": 4,
}
SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

Lang = tuple[str, str]  # (english, spanish)

ACTION_LABELS: dict[str, Lang] = {
    "block_and_escalate": ("Block & escalate", "Bloquear y escalar"),
    "escalate_tier2": ("Escalate to Tier 2", "Escalar a Tier 2"),
    "needs_more_data": ("Needs more data", "Faltan datos"),
    "monitor": ("Monitor", "Monitorear"),
    "close_false_positive": ("Close (false positive)", "Cerrar (falso positivo)"),
}

SEVERITY_LABELS: dict[str, Lang] = {
    "CRITICAL": ("Critical", "Crítica"),
    "HIGH": ("High", "Alta"),
    "MEDIUM": ("Medium", "Media"),
    "LOW": ("Low", "Baja"),
}

# All translatable UI chrome. Model-produced content (alert_id, summary,
# key_evidence, mitre_techniques, error text) is intentionally NOT in here —
# it is rendered verbatim in whichever language the model produced it.
STRINGS: dict[str, Lang] = {
    "doc_title": ("SOC Alert Triage Report", "Informe de Triage de Alertas — SOC"),
    "h1": ("SOC Alert Triage Report", "Informe de Triage de Alertas — SOC"),
    "meta_generated": ("Generated", "Generado"),
    "meta_source": ("Source", "Origen"),
    "meta_model": ("Model", "Modelo"),
    "tile_processed": ("Alerts processed", "Alertas procesadas"),
    "tile_escalation": ("Require escalation", "Requieren escalamiento"),
    "tile_needs_data": ("Needs more data", "Faltan datos"),
    "tile_monitor": ("Monitor", "Monitorear"),
    "tile_closed_fp": ("Closed as false positive", "Cerradas como falso positivo"),
    "tile_errors": ("Triage errors", "Errores de triage"),
    "h2_queue": ("Prioritized Queue", "Cola priorizada"),
    "th_num": ("#", "#"),
    "th_alert": ("Alert", "Alerta"),
    "th_severity": ("Severity", "Severidad"),
    "th_action": ("Recommended Action", "Acción recomendada"),
    "th_fp": ("FP Probability", "Prob. falso positivo"),
    "th_confidence": ("Confidence", "Confianza"),
    "mitre_label": ("MITRE ATT&CK", "MITRE ATT&CK"),
    "h2_errors": (
        "Unresolved Alerts — Manual Review Required",
        "Alertas sin triage — revisión manual",
    ),
    "errors_intro": (
        "These alerts did not produce a valid result. They must be triaged "
        "manually or retried.",
        "Estas alertas no produjeron un resultado válido. Deben triarse a mano "
        "o reintentarse.",
    ),
    "th_error": ("Error", "Error"),
    "h2_detail": ("Alert Detail", "Detalle por alerta"),
    "metric_fp": ("FP Probability", "Prob. falso positivo"),
    "metric_confidence": ("Confidence", "Confianza"),
    "h4_evidence": ("Key Evidence", "Evidencia clave"),
    "no_mapping": ("No mapping", "Sin mapeo"),
    "footer": (
        "This report was generated automatically by the Tier 1 triage agent. "
        "Every result was validated against the TriageOutput schema before "
        "being included. Alerts listed as “unresolved” require "
        "manual review. This document is self-contained and can be shared by "
        "e-mail or ticket.",
        "Este informe fue generado automáticamente por el agente de triage "
        "Tier 1. Cada resultado fue validado contra el esquema TriageOutput "
        "antes de incluirse. Las alertas listadas como «sin triage» requieren "
        "revisión manual. Este documento es autocontenido y puede compartirse "
        "por correo o ticket.",
    ),
}


def load_results(
    results_dir: Path | str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read every triage result and every recorded failure from a run directory.

    Returns `(results, errors)`. Files that are not valid JSON are reported as
    errors rather than skipped: a corrupt result must be visible in the report.
    """
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for path in sorted(Path(results_dir).glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"alert_id": path.stem, "error": f"unreadable file: {exc}"})
            continue
        if path.name.endswith(".error.json"):
            errors.append(payload)
        else:
            results.append(payload)
    return results, errors


def _sort_key(result: dict[str, Any]) -> tuple[int, int, float]:
    return (
        ACTION_PRIORITY.get(result.get("recommended_action", ""), 9),
        SEVERITY_PRIORITY.get(result.get("severity", ""), 9),
        result.get("false_positive_probability", 1.0),
    )


def _e(value: Any) -> str:
    """Escape model-produced text for HTML. Everything goes through here."""
    return html.escape(str(value), quote=True)


def _i18n(key: str, tag: str = "span", extra_class: str = "") -> str:
    """Render a translatable UI element: English text, both languages tagged.

    No-JS / default render shows the English text. The toggle script swaps
    `textContent` between `data-en` and `data-es` on every `.i18n` element.
    """
    en, es = STRINGS[key]
    cls = f"i18n {extra_class}".strip()
    return f'<{tag} class="{cls}" data-en="{_e(en)}" data-es="{_e(es)}">{_e(en)}</{tag}>'


def _severity_badge(severity: str) -> str:
    en, es = SEVERITY_LABELS.get(severity, (severity, severity))
    return (
        f'<span class="badge sev-{_e(severity.lower())} i18n" '
        f'data-en="{_e(en)}" data-es="{_e(es)}">{_e(en)}</span>'
    )


def _action_badge(action: str) -> str:
    en, es = ACTION_LABELS.get(action, (action, action))
    return (
        f'<span class="badge act-{_e(action)} i18n" '
        f'data-en="{_e(en)}" data-es="{_e(es)}">{_e(en)}</span>'
    )


def _meter(value: float) -> str:
    """A small horizontal meter with its numeric value beside it."""
    pct = max(0.0, min(1.0, float(value))) * 100
    return (
        '<span class="meter-wrap"><span class="meter">'
        f'<span class="meter-fill" style="width:{pct:.0f}%"></span></span>'
        f'<span class="meter-num">{value:.2f}</span></span>'
    )


def _summary_tiles(results: list[dict[str, Any]], errors: list[dict[str, Any]]) -> str:
    counts = {action: 0 for action in ACTION_PRIORITY}
    for result in results:
        action = result.get("recommended_action", "")
        if action in counts:
            counts[action] += 1
    escalated = counts["block_and_escalate"] + counts["escalate_tier2"]
    tiles = [
        ("tile_processed", str(len(results)), ""),
        ("tile_escalation", str(escalated), "tile-crit" if escalated else ""),
        ("tile_needs_data", str(counts["needs_more_data"]), ""),
        ("tile_monitor", str(counts["monitor"]), ""),
        ("tile_closed_fp", str(counts["close_false_positive"]), ""),
        ("tile_errors", str(len(errors)), "tile-crit" if errors else ""),
    ]
    cells = "".join(
        f'<div class="tile {extra}"><div class="tile-num">{_e(num)}</div>'
        f'<div class="tile-label">{_i18n(key)}</div></div>'
        for key, num, extra in tiles
    )
    return f'<section class="tiles">{cells}</section>'


def _queue_table(results: list[dict[str, Any]]) -> str:
    rows = []
    for i, result in enumerate(results, start=1):
        alert_id = result.get("alert_id", "?")
        rows.append(
            "<tr>"
            f'<td class="num">{i}</td>'
            f'<td><a href="#alert-{_e(alert_id)}">{_e(alert_id)}</a></td>'
            f"<td>{_severity_badge(result.get('severity', '?'))}</td>"
            f"<td>{_action_badge(result.get('recommended_action', '?'))}</td>"
            f'<td class="num">{_meter(result.get("false_positive_probability", 0.0))}</td>'
            f'<td class="num">{_meter(result.get("confidence", 0.0))}</td>'
            f'<td class="mitre-cell">{_e(", ".join(result.get("mitre_techniques", [])) or "—")}</td>'
            "</tr>"
        )
    header_cells = (
        _i18n("th_num", "th")
        + _i18n("th_alert", "th")
        + _i18n("th_severity", "th")
        + _i18n("th_action", "th")
        + _i18n("th_fp", "th")
        + _i18n("th_confidence", "th")
        + _i18n("mitre_label", "th")
    )
    return (
        f'<section>{_i18n("h2_queue", "h2")}<div class="table-scroll"><table>'
        f"<thead><tr>{header_cells}</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody></table></div></section>'
    )


def _detail_cards(results: list[dict[str, Any]]) -> str:
    cards = []
    for result in results:
        alert_id = result.get("alert_id", "?")
        evidence = "".join(
            f"<li>{_e(item)}</li>" for item in result.get("key_evidence", [])
        )
        mitre = (
            "".join(
                f'<span class="chip">{_e(technique)}</span>'
                for technique in result.get("mitre_techniques", [])
            )
            or _i18n("no_mapping", "span", "muted")
        )
        cards.append(
            f'<article class="card" id="alert-{_e(alert_id)}">'
            f'<header class="card-head"><h3>{_e(alert_id)}</h3>'
            f"{_severity_badge(result.get('severity', '?'))}"
            f"{_action_badge(result.get('recommended_action', '?'))}</header>"
            f'<p class="summary">{_e(result.get("summary", ""))}</p>'
            '<div class="card-metrics">'
            f'<div>{_i18n("metric_fp", "span", "metric-label")}'
            f'{_meter(result.get("false_positive_probability", 0.0))}</div>'
            f'<div>{_i18n("metric_confidence", "span", "metric-label")}'
            f'{_meter(result.get("confidence", 0.0))}</div>'
            "</div>"
            f'{_i18n("h4_evidence", "h4")}<ul>{evidence}</ul>'
            f'{_i18n("mitre_label", "h4")}<div class="chips">{mitre}</div>'
            "</article>"
        )
    return f'<section>{_i18n("h2_detail", "h2")}{"".join(cards)}</section>'


def _error_section(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return ""
    rows = "".join(
        f"<tr><td>{_e(err.get('alert_id', '?'))}</td><td>{_e(err.get('error', ''))}</td></tr>"
        for err in errors
    )
    header_cells = _i18n("th_alert", "th") + _i18n("th_error", "th")
    return (
        f'<section>{_i18n("h2_errors", "h2")}'
        f'{_i18n("errors_intro", "p")}'
        f'<div class="table-scroll"><table><thead><tr>{header_cells}</tr></thead>'
        f"<tbody>{rows}</tbody></table></div></section>"
    )


# Chart chrome / status tokens from the validated reference palette. Status
# colors are tinted backgrounds behind dark ink, and every badge repeats its
# meaning in words, so color never carries the information alone.
_CSS = """
:root {
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
  --accent: #256abf; --meter-track: #e1e0d9;
  --crit-bg: #f7dcdc; --crit-ink: #8c1f1f;
  --high-bg: #fbe4d9; --high-ink: #8a3c1a;
  --med-bg: #fdf0d2;  --med-ink: #7a5200;
  --low-bg: #ddf0dd;  --low-ink: #0e5c0e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
    --accent: #3987e5; --meter-track: #383835;
    --crit-bg: #4a1f1f; --crit-ink: #f2b8b8;
    --high-bg: #4a2d1c; --high-ink: #f4c9ae;
    --med-bg: #453a12;  --med-ink: #f2d996;
    --low-bg: #1c3a1c;  --low-ink: #b5e2b5;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
header.masthead { border-bottom: 2px solid var(--ink); padding-bottom: 16px; margin-bottom: 24px; }
.masthead-row { display: flex; justify-content: space-between; align-items: flex-start;
  gap: 16px; flex-wrap: wrap; }
h1 { font-size: 24px; margin: 0 0 4px; }
.meta { color: var(--ink-2); font-size: 13px; }
.meta strong { color: var(--ink); font-weight: 600; }
h2 { font-size: 17px; margin: 36px 0 12px; border-bottom: 1px solid var(--grid); padding-bottom: 6px; }
h3 { font-size: 15px; margin: 0; }
h4 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;
     color: var(--muted); margin: 16px 0 6px; }
.lang-toggle { display: inline-flex; border: 1px solid var(--grid); border-radius: 999px;
  overflow: hidden; flex-shrink: 0; margin-top: 2px; }
.lang-btn { border: none; background: var(--surface); color: var(--ink-2); font: inherit;
  font-size: 12.5px; font-weight: 700; padding: 6px 14px; cursor: pointer; }
.lang-btn + .lang-btn { border-left: 1px solid var(--grid); }
.lang-btn.active { background: var(--accent); color: #ffffff; }
.lang-btn:hover:not(.active) { background: var(--page); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.tile-num { font-size: 26px; font-weight: 650; }
.tile-label { font-size: 12px; color: var(--ink-2); }
.tile-crit .tile-num { color: var(--crit-ink); }
.table-scroll { overflow-x: auto; background: var(--surface);
  border: 1px solid var(--border); border-radius: 8px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px;
     text-transform: uppercase; letter-spacing: 0.04em; }
th, td { padding: 8px 12px; border-bottom: 1px solid var(--grid); vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
td a { color: var(--accent); text-decoration: none; }
td a:hover { text-decoration: underline; }
.mitre-cell { color: var(--ink-2); max-width: 260px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-size: 11.5px; font-weight: 600; white-space: nowrap; }
.sev-critical { background: var(--crit-bg); color: var(--crit-ink); }
.sev-high     { background: var(--high-bg); color: var(--high-ink); }
.sev-medium   { background: var(--med-bg);  color: var(--med-ink); }
.sev-low      { background: var(--low-bg);  color: var(--low-ink); }
.act-block_and_escalate { background: var(--crit-bg); color: var(--crit-ink); }
.act-escalate_tier2     { background: var(--high-bg); color: var(--high-ink); }
.act-needs_more_data    { background: var(--med-bg);  color: var(--med-ink); }
.act-monitor            { background: var(--surface); color: var(--ink-2); border: 1px solid var(--grid); }
.act-close_false_positive { background: var(--low-bg); color: var(--low-ink); }
.card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 18px 20px; margin-bottom: 14px; }
.card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.summary { color: var(--ink); margin: 12px 0 0; }
.card-metrics { display: flex; gap: 32px; margin-top: 12px; font-size: 13px; }
.metric-label { display: block; font-size: 11px; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 3px; }
ul { margin: 4px 0 0; padding-left: 20px; }
li { margin-bottom: 4px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { background: var(--page); border: 1px solid var(--grid); border-radius: 999px;
  padding: 2px 10px; font-size: 12px; color: var(--ink-2); }
.muted { color: var(--muted); }
.meter-wrap { display: inline-flex; align-items: center; gap: 8px; }
.meter { display: inline-block; width: 64px; height: 6px; border-radius: 3px;
  background: var(--meter-track); overflow: hidden; vertical-align: middle; }
.meter-fill { display: block; height: 100%; background: var(--accent); border-radius: 3px; }
.meter-num { font-variant-numeric: tabular-nums; font-size: 12.5px; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px;
  border-top: 1px solid var(--grid); padding-top: 12px; }
@media print { body { background: #fff; } .wrap { max-width: none; } .lang-toggle { display: none; } }
"""

# Toggles every `.i18n` element between its `data-en` and `data-es` text, no
# external dependencies. Persists the choice in localStorage so repeat opens
# of the same report (or another report from the same browser) remember it.
_JS = """
(function () {
  var STORAGE_KEY = "soc-triage-report-lang";
  function apply(lang) {
    document.querySelectorAll(".i18n").forEach(function (el) {
      var text = el.getAttribute("data-" + lang);
      if (text !== null) el.textContent = text;
    });
    document.querySelectorAll(".lang-btn").forEach(function (btn) {
      btn.classList.toggle("active", btn.getAttribute("data-set-lang") === lang);
    });
    document.documentElement.setAttribute("lang", lang);
    try { window.localStorage.setItem(STORAGE_KEY, lang); } catch (err) {}
  }
  document.querySelectorAll(".lang-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      apply(btn.getAttribute("data-set-lang"));
    });
  });
  var saved = null;
  try { saved = window.localStorage.getItem(STORAGE_KEY); } catch (err) {}
  if (saved === "es") apply("es");
})();
"""


def render_report(
    results: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    *,
    source: str = "",
    model: str | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render the full HTML document for one session's results.

    The document always renders in English by default; the language toggle in
    the header is a client-side script that swaps UI chrome to Spanish.
    """
    generated_at = generated_at or datetime.now().astimezone()
    ordered = sorted(results, key=_sort_key)
    stamp = generated_at.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

    meta_bits = [f'{_i18n("meta_generated")}: <strong>{_e(stamp)}</strong>']
    if source:
        meta_bits.append(f'{_i18n("meta_source")}: <strong>{_e(source)}</strong>')
    if model:
        meta_bits.append(f'{_i18n("meta_model")}: <strong>{_e(model)}</strong>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(STRINGS["doc_title"][0])} — {_e(generated_at.strftime("%Y-%m-%d %H:%M"))}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header class="masthead">
<div class="masthead-row">
<div>
{_i18n("h1", "h1")}
<p class="meta">{" &nbsp;·&nbsp; ".join(meta_bits)}</p>
</div>
<div class="lang-toggle" role="group" aria-label="Language / Idioma">
<button type="button" class="lang-btn active" data-set-lang="en">EN</button>
<button type="button" class="lang-btn" data-set-lang="es">ES</button>
</div>
</div>
</header>
{_summary_tiles(ordered, errors)}
{_queue_table(ordered)}
{_error_section(errors)}
{_detail_cards(ordered)}
<footer>{_i18n("footer", "p")}</footer>
</div>
<script>{_JS}</script>
</body>
</html>
"""


def write_report(
    results_dir: Path | str,
    out_dir: Path | str = Path("reports"),
    *,
    model: str | None = None,
    now: datetime | None = None,
) -> Path:
    """Generate the session report and return the path it was written to.

    The filename carries a timestamp so successive sessions never overwrite
    each other and the newest report sorts last.
    """
    now = now or datetime.now().astimezone()
    results, errors = load_results(results_dir)
    document = render_report(
        results, errors, source=str(results_dir), model=model, generated_at=now
    )
    out_path = Path(out_dir) / f"triage_report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document, encoding="utf-8")
    return out_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.reporting.html_report",
        description="Render a directory of triage results as a session HTML report.",
    )
    parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help="directory of TriageOutput JSON files",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("reports"), help="directory for the HTML report"
    )
    parser.add_argument("--model", help="model name shown in the report header")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    path = write_report(args.results, args.out, model=args.model)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
