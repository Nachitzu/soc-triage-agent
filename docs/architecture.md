# Architecture

This document describes how an alert becomes a validated triage decision, and
why each boundary in the system exists.

## The pipeline

```
                 ┌──────────────────────────────────────────────────────────┐
                 │                      src/ingest                          │
  CICIDS2017 ───▶│  cicids_parser.py   normalizer.py                        │
  CSV / logs     │  detect_layout → flow_to_alert → NormalizedAlert          │
                 └───────────────────────────┬──────────────────────────────┘
                                             │  NormalizedAlert (validated)
                                             ▼
                 ┌──────────────────────────────────────────────────────────┐
                 │                       src/agent                          │
                 │                                                          │
                 │   triage_agent.py                                        │
                 │   ┌────────────────────────────────────────────────┐    │
                 │   │  build_user_message  (wraps alert as DATA)      │    │
                 │   │            │                                     │    │
                 │   │            ▼                                     │    │
                 │   │  ┌──────────────────┐   tool_use   ┌─────────┐  │    │
                 │   │  │  model request   │─────────────▶│ tools.py │  │    │
                 │   │  │  (system prompt  │◀─────────────│ Toolbox  │  │    │
                 │   │  │   + tools)       │  tool_result └────┬─────┘  │    │
                 │   │  └────────┬─────────┘                   │        │    │
                 │   │           │ text (JSON)         lookup_ip_rep.   │    │
                 │   │           ▼                     check_history    │    │
                 │   │  ┌──────────────────┐                │          │    │
                 │   │  │  _validate       │           ┌────▼──────┐   │    │
                 │   │  │  parse + schema  │           │ SQLite    │   │    │
                 │   │  │  + alert_id      │           │ + AbuseIP │   │    │
                 │   │  └────────┬─────────┘           │   DB      │   │    │
                 │   │           │ fail → 1 retry      └───────────┘   │    │
                 │   │           ▼                                     │    │
                 │   │      TriageOutput  (validated)                  │    │
                 │   └────────────────────────────────────────────────┘    │
                 └───────────────────────────┬──────────────────────────────┘
                                             │  results/*.json
                                             ▼
                 ┌──────────────────────────────────────────────────────────┐
                 │                     src/evaluation                       │
                 │   evaluate.py   results + labels.json → EvaluationReport   │
                 └──────────────────────────────────────────────────────────┘
```

## Components

### `src/schemas` — the contracts

`NormalizedAlert` and `TriageOutput` are the two boundaries every other module
is written against. `TriageOutput` is more than a shape: its validator encodes
the escalation rules, so a model response that breaks them is rejected in the
same path as malformed JSON. Everything downstream can assume a `TriageOutput`
is already safe.

### `src/ingest` — normalization

`normalizer.py` holds source-agnostic primitives (column folding, label folding,
timestamp coercion, critical-asset tagging). `cicids_parser.py` knows the two
CICIDS2017 distributions and nothing about the model. `detect_layout()` chooses
between complete alerts (with IPs and timestamps) and degraded alerts (flow
features only), and never fabricates the fields a source did not provide.

### `src/agent` — the triage loop

`triage_agent.py` owns three nested concerns:

1. **The tool-use loop** (`_run_completion`) — while the model asks for a tool,
   the Toolbox runs it and the result is fed back, until the model produces text.
2. **The validation-retry loop** (`triage_alert`) — the text is parsed and
   validated; one failure earns a retry with the error appended, then a hard
   failure.
3. **The batch loop** (`triage_directory`) — one alert's failure is recorded and
   the run continues.

`tools.py` provides the enrichment tools behind a `Toolbox`. Both tools degrade
gracefully (a missing key, a private IP, or an HTTP error becomes a status the
model can reason about) and never take an action — they are pure data providers.
State lives in a local SQLite database: an IP-reputation cache that keeps a batch
run inside AbuseIPDB's free tier, and an alert-firing history the agent writes to
as it triages.

### `src/evaluation` — scoring

`evaluate.py` scores agent output against ground truth. The scoring function is
pure — outputs, labels, and the list of alerts that failed to validate go in; an
`EvaluationReport` comes out — so the metrics are testable without an API. The
escalation-safety metric is treated as the hard requirement: a real attack
closed as a false positive fails the run.

## Design boundaries, restated

- **The parser never invents evidence.** A source without IPs yields an alert
  without IPs, and the agent is told so explicitly.
- **The schema is the trust boundary.** No agent output is used until it has
  passed `TriageOutput`.
- **Tools inform, they never act.** Remediation belongs to a future SOAR layer
  with human approval gates.
- **Nothing reaches the network in tests.** The model client, the HTTP client,
  and the clock are all injected; the store runs in memory.
