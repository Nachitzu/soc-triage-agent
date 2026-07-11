# Prueba con 20 filas aleatorias de `dataset/MS_test.csv`

**Fecha:** 2026-07-10
**Modelo:** `claude-sonnet-4-6` (`TRIAGE_MODEL` en `.env`)
**Thinking:** `auto` → se envía `thinking={"type": "adaptive"}` porque `claude-sonnet-4-6` está en `ADAPTIVE_THINKING_MODELS` (`src/agent/triage_agent.py:56-61`)

## Qué se hizo

`dataset/MS_test.csv` es el dataset Microsoft GUIDE de incidentes (no CICIDS2017 — no existe parser en `src/ingest/` para él). Se armó una conversión ad-hoc de un solo uso (no forma parte del código del proyecto):

1. Muestreo por reservoir sampling de 20 filas al azar del CSV (4,147,992 filas).
2. Conversión a `NormalizedAlert` (`src/schemas/normalized_alert.py`):
   - `alert_id = "ms-{Id}"`, `rule_id = "MS-DETECTOR-{DetectorId}"`, `alert_type` = `Category` en snake_case.
   - `source_ip` / `dest_ip` / `protocol` / `port` quedaron en `None`: la columna `IpAddress` (y `DeviceId`, `Sha256`, `AccountSid`, etc.) son enteros anonimizados, no IPs/hashes reales — poblarlos habría inventado evidencia y además el validador de `NormalizedAlert` rechaza valores que no sean IPs válidas.
   - `raw_log` incluye todas las columnas no vacías de la fila (excluyendo las que filtran la respuesta correcta: `IncidentGrade`, `ActionGrouped`, `ActionGranular`).
3. `labels.json` de verdad de terreno: `IncidentGrade == TruePositive` → `ground_truth: attack`; `BenignPositive` / `FalsePositive` → `benign`. No hay severidad etiquetada en este dataset, así que `expected_severity` quedó `null` para las 20 alertas.
4. Ejecución: `python -m src.agent.triage_agent --batch data/raw/ms_test_sample --out results/ms_test_sample` (git-ignored, no se commiteó nada).
5. El proceso se detuvo manualmente a pedido del usuario por gasto excesivo de créditos, con 17/20 alertas ya escritas en disco (16 válidas + 1 error).
6. Evaluación de lo procesado: `python -m src.evaluation.evaluate --results results/ms_test_sample --labels data/raw/ms_test_sample/labels.json`.

## Resultados (16/20 procesadas antes del corte)

| Métrica | Resultado | Target |
|---|---|---|
| Validación de esquema | 80% (16/20) | — |
| Severity accuracy | n/a (sin severidad etiquetada en este dataset) | ≥ 80% |
| False-positive precision | n/a (el agente nunca usó `close_false_positive`) | — |
| False-positive recall | 0% | — |
| **Escalation safety** | **100%** | 100% (hard) |

- **Distribución de ground truth de la muestra:** 5 `attack`, 15 `benign` (11 `BenignPositive` + 4 `FalsePositive`).
- **Comportamiento observado:** el agente nunca recomendó `close_false_positive` — para las 16 alertas válidas usó `escalate_tier2` (9) o `needs_more_data` (7), con severidades `MEDIUM`/`HIGH` y `false_positive_probability` bajo (0.12–0.35). Es una postura conservadora consistente con datos muy degradados (sin IPs, hostnames ni timestamps de negocio reales), pero significa que esta muestra **no mide bien la precisión de falsos positivos** — solo confirma que el agente no cierra ataques reales cuando le falta contexto.
- **1 alerta falló:** `ms-790273985660` (detalle abajo).
- **3 alertas no llegaron a procesarse** (el batch se cortó antes).

## Bug a investigar: `model set stop_reason=tool_use but produced no tool_use blocks`

**Dónde:** `_resolve_tool_calls()`, `src/agent/triage_agent.py:239-260`.

```python
def _resolve_tool_calls(response: Any, toolbox: Toolbox) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for block in response.content:
        if getattr(block, "type", None) == "tool_use":
            ...
    if not results:
        raise TriageError(
            "model set stop_reason=tool_use but produced no tool_use blocks"
        )
    return results
```

**Qué pasó:** la API respondió con `response.stop_reason == "tool_use"` (lo que dispara el loop de herramientas en `_run_completion`, línea 277) pero `response.content` no contenía ningún bloque de tipo `tool_use` — solo, presumiblemente, un bloque de `thinking`/`redacted_thinking` y/o `text`. `_resolve_tool_calls` no tiene forma de continuar sin una tool call que resolver, así que lanza `TriageError`.

**Propagación:** este `TriageError` se lanza dentro de `_run_completion`, que es llamado *fuera* del `try/except` de `triage_alert` (ese `try` solo envuelve `_validate`, líneas ~332-352). Por lo tanto no se reintenta — sube directo hasta `triage_directory`, que lo captura y escribe `ms-790273985660.error.json`. **No genera un loop de reintentos ni llamadas extra a la API** para esa alerta puntual.

**Hipótesis a confirmar (no verificado aún, requiere log de la respuesta cruda):**
- Un turno donde el modelo solo "pensó" (bloque de thinking largo) sin emitir texto ni tool_use, pero la API igual marcó `stop_reason=tool_use` — posible interacción entre thinking adaptativo y el parámetro `tools` enviado en cada request.
- Un bloque de tool_use mal formado que el SDK no está exponiendo como `type == "tool_use"` (menos probable, pero no descartado sin ver el payload real).

**Cómo investigarlo cuando se retome:** capturar y loguear `[b.type for b in response.content]` justo antes del `raise` en `_resolve_tool_calls` para ver qué bloques llegaron realmente, y guardar el `response` crudo (o al menos su `.model_dump()`) del turno que falló para inspección.

## ¿Tiene conexión con el gasto de USD 0,94 (68.955 tokens de entrada / 48.574 de salida)?

Parcialmente, pero **no es la causa principal**:

- **Lo que el bug costó directamente:** el turno que falló para `ms-790273985660` sí gastó tokens de thinking + de la llamada que produjo el `stop_reason=tool_use` vacío — ese gasto se perdió sin producir un resultado válido (0 reintentos, así que el desperdicio se limita a esa única llamada, no se multiplica).
- **El driver real del gasto es el modo de thinking adaptativo, activo por defecto:** `TRIAGE_THINKING=auto` en `.env` + `claude-sonnet-4-6` → se envía `thinking={"type": "adaptive"}` en **cada** llamada (`thinking_param()`, línea 165-173). Los tokens de razonamiento se facturan como tokens de salida, y ~48.574 tokens de salida para ~17 alertas (≈2.860 tokens de salida por alerta) es alto para una salida que en teoría es solo un JSON de `TriageOutput` — la diferencia es thinking.
- **Multiplicador secundario — el loop de herramientas reenvía todo el historial:** `_run_completion()` (línea 264-282) hace `client.messages.create()` de nuevo con el historial completo (system prompt + definiciones de `lookup_ip_reputation`/`check_alert_history` + turnos previos) cada vez que el modelo pide una herramienta. Cualquier alerta donde el modelo invocó `check_alert_history` más de una vez paga varias veces el mismo system prompt + tool schemas como input.
- `raw_log` de esta muestra es más verboso que lo habitual (promedio 629 caracteres, incluye ~30 campos por fila) porque se optó por no inventar evidencia y listar todo lo que el CSV realmente trae — esto también infla el input por alerta, aunque en menor medida que el thinking.

**Conclusión:** el bug es un desperdicio puntual y menor, no la causa del gasto. El costo alto viene principalmente de correr `claude-sonnet-4-6` con thinking adaptativo en modo batch. Para pruebas exploratorias baratas, considerar `TRIAGE_MODEL=claude-haiku-4-5` y/o `TRIAGE_THINKING=off`, y `--no-enrichment` si no se necesita probar las herramientas de enriquecimiento.

## Pendientes

- [x] ~~Decidir si `_resolve_tool_calls` debería tener un fallback~~ — **Resuelto (2026-07-10):** un `stop_reason=tool_use` sin bloques `tool_use` ya no aborta la alerta. `_run_completion` sale del loop de herramientas y usa el bloque de texto del mismo turno (el caso observado: el modelo ya había emitido el JSON final pero marcó mal el stop reason). Si tampoco hay texto, falla ruidosamente como antes. Cubierto por `test_phantom_tool_use_*` en `tests/test_agent.py`.
- [x] ~~Reproducir y loguear el payload crudo~~ — **Instrumentado (2026-07-10):** `_run_completion` ahora loguea (`logging`, nivel WARNING) los tipos de bloques recibidos cuando ocurre el caso (`stop_reason=tool_use without tool_use blocks; content types=[...]`). La próxima aparición en un batch real queda registrada sin costo extra de API.
- [ ] Volver a correr las 20 alertas completas (o un batch nuevo) una vez que se decida el modelo/costo aceptable para pruebas. Con el fix, `ms-790273985660` ya no debería fallar.

## Optimizaciones de costo aplicadas (2026-07-10)

Sin cambiar el modelo ni apagar el razonamiento:

1. **Prompt caching** (`src/agent/triage_agent.py`, `cacheable_system()`): el system prompt viaja como bloque con `cache_control: ephemeral`. Como los `tools` se renderizan antes del system, un solo breakpoint cachea *tools + system* juntos: cada alerta después de la primera (y cada iteración del loop de herramientas, el multiplicador identificado arriba) lee ese prefijo a ~0,1× del precio de input en vez de pagarlo completo. Escritura de caché: 1,25× una sola vez por ventana de 5 min — en un batch continuo el ahorro es neto desde la segunda alerta. *Caveat:* `claude-sonnet-4-6` tiene un prefijo mínimo cacheable de 2.048 tokens; el prompt actual (~1.900 tokens con tools) está en el borde — si no cachea, el marcador se ignora en silencio y no cuesta nada. Verificar con `usage.cache_read_input_tokens > 0` en el próximo run; cuando el prompt v1.1 agregue few-shots superará el mínimo con holgura.
2. **`TRIAGE_EFFORT` (nuevo, `.env`)**: envía `output_config.effort`. El driver principal del gasto fue el thinking adaptativo (~2.860 tokens de salida por alerta); `TRIAGE_EFFORT=medium` o `low` reduce la profundidad de razonamiento **sin apagarlo** — mejor relación calidad/costo que `TRIAGE_THINKING=off` para triage. Valores: `low|medium|high|max` (default de la API: `high`). Se omite automáticamente para `claude-haiku-4-5`, que rechaza el parámetro.
3. **Palancas ya existentes, en orden de agresividad:** `TRIAGE_EFFORT=medium` (recomendado primero) → `TRIAGE_MODEL=claude-haiku-4-5` (~3× más barato por token; sin thinking) → `TRIAGE_THINKING=off` → `--no-enrichment` (elimina las iteraciones del loop de herramientas que reenvían todo el historial).
4. **Para lotes grandes no interactivos (futuro):** la Batches API cobra 50% de todos los tokens. No está integrada porque el loop de herramientas requiere round-trips (cada iteración sería un batch aparte); tiene sentido para corridas `--no-enrichment` de cientos de alertas.

## Reporte HTML por sesión (2026-07-10)

Los JSON de `results/` son un contrato de máquina, no una superficie de lectura. Ahora cada batch genera automáticamente `reports/triage_report_YYYYMMDD_HHMMSS.html` (autocontenido, se puede adjuntar a un ticket o correo): tarjetas resumen, cola priorizada por acción/severidad, tarjetas de detalle con evidencia y MITRE, y una sección de alertas sin triage. Desactivable con `--no-report`; generación manual: `python -m src.reporting.html_report --results results/ms_test_sample`.
