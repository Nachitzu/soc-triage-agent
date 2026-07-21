<h1 align="center">SOC Triage Agent</h1>

<p align="center">
  <em>Un agente LLM que ejecuta el ciclo de triage de un SOC Tier 1: clasificar, contextualizar, resumir — y escalar siempre que tenga dudas.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/validation-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-158%20passing-2EA043">
  <img alt="Coverage" src="https://img.shields.io/badge/coverage-87%25-2EA043">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.md">English</a> · Español</p>

---

## Resumen

Los analistas de un SOC Tier 1 pasan la mayor parte de su turno haciendo triage de alertas, la mayoría de las cuales son falsos positivos o ruido de baja prioridad. Esto provoca fatiga de alertas y retrasa la respuesta a las amenazas reales.

Este proyecto automatiza ese ciclo. Ingiere alertas de SIEM, clasifica severidad, estima la probabilidad de que una alerta sea un falso positivo, mapea el comportamiento observado a MITRE ATT&CK, y escribe un resumen de investigación sobre el que un analista Tier 2 puede actuar.

> **Principio de diseño** — el agente *aumenta* al analista, no reemplaza el juicio humano. Las evaluaciones de baja confianza siempre se escalan, nunca se auto-cierran. Esta regla la impone el schema de salida, no la convención.

**Autor:** Aaron — AI Security Engineer, Blue Team + arquitectura de agentes de IA.

---

## Estado

| Fase | Alcance | Estado |
|------|---------|--------|
| 1 | Schemas, parser del dataset, muestras curadas | ✅ Completo |
| 2 | Agente central, loop de validación, CLI, modo batch | ✅ Completo |
| 3 | Tools de enriquecimiento (reputación de IP, historial de alertas) | ✅ Completo |
| 4 | Harness de evaluación contra ground truth etiquetado | ✅ Completo |

158 tests unitarios, 87% de cobertura de sentencias en `src/`. Ningún test toca una API en vivo.

---

## Inicio rápido

```bash
git clone https://github.com/Nachitzu/ai-soc-triage-agent.git
cd ai-soc-triage-agent

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env      # luego completa ANTHROPIC_API_KEY
```

Triage de una sola alerta:

```bash
python -m src.agent.triage_agent --alert data/samples/a-2941.json
```

```json
{
  "alert_id": "a-2941",
  "severity": "CRITICAL",
  "false_positive_probability": 0.05,
  "confidence": 0.92,
  "mitre_techniques": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
  "key_evidence": [
    "47 failed SSH logins followed by a successful login",
    "Target 10.0.1.12 is a domain controller (critical asset)",
    "Activity outside business hours"
  ],
  "summary": "External IP 185.220.101.34 brute-forced the 'admin' account on domain controller 10.0.1.12 and achieved a successful login off-hours. This is a probable active compromise of a critical asset. Verify the session, disable the account, and review DC logs for post-authentication activity.",
  "recommended_action": "block_and_escalate"
}
```

Triage de un directorio, acotado y con control de costos:

```bash
TRIAGE_MODEL=claude-haiku-4-5 \
  python -m src.agent.triage_agent --batch data/samples --out results --max-alerts 20
```

Correr la suite de tests:

```bash
pytest --cov=src
```

### Ejecutar en la consola de Claude Code (sin API key)

Además del modo API (arriba, requiere `ANTHROPIC_API_KEY`), puedes hacer triage **dentro de la consola de [Claude Code](https://claude.com/claude-code) sin API key** — la sesión viva es el analista, y Python hace solo el trabajo determinista (tools de enriquecimiento, validación de `TriageOutput`, reporte HTML) a través de `soc-tool`:

```
/triage data/samples/a-2941.json
```

La sesión sigue el mismo `src/agent/prompts/SYSTEM_PROMPT.md` verbatim, llama a `soc-tool validate` para imponer el contrato (baja confianza no puede cerrar una alerta; `block_and_escalate` requiere CRITICAL + confianza ≥ 0.8), y enriquece offline vía `soc-tool tool …`. El slash-command vive en `.claude/commands/triage.md`.

---

## Arquitectura

```
┌──────────────────────┐
│    Fuente de alertas │   dataset CICIDS2017 / logs normalizados
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Ingesta y normaliz. │   Alertas heterogéneas → un schema común
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────┐      ┌──────────────────────┐
│    Agente de triage (LLM)    │◄─────│   Enriquecimiento    │
│   modelo + prompt versionado │      │  · Reputación de IP  │
│   razona sobre cada alerta   │      │  · Historial alertas │
└──────────┬───────────────────┘      └──────────────────────┘
           │
           ▼
┌──────────────────────┐
│  Salida estructurada │   JSON estricto, validado con Pydantic
└──────────┬───────────┘
           │
     ┌─────────────┬──────────┐
     ▼             ▼          ▼
┌──────────┐ ┌─────────────┐ ┌──────────────────┐
│ Severidad│ │  Probabil.  │ │  Resumen legible │
│ CRITICAL │ │  de falso   │ │   para humanos   │
│ HIGH/MED │ │  positivo   │ │    para Tier 2   │
│   LOW    │ │  + razones  │ │     analista     │
└──────────┘ └─────────────┘ └──────────────────┘
```

### Flujo de datos

1. **Fuente de alertas** — registros de flujo etiquetados de CICIDS2017, o logs de muestra.
2. **Ingesta y parser** — cada alerta se normaliza al schema `NormalizedAlert`.
3. **Agente de triage** — el modelo recibe la alerta más el system prompt, y puede llamar tools de enriquecimiento cuando cambiarían materialmente la evaluación.
4. **Tools de enriquecimiento** (invocadas por el agente, Fase 3):
   - `lookup_ip_reputation(ip)` → AbuseIPDB, solo IPs públicas
   - `check_alert_history(rule_id, source_ip)` → consulta local en SQLite de firings previos
5. **Salida estructurada** — JSON estricto, validado con Pydantic, un reintento ante falla de validación.
6. **Salidas** — severidad, probabilidad de falso positivo, mapeo MITRE, resumen listo para Tier 2.

---

## Restricciones de ingeniería

Son estructurales. Relajar cualquiera cambia lo que el sistema garantiza.

| Restricción | Justificación |
|-------------|---------------|
| El system prompt vive en `src/agent/prompts/SYSTEM_PROMPT.md` y se carga verbatim en runtime | El prompt es un artefacto revisable y versionado. Nunca se hardcodea en Python. |
| Toda salida del agente debe validar contra `TriageOutput` antes de aceptarse | El schema es la frontera de seguridad. Una salida inválida dispara un reintento con el error realimentado, y luego falla ruidosamente. |
| Las API keys vienen solo de variables de entorno | `.env`, `data/raw/` y `dataset/` están git-ignored. `.env.example` documenta cada variable. |
| Los módulos mantienen sus fronteras: ingest, schemas, agent, evaluation | Cada capa es testeable de forma independiente, y el parser no sabe nada del modelo. |
| La lógica de tool-calling se testea contra mocks | Ningún test toca una API en vivo. |
| Las fases se entregan en orden | Los tools de enriquecimiento no tienen sentido hasta que el contrato de alerta es estable. |

---

## Estructura del repositorio

```
ai-soc-triage-agent/
├── README.md
├── .env.example                   ← ANTHROPIC_API_KEY, ABUSEIPDB_API_KEY, TRIAGE_MODEL
├── pyproject.toml                 ← deps: anthropic, pydantic, pandas, httpx, pytest
├── src/
│   ├── ingest/
│   │   ├── cicids_parser.py       ← CICIDS2017 CSV → NormalizedAlert (ambos layouts)
│   │   └── normalizer.py          ← utilidades de normalización genéricas
│   ├── agent/
│   │   ├── triage_agent.py        ← loop del agente, tool use, reintento de validación, modo batch
│   │   ├── tools.py               ← lookup_ip_reputation, check_alert_history, store SQLite
│   │   └── prompts/
│   │       └── SYSTEM_PROMPT.md   ← el system prompt del agente
│   ├── schemas/
│   │   ├── normalized_alert.py    ← contrato de entrada
│   │   └── triage_output.py       ← contrato de salida, validado estrictamente
│   └── evaluation/
│       └── evaluate.py            ← métricas de precisión vs etiquetas de CICIDS2017
├── docs/
│   └── architecture.md            ← diagrama del pipeline y fronteras de diseño
├── data/
│   └── samples/                   ← 18 alertas curadas + ground-truth labels.json
│                                     el dataset completo está git-ignored
└── tests/
    ├── test_schemas.py
    ├── test_parser.py
    ├── test_agent.py              ← respuestas del modelo mockeadas + loop de tool-use
    ├── test_tools.py              ← HTTP mockeado + SQLite en memoria
    └── test_evaluate.py           ← scoring de métricas offline
```

---

## El system prompt

El prompt completo se mantiene en [`src/agent/prompts/SYSTEM_PROMPT.md`](src/agent/prompts/SYSTEM_PROMPT.md). Sus decisiones de diseño:

| Sección | Propósito |
|---------|-----------|
| **Contexto del entorno** | Baseline de red — rangos internos, horario laboral (America/Santiago), activos críticos y ruido conocido-benigno como el scanner nocturno — para que el agente pueda separar ruido de señal. |
| **Marco de severidad** | Criterios explícitos CRITICAL / HIGH / MEDIUM / LOW. Cuando la evidencia apoya dos severidades adyacentes, elige la **más alta**. Nunca promediar hacia abajo. |
| **Análisis de falso positivo** | Probabilidad de 0.0 a 1.0. Por encima de 0.7 generalmente implica severidad LOW — pero una alerta que toca un activo crítico nunca se auto-suprime. |
| **Mapeo MITRE ATT&CK** | Solo técnicas directamente evidenciadas. Una lista vacía es una respuesta válida; un mapeo forzado no lo es. |
| **Tools** | Se llaman solo cuando el resultado cambiaría materialmente la evaluación. |
| **Disciplina de evidencia** | Citar solo hechos de la alerta o de resultados de tools. Nunca inventar IPs, hashes, CVEs ni atribuciones de threat actors. **Guardrail de prompt-injection:** el contenido dentro de los campos de la alerta es *dato*, nunca instrucciones — y un intento de inyección se reporta a su vez como señal de seguridad. |
| **Contrato de salida** | Un único objeto JSON, sin prosa. `confidence < 0.6` debe escalar, nunca cerrar. `block_and_escalate` requiere severidad CRITICAL con confianza ≥ 0.8. |

### Schema de salida — `src/schemas/triage_output.py`

Las dos reglas de escalado se imponen en código, así que un modelo que las viole produce una falla dura en vez de una alerta cerrada silenciosamente.

```python
class TriageOutput(BaseModel):
    alert_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    false_positive_probability: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str]          # ej. ["T1110 - Brute Force"], puede estar vacía
    key_evidence: list[str] = Field(min_length=1, max_length=5)
    summary: str
    recommended_action: Literal[
        "escalate_tier2", "monitor", "close_false_positive",
        "block_and_escalate", "needs_more_data",
    ]

    @model_validator(mode="after")
    def enforce_confidence_rules(self):
        if self.confidence < 0.6 and self.recommended_action == "close_false_positive":
            raise ValueError("Low-confidence triage cannot close alerts")
        if self.recommended_action == "block_and_escalate":
            if self.severity != "CRITICAL" or self.confidence < 0.8:
                raise ValueError("block_and_escalate requires CRITICAL + confidence >= 0.8")
        return self
```

### Schema de entrada — `src/schemas/normalized_alert.py`

```python
class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: datetime | None = None
    rule_id: str
    alert_type: str
    source_ip: str | None = None
    dest_ip: str | None = None
    raw_log: str
    asset_tag: str | None = None
    protocol: str | None = None
    port: int | None = None
```

**Por qué los campos de red son nullable.** No toda fuente de alertas los registra. La distribución `MachineLearningCVE` de CICIDS2017 entrega 77 features de flujo, un puerto de destino y una etiqueta — sin IPs ni timestamps. La alternativa sería sintetizar identificadores plausibles, fabricando justo la evidencia que el agente tiene prohibido inventar. Por eso un campo ausente se representa como ausente.

`NormalizedAlert.has_network_context` separa las dos poblaciones, y `missing_fields` lista lo que una fuente dada omitió. Una alerta sin contexto de red todavía puede triagearse desde la evidencia de flujo, pero la mitad de baseline-de-entorno del system prompt no le aplica. El agente declara los campos ausentes en un bloque `<source_profile>` para que el modelo no confunda una fuente estructuralmente escasa con una alerta corrupta.

---

## Dataset: CICIDS2017

- **Fuente:** Canadian Institute for Cybersecurity — <https://www.unb.ca/cic/datasets/ids-2017.html>
- **Por qué:** etiquetado, gratis, académicamente reconocido. Contiene tráfico de ataque real: fuerza bruta (FTP/SSH), DoS/DDoS, Heartbleed, ataques web (SQL injection, XSS), infiltración, botnet, port scans.
- **El ground truth habilita la evaluación:** las etiquetas permiten medir la precisión de severidad y la tasa de detección de falsos positivos.
- **Manejo:** los CSV completos pesan gigabytes — manténlos git-ignored bajo `data/raw/` o `dataset/`. Solo las muestras curadas en `data/samples/` se commitean.

### Estrategia de mapeo

Las filas de CICIDS2017 son *registros de flujo*, no alertas de SIEM. Un flujo dice "el host A envió 47 paquetes al host B:22 y la etiqueta es SSH-Patator". Una alerta de SIEM dice "la regla SSH-BRUTE-01 se disparó". El parser tiende el puente: la etiqueta de ground truth selecciona la alerta que una regla hipotética de SIEM habría levantado, y los contadores de flujo se vuelven la evidencia que esa regla habría citado. El `raw_log` sintetizado renderiza solo lo que el dataset realmente provee — no se inventan usuarios, rutas HTTP ni nombres de proceso.

### Dos distribuciones — el parser lee ambas

`detect_layout()` elige entre ellas a partir del header del CSV.

| Layout | Columnas | Identificadores | Produce |
|--------|----------|-----------------|---------|
| `LABELLED_FLOWS` (*GeneratedLabelledFlows*) | 85 | `Flow ID`, `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Protocol`, `Timestamp` | Alertas completas. `has_network_context` es `True`. |
| `FEATURES_ONLY` (*MachineLearningCVE*) | 79 | ninguno — solo `Destination Port` | Alertas degradadas. IPs, timestamp y protocolo son `None`. |

> **Esto importa para la evaluación.** En `FEATURES_ONLY` el agente no puede razonar sobre activos críticos, horario laboral ni reputación de IP, porque el dato no los lleva, y `lookup_ip_reputation` no tiene entrada alguna. Las métricas calculadas desde ese layout son una cota inferior, no una medición del sistema diseñado. Usa `GeneratedLabelledFlows` para los números principales de abajo.

**Codificación de etiquetas.** Las tres etiquetas `Web Attack` contienen un byte no-UTF-8 que varía por mirror (`\x96`, `U+2013` o `U+FFFD`). Los CSV se leen como latin-1 y el normalizador de etiquetas lo descarta.

---

## Roadmap

### Fase 1 — Fundaciones
- [x] Andamiaje del proyecto: `pyproject.toml`, estructura del repo, `.env.example`, setup de pytest apto para CI
- [x] Schemas Pydantic `NormalizedAlert` y `TriageOutput` + tests
- [x] Parser de CICIDS2017: flujos etiquetados → alertas normalizadas sintéticas + tests (ambos layouts del dataset)
- [x] 18 alertas de muestra curadas cubriendo fuerza bruta, port scan, DoS/DDoS, ataques web, ruido benigno, una sonda de prompt-injection y una alerta malformada; ground truth en `labels.json`

### Fase 2 — Agente central
- [x] `triage_agent.py`: cargar el system prompt desde archivo, llamar al modelo, parsear y validar el JSON de salida
- [x] Loop de reintento-ante-falla-de-validación — un reintento con el error realimentado, luego falla elegante
- [x] Entry point de CLI: `python -m src.agent.triage_agent --alert data/samples/a-2941.json`
- [x] Modo batch: triage de un directorio de alertas, escribiendo resultados en `results/*.json`

### Fase 3 — Tools de enriquecimiento
- [x] `lookup_ip_reputation`: tier gratuito de AbuseIPDB vía `httpx`, con caché local en SQLite para respetar los rate limits
- [x] `check_alert_history`: store SQLite de firings pasados, consultado por `rule_id` + `source_ip`
- [x] Cablear ambos al agente vía tool use; el agente decide cuándo llamarlos
- [x] Tests mockeados para cada tool y para el loop de tool-calling

### Fase 4 — Evaluación
- [x] `evaluate.py`: puntuar el agente sobre N alertas etiquetadas y calcular
  - precisión de severidad (match exacto, y con tolerancia ±1 de severidad adyacente)
  - precisión y recall de detección de falsos positivos
  - seguridad de escalado: fracción de ataques reales *no* recomendados para cierre
- [x] `docs/architecture.md` con el diagrama final
- [x] "Limitaciones y trabajo futuro": no-determinismo, costo a escala, superficie de prompt-injection, dataset ≠ alertas de producción
- [ ] Publicar la tabla de resultados de abajo con números reales — pendiente de una corrida en vivo (ver [Resultados](#resultados))

### Más allá de v1
- Servicio FastAPI y un dashboard simple
- Integración en vivo con Wazuh (homelab)
- Extensión multi-agente: triage → investigación → sugerencia de respuesta, alimentando un orquestador SOAR

---

## Definición de terminado

| Métrica | Objetivo |
|---------|----------|
| Precisión de severidad, match exacto contra etiquetas | ≥ 80% |
| Precisión de severidad, ±1 severidad adyacente | ≥ 95% |
| **Seguridad de escalado — ataques reales nunca auto-cerrados** | **100%, requisito duro** |
| Tasa de aprobación de validación de schema, tras un reintento | ≥ 99% |
| Cobertura de tests unitarios en `src/` | ≥ 80% |

La seguridad de escalado es innegociable. Un agente de triage que cierra ataques reales es peor que no tener agente.

---

## Resultados

El harness de evaluación puntúa la salida del agente contra el ground truth en `labels.json`. El scoring es una función pura — entran salidas del agente, etiquetas y la lista de alertas que fallaron la validación; sale un reporte — así que la lógica de métricas está cubierta por tests sin tocar una API.

Dos formas de correrlo:

```bash
# Offline: puntuar archivos de resultado que una corrida batch ya produjo.
python -m src.evaluation.evaluate --results results

# Live: triagear el set de muestra y luego puntuarlo (requiere ANTHROPIC_API_KEY).
python -m src.evaluation.evaluate --run --alerts data/samples
```

El comando imprime cada métrica contra su objetivo y, lo más importante, nombra cualquier ataque real que se haya cerrado como falso positivo — la única falla que hace que la corrida termine con código distinto de cero.

**Los números principales están pendientes de una corrida en vivo.** Dependen de las respuestas reales del modelo sobre el set de muestra, así que publicarlos aquí sin haber corrido el agente contra un endpoint en vivo sería fabricarlos. La tabla de abajo se llena a partir de un `--run` real sobre las 18 muestras curadas; hasta entonces muestra los objetivos contra los que el harness valida.

| Métrica | Objetivo | Medido |
|---------|----------|--------|
| Precisión de severidad (exacta) | ≥ 80% | _pendiente de corrida live_ |
| Precisión de severidad (±1 nivel) | ≥ 95% | _pendiente de corrida live_ |
| Precisión / recall de falso positivo | — | _pendiente de corrida live_ |
| Seguridad de escalado | 100% | _pendiente de corrida live_ |
| Tasa de aprobación de validación de schema | ≥ 99% | _pendiente de corrida live_ |

Nota la advertencia de [la sección del dataset](#dos-distribuciones--el-parser-lee-ambas): puntuados sobre el layout `MachineLearningCVE` sin identificadores, estos números son una cota inferior. Las 18 muestras curadas en `data/samples/` llevan contexto de red completo y son la prueba justa del sistema diseñado.

---

## Limitaciones y trabajo futuro

- **No-determinismo del LLM.** La misma alerta puede triagearse ligeramente distinto entre corridas. El schema y las reglas de escalado acotan la *forma* y la *seguridad* de la salida, no su redacción exacta ni las decisiones de severidad limítrofes. Trata una sola corrida como la opinión de un analista, no como un veredicto fijo.
- **Costo a escala.** Cada alerta es al menos una llamada al modelo, más cuando el agente recurre a tools. El modo batch puede seleccionar el modelo más barato vía `TRIAGE_MODEL` y acotar una corrida con `--max-alerts`, pero triagear el volumen diario de un SIEM real a través de un modelo frontier es una línea de presupuesto real.
- **Superficie de prompt-injection.** La frontera `<alert>` y las reglas de disciplina de evidencia reducen el riesgo, y una muestra adversaria la ejercita, pero una inyección decidida embebida en contenido de log controlado por el atacante sigue siendo una amenaza abierta que la evaluación puede medir pero no eliminar.
- **Dataset ≠ alertas de producción.** Los flujos de CICIDS2017 se convierten en alertas de SIEM sintéticas; el `raw_log` lleva evidencia de flujo, no los usuarios, árboles de proceso o líneas de comando que un SIEM real llevaría. La precisión aquí es indicativa, no una promesa sobre un despliegue en producción.
- **Cobertura de enriquecimiento.** `check_alert_history` solo conoce los firings que este despliegue ha registrado, y `lookup_ip_reputation` necesita una IP pública y una key de AbuseIPDB — ninguno aplica al layout del dataset sin identificadores.

---

## Consideraciones de seguridad

- **Prompt injection.** Los campos de la alerta son datos controlados por el atacante. El system prompt instruye al agente a tratarlos como datos, el agente los envuelve en una frontera explícita `<alert>`, y el set de muestra incluye una alerta adversaria cuyo `raw_log` lleva una instrucción embebida. La evaluación debe verificar que el guardrail se sostiene.
- **Sin auto-remediación.** El agente clasifica y recomienda. Nunca bloquea una IP ni deshabilita una cuenta — esas acciones pertenecen a una capa SOAR con gates de aprobación humana.
- **Secretos.** Solo variables de entorno. `.env`, `data/raw/` y `dataset/` están git-ignored.
- **Control de costos.** Las corridas batch pueden seleccionar un modelo más barato vía `TRIAGE_MODEL`, y `--max-alerts` acota el tamaño de cualquier corrida individual.

---

## Stack tecnológico

| Componente | Elección | Razón |
|------------|----------|-------|
| Lenguaje | Python 3.11+ | Estándar para tooling de SOC y seguridad |
| LLM | Claude (SDK de Anthropic) | Razonamiento fuerte y tool use nativo |
| Validación | Pydantic v2 | Contratos de salida estrictos y ejecutables |
| Datos | pandas | Procesamiento de CSV de CICIDS2017 |
| HTTP | httpx | Llamadas a API listas para async |
| Almacenamiento | SQLite | Historial de alertas sin configuración |
| Testing | pytest + pytest-mock | Tests de API totalmente mockeados |

---

## Licencia

Publicado bajo la Licencia MIT.
