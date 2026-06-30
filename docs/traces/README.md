# Traces

Every guardrail scan can be recorded as a Langfuse trace, with the decision and the
detector counts attached as **scores** — so you can watch block/redact rates and
catch regressions per-input, not just in aggregate.

## Capture your own

```bash
docker compose --profile observability up -d   # local Langfuse at :3000
# create a project, copy the keys, then:
export LANGFUSE_PUBLIC_KEY=pk-...
export LANGFUSE_SECRET_KEY=sk-...
export LANGFUSE_HOST=http://localhost:3000
llm-guardrails redteam      # every scan is now a trace with scores
```

With no keys set, tracing is a no-op (`Tracer.active == False`) and everything runs
fully offline — CI and the test suite never depend on Langfuse.

## What a trace contains

- **span** `guardrail-input` / `guardrail-output` — one per scan.
- **input** — the scanned text; **output** — the action (`allow`/`redact`/`block`)
  or the sanitized text.
- **scores** — `blocked`, `pii_count`, `injection_count` (input); `pii_leaked` (output).

## Screenshots

Drop PNGs here and reference them from the top-level `README.md`:

- `redteam-scores.png` — the run, one row per attack with the block/redact score.
- `scan-detail.png` — a single scan span with the matched detector signals.
