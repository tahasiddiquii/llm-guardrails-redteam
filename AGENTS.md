# AGENTS.md

Operating guide for AI coding agents (and humans) working in this repo.

## What this project is

A **guardrails + red-team harness** for LLM apps. It detects PII/secrets and
prompt-injection/jailbreak attempts, turns those signals into an allow/redact/block
decision, and ships a **scored red-team attack suite** that measures the defense in
CI. Everything is rule-based, deterministic, and offline.

## Golden rules

1. **Offline + deterministic.** No network, no API keys, no randomness. The whole
   suite must pass with `pip install -e ".[dev]" && pytest`.
2. **Never fabricate metrics.** Every number in `reports/redteam_report_example.md`
   and the README is real output of `llm-guardrails redteam`. If you change a
   detector or the dataset, regenerate the report and update the README table.
3. **Keep the honest miss.** Attack `a14` is intentionally not caught — it documents
   that heuristic guardrails are defense-in-depth, not a silver bullet. Don't "fix"
   it just to reach 100%.
4. **Blocking beats sanitizing.** Never return a cleaned/redacted version of a
   prompt-injection attack; block it.

## Architecture (one breath)

```
input → detectors/{pii,injection} → policy.decide → allow | redact | block
                                          │
pipeline.scan_input / scan_output ────────┘  (+ optional Langfuse trace + scores)
redteam.run_redteam → score attacks vs benign controls → report + CI gate
```

## Layout

| Path | Purpose |
| --- | --- |
| `src/llm_guardrails/detectors/pii.py` | Regex+Luhn PII/secret detection (+optional Presidio). |
| `src/llm_guardrails/detectors/injection.py` | Severity-graded injection/jailbreak rules. |
| `src/llm_guardrails/policy.py` | `decide()` → `Action.{ALLOW,REDACT,BLOCK}`. |
| `src/llm_guardrails/pipeline.py` | `GuardrailPipeline.scan_input/scan_output/guard`. |
| `src/llm_guardrails/redteam/` | `attacks.py` (loaders), `runner.py` (scoring + `THRESHOLDS`). |
| `src/llm_guardrails/report.py` | Markdown report + console table. |
| `data/` | `attacks.jsonl` (adversarial), `benign.jsonl` (false-positive controls). |
| `reports/redteam_report_example.md` | Committed example; live report is gitignored. |

## Workflow

```bash
make dev       # venv + install
make lint      # ruff check + format --check
make test      # pytest (offline)
make redteam   # llm-guardrails redteam  (writes report, runs the gate)
make demo      # a few example scans
```

Before committing: `make fmt && make lint && make test && make redteam`.

## Adding detection rules

- Injection: append a `(name, severity, compiled_regex)` tuple to `_RULES` in
  `detectors/injection.py`. Severity ≥ `block_severity` (default 3) blocks.
- PII: append a `(label, compiled_regex)` to `_PATTERNS` in `detectors/pii.py`
  (most-specific first; overlapping matches are dropped). Add a Luhn-style validator
  if false positives are likely.
- After any change: add/extend a test, run `make redteam`, and refresh the example
  report + README numbers.
