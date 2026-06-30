"""The guardrail pipeline: the single entry point an app calls around an LLM.

    pipeline = GuardrailPipeline()
    decision = pipeline.scan_input(user_text)     # block / redact / allow
    safe_out = pipeline.scan_output(model_text)   # redact PII that leaked out

Every scan is optionally recorded as a Langfuse trace with the decision and
detector counts attached as scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from llm_guardrails.config import Settings, get_settings
from llm_guardrails.detectors import PiiEntity, detect_pii, redact
from llm_guardrails.policy import Action, PolicyDecision, decide
from llm_guardrails.tracing import Tracer


@dataclass
class OutputScan:
    text: str
    pii: list[PiiEntity] = field(default_factory=list)
    redacted: bool = False


class GuardrailPipeline:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.tracer = Tracer(self.settings)

    def scan_input(self, text: str) -> PolicyDecision:
        with self.tracer.trace("guardrail-input", input=text) as span:
            decision = decide(
                text,
                block_severity=self.settings.block_severity,
                redact_pii=self.settings.redact_pii,
            )
            span.update(output=decision.action.value, metadata={"reasons": decision.reasons})
            span.score("blocked", 1.0 if decision.blocked else 0.0)
            span.score("pii_count", float(len(decision.pii)))
            span.score("injection_count", float(len(decision.injection)))
            return decision

    def scan_output(self, text: str) -> OutputScan:
        with self.tracer.trace("guardrail-output", input=text) as span:
            pii = detect_pii(text)
            scan = OutputScan(
                text=redact(text, pii) if pii else text,
                pii=pii,
                redacted=bool(pii),
            )
            span.update(output=scan.text)
            span.score("pii_leaked", float(len(pii)))
            return scan

    def guard(self, user_text: str, model_text: str) -> tuple[PolicyDecision, OutputScan | None]:
        """Convenience: scan input, and only scan output if input was not blocked."""
        decision = self.scan_input(user_text)
        if decision.action is Action.BLOCK:
            return decision, None
        return decision, self.scan_output(model_text)
