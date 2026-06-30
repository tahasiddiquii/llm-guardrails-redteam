"""Policy engine: turn detector signals into an allow / redact / block decision."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from llm_guardrails.detectors import (
    InjectionSignal,
    PiiEntity,
    detect_injection,
    detect_pii,
    max_severity,
    redact,
)


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclass
class PolicyDecision:
    action: Action
    reasons: list[str] = field(default_factory=list)
    pii: list[PiiEntity] = field(default_factory=list)
    injection: list[InjectionSignal] = field(default_factory=list)
    sanitized_text: str = ""

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK


def decide(
    text: str,
    *,
    block_severity: int = 3,
    redact_pii: bool = True,
) -> PolicyDecision:
    """Block on high-severity injection; otherwise redact any PII; else allow.

    Blocking takes priority over redaction: a prompt-injection attempt is refused
    outright, and we do not return a 'cleaned' version of an attack.
    """
    injection = detect_injection(text)
    pii = detect_pii(text)
    reasons: list[str] = []

    if max_severity(injection) >= block_severity:
        reasons = [f"injection:{s.rule}(sev{s.severity})" for s in injection if s.severity >= block_severity]
        return PolicyDecision(Action.BLOCK, reasons, pii, injection, sanitized_text="")

    if pii and redact_pii:
        reasons = [f"pii:{e.type}" for e in pii]
        # also note any sub-threshold injection signals for observability
        reasons += [f"injection:{s.rule}(sev{s.severity})" for s in injection]
        return PolicyDecision(Action.REDACT, reasons, pii, injection, sanitized_text=redact(text, pii))

    if injection:
        reasons = [f"injection:{s.rule}(sev{s.severity})" for s in injection]

    return PolicyDecision(Action.ALLOW, reasons, pii, injection, sanitized_text=text)
