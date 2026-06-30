"""Prompt-injection and jailbreak detection.

A transparent, rule-based detector: each rule is a named regex with a severity
(1=low, 2=medium, 3=high). The pipeline aggregates matched rules into a decision.
Rule-based (not ML) on purpose — it is deterministic, auditable, and runs offline,
which is what you want for a guardrail you must reason about and red-team.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# severity: 1 low, 2 medium, 3 high
_RULES: list[tuple[str, int, re.Pattern[str]]] = [
    (
        "instruction_override",
        3,
        re.compile(
            r"\bignore\b.{0,40}\b(all\s+)?(previous|prior|above|earlier)\b.{0,20}\b(instruction|prompt|rule|message)",
            re.I,
        ),
    ),
    (
        "system_prompt_reset",
        3,
        re.compile(
            r"\b(disregard|forget|override)\b.{0,40}\b(system|your|previous|all)\b.{0,20}\b(prompt|instruction|rule|guideline)",
            re.I,
        ),
    ),
    (
        "new_instructions",
        2,
        re.compile(r"\b(new|updated|real)\s+(instruction|task|directive)s?\s*:", re.I),
    ),
    (
        "jailbreak_persona",
        3,
        re.compile(r"\b(DAN|do anything now|developer mode|jailbreak|unfiltered|no\s+restrictions?)\b", re.I),
    ),
    (
        "roleplay_bypass",
        2,
        re.compile(
            r"\b(pretend|act as|you are now|imagine you are)\b.{0,40}\b(no|without|free of)\b.{0,15}\b(filter|rule|restriction|guideline|limit)",
            re.I,
        ),
    ),
    (
        "system_prompt_leak",
        3,
        re.compile(
            r"\b(reveal|show|print|repeat|output|tell me)\b.{0,30}\b(your|the|initial|original)\b.{0,15}\b(system prompt|instructions|prompt|directive)",
            re.I,
        ),
    ),
    (
        "secret_exfiltration",
        3,
        re.compile(
            r"\b(send|email|post|exfiltrate|leak|reveal|give me)\b.{0,40}\b(api[\s_-]?key|password|secret|credential|token)",
            re.I,
        ),
    ),
    (
        "refusal_suppression",
        2,
        re.compile(
            r"\b(do not|don't|never)\b.{0,15}\b(refuse|decline|warn)\b|\byou must comply\b|\bwithout any (warning|disclaimer|refusal)",
            re.I,
        ),
    ),
    (
        "encoding_evasion",
        2,
        re.compile(r"\b(base64|rot13|hex|decode the following|reverse the)\b", re.I),
    ),
]


@dataclass(frozen=True)
class InjectionSignal:
    rule: str
    severity: int
    snippet: str


def detect_injection(text: str) -> list[InjectionSignal]:
    """Return all matched injection rules (deduplicated by rule name)."""
    seen: dict[str, InjectionSignal] = {}
    for name, severity, pattern in _RULES:
        m = pattern.search(text)
        if m and name not in seen:
            snippet = m.group(0)[:80]
            seen[name] = InjectionSignal(name, severity, snippet)
    return sorted(seen.values(), key=lambda s: (-s.severity, s.rule))


def max_severity(signals: list[InjectionSignal]) -> int:
    return max((s.severity for s in signals), default=0)
