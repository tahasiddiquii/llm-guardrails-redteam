"""PII / secret detection and redaction.

Default engine is pure-regex (offline, deterministic). The optional ``presidio``
extra swaps in Microsoft Presidio for NER-based detection without changing the
``PiiEntity`` interface or redaction format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Ordered most-specific first so overlapping matches resolve sensibly.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("API_KEY", re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]


@dataclass(frozen=True)
class PiiEntity:
    type: str
    value: str
    start: int
    end: int


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_pii(text: str) -> list[PiiEntity]:
    """Find PII/secret spans, non-overlapping, earliest + most-specific first."""
    entities: list[PiiEntity] = []
    claimed: list[tuple[int, int]] = []

    def _overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in claimed)

    for label, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            s, e = m.start(), m.end()
            if _overlaps(s, e):
                continue
            if label == "CREDIT_CARD" and not _luhn_ok(m.group()):
                continue
            entities.append(PiiEntity(label, m.group(), s, e))
            claimed.append((s, e))

    return sorted(entities, key=lambda x: x.start)


def redact(text: str, entities: list[PiiEntity] | None = None) -> str:
    """Replace each detected entity with a ``[TYPE]`` placeholder."""
    entities = entities if entities is not None else detect_pii(text)
    out = text
    for ent in sorted(entities, key=lambda x: x.start, reverse=True):
        out = out[: ent.start] + f"[{ent.type}]" + out[ent.end :]
    return out


def detect_pii_presidio(text: str) -> list[PiiEntity]:  # pragma: no cover - optional dep
    """Presidio-backed detection (requires the ``presidio`` extra)."""
    from presidio_analyzer import AnalyzerEngine

    results = AnalyzerEngine().analyze(text=text, language="en")
    return [PiiEntity(r.entity_type, text[r.start : r.end], r.start, r.end) for r in results]
