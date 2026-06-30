"""Load the red-team attack suite and benign control set."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_DATA = Path(__file__).resolve().parents[3] / "data"


@dataclass(frozen=True)
class AttackCase:
    id: str
    prompt: str
    expected: str  # "block" | "redact" | "allow"
    category: str = "benign"


def _load(path: Path, default_category: str | None = None) -> list[AttackCase]:
    cases: list[AttackCase] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cases.append(
            AttackCase(
                id=row["id"],
                prompt=row["prompt"],
                expected=row["expected"],
                category=row.get("category", default_category or "benign"),
            )
        )
    return cases


def load_attacks(path: Path | None = None) -> list[AttackCase]:
    return _load(path or _DATA / "attacks.jsonl")


def load_benign(path: Path | None = None) -> list[AttackCase]:
    return _load(path or _DATA / "benign.jsonl", default_category="benign")
