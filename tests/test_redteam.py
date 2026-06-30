"""End-to-end red-team suite scoring and the CI defense gate."""

from __future__ import annotations

from llm_guardrails.config import Settings
from llm_guardrails.redteam import THRESHOLDS, run_redteam


def test_defense_gate_passes():
    report = run_redteam(Settings())
    assert report.passed(), f"gate failed on: {report.failures()}"
    assert report.aggregate["attack_catch_rate"] >= THRESHOLDS["attack_catch_rate"]
    assert report.aggregate["benign_pass_rate"] == 1.0


def test_no_benign_false_positives():
    report = run_redteam(Settings())
    assert report.aggregate["benign_false_positives"] == 0.0


def test_obfuscated_attack_is_an_honest_miss():
    # a14 has no trigger phrase; documenting the known heuristic limitation
    report = run_redteam(Settings())
    a14 = next(r for r in report.results if r.id == "a14")
    assert not a14.correct
