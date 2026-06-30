"""Render the red-team report (markdown file + console table)."""

from __future__ import annotations

from pathlib import Path

from llm_guardrails.redteam.runner import THRESHOLDS, RedTeamReport

_ROOT = Path(__file__).resolve().parents[2]
REPORT = _ROOT / "reports" / "redteam_report.md"


def write_report(report: RedTeamReport, path: Path | None = None) -> Path:
    path = path or REPORT
    path.parent.mkdir(parents=True, exist_ok=True)
    agg = report.aggregate

    lines = [
        "# Red-team report",
        "",
        f"Attacks: {int(agg['attacks_total'])} · caught: {int(agg['attacks_caught'])} · "
        f"benign: {int(agg['benign_total'])} · false positives: {int(agg['benign_false_positives'])}",
        "",
        "## Gate",
        "",
        "| Metric | Value | Threshold | Pass |",
        "| --- | --- | --- | --- |",
    ]
    for key, thr in THRESHOLDS.items():
        val = agg[key]
        lines.append(f"| {key} | {val:.3f} | {thr:.2f} | {'✅' if val >= thr else '❌'} |")

    lines += [
        "",
        "## By attack category",
        "",
        "| Category | Caught | Total | Rate |",
        "| --- | --- | --- | --- |",
    ]
    for cat, (caught, total) in sorted(report.by_category.items()):
        rate = caught / total if total else 0.0
        lines.append(f"| {cat} | {caught} | {total} | {rate:.2f} |")

    lines += [
        "",
        "## Per case",
        "",
        "| id | category | expected | actual | ok | signals |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in report.results:
        ok = "✅" if r.correct else "❌"
        reasons = ", ".join(r.reasons) if r.reasons else "—"
        lines.append(f"| {r.id} | {r.category} | {r.expected} | {r.actual} | {ok} | {reasons} |")

    lines += [
        "",
        "> The obfuscated case `a14` carries no trigger phrase and slips past the rule-based "
        "detector — a deliberate, honest reminder that heuristic guardrails are one layer of "
        "defense-in-depth, not a complete solution. The harness measures exactly where the layer ends.",
        "",
    ]
    path.write_text("\n".join(lines))
    return path


def print_table(report: RedTeamReport) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="red-team · guardrail defense")
        table.add_column("metric")
        table.add_column("value", justify="right")
        table.add_column("gate", justify="center")
        for key, thr in THRESHOLDS.items():
            val = report.aggregate[key]
            table.add_row(key, f"{val:.3f}", "PASS" if val >= thr else "FAIL")
        Console().print(table)
    except ImportError:
        print(report.aggregate)
