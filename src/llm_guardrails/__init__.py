"""Guardrails + red-team harness for LLM applications.

Public API:
    GuardrailPipeline  — scan input/output for PII, prompt injection, jailbreaks.
    PolicyDecision     — the allow/redact/block verdict with reasons.
    Settings           — runtime configuration.
"""

from __future__ import annotations

from llm_guardrails.config import Settings, get_settings
from llm_guardrails.pipeline import GuardrailPipeline
from llm_guardrails.policy import Action, PolicyDecision

__all__ = [
    "Action",
    "GuardrailPipeline",
    "PolicyDecision",
    "Settings",
    "get_settings",
    "__version__",
]

__version__ = "0.1.0"
