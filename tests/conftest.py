"""Hermetic fixtures: clear guardrail/Langfuse env and reset cached settings."""

from __future__ import annotations

import pytest

from llm_guardrails.config import reset_settings

_VARS = (
    "PII_ENGINE",
    "BLOCK_SEVERITY",
    "REDACT_PII",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_HOST",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    reset_settings()
    yield
    reset_settings()
