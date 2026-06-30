"""Optional Langfuse tracing for guardrail scans (no-op when keys are absent)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any

from llm_guardrails.config import Settings


def _init_langfuse(settings: Settings) -> Any | None:
    try:
        from langfuse import Langfuse

        return Langfuse(
            public_key=settings.langfuse_public_key,
            secret_key=settings.langfuse_secret_key,
            host=settings.langfuse_host,
        )
    except Exception:
        return None


def _safe(obj: Any, method: str, /, **kwargs: Any) -> Any:
    fn = getattr(obj, method, None)
    if fn is None:
        return None
    try:
        return fn(**kwargs)
    except Exception:
        return None


class Span:
    def __init__(self, handle: Any | None) -> None:
        self._handle = handle

    def update(self, **kwargs: Any) -> None:
        if self._handle is not None:
            _safe(self._handle, "update", **kwargs)

    def score(self, name: str, value: float) -> None:
        if self._handle is not None:
            _safe(self._handle, "score", name=name, value=value)


class Tracer:
    def __init__(self, settings: Settings) -> None:
        self._client = _init_langfuse(settings) if settings.langfuse_enabled else None

    @property
    def active(self) -> bool:
        return self._client is not None

    @contextmanager
    def trace(self, name: str, *, input: Any = None, metadata: dict | None = None) -> Iterator[Span]:
        cm = None
        handle = None
        if self._client is not None:
            cm = _safe(self._client, "start_as_current_span", name=name, input=input)
            if cm is not None:
                with suppress(Exception):
                    handle = cm.__enter__()
                    _safe(handle, "update_trace", metadata=metadata or {})
        try:
            yield Span(handle)
        finally:
            if cm is not None:
                with suppress(Exception):
                    cm.__exit__(None, None, None)
            with suppress(Exception):
                if self._client is not None:
                    _safe(self._client, "flush")
