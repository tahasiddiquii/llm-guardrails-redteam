"""Runtime configuration (env-driven, with safe offline defaults)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Detection engine: "regex" (offline default) or "presidio" (optional extra).
    pii_engine: str = "regex"

    # Policy thresholds. Injection severity at/above this blocks the request.
    block_severity: int = 3  # 1=low, 2=medium, 3=high
    redact_pii: bool = True

    # Optional Langfuse tracing of every scan.
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    langfuse_host: str = "https://cloud.langfuse.com"

    @property
    def langfuse_enabled(self) -> bool:
        return bool(self.langfuse_public_key and self.langfuse_secret_key)


_CACHE: dict[str, Settings] = {}


def get_settings() -> Settings:
    if "default" not in _CACHE:
        _CACHE["default"] = Settings()
    return _CACHE["default"]


def reset_settings() -> None:
    _CACHE.clear()
