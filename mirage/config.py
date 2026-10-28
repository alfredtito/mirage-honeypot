from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    # --- Nebius Token Factory (OpenAI-compatible) ---
    api_key: str = ""
    base_url: str = "https://api.tokenfactory.nebius.com/v1/"
    # VERIFY these against `python scripts/list_models.py` before relying on them.
    model_fast: str = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"    # live, per-request calls
    model_smart: str = "nvidia/Nemotron-3-Ultra-550b-a55b"  # persona + offline analysis
    # Extra JSON merged into every request body, e.g. a switch that disables
    # reasoning on the fast model: {"chat_template_kwargs": {"enable_thinking": false}}
    llm_extra_body: dict = field(default_factory=dict)
    llm_timeout_s: float = 8.0          # fast tier (attacker tools time out quickly)
    llm_smart_timeout_s: float = 90.0   # smart tier (persona, analysis)
    llm_max_concurrency: int = 8

    # --- Honeypot behaviour ---
    mode: str = "mirage"                # "mirage" = generate on miss, "static" = baseline
    max_llm_calls_per_session: int = 60
    max_body_bytes: int = 8192
    max_response_bytes: int = 65536
    persona_theme: str = (
        "a mid-sized regional logistics and freight company with a customer "
        "tracking portal and a staff admin panel"
    )

    # --- Storage / server ---
    db_path: str = "mirage.db"
    host: str = "0.0.0.0"
    port: int = 8080
    forwarded_allow_ips: str = "127.0.0.1"

    @classmethod
    def from_env(cls) -> "Config":
        try:
            extra = json.loads(os.environ.get("LLM_EXTRA_BODY", "") or "{}")
            if not isinstance(extra, dict):
                extra = {}
        except json.JSONDecodeError:
            extra = {}
        d = cls()
        return cls(
            api_key=os.environ.get("NEBIUS_API_KEY", ""),
            base_url=os.environ.get("NEBIUS_BASE_URL", d.base_url),
            model_fast=os.environ.get("MODEL_FAST", d.model_fast),
            model_smart=os.environ.get("MODEL_SMART", d.model_smart),
            llm_extra_body=extra,
            llm_timeout_s=_float("LLM_TIMEOUT_S", d.llm_timeout_s),
            llm_smart_timeout_s=_float("LLM_SMART_TIMEOUT_S", d.llm_smart_timeout_s),
            llm_max_concurrency=_int("LLM_MAX_CONCURRENCY", d.llm_max_concurrency),
            mode=os.environ.get("MIRAGE_MODE", d.mode),
            max_llm_calls_per_session=_int("MAX_LLM_CALLS_PER_SESSION", d.max_llm_calls_per_session),
            max_body_bytes=_int("MAX_BODY_BYTES", d.max_body_bytes),
            max_response_bytes=_int("MAX_RESPONSE_BYTES", d.max_response_bytes),
            persona_theme=os.environ.get("PERSONA_THEME", d.persona_theme),
            db_path=os.environ.get("DB_PATH", d.db_path),
            host=os.environ.get("HOST", d.host),
            port=_int("PORT", d.port),
            forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", d.forwarded_allow_ips),
        )
