"""Thin Nebius Token Factory client with two model tiers.

fast  -> Nemotron Nano-class model: live, per-request deception (latency matters)
smart -> Nemotron Ultra-class model: persona design and offline analysis
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass

from openai import AsyncOpenAI

from .config import Config


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    text: str
    model: str
    latency_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


_THINK_RE = re.compile(r"<think>.*?</think>", re.S)


def strip_reasoning(text: str) -> str:
    """Remove <think> blocks (some reasoning models only emit the closing tag)."""
    if "</think>" in text and "<think>" not in text:
        text = text.split("</think>", 1)[1]
    return _THINK_RE.sub("", text).strip()


def _loosen(s: str) -> str:
    """Strip // comments and trailing commas that models sometimes emit."""
    s = re.sub(r"(?<![:\"\w])//[^\n]*", "", s)
    return re.sub(r",(\s*[}\]])", r"\1", s)


def extract_json(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("no JSON object in model output")
    chunk = text[start : end + 1]
    last: Exception | None = None
    for candidate in (chunk, _loosen(chunk)):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError as e:
            last = e
            continue
        if not isinstance(obj, dict):
            raise LLMError("model JSON was not an object")
        return obj
    raise LLMError(f"invalid JSON from model: {last}")


class LLM:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.enabled = bool(cfg.api_key)
        self._client = AsyncOpenAI(
            api_key=cfg.api_key or "unset",
            base_url=cfg.base_url,
            timeout=cfg.llm_timeout_s,
            max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
        )

    def model_for(self, tier: str) -> str:
        return self.cfg.model_smart if tier == "smart" else self.cfg.model_fast

    async def complete(
        self,
        tier: str,
        system: str,
        user: str,
        *,
        max_tokens: int = 900,
        temperature: float = 0.7,
    ) -> LLMResult:
        if not self.enabled:
            raise LLMError("NEBIUS_API_KEY is not set")
        model = self.model_for(tier)
        timeout = self.cfg.llm_smart_timeout_s if tier == "smart" else self.cfg.llm_timeout_s
        kwargs: dict = {}
        if self.cfg.llm_extra_body:
            kwargs["extra_body"] = self.cfg.llm_extra_body
        t0 = time.perf_counter()
        try:
            resp = await self._client.with_options(timeout=timeout).chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs,
            )
        except Exception as e:  # network, auth, 4xx/5xx, timeout
            raise LLMError(f"{type(e).__name__}: {e}") from e
        ms = int((time.perf_counter() - t0) * 1000)
        text = strip_reasoning((resp.choices[0].message.content or "") if resp.choices else "")
        usage = getattr(resp, "usage", None)
        return LLMResult(
            text=text,
            model=model,
            latency_ms=ms,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
        )
