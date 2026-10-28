"""Request handling: session tracking, cache lookup, on-demand generation, logging."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import parse_qsl

from fastapi import Request, Response

from .config import Config
from .db import Database
from .llm import LLM, LLMError
from .linking import link_record_rows
from .persona import fallback_page, matches_pattern, on_surface, persona_brief, surface_sets
from .prompts import SYSTEM_RESPONDER

log = logging.getLogger("mirage.engine")

ALLOWED_STATUS = {200, 400, 401, 403, 404, 405, 500}
SID_RE = re.compile(r"^[0-9a-f]{32}$")
STATIC_404_PATHS = {"/favicon.ico", "/apple-touch-icon.png"}
PROMPT_HEADERS = ("host", "user-agent", "content-type", "referer", "accept")


# ---------- pure helpers (unit-tested) ----------

def esc(s: str, limit: int) -> str:
    """Escape attacker text so it cannot close our prompt fences, and bound its size."""
    s = "".join(ch for ch in s[:limit] if ch in "\n\t" or ord(ch) >= 32)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def normalize_path(path: str) -> str:
    path = re.sub(r"/{2,}", "/", path)[:300] or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path


def cache_key(method: str, path: str, query: str) -> str:
    items = sorted(parse_qsl(query, keep_blank_values=True))
    q = "&".join(f"{k}={v}" for k, v in items)
    if len(q) > 200:
        q = "h:" + hashlib.sha256(q.encode()).hexdigest()[:16]
    return f"{method} {normalize_path(path)}" + (f"?{q}" if q else "")


def derive_session_id(cookie_value: str | None, ip: str, ua: str) -> str:
    if cookie_value and SID_RE.match(cookie_value):
        return cookie_value
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]


KNOWN_HEADERS = {
    "content-type", "content-length", "content-encoding", "cache-control", "pragma", "expires",
    "server", "date", "connection", "vary", "etag", "last-modified", "location", "set-cookie",
    "www-authenticate", "allow", "keep-alive", "transfer-encoding", "accept-ranges", "refresh",
}
_HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]{1,40}):[ \t]?.*$")
_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}\b.*$")


def strip_header_block(text: str) -> str:
    """Drop an HTTP status line and header lines the model wrote at the top of the body."""
    lines = text.split("\n")
    i = 0
    if lines and _STATUS_LINE.match(lines[0].rstrip("\r")):
        i = 1
    start = i
    while i < len(lines):
        m = _HEADER_LINE.match(lines[i].rstrip("\r"))
        if not m:
            break
        name = m.group(1).lower()
        if name not in KNOWN_HEADERS and not name.startswith("x-"):
            break
        i += 1
    if i == start and start == 0:
        return text
    return "\n".join(lines[i:]).lstrip("\r\n")


def parse_model_output(text: str) -> tuple[int, str]:
    status = 200
    m = re.match(r"\s*STATUS:\s*(\d{3})[ \t]*\r?\n", text)
    if m:
        code = int(m.group(1))
        status = code if code in ALLOWED_STATUS else 200
        text = text[m.end():]
    text = strip_header_block(text.lstrip("\r\n"))
    fence = re.match(r"^```[A-Za-z0-9]*\n(.*?)\n?```\s*$", text, re.S)
    if fence:
        text = strip_header_block(fence.group(1))
    return status, text


def guess_content_type(path: str, body: str) -> str:
    p = path.lower().split("?")[0]
    b = body.lstrip()
    if p.endswith(".json") or b.startswith(("{", "[")):
        return "application/json"
    if p.endswith(".xml") or b.startswith("<?xml"):
        return "application/xml"
    if p.endswith(".css"):
        return "text/css"
    if p.endswith(".js"):
        return "application/javascript"
    if p.endswith(".txt") or p == "/robots.txt":
        return "text/plain"
    if b.startswith("<"):
        return "text/html"
    return "text/plain"


def build_user_prompt(persona: dict[str, Any], history: list[tuple[str, str, int]], method: str,
                      path: str, query: str, headers: dict[str, str], body: str) -> str:
    hist = "\n".join(f"{m} {esc(p, 200)} -> {s}" for m, p, s in history) or "(first request)"
    hdrs = "\n".join(f"{k}: {esc(headers[k], 200)}" for k in PROMPT_HEADERS if k in headers)
    target = esc(path, 300) + (f"?{esc(query, 300)}" if query else "")
    known = {normalize_path(k.split("?")[0]) for k in persona.get("known_paths", []) + persona.get("lure_paths", [])}
    note = ""
    if method == "GET" and (normalize_path(path) in known or matches_pattern(persona, path)):
        note = (
            "\n<note>This page exists (a real page or record page of the site). It is NOT an attack probe: "
            "answer STATUS: 200 with its complete page content.</note>"
        )
    return (
        f"<persona>\n{persona_brief(persona)}\n</persona>\n"
        f"<history>\n{hist}\n</history>\n"
        f"<request>\n{method} {target}\n{hdrs}\n\n{esc(body, 2000)}\n</request>{note}"
    )


async def read_limited(request: Request, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        remaining = limit - total
        if remaining <= 0:
            return b"".join(chunks), True
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            return b"".join(chunks), True
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), False


# ---------- engine ----------

@dataclass
class GenResult:
    status: int
    ctype: str
    body: str
    source: str
    model: str | None = None
    llm_ms: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class Engine:
    def __init__(self, cfg: Config, db: Database, llm: LLM, persona: dict[str, Any]):
        self.cfg, self.db, self.llm, self.persona = cfg, db, llm, persona
        self.pid: str = persona["persona_id"]
        self._exact, self._sections = surface_sets(persona)
        self._sem = asyncio.Semaphore(cfg.llm_max_concurrency)
        self._inflight: dict[str, asyncio.Task] = {}  # single-flight per cache key

    # -- generation --
    async def _generate(self, sid: str | None, method: str, path: str, query: str,
                        headers: dict[str, str], body: str, must_exist: bool = False) -> GenResult:
        history = await asyncio.to_thread(self.db.recent_events, sid, 6) if sid else []
        user = build_user_prompt(self.persona, history, method, path, query, headers, body)
        status, text, res = 200, "", None
        for attempt in range(2 if must_exist else 1):
            prompt = user if attempt == 0 else (
                user + "\n<note>IMPORTANT: this page exists. STATUS must be 200 and the body the full page. "
                       "Do not answer 403 or 404.</note>")
            try:
                async with self._sem:
                    res = await asyncio.wait_for(
                        self.llm.complete("fast", SYSTEM_RESPONDER, prompt, max_tokens=1200, temperature=0.6),
                        timeout=self.cfg.llm_timeout_s + 2,
                    )
            except (LLMError, asyncio.TimeoutError) as e:
                log.warning("generation failed for %s %s: %s", method, path, e)
                return GenResult(*fallback_page(self.persona, 404, path), source="fallback")
            status, text = parse_model_output(res.text)
            if not (must_exist and status in (403, 404)):
                break
        if must_exist and status in (403, 404):
            log.warning("page %s should exist but the model answered %s; not cached", path, status)
            return GenResult(*fallback_page(self.persona, 404, path), source="fallback", model=res.model,
                             llm_ms=res.latency_ms, prompt_tokens=res.prompt_tokens,
                             completion_tokens=res.completion_tokens)
        ctype = guess_content_type(path, text)
        if ctype == "text/html" and method == "GET":
            text = link_record_rows(self.persona, path, text)[0]  # list rows always link to record pages
        text = text[: self.cfg.max_response_bytes]
        valid = bool(text.strip())
        if valid and ctype == "application/json":
            try:
                json.loads(text)
            except json.JSONDecodeError:
                valid = False
        if not valid:
            return GenResult(*fallback_page(self.persona, 404, path), source="fallback", model=res.model,
                             llm_ms=res.latency_ms, prompt_tokens=res.prompt_tokens,
                             completion_tokens=res.completion_tokens)
        return GenResult(status, ctype, text, "generated", res.model, res.latency_ms,
                         res.prompt_tokens, res.completion_tokens)

    async def warm(self, paths: list[str]) -> int:
        """Pre-generate GET artifacts for the site's real pages (skips {placeholder} templates)."""
        gate = asyncio.Semaphore(3)

        async def one(p: str) -> int:
            if "{" in p:
                return 0
            key = cache_key("GET", p, "")
            if await asyncio.to_thread(self.db.get_artifact, self.pid, key):
                return 0
            async with gate:
                res = await self._generate(None, "GET", p, "", {"host": self.persona["domain"]}, "",
                                           must_exist=True)
            if res.source == "generated":
                await asyncio.to_thread(self.db.put_artifact, self.pid, key, res.status, res.ctype, res.body)
                return 1
            return 0

        return sum(await asyncio.gather(*(one(p) for p in paths)))

    async def _generate_cached(self, sid: str, key: str, method: str, path: str, query: str,
                               headers: dict[str, str], body: str, must_exist: bool = False) -> GenResult:
        """Single-flight generation for cacheable (GET) requests."""
        task = self._inflight.get(key)
        leader = task is None
        if leader:
            task = asyncio.create_task(self._generate(sid, method, path, query, headers, body, must_exist))
            self._inflight[key] = task
            task.add_done_callback(lambda _t, k=key: self._inflight.pop(k, None))
        res = await asyncio.shield(task)
        if leader:
            if res.source == "generated":
                await asyncio.to_thread(self.db.put_artifact, self.pid, key, res.status, res.ctype, res.body)
            return res
        return replace(res, source="coalesced", model=None, llm_ms=None,
                       prompt_tokens=None, completion_tokens=None)

    # -- request entry point --
    async def handle(self, request: Request) -> Response:
        t0 = time.perf_counter()
        cfg, db = self.cfg, self.db
        method = request.method.upper()
        path = request.url.path
        query = request.url.query
        ip = request.client.host if request.client else "unknown"
        headers = {k.lower(): v[:512] for k, v in request.headers.items()}
        ua = headers.get("user-agent", "")[:300]
        cookie_name = self.persona["stack"]["session_cookie"]
        sid = derive_session_id(request.cookies.get(cookie_name), ip, ua)
        raw, truncated = await read_limited(request, cfg.max_body_bytes)
        body_text = raw.decode("utf-8", "replace")

        await asyncio.to_thread(db.touch_session, sid, self.pid, cfg.mode, ip, ua)

        extra_headers: dict[str, str] = {}
        key = cache_key("GET" if method == "HEAD" else method, path, query)
        cacheable = method in ("GET", "HEAD")

        if method == "OPTIONS":
            res = GenResult(200, "text/plain", "", "static")
            extra_headers["Allow"] = "GET, HEAD, POST, OPTIONS"
        elif path in STATIC_404_PATHS:
            res = GenResult(*fallback_page(self.persona, 404, path), source="static")
        else:
            art = await asyncio.to_thread(db.get_artifact, self.pid, key) if cacheable else None
            if art:
                await asyncio.to_thread(db.hit_artifact, self.pid, key)
                res = GenResult(art["status"], art["content_type"], art["body"], "cache")
            elif cfg.mode == "static":
                res = GenResult(*fallback_page(self.persona, 404, path), source="static")
            elif not on_surface(self._exact, self._sections, path):
                # not part of this site: answer like the real server would, instantly and for free
                res = GenResult(*fallback_page(self.persona, 404, path), source="offsurface")
            elif await asyncio.to_thread(db.session_llm_calls, sid) >= cfg.max_llm_calls_per_session:
                res = GenResult(*fallback_page(self.persona, 404, path), source="budget")
            else:
                gen_path = normalize_path(path)
                if cacheable:
                    # only bare page requests are forced to exist; a probe like /admin?id=1' may be refused
                    must_exist = not query and (gen_path in self._exact or matches_pattern(self.persona, gen_path))
                    res = await self._generate_cached(sid, key, "GET", gen_path, query, headers, body_text,
                                                      must_exist)
                else:
                    res = await self._generate(sid, method, gen_path, query, headers, body_text)
                if res.source == "generated":
                    await asyncio.to_thread(db.bump_llm_calls, sid)

        out_headers = {"Server": self.persona["stack"]["server_header"], **extra_headers}
        powered = self.persona["stack"].get("powered_by")
        if powered:
            out_headers["X-Powered-By"] = powered
        payload = b"" if method == "HEAD" else res.body.encode()
        response = Response(content=payload, status_code=res.status, media_type=res.ctype, headers=out_headers)
        response.set_cookie(cookie_name, sid, httponly=True, path="/")

        latency_ms = int((time.perf_counter() - t0) * 1000)
        await asyncio.to_thread(
            db.log_event,
            request_id=uuid.uuid4().hex, session_id=sid, persona_id=self.pid, mode=cfg.mode,
            ts=time.time(), src_ip=ip, method=method, path=path[:500], query=query[:1000],
            headers_json=json.dumps(headers), body=body_text, body_truncated=int(truncated),
            status=res.status, content_type=res.ctype, response_bytes=len(res.body.encode()),
            response_source=res.source, latency_ms=latency_ms, llm_model=res.model,
            llm_ms=res.llm_ms, prompt_tokens=res.prompt_tokens, completion_tokens=res.completion_tokens,
        )
        return response
