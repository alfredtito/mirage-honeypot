"""Persona store: the fictional 'site identity' that keeps every generated response consistent."""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import html
import json
import logging
import re
from typing import Any

from .db import Database
from .llm import LLM, LLMError, extract_json
from .prompts import SYSTEM_LURES, SYSTEM_NAV, SYSTEM_PERSONA

log = logging.getLogger("mirage.persona")

DEFAULT_PERSONA: dict[str, Any] = {
    "company": "Kalahari Freight Services",
    "domain": "portal.kalaharifreight.example",
    "tagline": "Moving goods across the region",
    "style": "plain corporate blue and grey, dated Bootstrap 3 look",
    "stack": {
        "server_header": "Apache/2.4.41 (Ubuntu)",
        "powered_by": "PHP/7.4.3",
        "framework": "custom PHP",
        "cms": "none",
        "database": "MySQL 5.7",
        "session_cookie": "PHPSESSID",
    },
    "users": [
        {"username": "admin", "full_name": "Site Administrator", "email": "admin@kalaharifreight.example", "role": "admin"},
        {"username": "tmoeng", "full_name": "Tebogo Moeng", "email": "t.moeng@kalaharifreight.example", "role": "dispatcher"},
        {"username": "lkgosi", "full_name": "Lerato Kgosi", "email": "l.kgosi@kalaharifreight.example", "role": "accounts"},
    ],
    "db_tables": [
        {"name": "users", "columns": ["id", "username", "email", "role", "created_at"]},
        {"name": "shipments", "columns": ["id", "tracking_no", "origin", "destination", "status", "customer_id"]},
        {"name": "customers", "columns": ["id", "company", "contact_email", "phone"]},
        {"name": "invoices", "columns": ["id", "customer_id", "amount", "due_date", "paid"]},
    ],
    "known_paths": ["/", "/login", "/admin", "/track", "/contact", "/about", "/api/v1/shipments", "/robots.txt"],
    "lure_paths": ["/admin/login", "/.env", "/phpinfo.php", "/backup/", "/api/v1/users"],
    "nav": [{"label": "Home", "path": "/"}, {"label": "Track a shipment", "path": "/track"},
            {"label": "About", "path": "/about"}, {"label": "Contact", "path": "/contact"},
            {"label": "Staff login", "path": "/login"}],
    "url_patterns": ["/track/{tracking_no}", "/api/v1/shipments/{shipment_id}"],
}


def _valid_path(p: Any) -> bool:
    return isinstance(p, str) and p.startswith("/") and " " not in p and len(p) <= 100 and "\n" not in p


def _clean_nav(nav: Any, allowed: list[str]) -> list[dict]:
    out = []
    for n in (nav or [])[:10]:
        if isinstance(n, dict) and _valid_path(n.get("path")) and n["path"] in allowed and n.get("label"):
            label = re.sub(r"[^\w &'/-]", "", str(n["label"])).strip()[:30]
            if label:
                out.append({"label": label, "path": n["path"]})
    return out[:8]


def derive_nav(known: list[str]) -> list[dict]:
    """Fallback menu: the site root plus its single-segment pages."""
    skip = {"logout", "robots.txt", "sitemap.xml", "favicon.ico"}
    nav = [{"label": "Home", "path": "/"}] if "/" in known else []
    for p in known:
        seg = p.strip("/")
        if p != "/" and "/" not in seg and "." not in seg and seg not in skip and len(nav) < 7:
            nav.append({"label": seg.replace("-", " ").replace("_", " ").title(), "path": p})
    return nav if len(nav) >= 3 else list(DEFAULT_PERSONA["nav"])


def _clip(s: Any, n: int = 120) -> str:
    return str(s)[:n]


def normalize_persona(spec: dict[str, Any]) -> dict[str, Any]:
    """Merge a model-produced spec over defaults and clamp sizes. Never trust model output shape."""
    d = DEFAULT_PERSONA
    out: dict[str, Any] = {
        "company": _clip(spec.get("company") or d["company"]),
        "domain": _clip(spec.get("domain") or d["domain"]),
        "tagline": _clip(spec.get("tagline") or d["tagline"]),
        "style": _clip(spec.get("style") or d["style"], 200),
    }
    stack_in = spec.get("stack") if isinstance(spec.get("stack"), dict) else {}
    out["stack"] = {k: _clip(stack_in.get(k) or v) for k, v in d["stack"].items()}

    users = []
    for u in (spec.get("users") or [])[:8]:
        if isinstance(u, dict) and u.get("username"):
            users.append({k: _clip(u.get(k, "")) for k in ("username", "full_name", "email", "role")})
    out["users"] = users or d["users"]

    tables = []
    for t in (spec.get("db_tables") or [])[:8]:
        if isinstance(t, dict) and t.get("name") and isinstance(t.get("columns"), list):
            tables.append({"name": _clip(t["name"], 40), "columns": [_clip(c, 40) for c in t["columns"][:12]]})
    out["db_tables"] = tables or d["db_tables"]

    raw_paths = [p for p in (spec.get("known_paths") or []) if _valid_path(p)]
    paths = [p for p in raw_paths if "{" not in p]
    out["known_paths"] = [_clip(p, 100) for p in paths[:16]] or d["known_paths"]
    # templates like /shipments/{id} are URL patterns, not pages
    templ = [p for p in raw_paths if "{" in p] + [p for p in (spec.get("url_patterns") or []) if _valid_path(p) and "{" in p]
    out["url_patterns"] = list(dict.fromkeys(_clip(p, 100) for p in templ))[:6] or d["url_patterns"]
    lures = [p for p in (spec.get("lure_paths") or []) if _valid_path(p) and "{" not in p and p not in out["known_paths"]]
    out["lure_paths"] = [_clip(p, 100) for p in lures[:8]] or [p for p in d["lure_paths"] if p not in out["known_paths"]]
    out["nav"] = _clean_nav(spec.get("nav"), out["known_paths"] + out["lure_paths"]) or derive_nav(out["known_paths"])
    return out


def persona_id_for(spec: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:12]


def persona_brief(p: dict[str, Any]) -> str:
    """Compact text form injected into every generation prompt."""
    s = p["stack"]
    lines = [
        f"Organization: {p['company']} ({p['domain']}) - {p['tagline']}",
        f"Visual style: {p['style']}",
        f"Stack: {s['server_header']}, {s['powered_by']}, framework={s['framework']}, "
        f"cms={s['cms']}, db={s['database']}",
        "Staff users: " + "; ".join(f"{u['username']} ({u['full_name']}, {u['role']}, {u['email']})" for u in p["users"]),
        "Database schema: " + "; ".join(f"{t['name']}({', '.join(t['columns'])})" for t in p["db_tables"]),
        "Known site paths: " + ", ".join(p["known_paths"]),
    ]
    if p.get("lure_paths"):
        lines.append("Other existing pages: " + ", ".join(p["lure_paths"]))
    if p.get("nav"):
        lines.append("Navigation menu (every HTML page shows it, same order; link text = label, href = path): " +
                     "; ".join(f"{n['label']} -> {n['path']}" for n in p["nav"]))
    if p.get("url_patterns"):
        lines.append("Record URL patterns (detail pages exist for concrete ids): " + ", ".join(p["url_patterns"]))
    lines.append(f"Today's date: {datetime.date.today().isoformat()} (use the current year in footers and for recent dates)")
    return "\n".join(lines)


async def ensure_persona(db: Database, llm: LLM, theme: str) -> dict[str, Any]:
    """Load the active persona, or design one (smart tier) and persist it.

    Retries once if the model's JSON is unusable, and falls back to the built-in persona
    if the model stays unavailable, so the honeypot still runs.
    """
    existing = await asyncio.to_thread(db.get_active_persona)
    if existing:
        return existing
    spec = DEFAULT_PERSONA
    if llm.enabled:
        for attempt in (1, 2):
            raw = ""
            try:
                res = await llm.complete(
                    "smart", SYSTEM_PERSONA, f"Theme: {theme}",
                    max_tokens=2500, temperature=0.7 if attempt == 1 else 0.2,
                )
                raw = res.text
                spec = normalize_persona(extract_json(raw))
                log.info("generated persona %s via %s in %dms", spec["company"], res.model, res.latency_ms)
                break
            except LLMError as e:
                log.warning("persona attempt %d failed (%s). Raw output starts: %r", attempt, e, raw[:600])
        else:
            log.warning("persona generation failed twice; using built-in persona")
    else:
        log.warning("no API key; using built-in persona")
    pid = persona_id_for(spec)
    await asyncio.to_thread(db.save_persona, pid, spec)
    spec = dict(spec)
    spec["persona_id"] = pid
    return spec


def fallback_page(persona: dict[str, Any], status: int, path: str) -> tuple[int, str, str]:
    """Persona-styled static error page used when generation is unavailable or budget is spent."""
    titles = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
              405: "Method Not Allowed", 500: "Internal Server Error"}
    title = titles.get(status, "Not Found")
    server = html.escape(persona["stack"]["server_header"])
    domain = html.escape(persona["domain"])
    body = (
        f"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
        f"<title>{status} {title}</title>\n</head><body>\n<h1>{title}</h1>\n"
        f"<p>The requested URL {html.escape(path)} could not be served on this server.</p>\n"
        f"<hr>\n<address>{server} Server at {domain} Port 80</address>\n</body></html>\n"
    )
    return status, "text/html", body


# ---------- site surface: which paths belong to this site ----------

def _norm(path: str) -> str:
    path = re.sub(r"/{2,}", "/", path.split("?")[0])
    return (path.rstrip("/") or "/")


def surface_sets(persona: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(exact paths, top-level sections) for the pages this site really has: known pages plus lures."""
    concrete = [p for p in list(persona.get("known_paths", [])) + list(persona.get("lure_paths", [])) if "{" not in p]
    templates = [p for p in list(persona.get("known_paths", [])) + list(persona.get("url_patterns", [])) if "{" in p]
    exact = {_norm(p) for p in concrete}
    sections = set()
    for p in list(exact) + [_norm(t) for t in templates]:
        seg = next((s for s in p.split("/") if s), "")
        if seg and "." not in seg and "{" not in seg:
            sections.add(seg.lower())
    return exact, sections


def surface_paths(persona: dict[str, Any]) -> list[str]:
    """Concrete pages to pre-build: known pages plus lures, without {placeholder} templates."""
    out: list[str] = []
    for p in list(persona.get("known_paths", [])) + list(persona.get("lure_paths", [])):
        if "{" not in p and p not in out:
            out.append(p)
    return out


def matches_pattern(persona: dict[str, Any], path: str) -> bool:
    """True if path fits one of the site's record URL patterns, e.g. /shipments/PRO-48213."""
    templates = list(persona.get("url_patterns", [])) + [p for p in persona.get("known_paths", []) if "{" in p]
    norm = _norm(path)
    for t in templates:
        rx = "^" + "[^/]+".join(re.escape(part) for part in re.split(r"\{[^}]*\}", _norm(t))) + "$"
        if re.match(rx, norm):
            return True
    return False


def on_surface(exact: set[str], sections: set[str], path: str) -> bool:
    norm = _norm(path)
    if norm in exact:
        return True
    seg = next((s for s in norm.split("/") if s), "")
    return bool(seg) and "." not in seg and seg.lower() in sections


async def design_lures(llm: LLM, persona: dict[str, Any]) -> list[str]:
    """Propose lure paths for an existing persona (smart tier), with a safe default."""
    known = set(persona.get("known_paths", []))
    if llm.enabled:
        try:
            res = await llm.complete("smart", SYSTEM_LURES, f"<persona>\n{persona_brief(persona)}\n</persona>",
                                     max_tokens=600, temperature=0.7)
            raw = extract_json(res.text).get("lure_paths") or []
            clean: list[str] = []
            for p in raw:
                if _valid_path(p) and p not in known and p not in clean and "<" not in p:
                    clean.append(p[:100])
            if len(clean) >= 3:
                return clean[:8]
        except LLMError as e:
            log.warning("lure design failed (%s); using defaults", e)
    return [p for p in DEFAULT_PERSONA["lure_paths"] if p not in known]


async def design_nav(llm: LLM, persona: dict[str, Any]) -> tuple[list[dict], list[str]]:
    """Design the menu and record URL patterns for an existing persona (smart tier), with fallbacks."""
    allowed = surface_paths(persona)
    nav, patterns = [], list(persona.get("url_patterns", []))
    if llm.enabled:
        try:
            res = await llm.complete("smart", SYSTEM_NAV, f"<persona>\n{persona_brief(persona)}\n</persona>",
                                     max_tokens=700, temperature=0.5)
            d = extract_json(res.text)
            nav = _clean_nav(d.get("nav"), allowed)
            _, sections = surface_sets(persona)
            found = [p for p in (d.get("url_patterns") or []) if _valid_path(p) and p.count("{") == 1]
            patterns = list(dict.fromkeys(patterns + [_clip(p, 100) for p in found]))[:6]
        except LLMError as e:
            log.warning("navigation design failed (%s); deriving it", e)
    return (nav if len(nav) >= 3 else derive_nav(persona.get("known_paths", []))), patterns
