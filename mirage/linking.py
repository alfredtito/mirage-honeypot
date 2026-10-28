"""Deterministic record linking.

Small models often print record ids in list tables without linking them. This turns a table row whose
first cells hold a record id (TRK-48213, INV-2026-0015, 10042) into a link to that record's detail page,
using the persona's own URL patterns, so list pages always lead somewhere deeper.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from .persona import _norm, matches_pattern

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._#-]{2,29}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ROW_RE = re.compile(r"(<tr\b[^>]*>)(.*?)(</tr>)", re.I | re.S)
CELL_RE = re.compile(r"(<td\b[^>]*>)(.*?)(</td>)", re.I | re.S)


def record_prefix(persona: dict[str, Any], path: str) -> str | None:
    """For a list page of a section (e.g. /shipments) return '/shipments/', else None."""
    norm = _norm(path)
    segs = [s for s in norm.split("/") if s]
    if not segs or matches_pattern(persona, norm):
        return None  # root, or already a record page
    for template in persona.get("url_patterns", []):
        parts = [s for s in _norm(template).split("/") if s]
        if (len(parts) == 2 and "{" not in parts[0] and parts[0].lower() == segs[0].lower()
                and parts[1].startswith("{") and parts[1].endswith("}")):
            return f"/{parts[0]}/"
    return None


def looks_like_id(text: str) -> bool:
    return bool(ID_RE.match(text)) and bool(re.search(r"\d", text)) and not DATE_RE.match(text)


def link_record_rows(persona: dict[str, Any], path: str, body: str) -> tuple[str, int]:
    """Link the record id in each table row (first two cells considered). Returns (new_body, links_added)."""
    prefix = record_prefix(persona, path)
    if not prefix or "<table" not in body.lower():
        return body, 0
    added = [0]

    def do_row(m: re.Match) -> str:
        seen = [0]
        done = [False]

        def do_cell(cm: re.Match) -> str:
            seen[0] += 1
            if done[0] or seen[0] > 2:
                return cm.group(0)
            text = cm.group(2).strip()
            if "<" in text or not looks_like_id(text):
                return cm.group(0)
            done[0] = True
            added[0] += 1
            return f'{cm.group(1)}<a href="{prefix}{quote(text, safe="")}">{text}</a>{cm.group(3)}'

        return m.group(1) + CELL_RE.sub(do_cell, m.group(2)) + m.group(3)

    return ROW_RE.sub(do_row, body), added[0]
