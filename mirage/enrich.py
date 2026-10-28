"""Tavily enrichment: look up what the observed probes and the advertised software relate to."""
from __future__ import annotations

import re

import httpx

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


async def tavily_search(api_key: str, query: str, max_results: int = 4) -> list[dict]:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://api.tavily.com/search",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"query": query, "max_results": max_results, "search_depth": "basic"},
        )
        r.raise_for_status()
        return r.json().get("results", [])


def cves_from_results(results: list[dict], query: str) -> list[dict]:
    """CVE ids mentioned in the retrieved pages, with the page they came from.

    These are mentions in search results, not verified applicability: treat as leads.
    """
    found: dict[str, dict] = {}
    for res in results:
        text = f"{res.get('title', '')} {res.get('content', '')}"
        for cve in CVE_RE.findall(text):
            cid = cve.upper()
            found.setdefault(cid, {"id": cid, "source": res.get("url", ""), "query": query})
    return list(found.values())
