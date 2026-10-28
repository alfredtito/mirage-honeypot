"""A synthetic baseline of legitimate requests, used to measure false positives of proposed rules.

It is built from the persona's real pages plus typical customer and monitoring traffic. It is a
stand-in: with real benign logs from a production site, replace it.
"""
from __future__ import annotations

from typing import Any

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
    "curl/8.5.0",
]
# (method, path, query, body)
EXTRAS = [
    ("GET", "/track", "id=BW-10042", ""),
    ("GET", "/track", "id=BW-10042&ref=email", ""),
    ("GET", "/search", "q=freight+rates+Gaborone", ""),
    ("GET", "/search", "q=O%27Brien+Freight", ""),
    ("GET", "/api/v1/shipments", "page=2&limit=20", ""),
    ("GET", "/api/v1/shipments/10042", "", ""),
    ("GET", "/static/css/main.css", "", ""),
    ("GET", "/static/js/app.js", "", ""),
    ("GET", "/images/logo.png", "", ""),
    ("GET", "/downloads/rate-card-2026.pdf", "", ""),
    ("GET", "/downloads/annual-report-2025.zip", "", ""),
    ("GET", "/downloads/tariffs-2026.csv", "", ""),
    ("GET", "/exports/shipments-october.xlsx", "", ""),
    ("GET", "/files/invoice-INV-1042.pdf", "", ""),
    ("GET", "/about/data-backup-policy", "", ""),
    ("GET", "/static/images/admin-team.jpg", "", ""),
    ("GET", "/contact", "subject=quote+request", ""),
    ("GET", "/health", "", ""),
    ("POST", "/login", "", "username=jdoe&password=Correct-Horse-9"),
    ("POST", "/contact", "", "name=Thabo+K&email=thabo%40example.com&message=Please+send+a+quote"),
]


def benign_events(persona: dict[str, Any]) -> list[dict]:
    evs: list[dict] = []

    def add(method, path, query, body, ua):
        evs.append({"session_id": "benign-corpus", "method": method, "path": path, "query": query,
                    "body": body, "ua": ua, "status": 200, "source": "benign-corpus", "ts": 0})

    paths = []
    for p in persona.get("known_paths", []):
        base = p.split("?")[0]
        if base not in paths:
            paths.append(base)
    for i, p in enumerate(paths):
        add("GET", p, "", "", BROWSERS[i % len(BROWSERS)])
        add("GET", p, "", "", BROWSERS[(i + 1) % len(BROWSERS)])
    for i, (m, p, q, b) in enumerate(EXTRAS):
        add(m, p, q, b, BROWSERS[i % len(BROWSERS)])
    for i, ua in enumerate(BOT_UAS):
        add("GET", "/", "", "", ua)
        add("GET", "/health", "", "", ua)
    return evs
