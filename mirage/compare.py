"""Static-vs-Mirage comparison statistics, computed from two honeypot databases."""
from __future__ import annotations

import re
import sqlite3
import statistics
from collections import defaultdict
from urllib.parse import unquote_plus

from .analyst import INDICATORS

PROFILES = (("recon", "nmap"), ("scanner", "nikto"), ("brute", "python-requests"), ("crawler", "chrome"))
IMPROVISED = {"generated", "coalesced"}
DEAD_END = {"static", "fallback", "budget", "offsurface"}
PAYLOADS = ("sqli_probe", "path_traversal", "xss_probe")


def profile_of(ua: str) -> str | None:
    low = (ua or "").lower()
    return next((name for name, key in PROFILES if key in low), None)


def run_of(ua: str) -> int:
    m = re.search(r"\br(\d+)$", ua or "")
    return int(m.group(1)) if m else 0


def _session_numbers(rows: list[sqlite3.Row]) -> dict:
    paths = {r["path"] for r in rows if r["path"] != "/favicon.ico"}
    reached = {r["path"] for r in rows if r["status"] == 200 and r["path"] != "/favicon.ico"}
    payloads = answered = 0
    for r in rows:
        blob = f"{r['path']}?{unquote_plus(r['query'] or '')}"
        if any(INDICATORS[n].search(blob) for n in PAYLOADS):
            payloads += 1
            answered += r["status"] != 404
    posts = [r for r in rows if r["method"] == "POST"]
    return {
        "requests": len(rows),
        "distinct_paths": len(paths),
        "reached_pages": len(reached),
        "payloads": payloads,
        "payloads_answered": answered,
        "posts": len(posts),
        "posts_answered": sum(1 for r in posts if r["status"] != 404),
        "improvised": sum(1 for r in rows if r["response_source"] in IMPROVISED),
        "dead_ends": sum(1 for r in rows if r["response_source"] in DEAD_END and r["status"] == 404
                         and r["path"] != "/favicon.ico"),
        "model_failures": sum(1 for r in rows if r["response_source"] == "fallback"),
    }


def _sum(items: list[dict]) -> dict:
    keys = ("requests", "distinct_paths", "reached_pages", "payloads", "payloads_answered", "posts", "posts_answered",
            "improvised", "dead_ends", "model_failures")
    out = {k: sum(i[k] for i in items) for k in keys}
    out["sessions"] = len(items)
    return out


def mode_stats(db_path: str, cap: int | None = None) -> dict:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT e.session_id, e.method, e.path, e.query, e.status, e.response_source, e.llm_ms, "
        "e.completion_tokens, s.user_agent FROM events e JOIN sessions s ON s.id = e.session_id").fetchall()
    con.close()
    by_session: dict[str, list] = defaultdict(list)
    for r in rows:
        by_session[r["session_id"]].append(r)
    per_session = []
    for sid, rs in by_session.items():
        prof = profile_of(rs[0]["user_agent"])
        if prof:
            per_session.append({"profile": prof, "run": run_of(rs[0]["user_agent"]), **_session_numbers(rs)})
    capped = sum(1 for s in per_session if cap and s["requests"] >= cap)
    per_profile = {p: _sum([s for s in per_session if s["profile"] == p]) for p, _ in PROFILES}
    runs = sorted({s["run"] for s in per_session})
    per_run = {r: _sum([s for s in per_session if s["run"] == r]) for r in runs}
    lat = sorted(r["llm_ms"] for r in rows if r["response_source"] == "generated" and r["llm_ms"])
    return {
        "totals": {**_sum(per_session), "capped_sessions": capped, "cap": cap},
        "per_profile": per_profile,
        "per_run": per_run,
        "generation": {
            "calls": len(lat),
            "median_ms": int(statistics.median(lat)) if lat else None,
            "p90_ms": lat[int(0.9 * (len(lat) - 1))] if lat else None,
            "completion_tokens": sum(r["completion_tokens"] or 0 for r in rows),
        },
    }


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "n/a"


def _ratio(a: float, b: float) -> str:
    return f"{a / b:.1f}x" if b else ("n/a" if not a else "inf")


def render_report(static: dict, mirage: dict) -> str:
    s, m = static["totals"], mirage["totals"]
    rows = [
        ("Attacker sessions", s["sessions"], m["sessions"], ""),
        ("Requests the attackers made", s["requests"], m["requests"], _ratio(m["requests"], s["requests"])),
        ("Distinct pages that returned content", s["reached_pages"], m["reached_pages"],
         _ratio(m["reached_pages"], s["reached_pages"])),
        ("Attack payloads sent / answered (not 404)", f"{s['payloads']} / {s['payloads_answered']}",
         f"{m['payloads']} / {m['payloads_answered']}", ""),
        ("Responses that were dead-end 404s", _pct(s["dead_ends"], s["requests"]),
         _pct(m["dead_ends"], m["requests"]), ""),
        ("Responses improvised by the model", _pct(s["improvised"], s["requests"]),
         _pct(m["improvised"], m["requests"]), ""),
        ("Login POSTs answered (not 404)", _pct(s["posts_answered"], s["posts"]),
         _pct(m["posts_answered"], m["posts"]), ""),
        ("Model failures (fell back to 404)", s["model_failures"], m["model_failures"], ""),
    ]
    w = max(len(r[0]) for r in rows)
    lines = [f"{'':<{w}}  {'static':>8}  {'mirage':>8}  {'ratio':>6}", "-" * (w + 28)]
    lines += [f"{a:<{w}}  {str(b):>8}  {str(c):>8}  {d:>6}" for a, b, c, d in rows]
    g = mirage["generation"]
    if g["calls"]:
        lines.append(f"\nMirage generation: {g['calls']} model calls, median {g['median_ms']} ms, "
                     f"p90 {g['p90_ms']} ms, {g['completion_tokens']} completion tokens")
    lines += ["", "Distinct pages that returned content, per attacker profile (static -> mirage):"]
    for p, _ in PROFILES:
        sp, mp = static["per_profile"][p], mirage["per_profile"][p]
        lines.append(f"  {p:<8} {sp['reached_pages']:>4} -> {mp['reached_pages']:<4}"
                     f"  payloads answered {sp['payloads_answered']}/{sp['payloads']} -> "
                     f"{mp['payloads_answered']}/{mp['payloads']}")
    lines += ["", "Per run (pages that returned content, static -> mirage):"]
    for r in sorted(set(static["per_run"]) | set(mirage["per_run"])):
        a = static["per_run"].get(r, {}).get("reached_pages", 0)
        b = mirage["per_run"].get(r, {}).get("reached_pages", 0)
        lines.append(f"  run {r}: {a} -> {b}")
    if m.get("cap"):
        lines += ["", f"Note: each attacker profile stops after {m['cap']} requests per run. Sessions that hit that cap: "
                      f"static {s.get('capped_sessions', 0)}, mirage {m.get('capped_sessions', 0)}. "
                      "For those sessions the counts above are lower bounds."]
    return "\n".join(lines)
