"""Read-only dashboard: sessions, findings, verified rules and the static-vs-Mirage comparison.

Security: every value read from the database is attacker-controlled text. It is HTML-escaped, the pages use no
JavaScript, and a strict Content-Security-Policy blocks scripts even if escaping were ever missed.
Bind to localhost only.
"""
from __future__ import annotations

import html
import json
import pathlib
import re
import sqlite3
from collections import Counter, defaultdict

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

from .compare import render_report

CSP = ("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")
SID_RE = re.compile(r"^[0-9a-f]{32}$")
SOURCE_ORDER = ["cache", "generated", "coalesced", "offsurface", "static", "fallback", "budget"]
CSS = """
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1c2330;--card:#fff;--line:#d9dde4;--mut:#667085;--acc:#2457d6;--bad:#c0392b;--ok:#1e8e4e}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6e9ef;--card:#181e28;--line:#2a3342;--mut:#98a2b3;--acc:#7aa2ff;--bad:#ff7b6b;--ok:#4cd08a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:20px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.sub{color:var(--mut);margin-bottom:16px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card b{display:block;font-size:22px}
.card span{color:var(--mut);font-size:12px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}th{font-size:12px;color:var(--mut);font-weight:600}
.wrap{overflow-x:auto}a{color:var(--acc)}.tag{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:12px}
.bad{color:var(--bad);border-color:var(--bad)}.ok{color:var(--ok);border-color:var(--ok)}.mut{color:var(--mut)}
.bar{display:flex;height:22px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}.bar div{height:100%}
.legend span{margin-right:14px;font-size:12px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;white-space:pre-wrap;margin:6px 0}
details{margin:4px 0}summary{cursor:pointer;color:var(--acc)}.rule{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:10px}
"""
COLORS = {"cache": "#6c8cd5", "generated": "#2e9e6b", "coalesced": "#7fc8a9", "offsurface": "#b8bfcc",
          "static": "#9aa3b2", "fallback": "#d9534f", "budget": "#e6a23c"}


def e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def mask_ip(ip: str | None, on: bool) -> str:
    if not on or not ip:
        return e(ip)
    parts = ip.split(".")
    return e(".".join(parts[:2]) + ".x.x") if len(parts) == 4 else e(ip[:4] + "…")


def page(title: str, body: str, refresh: int | None = None) -> HTMLResponse:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(title)}</title>{meta}'
           f'<meta name="viewport" content="width=device-width,initial-scale=1"><style>{CSS}</style></head>'
           f"<body><main>{body}</main></body></html>")
    return HTMLResponse(doc, headers={"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                                      "Referrer-Policy": "no-referrer"})


def _rows(con, sql, params=()):
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _card(label: str, value) -> str:
    return f'<div class="card"><b>{e(value)}</b><span>{e(label)}</span></div>'


def _pct(n, d) -> str:
    return f"{100 * n / d:.0f}%" if d else "0%"


def _load_json(text: str | None, default):
    try:
        return json.loads(text) if text else default
    except json.JSONDecodeError:
        return default


def create_dashboard(db_path: str, ab_path: str = "ab_results.json", mask_ips: bool = False) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def connect() -> sqlite3.Connection:
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only = ON")
        return con

    @app.get("/", response_class=HTMLResponse)
    def home():
        con = connect()
        try:
            persona = _rows(con, "SELECT spec_json FROM personas WHERE active = 1 LIMIT 1")
            company = _load_json(persona[0]["spec_json"], {}).get("company", "unknown") if persona else "no persona yet"
            ev = con.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            sessions = con.execute("SELECT COUNT(*) n FROM sessions").fetchone()["n"]
            src = Counter({r[0]: r[1] for r in con.execute("SELECT response_source, COUNT(*) FROM events GROUP BY 1")})
            gen = con.execute("SELECT COUNT(*) n, AVG(llm_ms) a, SUM(prompt_tokens) p, SUM(completion_tokens) c "
                              "FROM events WHERE response_source = 'generated'").fetchone()
            body = [f"<h1>Mirage dashboard</h1><div class='sub'>Honeypot persona: <b>{e(company)}</b> &middot; "
                    f"database: {e(pathlib.Path(db_path).name)} &middot; read-only</div>"]
            body.append("<div class='cards'>" + _card("sessions", sessions) + _card("requests logged", ev) +
                        _card("answered from cache", _pct(src["cache"], ev)) +
                        _card("generated live", f"{gen['n']}") +
                        _card("avg generation time", f"{(gen['a'] or 0) / 1000:.1f}s") +
                        _card("model tokens (in/out)", f"{gen['p'] or 0}/{gen['c'] or 0}") + "</div>")
            if ev:
                bar = "".join(f"<div title='{e(k)}: {src[k]}' style='width:{100 * src[k] / ev:.2f}%;background:{COLORS.get(k, '#999')}'></div>"
                              for k in SOURCE_ORDER if src[k])
                legend = "".join(f"<span><i class='sw' style='background:{COLORS.get(k, '#999')}'></i>{e(k)} {src[k]}</span>"
                                 for k in SOURCE_ORDER if src[k])
                body.append(f"<h2>How requests were answered</h2><div class='bar'>{bar}</div><div class='legend'>{legend}</div>")

            run = _rows(con, "SELECT id, finished_at, notes FROM analysis_runs ORDER BY id DESC LIMIT 1")
            run_id = run[0]["id"] if run else None
            findings = _rows(con, "SELECT * FROM findings WHERE run_id = ? ORDER BY id", (run_id,)) if run_id else []
            by_sid = {f["session_id"]: f for f in findings}

            srows = _rows(con, "SELECT * FROM session_stats ORDER BY last_seen DESC LIMIT 60")
            body.append("<h2>Sessions</h2><div class='wrap'><table><tr><th>Session</th><th>Visitor (user agent)</th><th>Source</th>"
                        "<th>Requests</th><th>Pages</th><th>Generated</th><th>Analyst label</th></tr>")
            for s in srows:
                f = by_sid.get(s["session_id"])
                ev_j = _load_json(f["evidence_json"], {}) if f else {}
                label = "<span class='mut'>not analysed</span>"
                if f:
                    cls = "bad" if ev_j.get("malicious") else "ok"
                    label = f"<span class='tag {cls}'>{e(f['intent'])}</span>"
                body.append(f"<tr><td><a href='/session/{e(s['session_id'])}'>{e(s['session_id'][:8])}</a></td>"
                            f"<td>{e((s['user_agent'] or '')[:70])}</td><td>{mask_ip(s['src_ip'], mask_ips)}</td>"
                            f"<td>{s['request_count']}</td><td>{s['distinct_paths']}</td><td>{s['llm_calls']}</td><td>{label}</td></tr>")
            body.append("</table></div>")

            body.append(f"<h2>Analyst findings{' (run ' + str(run_id) + ')' if run_id else ''}</h2>")
            if not findings:
                body.append("<p class='mut'>No analysis yet. Run <code>python scripts/analyze.py</code>.</p>")
            else:
                body.append("<div class='wrap'><table><tr><th>Session</th><th>Intent</th><th>ATT&amp;CK</th><th>Confidence</th>"
                            "<th>Summary</th><th>CVE mentions (Tavily)</th></tr>")
                for f in findings:
                    ev_j = _load_json(f["evidence_json"], {})
                    cves = _load_json(f["cves_json"], [])
                    ids = sorted({c.get("id", "") for c in cves if isinstance(c, dict)})
                    cls = "bad" if ev_j.get("malicious") else "ok"
                    body.append(f"<tr><td><a href='/session/{e(f['session_id'])}'>{e(f['session_id'][:8])}</a></td>"
                                f"<td><span class='tag {cls}'>{e(f['intent'])}</span><br><span class='mut'>{e(ev_j.get('severity', ''))}</span></td>"
                                f"<td>{e(f['attack_technique'])}</td><td>{(f['confidence'] or 0) * 100:.0f}%</td>"
                                f"<td>{e(f['summary'])}</td><td>{e(', '.join(ids[:6]) or '-')}</td></tr>")
                body.append("</table></div>")

            body.append("<h2>Detection rules (replay-verified)</h2>")
            rules = _rows(con, "SELECT * FROM proposed_rules WHERE run_id = ? ORDER BY id", (run_id,)) if run_id else []
            grouped: dict[str, list] = defaultdict(list)
            for r in rules:
                grouped[r["title"] or "rule"].append(r)
            verified = {t: rs for t, rs in grouped.items() if rs[0]["status"] == "verified"}
            rejected = len(grouped) - len(verified)
            if not verified:
                body.append("<p class='mut'>No verified rules yet.</p>")
            for title, rs in verified.items():
                r0 = rs[0]
                body.append(f"<div class='rule'><b>{e(title)}</b> <span class='tag ok'>verified</span> "
                            f"<span class='mut'>caught {r0['true_pos']} attack requests, {r0['false_pos']} false positives "
                            f"out of {r0['replay_total']} replayed requests</span>")
                for r in rs:
                    body.append(f"<details><summary>{e(r['kind'])}</summary><pre>{e(r['rule_text'])}</pre></details>")
                body.append("</div>")
            if rejected:
                body.append(f"<p class='mut'>{rejected} proposed rule(s) were rejected by the replay check.</p>")

            body.append("<h2>Static baseline vs Mirage</h2>")
            ab = pathlib.Path(ab_path)
            if ab.exists():
                data = _load_json(ab.read_text(), None)
                if isinstance(data, dict) and "static" in data and "mirage" in data:
                    try:
                        body.append(f"<pre>{e(render_report(data['static'], data['mirage']))}</pre>")
                    except Exception:  # malformed results file
                        body.append("<p class='mut'>ab_results.json could not be read.</p>")
                else:
                    body.append("<p class='mut'>ab_results.json could not be read.</p>")
            else:
                body.append("<p class='mut'>Run <code>python scripts/ab_run.py --runs 3</code> to produce the comparison.</p>")
            return page("Mirage dashboard", "".join(body), refresh=30)
        finally:
            con.close()

    @app.get("/session/{sid}", response_class=HTMLResponse)
    def session(sid: str):
        if not SID_RE.match(sid):
            return PlainTextResponse("not found", status_code=404)
        con = connect()
        try:
            s = _rows(con, "SELECT * FROM session_stats WHERE session_id = ?", (sid,))
            if not s:
                return PlainTextResponse("not found", status_code=404)
            s = s[0]
            evs = _rows(con, "SELECT * FROM events WHERE session_id = ? ORDER BY id LIMIT 500", (sid,))
            t0 = evs[0]["ts"] if evs else 0
            f = _rows(con, "SELECT * FROM findings WHERE session_id = ? ORDER BY id DESC LIMIT 1", (sid,))
            body = [f"<p><a href='/'>&larr; back</a></p><h1>Session {e(sid[:8])}</h1>",
                    f"<div class='sub'>{e(s['user_agent'])} &middot; {mask_ip(s['src_ip'], mask_ips)} &middot; "
                    f"{s['request_count']} requests &middot; {s['distinct_paths']} distinct pages &middot; mode {e(s['mode'])}</div>"]
            if f:
                body.append(f"<div class='rule'><b>{e(f[0]['intent'])}</b> <span class='mut'>{e(f[0]['attack_technique'])}</span>"
                            f"<br>{e(f[0]['summary'])}</div>")
            body.append("<div class='wrap'><table><tr><th>+time</th><th>Request</th><th>Status</th><th>Answered by</th>"
                        "<th>Model ms</th><th>Body sent by visitor</th></tr>")
            for r in evs:
                q = f"?{r['query']}" if r["query"] else ""
                body.append(f"<tr><td>+{r['ts'] - t0:.1f}s</td><td>{e(r['method'])} {e((r['path'] or '') + q)[:200]}</td>"
                            f"<td>{e(r['status'])}</td><td>{e(r['response_source'])}</td><td>{e(r['llm_ms'] or '')}</td>"
                            f"<td>{e((r['body'] or '')[:160])}</td></tr>")
            body.append("</table></div>")
            return page(f"Session {sid[:8]}", "".join(body))
        finally:
            con.close()

    return app
