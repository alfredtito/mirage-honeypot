from mirage.compare import mode_stats, profile_of, render_report, run_of
from mirage.db import Database


def fill(path, rows):
    db = Database(str(path))
    ua = "Mozilla/5.00 (Nikto/2.5.0) r1"
    for i, (m, p, q, status, src) in enumerate(rows):
        db.touch_session("s" * 32, "t", "mirage", "1.1.1.1", ua)
        db.log_event(request_id=str(i), session_id="s" * 32, persona_id="t", mode="x", ts=1.0, method=m, path=p,
                     query=q, body_truncated=0, status=status, response_source=src, llm_ms=40 if src == "generated" else None,
                     completion_tokens=7 if src == "generated" else None)
    db.close()


def test_profiles_and_runs():
    assert profile_of("Mozilla/5.00 (Nikto/2.5.0) r2") == "scanner"
    assert profile_of("python-requests/2.31.0 r1") == "brute"
    assert profile_of("Mozilla/5.0 (X11) Chrome/124 r3") == "crawler"
    assert profile_of("curl/8") is None and run_of("x r12") == 12 and run_of("x") == 0


def test_stats_and_report(tmp_path):
    fill(tmp_path / "s.db", [("GET", "/admin", "", 200, "cache"), ("GET", "/.env", "", 404, "static"),
                             ("GET", "/admin", "id=1'", 404, "static"), ("POST", "/login", "", 404, "static"),
                             ("GET", "/favicon.ico", "", 404, "static")])
    fill(tmp_path / "m.db", [("GET", "/admin", "", 200, "cache"), ("GET", "/.env", "", 200, "generated"),
                             ("GET", "/admin", "id=1'", 403, "generated"), ("POST", "/login", "", 401, "generated"),
                             ("GET", "/staff", "", 200, "generated"), ("GET", "/x", "", 404, "fallback")])
    s, m = mode_stats(str(tmp_path / "s.db"), cap=5), mode_stats(str(tmp_path / "m.db"), cap=5)
    assert s["totals"]["reached_pages"] == 1 and m["totals"]["reached_pages"] == 3
    assert (s["totals"]["payloads"], s["totals"]["payloads_answered"]) == (1, 0)
    assert (m["totals"]["payloads"], m["totals"]["payloads_answered"]) == (1, 1)
    assert s["totals"]["posts_answered"] == 0 and m["totals"]["posts_answered"] == 1
    assert m["totals"]["model_failures"] == 1 and m["totals"]["capped_sessions"] == 1
    assert m["generation"]["calls"] == 4 and m["generation"]["median_ms"] == 40
    assert 1 in m["per_run"]
    text = render_report(s, m)
    assert "Distinct pages that returned content" in text and "lower bounds" in text
