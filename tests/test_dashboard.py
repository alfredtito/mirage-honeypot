import json
import time

from fastapi.testclient import TestClient

from mirage.analyst import _ensure_schema
from mirage.dashboard import create_dashboard, mask_ip
from mirage.db import Database

XSS = "<script>alert(1)</script>"
IMG = '"><img src=x onerror=alert(2)>'
SID = "a" * 32


def seed(path):
    db = Database(str(path))
    db.save_persona("p1", {"company": f"Acme {XSS}"})
    now = time.time()
    for i, (m, p, q, body, st, src) in enumerate([
        ("GET", "/" + XSS, "id=1'" + IMG, "", 404, "offsurface"),
        ("POST", "/login", "", f"username={XSS}&password=x", 200, "generated"),
        ("GET", "/admin", "", "", 200, "cache"),
    ]):
        db.touch_session(SID, "p1", "mirage", "10.20.30.40", "Nikto " + IMG)
        db.log_event(request_id=str(i), session_id=SID, persona_id="p1", mode="mirage", ts=now + i, src_ip="10.20.30.40",
                     method=m, path=p, query=q, body=body, body_truncated=0, status=st, response_source=src,
                     llm_ms=1200 if src == "generated" else None, prompt_tokens=10, completion_tokens=5)
    _ensure_schema(db)
    db._run("INSERT INTO analysis_runs (id, started_at, finished_at, notes) VALUES (1, 1, 2, '{}')")
    db._run("INSERT INTO findings (run_id, session_id, intent, attack_technique, confidence, summary, evidence_json, cves_json, created_at) "
            "VALUES (1, ?, 'vuln_scanning', 'T1595.002', 0.9, ?, ?, ?, 1)",
            (SID, f"Scanner {XSS}", json.dumps({"malicious": True, "severity": "high"}),
             json.dumps([{"id": "CVE-2021-41773", "source": "http://x"}])))
    for kind in ("nginx", "modsecurity", "sigma"):
        db._run("INSERT INTO proposed_rules (run_id, finding_id, kind, rule_text, replay_total, true_pos, false_pos, status, "
                "created_at, spec_json, title) VALUES (1, 1, ?, ?, 148, 9, 0, 'verified', 1, '{}', ?)",
                (kind, f"# rule {XSS}", "Sensitive file probe"))
    db._run("INSERT INTO proposed_rules (run_id, kind, rule_text, replay_total, true_pos, false_pos, status, created_at, spec_json, title) "
            "VALUES (1, 'nginx', 'x', 148, 3, 2, 'rejected', 1, '{}', 'Bad rule')")
    db.close()


def client(tmp_path, ab=None):
    if not (tmp_path / "t.db").exists():
        seed(tmp_path / "t.db")
    return TestClient(create_dashboard(str(tmp_path / "t.db"), str(ab or tmp_path / "none.json")))


def test_home_renders_everything_and_escapes_attacker_text(tmp_path):
    c = client(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    html = r.text
    for needle in ("Mirage dashboard", "Sensitive file probe", "verified", "CVE-2021-41773", "vuln_scanning",
                   "T1595.002", "1 proposed rule(s) were rejected", "How requests were answered"):
        assert needle in html, needle
    assert XSS not in html and IMG not in html            # nothing hostile arrives unescaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script" not in html.lower().replace("&lt;script", "")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp and "unsafe-eval" not in csp


def test_session_page_escapes_and_validates_id(tmp_path):
    c = client(tmp_path)
    r = c.get(f"/session/{SID}")
    assert r.status_code == 200 and XSS not in r.text and IMG not in r.text
    assert "&lt;script&gt;" in r.text and "POST /login" in r.text and "+2.0s" in r.text
    assert c.get("/session/nothex").status_code == 404
    assert c.get("/session/" + "b" * 32).status_code == 404
    assert c.get("/session/..%2f..%2fetc%2fpasswd").status_code == 404


def test_ab_section_and_ip_masking(tmp_path):
    from mirage.compare import mode_stats
    seed(tmp_path / "s.db")
    data = {"static": mode_stats(str(tmp_path / "s.db"), 40), "mirage": mode_stats(str(tmp_path / "s.db"), 40)}
    ab = tmp_path / "ab.json"
    ab.write_text(json.dumps(data, default=str))
    assert "Distinct pages that returned content" in client(tmp_path, ab).get("/").text
    ab.write_text("not json")
    assert "could not be read" in client(tmp_path, ab).get("/").text
    assert mask_ip("10.20.30.40", True) == "10.20.x.x" and mask_ip("10.20.30.40", False) == "10.20.30.40"
    assert "10.20.30.40" not in TestClient(create_dashboard(str(tmp_path / "t.db"), mask_ips=True)).get("/").text
