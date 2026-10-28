import asyncio
import json
import shutil
import subprocess
import textwrap
import time

import pytest
import yaml

from mirage.analyst import heuristic_finding, normalize_finding, run_analysis, session_features
from mirage.benign import benign_events
from mirage.config import Config
from mirage.db import Database
from mirage.enrich import cves_from_results
from mirage.llm import LLMResult
from mirage.persona import DEFAULT_PERSONA
from mirage.rules import (RuleError, matches, render_modsecurity, render_nginx, render_sigma,
                          spec_from_dict)

PERSONA = DEFAULT_PERSONA | {"persona_id": "t"}


def good_spec(**kw):
    d = {"title": "Sensitive file probe", "method": "GET", "technique": "T1595.002",
         "path_regex": r"\.(env|git/config|htpasswd)$|/\.git/", "rationale": "scanner probing secrets"}
    return spec_from_dict(d | kw)


def test_spec_validation_rejects_dangerous_rules():
    for bad in [{"path_regex": ".*"}, {"path_regex": "(a+)+"}, {"path_regex": 'a"b'}, {"method": "GET"},
                {"path_regex": r"$HOME"}, {"path_regex": "x" * 200}, {"path_regex": "("}, {"method": "TRACE", "path_regex": "a"}]:
        with pytest.raises(RuleError):
            spec_from_dict(bad)


def test_matching_semantics():
    s = good_spec()
    assert matches(s, {"method": "GET", "path": "/.env", "query": "", "body": "", "ua": "x"})
    assert not matches(s, {"method": "POST", "path": "/.env", "query": "", "body": "", "ua": "x"})
    q = spec_from_dict({"query_regex": r"\.\./"})
    # the query is URL-decoded before matching, so encoded traversal is caught too
    assert matches(q, {"method": "GET", "path": "/x", "query": "file=..%2F..%2Fetc", "body": "", "ua": ""})
    assert matches(q, {"method": "GET", "path": "/x", "query": "file=../../etc", "body": "", "ua": ""})
    b = spec_from_dict({"path_regex": "^/login$", "body_regex": "password=(admin|123456)$"})
    assert matches(b, {"method": "POST", "path": "/login", "query": "", "body": "username=a&password=123456", "ua": ""})


def test_benign_corpus_has_tricky_cases():
    evs = benign_events(PERSONA)
    assert len(evs) > 30
    assert any("O%27Brien" in e["query"] for e in evs)
    assert any(e["method"] == "POST" for e in evs)


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_rules_pass_nginx_t(tmp_path):
    specs = [good_spec(),
             spec_from_dict({"title": "Traversal", "path_regex": r"\.\./|%2e%2e", "query_regex": r"(\.\./|/etc/passwd)"}),
             spec_from_dict({"title": "Scanner UA", "ua_regex": "(nikto|sqlmap|gobuster)", "method": "GET"}),
             spec_from_dict({"title": "Backslash", "path_regex": r"\\\\admin"})]
    snippet = "\n".join(render_nginx(s) for s in specs)
    conf = tmp_path / "nginx.conf"
    conf.write_text(textwrap.dedent(f"""
        pid {tmp_path}/n.pid; error_log {tmp_path}/e.log;
        events {{}}
        http {{
          access_log off;
          client_body_temp_path {tmp_path}/b; proxy_temp_path {tmp_path}/p; fastcgi_temp_path {tmp_path}/f;
          uwsgi_temp_path {tmp_path}/u; scgi_temp_path {tmp_path}/s;
          server {{
            listen 127.0.0.1:18999;
            {snippet}
            location / {{ return 200 ok; }}
          }}
        }}
    """))
    r = subprocess.run(["nginx", "-t", "-c", str(conf)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_rule_behaves_like_replay(tmp_path):
    """Run a real nginx with the rule and compare its decisions with our matcher."""
    import urllib.request, urllib.error
    spec = spec_from_dict({"title": "dotfiles", "method": "GET", "path_regex": r"/\.(env|git)(/|$)"})
    conf = tmp_path / "nginx.conf"
    conf.write_text(textwrap.dedent(f"""
        pid {tmp_path}/n.pid; error_log {tmp_path}/e.log; daemon on;
        events {{}}
        http {{
          access_log off;
          client_body_temp_path {tmp_path}/b; proxy_temp_path {tmp_path}/p; fastcgi_temp_path {tmp_path}/f;
          uwsgi_temp_path {tmp_path}/u; scgi_temp_path {tmp_path}/s;
          server {{ listen 127.0.0.1:18998;
            {render_nginx(spec)}
            location / {{ return 200 ok; }} }}
        }}
    """))
    subprocess.run(["nginx", "-c", str(conf)], check=True)
    try:
        time.sleep(0.5)
        for path in ["/.env", "/.git/config", "/index.html", "/env", "/a/.envx", "/track"]:
            try:
                code = urllib.request.urlopen(f"http://127.0.0.1:18998{path}").status
            except urllib.error.HTTPError as e:
                code = e.code
            assert (code == 403) == matches(spec, {"method": "GET", "path": path, "query": "", "body": "", "ua": ""}), path
    finally:
        subprocess.run(["nginx", "-c", str(conf), "-s", "stop"])


def test_sigma_is_valid_yaml_and_modsec_shape():
    s = good_spec(query_regex=r"(\.\./)", ua_regex="nikto")
    doc = yaml.safe_load(render_sigma(s))
    assert doc["logsource"]["category"] == "webserver"
    assert doc["detection"]["selection"]["cs-method"] == "GET"
    assert doc["tags"] == ["attack.t1595.002"]
    ms = render_modsecurity(s).splitlines()
    assert ms[1].startswith("SecRule REQUEST_METHOD") and ms[1].endswith('chain"')
    assert ms[-1].strip().endswith('"t:none"')


def test_cve_extraction_and_normalisation():
    res = [{"title": "Apache 2.4.41 issues CVE-2021-41773", "content": "also cve-2021-42013 and CVE-2021-41773", "url": "http://x"}]
    got = cves_from_results(res, "q")
    assert sorted(c["id"] for c in got) == ["CVE-2021-41773", "CVE-2021-42013"]
    fb = heuristic_finding({"login_posts": 0, "indicator_counts": {}, "distinct_paths": 1, "scanner_user_agent": False})
    n = normalize_finding({"intent": "bogus", "confidence": "high", "techniques": [{"id": "T9999"}, {"id": "T1190"}],
                           "search_queries": ["a", "b", "c"]}, fb)
    assert n["intent"] == "benign_browsing" and n["confidence"] == 0.5 and len(n["techniques"]) == 1
    assert len(n["search_queries"]) == 2


# ---------- end to end with a scripted model ----------

class ScriptedLLM:
    enabled = True

    def __init__(self):
        self.cfg = Config(api_key="x")
        self.rule_calls = 0

    async def complete(self, tier, system, user, **kw):
        if "SOC analyst" in system:
            if "Nikto" in user:
                d = {"intent": "vuln_scanning", "malicious": True, "severity": "medium", "confidence": 0.9,
                     "techniques": [{"id": "T1595.002"}], "summary": "Nikto-style scan.", "indicators": ["GET /.env"],
                     "search_queries": ["Apache 2.4.41 path traversal CVE"]}
            elif "python-requests" in user:
                d = {"intent": "credential_attack", "malicious": True, "severity": "high", "confidence": 0.85,
                     "techniques": [{"id": "T1110.001"}], "summary": "Password guessing on /login.", "indicators": []}
            else:
                d = {"intent": "benign_browsing", "malicious": False, "confidence": 0.9, "summary": "Normal user."}
            return LLMResult(json.dumps(d), "fake-ultra", 5)
        self.rule_calls += 1
        if "<feedback>" in user:  # revision: tighten the over-broad rule
            rules = [{"title": "Sensitive file probe", "technique": "T1595.002",
                      "path_regex": r"/\.(env|git)(/|$)|/(phpmyadmin|backup\.zip)", "rationale": "probes for secrets"}]
        elif "<group>vuln_scanning" in user:
            rules = [{"title": "Quote in query", "query_regex": "'", "rationale": "too broad on purpose"}]
        else:
            rules = [{"title": "Weak password guess", "method": "POST", "path_regex": "^/login$",
                      "body_regex": "password=(admin|123456|password|toor)(&|$)", "technique": "T1110.001",
                      "rationale": "common weak passwords"}]
        return LLMResult(json.dumps({"rules": rules}), "fake-ultra", 5)


def seed(db):
    def sess(sid, ua, reqs):
        now = time.time()
        db.touch_session(sid, "t", "mirage", "10.0.0.5", ua)
        for m, p, q, b in reqs:
            db.touch_session(sid, "t", "mirage", "10.0.0.5", ua)
            db.log_event(request_id=sid + p, session_id=sid, persona_id="t", mode="mirage", ts=now, src_ip="10.0.0.5",
                         method=m, path=p, query=q, headers_json=json.dumps({"user-agent": ua}), body=b,
                         body_truncated=0, status=200, content_type="text/html", response_bytes=10,
                         response_source="generated", latency_ms=5)
    sess("a" * 32, "Mozilla/5.00 (Nikto/2.5.0)", [("GET", "/.env", "", ""), ("GET", "/.git/config", "", ""),
         ("GET", "/phpmyadmin/", "", ""), ("GET", "/backup.zip", "", ""), ("GET", "/x", "id=1'", "")])
    sess("b" * 32, "python-requests/2.31.0", [("GET", "/login", "", "")] +
         [("POST", "/login", "", f"username=admin&password={p}") for p in ("admin", "123456", "password", "toor")])
    sess("c" * 32, "Mozilla/5.0 Chrome/124", [("GET", "/", "", ""), ("GET", "/track", "id=BW-1", ""), ("GET", "/about", "", "")])


def test_end_to_end_verify_and_revise():
    db = Database(":memory:")
    seed(db)
    llm = ScriptedLLM()
    out = []

    async def fake_search(q):
        return [{"title": "CVE-2021-41773 Apache path traversal", "content": "", "url": "http://nvd"}]

    res = asyncio.run(run_analysis(db, llm, PERSONA, search_fn=fake_search, progress=out.append))
    by_intent = {f["intent"] for f in res["findings"]}
    assert by_intent == {"vuln_scanning", "credential_attack", "benign_browsing"}
    assert "CVE-2021-41773" in res["cves"]
    rules = {(r["title"], r["kind"]): r for r in res["rules"]}
    probe = rules[("Sensitive file probe", "nginx")]
    assert probe["status"] == "verified" and probe["fp"] == 0 and probe["attempts"] >= 2  # revised once
    assert ("Quote in query", "nginx") not in rules  # replaced by the revision
    weak = rules[("Weak password guess", "modsecurity")]
    assert weak["status"] == "verified" and weak["tp"] >= 3
    assert db._one("SELECT COUNT(*) c FROM proposed_rules WHERE status='verified'")["c"] == 6  # 2 specs x 3 kinds
    assert db._one("SELECT COUNT(*) c FROM findings")["c"] == 3
    assert json.loads(db._one("SELECT cves_json c FROM findings WHERE intent='vuln_scanning'")["c"])[0]["id"].startswith("CVE-")


def test_benign_baseline_catches_overbroad_file_rule():
    # the rule the model proposed in the first real run would have blocked legitimate .zip downloads
    s = spec_from_dict({"path_regex": r"\.(env|git/config|sql|zip)$"})
    hits = [e["path"] for e in benign_events(PERSONA) if matches(s, e)]
    assert "/downloads/annual-report-2025.zip" in hits


class DupLLM(ScriptedLLM):
    async def complete(self, tier, system, user, **kw):
        if "SOC analyst" in system:
            return await super().complete(tier, system, user, **kw)
        r = {"ua_regex": "nikto", "rationale": "a", "title": "Nikto UA"}
        rules = [r, r | {"title": "Nikto scanner", "rationale": "different wording"}]
        return LLMResult(json.dumps({"rules": rules}), "fake", 5)


def test_duplicate_rules_dropped_and_ua_only_flagged():
    db = Database(":memory:")
    seed(db)
    res = asyncio.run(run_analysis(db, DupLLM(), PERSONA, progress=lambda s: None))
    ver = [r for r in res["rules"] if r["kind"] == "nginx" and r["status"] == "verified"]
    assert len(ver) == 1 and ver[0]["brittle"] is True


def test_sigma_never_broader_than_verified_rule():
    s = spec_from_dict({"title": "pw", "method": "POST", "path_regex": "^/login$", "body_regex": "password=admin"})
    out = render_sigma(s)
    assert yaml.safe_load(out) is None and "ModSecurity" in out  # comment only, no selection that matches every login


class TechLLM(ScriptedLLM):
    async def complete(self, tier, system, user, **kw):
        if "SOC analyst" in system:
            return await super().complete(tier, system, user, **kw)
        rule = {"title": "Dotfiles", "technique": "T1083", "path_regex": r"/\.(env|git)(/|$)"}
        return LLMResult(json.dumps({"rules": [rule]}), "fake", 5)


def test_rule_technique_is_checked_against_allowed_list():
    db = Database(":memory:")
    seed(db)
    res = asyncio.run(run_analysis(db, TechLLM(), PERSONA, progress=lambda s: None))
    from mirage.analyst import TECHNIQUES
    specs = [json.loads(r["spec_json"]) for r in db._all("SELECT spec_json FROM proposed_rules WHERE status='verified'")]
    assert specs and all(sp["technique"] in TECHNIQUES for sp in specs)
