import os
import subprocess
import sys

from fastapi.testclient import TestClient

from mirage.config import Config
from mirage.db import Database
from mirage.honeypot import create_app
from mirage.linking import link_record_rows, looks_like_id, record_prefix
from mirage.llm import LLMResult
from mirage.persona import DEFAULT_PERSONA, normalize_persona

P = normalize_persona({"known_paths": ["/", "/shipments", "/customers", "/dashboard"],
                       "url_patterns": ["/shipments/{tracking_number}", "/customers/{customer_id}"]}) | {"persona_id": "pid"}
TABLE = """<table><tr><th>ID</th><th>Status</th></tr>
<tr><td>TRK-48213</td><td>In transit</td><td>2026-10-27</td></tr>
<tr><td>1</td><td>INV-2026-0015</td><td>$1,250</td></tr>
<tr><td>Truck 12</td><td>12:30</td></tr>
<tr><td><a href="/x">TRK-9</a></td><td>done</td></tr></table>"""


def test_id_detection():
    for ok in ("TRK-48213", "INV-2026-0015", "10042", "D-204", "CUST_1042"):
        assert looks_like_id(ok), ok
    for bad in ("2026-10-27", "Truck 12", "12:30", "$1,250", "98%", "1", "Pro Number", "In Transit", "John Smith"):
        assert not looks_like_id(bad), bad


def test_prefix_only_for_list_pages_of_a_section():
    assert record_prefix(P, "/shipments") == "/shipments/" and record_prefix(P, "/SHIPMENTS/") == "/shipments/"
    assert record_prefix(P, "/shipments/active") is None  # fits the record pattern, so it is ambiguous: left alone
    assert record_prefix(P, "/shipments/TRK-48213") is None   # a record page itself
    assert record_prefix(P, "/dashboard") is None and record_prefix(P, "/") is None


def test_rows_are_linked_once_and_safely():
    out, n = link_record_rows(P, "/shipments", TABLE)
    assert n == 2
    assert '<td><a href="/shipments/TRK-48213">TRK-48213</a></td>' in out
    assert '<a href="/shipments/INV-2026-0015">INV-2026-0015</a>' in out      # id in the second column
    assert "2026-10-27</td>" in out and "<td>Truck 12</td>" in out and "$1,250</td>" in out
    assert 'href="/x">TRK-9</a>' in out                                        # existing links untouched
    again, n2 = link_record_rows(P, "/shipments", out)
    assert n2 == 0 and again == out                                            # idempotent
    assert link_record_rows(P, "/dashboard", TABLE) == (TABLE, 0)
    assert link_record_rows(P, "/shipments", "<p>no table 12345</p>")[1] == 0


class TableLLM:
    enabled = True

    async def complete(self, tier, system, user, **kw):
        from mirage.llm import LLMError
        if tier == "smart":
            raise LLMError("no")
        body = "<html><body><table><tr><td>TRK-48213</td><td>ok</td></tr></table></body></html>"
        return LLMResult("STATUS: 200\n\n" + body, "fake", 5, 1, 1)


def test_generated_pages_get_linked_and_cached_that_way():
    db = Database(":memory:")
    with TestClient(create_app(Config(api_key="x"), llm=TableLLM(), db=db)) as c:
        r = c.get("/track")  # DEFAULT_PERSONA: /track is a page, /track/{tracking_no} a record pattern
        assert 'href="/track/TRK-48213"' in r.text
        assert 'href="/track/TRK-48213"' in c.get("/track").text   # served from cache, still linked


def test_relink_script_updates_existing_pages(tmp_path):
    path = tmp_path / "t.db"
    db = Database(str(path))
    spec = {k: v for k, v in P.items() if k != "persona_id"}
    db.save_persona("pid", spec)
    db.put_artifact("pid", "GET /shipments", 200, "text/html", TABLE)
    db.put_artifact("pid", "GET /customers", 200, "text/html", "<p>nothing</p>")
    db.close()
    env = {**os.environ, "DB_PATH": str(path)}
    out = subprocess.run([sys.executable, "scripts/relink_pages.py", "--dry-run"], env=env, capture_output=True, text=True)
    assert "would link 2 record ids on 1 pages" in out.stdout, out.stdout + out.stderr
    assert 'href="/shipments/' not in Database(str(path)).get_artifact("pid", "GET /shipments")["body"]
    out = subprocess.run([sys.executable, "scripts/relink_pages.py"], env=env, capture_output=True, text=True)
    assert "linked 2 record ids on 1 pages" in out.stdout
    assert 'href="/shipments/TRK-48213"' in Database(str(path)).get_artifact("pid", "GET /shipments")["body"]
