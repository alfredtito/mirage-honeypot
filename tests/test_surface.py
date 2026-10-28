import asyncio
import json

from fastapi.testclient import TestClient

from mirage.config import Config
from mirage.db import Database
from mirage.engine import build_user_prompt
from mirage.honeypot import create_app
from mirage.llm import LLMError, LLMResult
from mirage.persona import (DEFAULT_PERSONA, design_lures, normalize_persona, on_surface, persona_brief,
                            surface_sets)

PERSONA = DEFAULT_PERSONA | {"persona_id": "t"}


class FakeLLM:
    enabled = True

    def __init__(self, lure_json=None):
        self.calls, self.lure_json = [], lure_json

    async def complete(self, tier, system, user, **kw):
        self.calls.append(tier)
        if tier == "smart":
            if self.lure_json is None:
                raise LLMError("no")
            return LLMResult(self.lure_json, "fake", 1)
        return LLMResult("STATUS: 200\n\n<html>page</html>", "fake-nano", 5, 1, 1)


def test_normalize_lures_filters_and_defaults():
    spec = normalize_persona({"known_paths": ["/", "/shop"], "lure_paths": ["/.env", "/shop", "bad", "/has space", "/backup/"]})
    assert spec["lure_paths"] == ["/.env", "/backup/"]
    assert normalize_persona({})["lure_paths"] == DEFAULT_PERSONA["lure_paths"]
    assert "Other existing pages" in persona_brief(PERSONA)
    assert "Other existing pages" not in persona_brief({k: v for k, v in PERSONA.items() if k != "lure_paths"})


def test_on_surface_rules():
    exact, sections = surface_sets(PERSONA)
    yes = ["/", "/admin", "/admin/", "/admin/users/7", "/ADMIN/x", "/track/BW-123", "/api/v1/users", "/.env", "/admin?id=1"]
    no = ["/wp-login.php", "/phpmyadmin/", "/server-status", "/cgi-bin/", "/robots.txt/x", "/xmlrpc.php", "/console"]
    assert all(on_surface(exact, sections, p) for p in yes), [p for p in yes if not on_surface(exact, sections, p)]
    assert not any(on_surface(exact, sections, p) for p in no), [p for p in no if on_surface(exact, sections, p)]


def test_off_surface_requests_cost_nothing():
    llm = FakeLLM()
    db = Database(":memory:")
    with TestClient(create_app(Config(api_key="x"), llm=llm, db=db)) as c:
        r = c.get("/wp-login.php")
        assert r.status_code == 404 and "Not Found" in r.text
        c.get("/admin/reports/2026")  # on a real section: generated
    assert [r["response_source"] for r in db._all("SELECT response_source FROM events ORDER BY id")] == ["offsurface", "generated"]
    assert llm.calls.count("fast") == 1


def test_prompt_marks_lure_pages_as_existing():
    p = build_user_prompt(PERSONA, [], "GET", "/.env", "", {}, "")
    assert "<note>" in p
    assert "<note>" not in build_user_prompt(PERSONA, [], "GET", "/zzz", "", {}, "")


def test_design_lures_sanitises_and_falls_back():
    good = json.dumps({"lure_paths": ["/backup/", "/.env", "/server-status", "/admin", "/x y", "<script>", "/api/v2/keys"]})
    got = asyncio.run(design_lures(FakeLLM(good), PERSONA))
    assert got == ["/backup/", "/.env", "/server-status", "/api/v2/keys"]  # '/admin' is a known path; junk dropped
    assert asyncio.run(design_lures(FakeLLM(None), PERSONA)) == DEFAULT_PERSONA["lure_paths"]
    assert asyncio.run(design_lures(FakeLLM(json.dumps({"lure_paths": ["/only-one"]})), PERSONA)) == DEFAULT_PERSONA["lure_paths"]


# ---------- navigation, URL patterns, must-exist pages ----------
from mirage.engine import Engine, cache_key, parse_model_output  # noqa: E402
from mirage.persona import design_nav, derive_nav, matches_pattern, surface_paths  # noqa: E402

LEGACY = {"company": "Old Co", "domain": "old.example",
          "known_paths": ["/", "/shipments", "/shipments/{pro_number}", "/api/track/{pro_number}", "/drivers", "/dashboard"],
          "lure_paths": ["/.env"]}


def test_placeholders_become_patterns_and_menu_is_derived():
    spec = normalize_persona(LEGACY)
    assert spec["known_paths"] == ["/", "/shipments", "/drivers", "/dashboard"]
    assert spec["url_patterns"] == ["/shipments/{pro_number}", "/api/track/{pro_number}"]
    assert [n["path"] for n in spec["nav"]] == ["/", "/shipments", "/drivers", "/dashboard"]
    assert surface_paths(spec | {"persona_id": "t"}) == ["/", "/shipments", "/drivers", "/dashboard", "/.env"]
    brief = persona_brief(spec)
    assert "Navigation" in brief and "Record URL patterns" in brief


def test_pattern_matching_and_surface():
    spec = normalize_persona(LEGACY)
    assert matches_pattern(spec, "/shipments/PRO-48213") and matches_pattern(spec, "/api/track/123456")
    assert not matches_pattern(spec, "/shipments") and not matches_pattern(spec, "/shipments/a/b")
    exact, sections = surface_sets(spec)
    assert "/shipments/{pro_number}" not in exact and "shipments" in sections and "api" in sections
    assert on_surface(exact, sections, "/shipments/PRO-48213") and not on_surface(exact, sections, "/wp-login.php")


def test_nav_validation_rejects_unknown_paths():
    spec = normalize_persona(LEGACY | {"nav": [{"label": "Hax", "path": "/not-a-page"}, {"label": "Fleet <b>", "path": "/drivers"}]})
    assert spec["nav"] == [{"label": "Fleet b", "path": "/drivers"}] or len(spec["nav"]) >= 3  # unknown path dropped
    assert all(n["path"] in spec["known_paths"] + spec["lure_paths"] for n in spec["nav"])


def test_design_nav_uses_model_and_falls_back():
    spec = normalize_persona(LEGACY) | {"persona_id": "t"}
    good = json.dumps({"nav": [{"label": "Overview", "path": "/dashboard"}, {"label": "Loads", "path": "/shipments"},
                               {"label": "Drivers", "path": "/drivers"}, {"label": "Evil", "path": "/nope"}],
                       "url_patterns": ["/drivers/{driver_id}", "bad", "/two/{a}/{b}"]})
    nav, pats = asyncio.run(design_nav(FakeLLM(good), spec))
    assert [n["path"] for n in nav] == ["/dashboard", "/shipments", "/drivers"]
    assert "/drivers/{driver_id}" in pats and "/shipments/{pro_number}" in pats and "bad" not in pats
    nav2, pats2 = asyncio.run(design_nav(FakeLLM(None), spec))
    assert nav2 == derive_nav(spec["known_paths"]) and pats2 == spec["url_patterns"]


class StatusLLM(FakeLLM):
    """Answers 404 for the first N fast calls, then 200."""
    def __init__(self, bad_calls):
        super().__init__()
        self.bad_calls = bad_calls

    async def complete(self, tier, system, user, **kw):
        if tier == "smart":
            raise LLMError("no")
        self.calls.append(tier)
        code = 404 if len([c for c in self.calls if c == "fast"]) <= self.bad_calls else 200
        return LLMResult(f"STATUS: {code}\n\n<html>page</html>", "fake", 5, 1, 1)


def make_engine(llm):
    from mirage.engine import Engine
    from mirage.llm import LLM  # noqa: F401
    db = Database(":memory:")
    persona = normalize_persona(LEGACY) | {"persona_id": "pid"}
    return Engine(Config(api_key="x"), db, llm, persona), db


def test_must_exist_retries_once_then_caches_a_real_page():
    eng, db = make_engine(StatusLLM(bad_calls=1))
    res = asyncio.run(eng._generate(None, "GET", "/drivers", "", {}, "", must_exist=True))
    assert res.source == "generated" and res.status == 200 and eng.llm.calls.count("fast") == 2


def test_must_exist_never_returns_or_caches_a_bad_answer():
    eng, db = make_engine(StatusLLM(bad_calls=5))
    res = asyncio.run(eng._generate(None, "GET", "/drivers", "", {}, "", must_exist=True))
    assert res.source == "fallback"
    n = asyncio.run(eng.warm(["/drivers", "/shipments/{pro_number}"]))
    assert n == 0 and db.get_artifact("pid", cache_key("GET", "/drivers", "")) is None


def test_warm_builds_real_pages_and_skips_templates():
    eng, db = make_engine(StatusLLM(bad_calls=0))
    n = asyncio.run(eng.warm(["/drivers", "/dashboard", "/shipments/{pro_number}"]))
    assert n == 2
    assert db.get_artifact("pid", cache_key("GET", "/drivers", ""))["status"] == 200
    assert db.get_artifact("pid", cache_key("GET", "/shipments/{pro_number}", "")) is None


def test_prompt_note_covers_record_pages():
    spec = normalize_persona(LEGACY) | {"persona_id": "t"}
    assert "<note>" in build_user_prompt(spec, [], "GET", "/shipments/PRO-48213", "", {}, "")
    assert "<note>" not in build_user_prompt(spec, [], "GET", "/wp-login.php", "", {}, "")


class PayloadLLM(FakeLLM):
    async def complete(self, tier, system, user, **kw):
        if tier == "smart":
            raise LLMError("no")
        self.calls.append(tier)
        return LLMResult("STATUS: 403\n\n<h1>Forbidden</h1>", "fake", 5, 1, 1)


def test_probe_on_a_known_page_may_be_refused_and_is_not_a_failure():
    llm = PayloadLLM()
    db = Database(":memory:")
    with TestClient(create_app(Config(api_key="x"), llm=llm, db=db)) as c:
        r = c.get("/admin?id=1'")
        assert r.status_code == 403
    row = db._one("SELECT response_source s, status FROM events")
    assert (row["s"], row["status"]) == ("generated", 403) and llm.calls.count("fast") == 1


def test_brief_separates_menu_label_from_href():
    brief = persona_brief(normalize_persona(LEGACY))
    assert "Home -> /" in brief and "Shipments -> /shipments" in brief
    from mirage.prompts import SYSTEM_RESPONDER
    assert "link text is only the label" in SYSTEM_RESPONDER and "working business application" in SYSTEM_RESPONDER
