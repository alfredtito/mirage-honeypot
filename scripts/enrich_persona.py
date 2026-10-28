"""Upgrade your EXISTING persona in place, then rebuild its pre-built pages.

Keeps the company, users, schema and its identity. Adds (if missing): lure pages, a consistent navigation
menu and record URL patterns; turns {placeholder} paths into URL patterns; then regenerates every pre-built
page so they all carry the menu and link to deeper record pages.

    python scripts/enrich_persona.py                # upgrade + rebuild all pre-built pages
    python scripts/enrich_persona.py --keep-pages   # upgrade only, do not regenerate pages
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import asyncio

from mirage.config import Config
from mirage.db import Database
from mirage.engine import Engine, cache_key
from mirage.llm import LLM
from mirage.persona import design_lures, design_nav, ensure_persona, normalize_persona, surface_paths


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-pages", action="store_true")
    a = ap.parse_args()
    cfg = Config.from_env()
    db, llm = Database(cfg.db_path), LLM(cfg)
    if not llm.enabled:
        raise SystemExit('NEBIUS_API_KEY is not set. Run: set -a && . ./.env && set +a   (nothing was changed)')
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    pid, had_lures = persona["persona_id"], bool(persona.get("lure_paths"))

    spec = normalize_persona({k: v for k, v in persona.items() if k != "persona_id"})
    if not had_lures:
        spec["lure_paths"] = await design_lures(llm, spec | {"persona_id": pid})
    spec["nav"], spec["url_patterns"] = await design_nav(llm, spec | {"persona_id": pid})
    db.save_persona(pid, spec)
    persona = spec | {"persona_id": pid}

    print(f"company: {persona['company']}")
    print("navigation:", " | ".join(f"{n['label']} {n['path']}" for n in persona["nav"]))
    print("record URL patterns:", ", ".join(persona["url_patterns"]))
    print("lures:", ", ".join(persona["lure_paths"]))

    if not a.keep_pages:
        db._run("DELETE FROM artifacts WHERE persona_id = ?", (pid,))
        print("cleared old pre-built pages")
    paths = surface_paths(persona)
    print(f"building {len(paths)} pages (about {max(1, len(paths) // 3)} to {len(paths)} minutes)...")
    n = await Engine(cfg, db, llm, persona).warm(paths)
    missing = [p for p in paths if not db.get_artifact(pid, cache_key("GET", p, ""))]
    print(f"built {n} pages; {len(paths) - len(missing)}/{len(paths)} available")
    if missing:
        print("not built (timed out, or the model kept answering 403/404):", ", ".join(missing))
        print("retry ONLY the missing pages (keeps the built ones) with:\n  LLM_TIMEOUT_S=90 python scripts/enrich_persona.py --keep-pages")


asyncio.run(main())
