"""Add lure paths to your EXISTING persona (the company and its cached pages stay the same), then
pre-generate the lure pages.

    python scripts/add_lures.py            # adds lures if the persona has none
    python scripts/add_lures.py --force    # redesign the lures
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import asyncio

from mirage.config import Config
from mirage.db import Database
from mirage.engine import Engine
from mirage.llm import LLM
from mirage.persona import design_lures, ensure_persona


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    cfg = Config.from_env()
    db, llm = Database(cfg.db_path), LLM(cfg)
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    if persona.get("lure_paths") and not a.force:
        print("persona already has lures:", ", ".join(persona["lure_paths"]), "(use --force to redesign)")
    else:
        persona["lure_paths"] = await design_lures(llm, persona)
        spec = {k: v for k, v in persona.items() if k != "persona_id"}
        db.save_persona(persona["persona_id"], spec)
        print(f"lures for {persona['company']}:", ", ".join(persona["lure_paths"]))
    n = await Engine(cfg, db, llm, persona).warm(persona["lure_paths"])
    print(f"generated and cached {n} lure pages")


asyncio.run(main())
