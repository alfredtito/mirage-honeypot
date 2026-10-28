"""Pre-generate the persona's known pages. Run once with MIRAGE_MODE=static to build the
baseline honeypot (cloned pages only, no improvisation) for the A/B comparison.

    python scripts/warm_cache.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncio

from mirage.config import Config
from mirage.db import Database
from mirage.engine import Engine
from mirage.llm import LLM
from mirage.persona import ensure_persona


async def main() -> None:
    cfg = Config.from_env()
    db, llm = Database(cfg.db_path), LLM(cfg)
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    n = await Engine(cfg, db, llm, persona).warm(persona["known_paths"])
    print(f"warmed {n} pages for {persona['company']} ({persona['persona_id']})")


asyncio.run(main())
