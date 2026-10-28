"""Preview what the honeypot would serve for one path, without touching the cache.

    python scripts/preview_page.py /dashboard
    python scripts/preview_page.py /shipments/PRO-48213

Writes preview.html (or .json / .txt) in the current folder and prints status, time and size.
Open the file in your browser: links inside it will not work (it is a local file), but you can judge the look.
Takes one model call (roughly 10 to 40 seconds).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import asyncio
import time

from mirage.config import Config
from mirage.db import Database
from mirage.engine import Engine, normalize_path
from mirage.llm import LLM
from mirage.persona import ensure_persona, matches_pattern


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    a = ap.parse_args()
    cfg = Config.from_env()
    db, llm = Database(cfg.db_path), LLM(cfg)
    if not llm.enabled:
        raise SystemExit("NEBIUS_API_KEY is not set. Run: set -a && . ./.env && set +a")
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    eng = Engine(cfg, db, llm, persona)
    path = normalize_path(a.path)
    must = path in eng._exact or matches_pattern(persona, path)
    t0 = time.time()
    res = await eng._generate(None, "GET", path, "", {"host": persona["domain"]}, "", must_exist=must)
    ext = {"text/html": "html", "application/json": "json"}.get(res.ctype, "txt")
    out = pathlib.Path(f"preview.{ext}").resolve()
    out.write_text(res.body)
    print(f"{path}: status {res.status}, source {res.source}, {time.time() - t0:.0f}s, "
          f"{len(res.body)} bytes, {res.completion_tokens} tokens")
    print(f"open this in your browser:  file://{out}")


asyncio.run(main())
