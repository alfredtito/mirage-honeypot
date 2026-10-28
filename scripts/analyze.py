"""Run the analyst agent over captured sessions.

    python scripts/analyze.py                      # all sessions with >= 3 requests
    python scripts/analyze.py --since-minutes 90   # only recent traffic
    python scripts/analyze.py --no-tavily

Needs the same .env as the honeypot. Optional: TAVILY_API_KEY for CVE enrichment.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import asyncio
import json
import logging
import os

from mirage.analyst import run_analysis
from mirage.config import Config
from mirage.db import Database
from mirage.llm import LLM
from mirage.persona import ensure_persona


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--min-requests", type=int, default=3)
    ap.add_argument("--max-sessions", type=int, default=20)
    ap.add_argument("--since-minutes", type=float, default=None)
    ap.add_argument("--no-tavily", action="store_true")
    ap.add_argument("--out", default="analysis_latest.json")
    a = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(name)s %(levelname)s %(message)s")
    cfg = Config.from_env()
    db, llm = Database(a.db or cfg.db_path), LLM(cfg)
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    key = None if a.no_tavily else os.environ.get("TAVILY_API_KEY")
    result = await run_analysis(db, llm, persona, min_requests=a.min_requests, max_sessions=a.max_sessions,
                                since_minutes=a.since_minutes, tavily_key=key)
    ver = [r for r in result["rules"] if r["status"] == "verified"]
    print(f"\n== {len(result['findings'])} findings, {len({r['title'] for r in ver})} verified rules "
          f"({result['notes'].get('rejected_specs', 0)} rejected) ==")
    for kind in ("nginx", "modsecurity", "sigma"):
        for r in ver:
            if r["kind"] == kind:
                print(f"\n--- {kind}: {r['title']}  [tp={r['tp']} fp={r['fp']} of {r['total']} replayed]"
                      f"{'  (UA-only: easy to evade)' if r.get('brittle') else ''} ---")
                print(r["text"])
    slim = {**result, "findings": [{k: v for k, v in f.items() if k != "features"} for f in result["findings"]]}
    pathlib.Path(a.out).write_text(json.dumps(slim, indent=2, default=str))
    print(f"\nsaved {a.out} and database tables findings / proposed_rules")


asyncio.run(main())
