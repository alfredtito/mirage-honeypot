"""Link the record ids in your EXISTING pre-built list pages (no model calls, instant).

    python scripts/relink_pages.py --dry-run   # show what would change
    python scripts/relink_pages.py             # apply
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse

from mirage.config import Config
from mirage.db import Database
from mirage.linking import link_record_rows

ap = argparse.ArgumentParser()
ap.add_argument("--dry-run", action="store_true")
a = ap.parse_args()
cfg = Config.from_env()
db = Database(cfg.db_path)
persona = db.get_active_persona()
if not persona:
    raise SystemExit("no persona in this database")
pid, pages, links = persona["persona_id"], 0, 0
print("record URL patterns:", ", ".join(persona.get("url_patterns", [])) or "(none)")
for r in db._all("SELECT cache_key, content_type, body FROM artifacts WHERE persona_id = ? ORDER BY cache_key", (pid,)):
    key = r["cache_key"]
    if not key.startswith("GET ") or "?" in key or r["content_type"] != "text/html":
        continue
    new, n = link_record_rows(persona, key[4:], r["body"])
    if n:
        pages, links = pages + 1, links + n
        print(f"  {key[4:]:<28} +{n} record links")
        if not a.dry_run:
            db._run("UPDATE artifacts SET body = ? WHERE persona_id = ? AND cache_key = ?", (new, pid, key))
print(f"{'would link' if a.dry_run else 'linked'} {links} record ids on {pages} pages")
