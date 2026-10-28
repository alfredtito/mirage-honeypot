"""Start the read-only dashboard (localhost only).

    python scripts/dashboard.py                      # reads mirage.db (or DB_PATH) and ab_results.json
    python scripts/dashboard.py --db ab_work/mirage.db --mask-ips
Then open http://127.0.0.1:8081
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import os

import uvicorn

from mirage.dashboard import create_dashboard

ap = argparse.ArgumentParser()
ap.add_argument("--db", default=os.environ.get("DB_PATH", "mirage.db"))
ap.add_argument("--ab", default="ab_results.json")
ap.add_argument("--port", type=int, default=8081)
ap.add_argument("--mask-ips", action="store_true", help="hide the last two octets of source IPs (for demos)")
a = ap.parse_args()
if not pathlib.Path(a.db).exists():
    raise SystemExit(f"database not found: {a.db}")
print(f"dashboard on http://127.0.0.1:{a.port}  (database: {a.db})")
uvicorn.run(create_dashboard(a.db, a.ab, a.mask_ips), host="127.0.0.1", port=a.port, log_level="warning")
