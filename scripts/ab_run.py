#!/usr/bin/env python3
"""Static-vs-Mirage comparison, one command.

Copies your honeypot database twice (same persona, same pre-generated known pages, no traffic),
starts one copy in static mode and one in Mirage mode, runs the SAME scripted attackers against
both, then compares what the attackers reached.

    python scripts/ab_run.py --runs 3

Static mode = cloned pages only; anything else is a 404 (similar in spirit to a SNARE-style clone
without TANNER's emulators). Mirage mode = the same pages plus on-demand generation.
Uses ports 8091/8092 so your normal honeypot on 8080 can keep running.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import argparse
import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.request

from mirage.compare import mode_stats, render_report
from mirage.config import Config
from mirage.db import Database
from mirage.engine import Engine, cache_key
from mirage.llm import LLM
from mirage.persona import ensure_persona, surface_paths

CLEAN_TABLES = ("events", "sessions", "findings", "proposed_rules", "analysis_runs")


async def warm_source(cfg, db_path):
    db, llm = Database(db_path), LLM(cfg)
    persona = await ensure_persona(db, llm, cfg.persona_theme)
    paths = surface_paths(persona)
    await Engine(cfg, db, llm, persona).warm(paths)
    keys = [cache_key("GET", p, "") for p in paths]
    have = sum(1 for k in keys if db.get_artifact(persona["persona_id"], k))
    db.close()
    return persona, keys, have


def prepare(src, dst, persona_id, keys):
    s, d = sqlite3.connect(src), sqlite3.connect(dst)
    s.backup(d)
    s.close()
    for t in CLEAN_TABLES:
        try:
            d.execute(f"DELETE FROM {t}")
        except sqlite3.OperationalError:
            pass
    marks = ",".join("?" * len(keys))
    d.execute(f"DELETE FROM artifacts WHERE persona_id != ? OR cache_key NOT IN ({marks})", (persona_id, *keys))
    d.execute("UPDATE artifacts SET hits = 0")
    d.commit()
    d.close()


def start_server(mode, port, db_path, log_path):
    env = {**os.environ, "MIRAGE_MODE": mode, "PORT": str(port), "DB_PATH": str(db_path), "HOST": "127.0.0.1"}
    return subprocess.Popen([sys.executable, "-m", "mirage"], cwd=ROOT, env=env,
                            stdout=open(log_path, "w"), stderr=subprocess.STDOUT)


def wait_ready(port, proc, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise SystemExit(f"server on port {port} exited early; see ab_work/*.log")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10).read()
            return
        except Exception:
            time.sleep(1)
    raise SystemExit(f"server on port {port} did not become ready")


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--max", type=int, default=40, help="max requests per attacker profile per run")
    ap.add_argument("--delay", type=float, default=0.1)
    ap.add_argument("--source-db", default=None)
    ap.add_argument("--mirage-port", type=int, default=8091)
    ap.add_argument("--static-port", type=int, default=8092)
    a = ap.parse_args()

    cfg = Config.from_env()
    src = a.source_db or cfg.db_path
    work = ROOT / "ab_work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()

    print("warming known pages in the source database (skips pages that already exist)...")
    persona, keys, have = asyncio.run(warm_source(cfg, src))
    print(f"persona: {persona['company']}   known pages available: {have}/{len(keys)}")
    if have < len(keys):
        print("  note: some known pages could not be generated; both modes will lack them equally")
    dbs = {"static": work / "static.db", "mirage": work / "mirage.db"}
    for p in dbs.values():
        prepare(src, p, persona["persona_id"], keys)

    ports = {"static": a.static_port, "mirage": a.mirage_port}
    servers = {m: start_server(m, ports[m], dbs[m], work / f"{m}.log") for m in dbs}
    try:
        for m, proc in servers.items():
            wait_ready(ports[m], proc)
        print(f"servers up: static on :{ports['static']}, mirage on :{ports['mirage']}\n")
        for r in range(1, a.runs + 1):
            t0 = time.time()
            procs = {m: subprocess.Popen(
                [sys.executable, str(ROOT / "scripts/simulate_scan.py"), f"http://127.0.0.1:{ports[m]}",
                 "--profile", "all", "--max", str(a.max), "--delay", str(a.delay), "--tag", f"r{r}"],
                stdout=open(work / f"attack_{m}_{r}.log", "w"), stderr=subprocess.STDOUT) for m in dbs}
            done = {}
            while len(done) < len(procs):
                for m, p in procs.items():
                    if m not in done and p.poll() is not None:
                        done[m] = int(time.time() - t0)
                time.sleep(1)
            print(f"run {r}/{a.runs} finished: static {done['static']}s, mirage {done['mirage']}s")
    finally:
        for proc in servers.values():
            stop(proc)

    static, mirage = mode_stats(str(dbs["static"]), a.max), mode_stats(str(dbs["mirage"]), a.max)
    report = render_report(static, mirage)
    print("\n" + report)
    (ROOT / "ab_results.json").write_text(json.dumps({"static": static, "mirage": mirage}, indent=2, default=str))
    (ROOT / "ab_report.txt").write_text(report + "\n")
    print("\nsaved ab_results.json and ab_report.txt (databases and logs are in ab_work/)")


if __name__ == "__main__":
    main()
