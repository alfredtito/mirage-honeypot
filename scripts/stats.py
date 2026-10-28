"""Headline numbers for the static-vs-Mirage comparison and the Nebius feedback form.

    python scripts/stats.py [mirage.db]
"""
import sqlite3
import sys

con = sqlite3.connect(sys.argv[1] if len(sys.argv) > 1 else "mirage.db")
con.row_factory = sqlite3.Row

print("== sessions by mode (only sessions with >1 request) ==")
for r in con.execute("""
    SELECT mode, COUNT(*) sessions, ROUND(AVG(request_count),1) avg_requests,
           ROUND(AVG(distinct_paths),1) avg_distinct_paths, ROUND(AVG(duration_s),1) avg_duration_s
    FROM session_stats WHERE request_count > 1 GROUP BY mode"""):
    print(dict(r))

print("\n== response sources ==")
for r in con.execute("SELECT mode, response_source, COUNT(*) n FROM events GROUP BY 1,2 ORDER BY 1,3 DESC"):
    print(dict(r))

print("\n== LLM latency / tokens (generated only) ==")
for r in con.execute("""
    SELECT llm_model, COUNT(*) n, ROUND(AVG(llm_ms)) avg_ms, MAX(llm_ms) max_ms,
           SUM(prompt_tokens) prompt_tok, SUM(completion_tokens) completion_tok
    FROM events WHERE response_source='generated' GROUP BY 1"""):
    print(dict(r))
