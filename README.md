# Mirage

**A web honeypot that improvises.** Static honeypots get fingerprinted because they only serve
cloned pages and fail on anything else. Mirage uses NVIDIA Nemotron models on Nebius Token Factory
to generate consistent, persona-matched responses to *whatever* an attacker asks for, then an
analyst agent turns the captured sessions into tested defensive rules.

> Hackathon: Nebius x NVIDIA Global AI Hackathon 2026, track *Best Apps and Agents*.
> Status: day-1 scaffold (proxy, persona store, Token Factory client, logging schema).

## How it works

```
attacker -> FastAPI catch-all proxy (mirage/honeypot.py)
              |- session id (cookie, or hash of IP+UA)
              |- cache hit?  -> serve stored artifact            (consistency + cost)
              |- miss        -> Nemotron (fast tier) generates the response
              |                 using the persona brief + this visitor's history
              |- log everything to SQLite (events / sessions)
persona store (mirage/persona.py): fictional org, stack, users, DB schema, known paths.
                                   Designed once by the smart tier, reused for every response.
analyst (next): smart tier reads sessions -> intent + MITRE ATT&CK + Tavily CVE lookup
                -> WAF/Sigma rules -> replay against logged traffic -> true/false positives
```

Design choices worth knowing:

- **Two model tiers.** `MODEL_FAST` (Nano-class) answers live requests; `MODEL_SMART` (Ultra-class) designs the persona and will do the offline analysis.
- **Consistency by construction.** Every generated GET response is stored; the same URL always returns the same page. Concurrent requests for one URL are coalesced into a single model call.
- **Cost and abuse controls.** Per-session LLM call budget, global concurrency limit, hard timeouts, persona-styled static fallback when the model is slow or unavailable.
- **Untrusted input.** Attacker-controlled text is escaped and fenced in prompts; the model is told never to follow it. Bodies are size-capped while streaming.
- **No fingerprints we control.** No `/docs`, no health route, `Server`/`X-Powered-By` come from the persona, uvicorn's own banner is disabled.
- **A/B built in.** `MIRAGE_MODE=static` serves only pre-warmed pages (404 otherwise). `scripts/stats.py` compares session depth between modes.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env && set -a && . ./.env && set +a   # add your NEBIUS_API_KEY first

python scripts/list_models.py nemotron   # confirm MODEL_FAST / MODEL_SMART IDs
python scripts/check_llm.py              # latency per tier, persona JSON sanity check
python -m pytest -q                      # tests use a fake model, no key needed
python -m mirage                         # honeypot on :8080
sh scripts/try_it.sh                     # benign requests against your own instance
```

Without `NEBIUS_API_KEY` the honeypot still runs, serving fallback pages with the built-in persona.

## Layout

| Path | Purpose |
|---|---|
| `mirage/honeypot.py` | FastAPI app, single catch-all route |
| `mirage/engine.py` | session handling, cache, generation, single-flight, event logging |
| `mirage/persona.py` | persona generation, normalisation, persistence, fallback pages |
| `mirage/llm.py` | Token Factory client (OpenAI-compatible), tiers, `<think>` stripping |
| `mirage/db.py` | SQLite schema: `events`, `sessions`, `artifacts`, `personas`, plus analyst tables and the `session_stats` view |
| `scripts/` | `list_models`, `check_llm`, `warm_cache`, `stats`, `try_it.sh` |

## Safety notes (read before exposing it)

- Run it on an isolated host with **no real data and no credentials** that matter. Only test against infrastructure you own.
- Everything in the database is attacker-controlled text. When you build the dashboard, **escape it** (stored XSS) and never render logged bodies as HTML.
- Source IPs are personal data in many jurisdictions: keep retention short and don't publish raw IPs in your demo.
- Generated content must stay fictional; the prompt enforces it, but spot-check outputs.

## Roadmap

- [x] Proxy, persona store, Token Factory client, logging schema, tests
- [ ] Verify model IDs; tune fast-tier latency (disable reasoning if needed)
- [ ] Analyst agent (Serverless Job): clustering, intent, ATT&CK mapping, Tavily CVE enrichment
- [ ] Rule generator + replay verifier (true/false positive counts into `proposed_rules`)
- [ ] Dashboard (live sessions, findings, rules)
- [ ] Static-vs-Mirage comparison write-up

## Hackathon submission notes

**Nemotron / Nebius usage:** fast tier = live deception on every cache miss; smart tier = persona design
and offline analysis. *(Fill in model names, measured latency and token counts from `scripts/stats.py`.)*

Licence: MIT.
