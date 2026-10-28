"""End-to-end check of the Token Factory client: latency per tier, <think> handling, persona JSON.

    export NEBIUS_API_KEY=...
    python scripts/check_llm.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncio

from mirage.config import Config
from mirage.engine import parse_model_output
from mirage.llm import LLM, extract_json
from mirage.persona import normalize_persona
from mirage.prompts import SYSTEM_PERSONA, SYSTEM_RESPONDER


async def main() -> None:
    cfg = Config.from_env()
    llm = LLM(cfg)
    print(f"fast={cfg.model_fast}\nsmart={cfg.model_smart}\n")

    user = ("<persona>\nOrganization: Kalahari Freight Services\nStack: Apache/2.4.41, PHP 7.4\n</persona>\n"
            "<history>\n(first request)\n</history>\n<request>\nGET /admin\nhost: portal.example\n</request>")
    for i in range(3):
        r = await llm.complete("fast", SYSTEM_RESPONDER, user, max_tokens=600, temperature=0.6)
        status, body = parse_model_output(r.text)
        print(f"[fast #{i+1}] {r.latency_ms} ms, tokens in/out={r.prompt_tokens}/{r.completion_tokens}, "
              f"status={status}, body_chars={len(body)}")
    print("\n--- sample body ---\n" + body[:400] + "\n")
    print("TIP: if fast latency is >2-3s, the model is probably reasoning. Set LLM_EXTRA_BODY to disable it.")

    r = await llm.complete("smart", SYSTEM_PERSONA, f"Theme: {cfg.persona_theme}", max_tokens=2500)
    print(f"[smart] {r.latency_ms} ms")
    try:
        persona = normalize_persona(extract_json(r.text))
        print("persona OK:", persona["company"], "|", persona["stack"]["server_header"])
    except Exception as e:
        print("PERSONA PARSE FAILED:", e)
        print("--- raw model output ---")
        print(r.text[:1500])


asyncio.run(main())
