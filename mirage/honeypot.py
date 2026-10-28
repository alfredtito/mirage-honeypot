"""FastAPI app: a single catch-all route. No docs/openapi/health routes (they would fingerprint us)."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from .config import Config
from .db import Database
from .engine import Engine
from .llm import LLM
from .persona import ensure_persona

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def create_app(cfg: Config | None = None, llm=None, db: Database | None = None) -> FastAPI:
    cfg = cfg or Config.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database = db or Database(cfg.db_path)
        client = llm or LLM(cfg)
        persona = await ensure_persona(database, client, cfg.persona_theme)
        app.state.engine = Engine(cfg, database, client, persona)
        logging.getLogger("mirage").info(
            "persona=%s mode=%s fast=%s smart=%s", persona["company"], cfg.mode, cfg.model_fast, cfg.model_smart
        )
        yield
        if db is None:
            database.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{full_path:path}", methods=METHODS)
    async def catch_all(request: Request, full_path: str):
        return await request.app.state.engine.handle(request)

    return app
