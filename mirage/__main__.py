import logging

import uvicorn

from .config import Config

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = Config.from_env()
    uvicorn.run(
        "mirage.honeypot:create_app",
        factory=True,
        host=cfg.host,
        port=cfg.port,
        server_header=False,   # we set the persona's Server header ourselves
        date_header=True,
        proxy_headers=True,
        forwarded_allow_ips=cfg.forwarded_allow_ips,
        access_log=False,      # events table is our access log
    )
