"""Run the gateway: ``forgejo-mcp-gateway`` or ``python -m forgejo_mcp_gateway``."""

from __future__ import annotations

import uvicorn

from . import logs
from .app import create_app
from .config import Settings


def main() -> None:
    settings = Settings()  # type: ignore[call-arg]  # read from the environment
    logs.configure(settings.log_level)
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    main()
