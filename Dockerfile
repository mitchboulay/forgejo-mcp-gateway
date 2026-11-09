# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.8 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/mitchboulay/forgejo-mcp-gateway" \
      org.opencontainers.image.description="A multi-user MCP gateway for Forgejo" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 gateway \
 && useradd --system --uid 10001 --gid gateway --home-dir /data --no-create-home gateway \
 && install -d -o gateway -g gateway -m 0700 /data
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/gateway.sqlite3 \
    HOST=0.0.0.0 \
    PORT=8080
USER gateway
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ['PORT']}/healthz\", timeout=4)"]
ENTRYPOINT ["forgejo-mcp-gateway"]
