#!/usr/bin/env bash
# Check, build and publish the image for the version in pyproject.toml. Runs locally; nothing
# here depends on a hosted CI service.
#
#   scripts/release.sh            # checks, then a multi-arch build pushed to GHCR
#   scripts/release.sh --dry-run  # checks and a local single-arch build only
#
# Needs: uv, docker with buildx, and a `docker login ghcr.io` that can write packages.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-ghcr.io/mitchboulay/forgejo-mcp-gateway}"
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -1)
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "unexpected version '${VERSION}'" >&2; exit 1; }
DRY_RUN=false
[[ "${1:-}" == --dry-run ]] && DRY_RUN=true

if [[ -n "$(git status --porcelain)" ]]; then
  echo "the working tree has uncommitted changes; release from a clean commit" >&2
  exit 1
fi

echo "==> checks"
uv sync --frozen --quiet
uv run --frozen ruff format --check src tests
uv run --frozen ruff check src tests
uv run --frozen mypy
uv run --frozen pytest -q

REVISION=$(git rev-parse HEAD)
LABELS=(--label "org.opencontainers.image.version=${VERSION}" --label "org.opencontainers.image.revision=${REVISION}")

if ${DRY_RUN}; then
  echo "==> local build ${IMAGE}:${VERSION} (dry run)"
  docker build "${LABELS[@]}" -t "${IMAGE}:${VERSION}" .
  exit 0
fi

if docker manifest inspect "${IMAGE}:${VERSION}" >/dev/null 2>&1; then
  echo "${IMAGE}:${VERSION} is already published; bump the version in pyproject.toml" >&2
  exit 1
fi

# Multi-platform builds need a docker-container builder; the default docker driver can't do them.
BUILDER=forgejo-mcp-gateway-release
docker buildx inspect "${BUILDER}" >/dev/null 2>&1 || docker buildx create --name "${BUILDER}" --driver docker-container >/dev/null

echo "==> build and push ${IMAGE}:${VERSION} and :latest (linux/amd64, linux/arm64)"
docker buildx build --builder "${BUILDER}" --platform linux/amd64,linux/arm64 "${LABELS[@]}" \
  -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" --push .
docker buildx imagetools inspect "${IMAGE}:${VERSION}" | sed -n '1,12p'
