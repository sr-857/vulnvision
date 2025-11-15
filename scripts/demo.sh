#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

if ! command -v docker-compose >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the demo." >&2
  exit 1
fi

echo "Building and starting VulnVision demo stack..."
COMPOSE_CMD="docker compose"
if ! command -v docker compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
fi

${COMPOSE_CMD} -f "${PROJECT_ROOT}/docker-compose.yml" up --build
