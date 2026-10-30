#!/usr/bin/env bash
# Builds the gateway image the way the release is built: linux/amd64, every timestamp clamped to
# SOURCE_DATE_EPOCH, no provenance attached, so the same commit gives the same image id on any machine.
# Usage: ./build.sh [tag]    Needs Docker with buildx.
set -euo pipefail
cd "$(dirname "$0")"
TAG=${1:-paranoid-gateway:local}
docker buildx inspect paranoid-gate >/dev/null 2>&1 || docker buildx create --name paranoid-gate --driver docker-container >/dev/null
SOURCE_DATE_EPOCH=1767225600 docker buildx build --builder paranoid-gate --platform linux/amd64 --provenance=false \
  --output "type=docker,name=$TAG,rewrite-timestamp=true" .
docker image inspect "$TAG" --format 'image {{.Id}}'
