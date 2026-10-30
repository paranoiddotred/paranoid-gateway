#!/usr/bin/env bash
# Builds the gateway image the way the release is built: linux/amd64, every timestamp clamped to
# SOURCE_DATE_EPOCH, no provenance attached and no build cache (a cached layer keeps the file times of the
# build that made it), so the same commit gives the same image on any machine.
# Prints the image's config digest, which names the same image whatever Docker image store is in use.
# Usage: ./build.sh [tag]    Needs Docker with buildx.
set -euo pipefail
cd "$(dirname "$0")"
TAG=${1:-paranoid-gateway:local}
docker buildx inspect paranoid-gate >/dev/null 2>&1 || docker buildx create --name paranoid-gate --driver docker-container >/dev/null
SOURCE_DATE_EPOCH=1767225600 docker buildx build --builder paranoid-gate --platform linux/amd64 --provenance=false \
  --no-cache --output "type=docker,name=$TAG,rewrite-timestamp=true" .
echo "image sha256:$(docker save "$TAG" | tar -xOf - manifest.json | grep -o '"Config":"[^"]*"' | grep -o '[0-9a-f]\{64\}')"
