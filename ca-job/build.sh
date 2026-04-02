#!/usr/bin/env bash
set -o errexit
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

CONTAINER_REPO="${CONTAINER_REPO:-ghcr.io/inspektor-gadget}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${CONTAINER_REPO}/ca-job:${IMAGE_TAG}"

echo "Building ${IMAGE_NAME} ..."
DOCKER_BUILDKIT=1 docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/ca-job/Dockerfile" "${REPO_ROOT}"

echo "Pushing ${IMAGE_NAME} ..."
docker push "${IMAGE_NAME}"

echo "Done: ${IMAGE_NAME}"
