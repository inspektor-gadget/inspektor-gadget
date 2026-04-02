#!/usr/bin/env bash
set -o errexit
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="ghcr.io/inspektor-gadget/ca-job:${IMAGE_TAG}"

echo "Building ${IMAGE_NAME} ..."
DOCKER_BUILDKIT=1 docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/ca-job/Dockerfile" "${REPO_ROOT}"

echo "Loading image into minikube ..."
minikube image load "${IMAGE_NAME}"

echo "Ensuring namespace gadget exists ..."
kubectl get namespace gadget >/dev/null 2>&1 || kubectl create namespace gadget

echo "Cleaning up previous job (if any) ..."
kubectl delete job gadget-ca-job -n gadget --ignore-not-found

echo "Applying manifests ..."
kubectl apply -f "${REPO_ROOT}/ca-job/job.yaml"

echo "Waiting for job to complete ..."
kubectl wait --for=condition=complete --timeout=60s job/gadget-ca-job -n gadget || {
    echo "Job did not complete successfully. Logs:"
    kubectl logs -n gadget job/gadget-ca-job
    exit 1
}

echo ""
echo "=== Job logs ==="
kubectl logs -n gadget job/gadget-ca-job

echo ""
echo "=== Secret content ==="
kubectl get secret gadget-kubelet-certificate -n gadget -o jsonpath='{.data.ca\.crt}' | base64 -d
