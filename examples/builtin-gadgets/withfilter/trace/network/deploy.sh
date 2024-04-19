#!/bin/bash

set -eo pipefail

# This script is used to build container-network-tracer container image and
# import it with the crt command to the containerd runtime in the k8s.io
# namespace. Finally, it creates a DaemonSet to deploy container-network-tracer
# on each Kubernetes cluster node.

cd "$(dirname "$0")"
WORKDIR="$(pwd)"

IMAGEREF=docker.io/gadget/container-network-tracer:v1alpha1
EXAMPLESNAMESPACE="gadget-examples"
IMAGEARCHIVE=/tmp/container-network-tracer.tar
CTRNAMESPACE=k8s.io

install() {
  docker buildx build -t $IMAGEREF -f Dockerfile "$WORKDIR/../../../../../"
  rm -rf $IMAGEARCHIVE
  if command -v ctr &> /dev/null
  then
    docker save -o $IMAGEARCHIVE $IMAGEREF
    sudo ctr --namespace=$CTRNAMESPACE image import $IMAGEARCHIVE
  fi
  kubectl apply -f deploy.yaml
  kubectl rollout status --namespace=$EXAMPLESNAMESPACE daemonset/container-network-tracer
}

uninstall() {
  kubectl delete -f "$WORKDIR/deploy.yaml"
  if command -v ctr &> /dev/null
  then
    sudo ctr --namespace=$CTRNAMESPACE image rm $IMAGEREF
  fi
}

case $1 in
  "install") install ;;
  "i") install ;;
  "uninstall") uninstall ;;
  "u") uninstall ;;
  *) echo "error: unknown command \"$1\"" && exit 1
esac
