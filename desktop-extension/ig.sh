#!/bin/sh
export HOST_ROOT="/proc/$(pidof -s lifecycle-server)/root/"
ig --docker-socketpath=$INSPEKTOR_GADGET_DOCKER_SOCKETPATH -v -r docker "$@"

