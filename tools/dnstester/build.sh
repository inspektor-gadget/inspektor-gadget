#!/bin/bash

set -e

docker buildx build --platform=linux/amd64,linux/arm64 -t ghcr.io/inspektor-gadget/dnstester:latest -f Dockerfile --push .
