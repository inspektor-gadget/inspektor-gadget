#!/bin/bash

set -e

docker build -t ghcr.io/inspektor-gadget/dnstester:latest -f Dockerfile .
docker push ghcr.io/inspektor-gadget/dnstester:latest
