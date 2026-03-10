#!/bin/bash

set -euo pipefail

VERSION="v7.6.0"
latest=$(curl -s "https://api.github.com/repos/libbpf/bpftool/releases/latest" | jq -r '.tag_name')

if [ "${VERSION}" != "${latest}" ]; then
        echo "${VERSION} does not correspond to the latest version: ${latest}. This script need to be updated." >&2
        exit 1
fi

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
        ARCH="arm64"
fi

curl -sL "https://github.com/libbpf/bpftool/releases/download/${VERSION}/bpftool-${VERSION}-${ARCH}.tar.gz" > /tmp/bpftool.tar.gz
tar -xzf /tmp/bpftool.tar.gz -C /tmp/
chmod +x /tmp/bpftool
