#!/bin/bash

set -euo pipefail

VERSION=$(curl -s "https://api.github.com/repos/libbpf/bpftool/releases/latest" | jq -r '.tag_name')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
        ARCH="arm64"
fi

curl -sL "https://github.com/libbpf/bpftool/releases/download/${VERSION}/bpftool-${VERSION}-${ARCH}.tar.gz" > /tmp/bpftool.tar.gz
tar -xzf /tmp/bpftool.tar.gz -C /tmp/
chmod +x /tmp/bpftool
