#!/bin/bash

set -euo pipefail

REPO="libbpf/bpftool"

# bpftool GitHub releases are mutable, so we pin the VERSION and the SHA-256 of
# each per-arch release tarball (asset-rewrite protection). To bump to a new
# release, update all three values together after manual review; partial
# bumps will fail the integrity checks below.
VERSION="v7.7.0"
EXPECTED_SHA256_AMD64="09150596f09356b0ff632dd7f9856e0ea86bf96b269e9bc94278d9a9432a268c"
EXPECTED_SHA256_ARM64="d68443d945c146080151eb215bebaa400294ab7ada22af4f5d0a940f5992b9d9"

case "$(uname -m)" in
        x86_64)  arch="amd64"; expected_sha256="${EXPECTED_SHA256_AMD64}" ;;
        aarch64) arch="arm64"; expected_sha256="${EXPECTED_SHA256_ARM64}" ;;
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TARBALL="bpftool-${VERSION}-${arch}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
curl -sSfL -o "/tmp/${TARBALL}" "${BASE}/${TARBALL}"

# Unfortunately, bpftool release are mutable, this means an attacker could also
# rewrite the *.sha256sum in order to trick us.
# Let's use the $expected_sha256 instead.
echo "${expected_sha256}  /tmp/${TARBALL}" | sha256sum --quiet -c -

tar -xzf "/tmp/${TARBALL}" -C /tmp/
chmod +x /tmp/bpftool
