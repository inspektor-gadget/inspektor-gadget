#!/bin/bash

set -euo pipefail

REPO="libbpf/bpftool"

# bpftool GitHub releases are mutable, so we pin both the git commit that
# VERSION must resolve to (tag-rewrite protection) and the SHA-256 of each
# per-arch release tarball (asset-rewrite protection). To bump to a new
# release, update all four values together after manual review; partial
# bumps will fail the integrity checks below.
VERSION="v7.7.0"
PINNED_COMMIT="4222ef1c8cdb0a1ea03c7a8c650ec334b782902d"
EXPECTED_SHA256_AMD64="09150596f09356b0ff632dd7f9856e0ea86bf96b269e9bc94278d9a9432a268c"
EXPECTED_SHA256_ARM64="d68443d945c146080151eb215bebaa400294ab7ada22af4f5d0a940f5992b9d9"

api() {
        local auth=()
        if [ -n "${GITHUB_TOKEN:-}" ]; then
                auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
        fi
        curl -sSfL -H 'Accept: application/vnd.github+json' "${auth[@]}" "$@"
}

ref_json=$(api "https://api.github.com/repos/${REPO}/git/ref/tags/${VERSION}")
obj_type=$(echo "${ref_json}" | jq -r '.object.type')
obj_sha=$(echo  "${ref_json}" | jq -r '.object.sha')

# If the release points to a tag, we need to dereference it again to get the
# commit.
if [ "${obj_type}" = "tag" ]; then
        obj_sha=$(api "https://api.github.com/repos/${REPO}/git/tags/${obj_sha}" \
                  | jq -r '.object.sha')
fi

if [ "${PINNED_COMMIT}" != "${obj_sha}" ]; then
        echo "Tag ${VERSION} of ${REPO} resolves to ${obj_sha}," >&2
        echo "but PINNED_COMMIT is ${PINNED_COMMIT}:" >&2
        echo "* Either maintainers re-tagged the release: review the new commit" >&2
        echo "  and update PINNED_COMMIT (and EXPECTED_SHA256_*) accordingly." >&2
        echo "* Or the tag was rewritten maliciously: do NOT proceed." >&2
        exit 1
fi

latest=$(api "https://api.github.com/repos/${REPO}/releases/latest" \
         | jq -r '.tag_name')
if [ "${latest}" != "${VERSION}" ]; then
        echo "A newer release of ${REPO} is available: ${latest} (pinned: ${VERSION})." >&2
        echo "Review it and bump VERSION + PINNED_COMMIT + EXPECTED_SHA256_* in this script." >&2
fi

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
