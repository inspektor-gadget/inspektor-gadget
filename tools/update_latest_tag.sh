#!/bin/bash

# This script updates the latest tag for all images in the inspektor-gadget
# Github organization to point to the latest release.

set -euo pipefail

OWNER="mauriciovasquezbernal"
OLD_TAG="$1"
NEW_TAG="latest"

get_all_repos() {
  local page=1
  local per_page=100
  local repos=()

  while :; do
    response=$(gh api -H "Accept: application/vnd.github.v3+json" \
      "/users/$OWNER/packages?package_type=container&per_page=$per_page&page=$page")

    current_repos=$(echo "$response" | jq -r '.[].name')
    if [[ -z "$current_repos" ]]; then
      break
    fi

    repos+=($current_repos)
    ((page++))
  done

  echo "${repos[@]}"
}

REPOS=$(get_all_repos)

for REPO in $REPOS; do
    echo "Checking image: $REPO"
    if crane manifest "ghcr.io/$OWNER/$REPO:$OLD_TAG" > /dev/null 2>&1; then
        echo "Tag $OLD_TAG exists for $REPO"
        crane copy "ghcr.io/$OWNER/$REPO:$OLD_TAG" "ghcr.io/$OWNER/$REPO:$NEW_TAG"
    fi
done
