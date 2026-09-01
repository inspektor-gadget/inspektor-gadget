#!/bin/bash
# Check that gadget documentation (gadgets/*/README.mdx) follows the
# canonical section structure, so new and edited gadget docs stay
# consistent (see #5635):
#
#   # <gadget-name>
#   ## Requirements      (optional)
#   ## Getting started
#   ## Flags             (optional)
#   ## Guide
#   ... any additional sections ...
#
# Pre-existing violations are listed in
# tools/check-gadget-docs-exceptions.txt and skipped until they are
# fixed (tracked in #5628), so the check can be blocking for everything
# else. Remove a gadget from that file once its README is fixed.
#
# Usage: tools/check-gadget-docs.sh [gadgets-dir]

set -o pipefail

GADGETS_DIR="${1:-gadgets}"
EXCEPTIONS_FILE="$(dirname "$0")/check-gadget-docs-exceptions.txt"

NO_COLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
LIGHT_YELLOW='\033[0;33m'

errors=()
skipped=()
checked=0

add_error() {
  errors+=("$1: $2")
}

is_exception() {
  [ -f "$EXCEPTIONS_FILE" ] && grep -vE '^(#|$)' "$EXCEPTIONS_FILE" | grep -qxF "$1"
}

for readme in "$GADGETS_DIR"/*/README.mdx; do
  [ -e "$readme" ] || continue
  gadget=$(basename "$(dirname "$readme")")

  if is_exception "$gadget"; then
    skipped+=("$gadget")
    continue
  fi

  checked=$((checked + 1))

  # Title heading must be exactly '# <gadget-name>'
  first_heading=$(grep -m1 -E '^# ' "$readme")
  if [ "$first_heading" != "# $gadget" ]; then
    add_error "$readme" "first heading must be '# $gadget' (found '${first_heading:-none}')"
  fi

  # Canonical headings must use exact casing and spacing
  while IFS=: read -r lineno text; do
    normalized=$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]' | sed -E 's/^##[[:space:]]+/## /; s/[[:space:]]+$//')
    canonical=""
    case "$normalized" in
      '## requirements') canonical='## Requirements' ;;
      '## getting started') canonical='## Getting started' ;;
      '## flags') canonical='## Flags' ;;
      '## guide') canonical='## Guide' ;;
      *) continue ;;
    esac
    if [ "$text" != "$canonical" ]; then
      add_error "$readme" "line $lineno: heading must be exactly '$canonical' (found '$text')"
    fi
  done < <(grep -nE '^##[[:space:]]' "$readme")

  # Mandatory sections
  grep -qxF '## Getting started' "$readme" || add_error "$readme" "missing mandatory section '## Getting started'"
  grep -qxF '## Guide' "$readme" || add_error "$readme" "missing mandatory section '## Guide'"

  # Canonical sections that are present must appear in canonical order
  prev_line=0
  prev_name=""
  for section in '## Requirements' '## Getting started' '## Flags' '## Guide'; do
    line=$(grep -nxF "$section" "$readme" | head -1 | cut -d: -f1)
    [ -z "$line" ] && continue
    if [ "$line" -lt "$prev_line" ]; then
      add_error "$readme" "'$section' (line $line) must come after '$prev_name' (line $prev_line)"
    else
      prev_line=$line
      prev_name=$section
    fi
  done

  # Non-canonical sections are only allowed after '## Guide'
  guide_line=$(grep -nxF '## Guide' "$readme" | head -1 | cut -d: -f1)
  if [ -n "$guide_line" ]; then
    while IFS=: read -r lineno text; do
      normalized=$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]' | sed -E 's/^##[[:space:]]+/## /; s/[[:space:]]+$//')
      case "$normalized" in
        '## requirements'|'## getting started'|'## flags'|'## guide') continue ;;
      esac
      if [ "$lineno" -lt "$guide_line" ]; then
        add_error "$readme" "line $lineno: section '$text' must come after '## Guide'"
      fi
    done < <(grep -nE '^##[[:space:]]' "$readme")
  fi

  # The Guide section must have real content, not a TODO placeholder
  if awk '/^## Guide$/{f=1; next} /^## /{f=0} f' "$readme" | grep -q 'TODO'; then
    add_error "$readme" "'## Guide' section contains a TODO placeholder"
  fi
done

if [ ${#skipped[@]} -gt 0 ]; then
  echo -e "${LIGHT_YELLOW}Skipped known pre-existing violations (see ${EXCEPTIONS_FILE}): ${skipped[*]}${NO_COLOR}"
fi

if [ ${#errors[@]} -gt 0 ]; then
  >&2 echo -e "${RED}Found ${#errors[@]} gadget documentation issue(s):${NO_COLOR}"
  for error in "${errors[@]}"; do
    >&2 echo -e "${RED}  - ${error}${NO_COLOR}"
  done
  exit 1
fi

echo -e "${GREEN}All ${checked} checked gadget docs follow the canonical structure${NO_COLOR}"
