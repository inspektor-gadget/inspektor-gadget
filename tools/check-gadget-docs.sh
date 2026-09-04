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
# Known pre-existing violations are listed in
# tools/check-gadget-docs-exceptions.txt as '<gadget>|<rule>'. A rule
# identifies one individual violation rather than a category, so an
# exception silences exactly the known problem and every other check
# still applies to that gadget. Once a violation is fixed its exception
# becomes stale and this check fails until the entry is removed, so the
# list can only shrink.
#
# Rules:
#   title                     first heading must be '# <gadget-name>'
#   heading-casing-<section>  that heading must use canonical casing and spacing
#   missing-<section>         that mandatory section is missing
#   order-<section>           that section appears out of canonical order
#   extra-section-<section>   that non-canonical section appears before '## Guide'
#   guide-todo                the Guide section still holds a TODO placeholder
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
used_exceptions=()
checked=0

exceptions=""
if [ -f "$EXCEPTIONS_FILE" ]; then
  exceptions=$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$EXCEPTIONS_FILE" | grep -v '^$')
fi

add_error() {
  local gadget="$1" rule="$2" readme="$3" message="$4"
  if printf '%s\n' "$exceptions" | grep -qxF "$gadget|$rule"; then
    used_exceptions+=("$gadget|$rule")
    return
  fi
  errors+=("$readme [$rule]: $message")
}

slugify() {
  # '## Getting started' -> 'getting-started', so a rule id names the
  # individual section it is about.
  printf '%s' "$1" | sed -E 's/^#+[[:space:]]*//' |
    tr '[:upper:]' '[:lower:]' |
    sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

canonical_heading() {
  # Echo the canonical spelling of a '##' heading, or nothing if the
  # heading is not one of the canonical sections.
  local normalized
  normalized=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/^##[[:space:]]+/## /; s/[[:space:]]+$//')
  case "$normalized" in
  '## requirements') echo '## Requirements' ;;
  '## getting started') echo '## Getting started' ;;
  '## flags') echo '## Flags' ;;
  '## guide') echo '## Guide' ;;
  esac
}

for readme in "$GADGETS_DIR"/*/README.mdx; do
  [ -e "$readme" ] || continue
  gadget=$(basename "$(dirname "$readme")")
  # Gadgets under gadgets/ci are test fixtures and out of scope (#5635).
  [ "$gadget" = ci ] && continue

  checked=$((checked + 1))

  # The first heading of any level must be the '# <gadget-name>' title,
  # so a section cannot slip in above it.
  first_heading=$(grep -m1 -E '^#{1,6}[[:space:]]' "$readme")
  if [ "$first_heading" != "# $gadget" ]; then
    add_error "$gadget" title "$readme" \
      "first heading must be '# $gadget' (found '${first_heading:-none}')"
  fi

  # Canonical headings must use exact casing and spacing
  while IFS=: read -r lineno text; do
    canonical=$(canonical_heading "$text")
    [ -z "$canonical" ] && continue
    if [ "$text" != "$canonical" ]; then
      add_error "$gadget" "heading-casing-$(slugify "$canonical")" "$readme" \
        "line $lineno: heading must be exactly '$canonical' (found '$text')"
    fi
  done < <(grep -nE '^##[[:space:]]' "$readme")

  # Mandatory sections
  for section in '## Getting started' '## Guide'; do
    grep -qxF "$section" "$readme" ||
      add_error "$gadget" "missing-$(slugify "$section")" "$readme" \
        "missing mandatory section '$section'"
  done

  # Canonical sections that are present must appear in canonical order
  prev_line=0
  prev_name=""
  for section in '## Requirements' '## Getting started' '## Flags' '## Guide'; do
    line=$(grep -nxF "$section" "$readme" | head -1 | cut -d: -f1)
    [ -z "$line" ] && continue
    if [ "$line" -lt "$prev_line" ]; then
      add_error "$gadget" "order-$(slugify "$section")" "$readme" \
        "'$section' (line $line) must come after '$prev_name' (line $prev_line)"
    else
      prev_line=$line
      prev_name=$section
    fi
  done

  # Non-canonical sections are only allowed after '## Guide'
  guide_line=$(grep -nxF '## Guide' "$readme" | head -1 | cut -d: -f1)
  if [ -n "$guide_line" ]; then
    while IFS=: read -r lineno text; do
      [ -n "$(canonical_heading "$text")" ] && continue
      if [ "$lineno" -lt "$guide_line" ]; then
        add_error "$gadget" "extra-section-$(slugify "$text")" "$readme" \
          "line $lineno: section '$text' must come after '## Guide'"
      fi
    done < <(grep -nE '^##[[:space:]]' "$readme")
  fi

  # The Guide section must have real content, not a TODO placeholder
  if awk '/^## Guide$/{f=1; next} /^## /{f=0} f' "$readme" | grep -q 'TODO'; then
    add_error "$gadget" guide-todo "$readme" "'## Guide' section contains a TODO placeholder"
  fi
done

# An exception that never fired means the violation is gone: fail so the
# entry gets removed and the list keeps shrinking.
stale=()
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  found=""
  for used in ${used_exceptions[@]+"${used_exceptions[@]}"}; do
    if [ "$used" = "$entry" ]; then
      found=1
      break
    fi
  done
  [ -z "$found" ] && stale+=("$entry")
done <<<"$exceptions"

if [ ${#used_exceptions[@]} -gt 0 ]; then
  echo -e "${LIGHT_YELLOW}Ignored ${#used_exceptions[@]} known pre-existing violation(s), see ${EXCEPTIONS_FILE}${NO_COLOR}"
fi

if [ ${#stale[@]} -gt 0 ]; then
  >&2 echo -e "${RED}${#stale[@]} stale exception(s) - the violation is fixed, remove the entry from ${EXCEPTIONS_FILE}:${NO_COLOR}"
  for entry in "${stale[@]}"; do
    >&2 echo -e "${RED}  - ${entry}${NO_COLOR}"
  done
fi

if [ ${#errors[@]} -gt 0 ]; then
  >&2 echo -e "${RED}Found ${#errors[@]} gadget documentation issue(s):${NO_COLOR}"
  for error in "${errors[@]}"; do
    >&2 echo -e "${RED}  - ${error}${NO_COLOR}"
  done
fi

if [ ${#errors[@]} -gt 0 ] || [ ${#stale[@]} -gt 0 ]; then
  exit 1
fi

echo -e "${GREEN}All ${checked} gadget docs follow the canonical structure${NO_COLOR}"
