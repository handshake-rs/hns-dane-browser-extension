#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MACOSX_DEPLOYMENT_TARGET:-}" ||
      ! "$MACOSX_DEPLOYMENT_TARGET" =~ ^[0-9]+\.[0-9]+$ ||
      "$#" -eq 0 ]]; then
  echo "::error::MACOSX_DEPLOYMENT_TARGET and at least one Mach-O binary are required."
  exit 1
fi

for binary in "$@"; do
  if [[ ! -f "$binary" ]]; then
    echo "::error::macOS release binary is missing: $binary"
    exit 1
  fi
  while IFS= read -r dependency; do
    case "$dependency" in
      /System/Library/* | /usr/lib/*) ;;
      *)
        echo "::error::$binary has a non-system dependency: $dependency"
        exit 1
        ;;
    esac
  done < <(otool -L "$binary" | tail -n +2 | awk '{print $1}')

  minimum="$(
    otool -l "$binary" |
      awk '
        $1 == "cmd" && $2 == "LC_BUILD_VERSION" { build = 1; next }
        build && $1 == "minos" { print $2; exit }
      '
  )"
  if [[ "$minimum" != "$MACOSX_DEPLOYMENT_TARGET" ]]; then
    echo "::error::$binary has LC_BUILD_VERSION minos ${minimum:-missing}; expected $MACOSX_DEPLOYMENT_TARGET."
    exit 1
  fi
done

printf 'macOS system dependencies and %s deployment target verified.\n' \
  "$MACOSX_DEPLOYMENT_TARGET"
