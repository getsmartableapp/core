#!/usr/bin/env bash
# Cargo.lock may only grow: every package the committed lock names is still
# there, at the same version and checksum. What is new is listed, not judged.
#
# Why: adding a crate offline makes Cargo resolve again from what is cached
# here, and a crate the lock names but no target of ours builds is not cached.
# `syn` 3.0.9, which only `wasm-bindgen-macro-support` (wasm32) needs, was
# twice moved to 3.0.6 that way, and `--locked` does not notice a lock edited
# before it runs. (`docs/RUST_KEY_CORE_DESIGN.md#phase-2c`.)
#
#   native/key_core/tool/check_lock.sh [base] [crate...]
#
# base: the commit to compare with (default HEAD). Each crate named after it
# may change, for an update the owner approved; anything else that changes
# fails. LOCK names another file to check in place of Cargo.lock.
set -euo pipefail

cd "$(dirname "$0")/.."
BASE="${1:-HEAD}"
shift || true
LOCK="${LOCK:-Cargo.lock}"

# One line per package: name, version, checksum (none for key_core itself).
packages() {
  awk '
    /^\[\[package\]\]/ { if (name != "") print name, version, sum; name = version = sum = "" }
    /^name = /     { name = $3 }
    /^version = /  { version = $3 }
    /^checksum = / { sum = $3 }
    END { if (name != "") print name, version, sum }
  ' | tr -d '"' | sort
}

base=$(git show "$BASE:native/key_core/Cargo.lock" | packages)
now=$(packages < "$LOCK")

# Whether the crate named first is among the rest.
allowed() {
  local target="$1" crate
  shift
  for crate in "$@"; do [[ "$target" == "$crate" ]] && return 0; done
  return 1
}

failed=0
while read -r name version sum; do
  [[ -z "$name" ]] && continue
  if grep -qxF "$name $version $sum" <<< "$now"; then continue; fi
  if [[ $# -gt 0 ]] && allowed "$name" "$@"; then
    echo "moved, allowed: $name $version"
    continue
  fi
  echo "error: $name $version${sum:+ ($sum)} is in $BASE's lock and not, as it was, in $LOCK"
  failed=1
done <<< "$base"

while read -r name version sum; do
  [[ -z "$name" ]] && continue
  grep -qxF "$name $version $sum" <<< "$base" || echo "added: $name $version"
done <<< "$now"

if [[ $failed -ne 0 ]]; then
  echo "check_lock: a locked package moved; restore its lines, or name it if the move was approved"
  exit 1
fi
echo "check_lock: nothing locked in $BASE moved"
