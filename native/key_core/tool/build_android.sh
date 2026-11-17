#!/usr/bin/env bash
# Builds libkey_core.so for the three ABIs the release splits into, with the
# NDK the app itself builds with and against the app's floor (android_env.sh).
#
#   native/key_core/tool/build_android.sh [--full-tables]
#
# Offline and locked: every crate comes from ~/.cargo/registry as Cargo.lock
# pins it. The Android targets must already be installed. `check_android.sh`
# reads the results back rather than trusting the flags.
#
# libsecp256k1 is built with its small tables (`lowmemory`, decision O8).
# --full-tables builds without them, into target/full-tables/, for comparison.
set -euo pipefail

cd "$(dirname "$0")/.."
. tool/android_env.sh

FEATURES=()
TARGET_DIR="target"
if [ "${1:-}" = "--full-tables" ]; then
  FEATURES=(--no-default-features)
  TARGET_DIR="target/full-tables"
fi

# Rust triple, the NDK's clang prefix, the APK's ABI directory.
for row in \
  "aarch64-linux-android aarch64-linux-android arm64-v8a" \
  "armv7-linux-androideabi armv7a-linux-androideabi armeabi-v7a" \
  "x86_64-linux-android x86_64-linux-android x86_64"; do
  read -r triple clang abi <<<"$row"
  android_target "$triple" "$clang"
  cargo build --release --offline --locked --target "$triple" \
    --target-dir "$TARGET_DIR" ${FEATURES[@]+"${FEATURES[@]}"}
  out="$TARGET_DIR/android/$abi"
  mkdir -p "$out"
  cp "$TARGET_DIR/$triple/release/libkey_core.so" "$out/"
  echo "$abi: $(wc -c <"$out/libkey_core.so" | tr -d ' ') bytes"
done
