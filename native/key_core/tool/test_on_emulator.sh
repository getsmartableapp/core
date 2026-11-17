#!/usr/bin/env bash
# Runs the crate's tests, and so_smoke.c over the arm64 library
# build_android.sh made, on an Android device or emulator: bionic's loader,
# the device's page size and its stacks, rather than the host's.
#
#   native/key_core/tool/test_on_emulator.sh <adb serial>
#
# Writes only under /data/local/tmp/key_core and removes it on the way out.
# Touches no app and no wallet. Exits non-zero if either run fails.
set -euo pipefail

cd "$(dirname "$0")/.."
. tool/android_env.sh

SERIAL="${1:?an adb serial, e.g. emulator-5556}"
adb_() { adb -s "$SERIAL" "$@"; }

abi="$(adb_ shell getprop ro.product.cpu.abi | tr -d '\r')"
[ "$abi" = "arm64-v8a" ] || {
  echo "the device is $abi; this runs the arm64-v8a build" >&2
  exit 1
}
[ -f target/android/arm64-v8a/libkey_core.so ] || {
  echo "run tool/build_android.sh first" >&2
  exit 1
}

android_target aarch64-linux-android aarch64-linux-android
tests="$(cargo test --release --offline --locked --target aarch64-linux-android \
  --no-run --message-format=json 2>/dev/null |
  python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") \
            and m["target"]["name"] == "key_core" and m.get("executable"):
        print(m["executable"])
')"
[ -n "$tests" ] || {
  echo "no test binary was built" >&2
  exit 1
}
"$BIN/aarch64-linux-android$API-clang" -std=c11 -Wall -Werror -Iinclude \
  tool/so_smoke.c -Ltarget/android/arm64-v8a -lkey_core \
  -Wl,-z,max-page-size=16384 -o target/android/so_smoke

DIR=/data/local/tmp/key_core
trap 'adb_ shell "rm -rf $DIR" >/dev/null 2>&1 || true' EXIT
adb_ shell "rm -rf $DIR && mkdir -p $DIR"
adb_ push "$tests" "$DIR/key_core_tests" >/dev/null
adb_ push target/android/arm64-v8a/libkey_core.so "$DIR/" >/dev/null
adb_ push target/android/so_smoke "$DIR/" >/dev/null

echo "device: $(adb_ shell getprop ro.build.version.release | tr -d '\r'), API \
$(adb_ shell getprop ro.build.version.sdk | tr -d '\r'), page size \
$(adb_ shell getconf PAGE_SIZE | tr -d '\r')"

# The exit status is echoed and read back rather than taken from `adb shell`.
run() {
  local output status
  output="$(adb_ shell "cd $DIR && $1; echo exit=\$?" | tr -d '\r')"
  echo "$output"
  status="$(echo "$output" | sed -n 's/^exit=//p' | tail -1)"
  [ "$status" = "0" ]
}

failed=0
run "./key_core_tests --nocapture" || failed=1
run "LD_LIBRARY_PATH=$DIR ./so_smoke" || failed=1
run "./key_core_tests --ignored --nocapture timing" || failed=1
exit "$failed"
