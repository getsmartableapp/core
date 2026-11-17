#!/usr/bin/env bash
# Runs the crate's tests, and so_smoke.c over the simulator library, on an iOS
# simulator: dyld, the simulator's libSystem and its threads' stacks, rather
# than the host's.
#
#   native/key_core/tool/test_on_ios_simulator.sh
#
# Creates an iPhone simulator of its own on the newest iOS runtime this
# Xcode can run, boots it, runs the binaries where they were built (a simulator
# process reads the Mac's files, so nothing is copied into it), and deletes
# the simulator on the way out. Touches no other simulator, no app and no
# Keychain. Offline and locked, like the Android scripts. Exits non-zero if a
# run fails.
set -euo pipefail

cd "$(dirname "$0")/.."

# rustup installs nothing it was not asked for by name.
export RUSTUP_AUTO_INSTALL=0
TRIPLE=aarch64-apple-ios-sim
# The simulator on Apple silicon starts at iOS 14.
export IPHONEOS_DEPLOYMENT_TARGET=14.0
# Apple's linker strips, not rustc, as hook/build.dart has it: rustc's strip
# left the string table misaligned and `ld` refused to link so_smoke.
export CARGO_PROFILE_RELEASE_STRIP=none
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="-C link-arg=-Wl,-x -C link-arg=-Wl,-S"
OUT="$PWD/target/ios-sim"

cargo build --release --offline --locked --target "$TRIPLE"
tests="$(cargo test --release --offline --locked --target "$TRIPLE" \
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
mkdir -p "$OUT"
cp "target/$TRIPLE/release/libkey_core.dylib" "$OUT/"
xcrun --sdk iphonesimulator clang -target arm64-apple-ios14.0-simulator \
  -std=c11 -Wall -Werror -Iinclude tool/so_smoke.c \
  -L"$OUT" -lkey_core -Wl,-rpath,"$OUT" -o "$OUT/so_smoke"

# The newest iOS runtime Xcode can run, and the first iPhone it supports: a
# runtime runs only the devices it lists (iOS 27.1 lists no iPhone 17).
read -r runtime device < <(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
ios = [r for r in json.load(sys.stdin)["runtimes"]
       if r.get("platform") == "iOS" and r.get("isAvailable")]
phones = [d["identifier"] for d in (ios[-1]["supportedDeviceTypes"] if ios else [])
          if d.get("productFamily") == "iPhone"]
print(ios[-1]["identifier"], phones[0]) if phones else print()
')
[ -n "${device:-}" ] || {
  echo "no available iOS simulator runtime with an iPhone" >&2
  exit 1
}
udid="$(xcrun simctl create key-core-check "$device" "$runtime")"
trap 'xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
      xcrun simctl delete "$udid" >/dev/null 2>&1 || true' EXIT
xcrun simctl bootstatus "$udid" -b >/dev/null

echo "simulator $udid: $(xcrun simctl list devices -j | python3 -I -c '
import json, sys
for runtime, devices in json.load(sys.stdin)["devices"].items():
    for d in devices:
        if d["udid"] == sys.argv[1]:
            print(runtime.rsplit(".", 1)[-1], d["state"])
' "$udid")"

failed=0
xcrun simctl spawn "$udid" "$tests" --nocapture || failed=1
xcrun simctl spawn "$udid" "$OUT/so_smoke" || failed=1
xcrun simctl spawn "$udid" "$tests" --ignored --nocapture timing || failed=1
exit "$failed"
