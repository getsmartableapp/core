# shellcheck shell=bash
# Sourced by the Android scripts here: the NDK the app builds with, the app's
# floor, and the variables Cargo and the `cc` crate read for one target.

# Flutter 3.44.8's `flutter.ndkVersion`, which android/app/build.gradle uses.
NDK_VERSION="28.2.13676358"
# android/app/build.gradle's minSdk.
API=30
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/$NDK_VERSION}"
LLVM="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"
BIN="$LLVM/bin"
[ -x "$BIN/aarch64-linux-android$API-clang" ] || {
  echo "NDK $NDK_VERSION not found at $NDK" >&2
  exit 1
}

# rustup installs nothing it was not asked for by name.
export RUSTUP_AUTO_INSTALL=0

# android_target <Rust triple> <the NDK's clang prefix for it>
#
# The linker, and the C compiler `cc` uses for libsecp256k1, both the NDK's
# clang for API $API; pages aligned to 16 KiB, which Android 15 and later need
# on devices with 16 KiB pages.
android_target() {
  local triple="$1" clang="$2" upper
  upper="$(echo "$triple" | tr '[:lower:]-' '[:upper:]_')"
  export "CARGO_TARGET_${upper}_LINKER=$BIN/$clang$API-clang"
  export "CARGO_TARGET_${upper}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384"
  export "CC_${triple//-/_}=$BIN/$clang$API-clang"
  export "AR_${triple//-/_}=$BIN/llvm-ar"
}
