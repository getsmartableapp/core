#!/usr/bin/env bash
# Reads back what tool/build_android.sh made, rather than trusting its flags:
#
#   - each library is the ABI it is filed under;
#   - every LOAD segment is aligned to at least 16 KiB;
#   - it exports the fifty-six kc_* functions of include/key_core.h, no others;
#   - every symbol it needs from the system is in the NDK's API 30 stubs, so
#     it loads on the app's floor and not only on the phone it was tried on;
#   - it needs no library but libc, libm and libdl.
#
#   native/key_core/tool/check_android.sh [target-dir]   # default: target
set -euo pipefail

cd "$(dirname "$0")/.."
. tool/android_env.sh
TARGET_DIR="${1:-target}"
SYSROOT="$LLVM/sysroot/usr/lib"

EXPECTED_EXPORTS="kc_abi_version kc_algorand_read_transaction kc_aptos_read_transaction kc_bitcoin_read_transaction kc_bitcoin_sign_transaction kc_cardano_export_private_key kc_cardano_icarus_public_key kc_cardano_public_key kc_cardano_read_transaction \
kc_cardano_sign kc_close kc_close_all kc_cosmos_read_sign_doc \
kc_ed25519_export_private_key kc_ed25519_public_key kc_ed25519_sign kc_evm_read_transaction kc_evm_read_typed_data kc_evm_sign_personal_message kc_evm_sign_typed_data kc_filecoin_read_message kc_icp_read_call kc_kaspa_read_transaction kc_kaspa_sign_transaction \
kc_matches_phrase kc_matches_session kc_multiversx_read_transaction kc_near_read_transaction kc_open kc_open_key kc_open_sealed kc_open_sealed_key kc_polkadot_read_transaction \
kc_seal_phrase kc_secp256k1_export_private_key kc_secp256k1_extended_public_key kc_secp256k1_public_key kc_secp256k1_schnorr_sign \
kc_secp256k1_sign_digest kc_secp256k1_sign_digest_low_r kc_secp256k1_sign_evm_transaction kc_slip39_backup kc_slip39_check kc_slip39_restore kc_solana_read_message \
kc_starknet_export_private_key kc_starknet_public_key kc_starknet_read_transaction kc_starknet_sign kc_stellar_read_transaction kc_sui_read_transaction kc_tezos_read_operation kc_ton_read_transfer kc_tron_read_transaction \
kc_xrpl_read_transaction kc_xrpl_sign_transaction kc_zcash_read_transaction kc_zcash_sign_transaction"

failures=0
fail() {
  echo "  FAIL: $*"
  failures=$((failures + 1))
}

for row in \
  "arm64-v8a aarch64-linux-android AArch64" \
  "armeabi-v7a arm-linux-androideabi ARM" \
  "x86_64 x86_64-linux-android X86-64"; do
  read -r abi stubs machine <<<"$row"
  so="$TARGET_DIR/android/$abi/libkey_core.so"
  echo "$abi: $so"
  [ -f "$so" ] || { fail "missing"; continue; }

  # Read into a variable first: `grep -q` quits at the first match, and under
  # pipefail the reader it cut off would count as a failure.
  header="$("$LLVM/bin/llvm-readelf" -h "$so")"
  grep -q "Machine:.*$machine" <<<"$header" || fail "not $machine"

  while read -r align; do
    [ $((align)) -ge 16384 ] || fail "a LOAD segment aligned to $align"
  done < <("$LLVM/bin/llvm-readelf" -lW "$so" | awk '$1 == "LOAD" {print $NF}')

  exports="$("$LLVM/bin/llvm-nm" -D --defined-only "$so" |
    awk '$2 == "T" {print $3}' | grep -v '^rustsecp256k1_' | sort | tr '\n' ' ' | sed 's/ $//')"
  [ "$exports" = "$EXPECTED_EXPORTS" ] ||
    fail "exports are: $exports"

  needed="$("$LLVM/bin/llvm-readelf" -dW "$so" | awk '/NEEDED/ {print $NF}' | tr -d '[]' | sort | tr '\n' ' ')"
  for lib in $needed; do
    case "$lib" in libc.so | libm.so | libdl.so) ;; *) fail "needs $lib" ;; esac
  done

  available="$(for lib in libc.so libm.so libdl.so; do
    "$LLVM/bin/llvm-nm" -D --defined-only "$SYSROOT/$stubs/$API/$lib" | awk '{print $NF}'
  done | sed 's/@.*//' | sort -u)"
  missing=0
  while read -r symbol; do
    [ -n "$symbol" ] || continue
    grep -qx "$symbol" <<<"$available" || {
      fail "$symbol is not in API $API"
      missing=$((missing + 1))
    }
  done < <("$LLVM/bin/llvm-nm" -D --undefined-only "$so" | awk '{print $NF}' | sed 's/@.*//' | sort -u)
  count="$("$LLVM/bin/llvm-nm" -D --undefined-only "$so" | wc -l | tr -d ' ')"
  echo "  $(wc -c <"$so" | tr -d ' ') bytes; needs: $needed; $count system symbols, $missing missing at API $API"
done

if [ "$failures" -ne 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all three libraries pass"
