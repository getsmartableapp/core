//! Zeros over the stack a call into the core used.
//!
//! `bip32` keeps every key of a derivation in plain values, `secp256k1`'s
//! `SecretKey` is `Copy` with no eraser of its own, and the seed passes through
//! `bip39`'s PBKDF2 on the way in. All of it lives on the stack and stays there
//! after the call returns, until something happens to overwrite it — which on
//! a locked wallet may be never. A library's frames cannot be reached one value
//! at a time from here, so the whole area below the entry point is written
//! over instead, once per call, after the work and before the return.

use zeroize::Zeroize;

/// How far below the entry point's frame the zeros reach.
///
/// `tests::stack_use_is_well_inside_the_scrub` measures what the calls use and
/// holds it to half of this.
pub(crate) const STACK_SCRUB_BYTES: usize = 64 * 1024;

/// Writes zeros over the [`STACK_SCRUB_BYTES`] of stack below the caller.
///
/// **Called from the frame that made the call**, so this function's frame
/// starts where the call's did and its array covers what the call used. Not
/// inlined, or the array would join the caller's frame instead of lying below
/// it; the writes are volatile (`zeroize`), so they are not removed as dead.
#[inline(never)]
pub(crate) fn stack() {
    let mut area = [0u64; STACK_SCRUB_BYTES / 8];
    area.zeroize();
    core::hint::black_box(&area);
}
