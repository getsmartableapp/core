# starknet-crypto 0.8.1, modified by Smartable

This is `starknet-crypto` 0.8.1 as published on crates.io by Jonathan LEI
(https://github.com/xJonathanLEI/starknet-rs), licensed MIT OR Apache-2.0, with
these changes made on 17 November 2026:

- `src/rfc6979.rs` and the `rfc6979_generate_k` export in `src/lib.rs` are
  removed, with the benchmark that used them;
- the dependencies only that file used — `crypto-bigint` 0.5, `hmac`,
  `rfc6979`, `sha2` and `zeroize` — are removed from `Cargo.toml`.

Why: `crypto-bigint` before 0.7.6 is affected by RUSTSEC-2026-0387 (operations
meant to be constant-time could branch on secret values), the nonce is a
secret, and no release of `starknet-crypto` depends on a fixed version. The key
core makes the same nonce itself (`keys::stark_nonce`, on `crypto-bigint`
0.7.10 and `rfc6979` 0.4.0's HMAC-DRBG) and passes it to `sign`. Every other
file is unchanged; the curve, signing and verification are the crate's own.
