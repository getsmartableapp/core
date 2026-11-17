# Third-party notices

What in this repository came from somebody else, and what its licence asks in
return. Everything else is the project's own work under the Apache License,
Version 2.0 — see [LICENSE](LICENSE).

## SLIP-39 word list and test vectors

- **In:** `lib/core/slip39_wordlist.dart` and, written out from it,
  `native/key_core/src/slip39_wordlist.rs` (the word list); and
  `test/support/slip39_vectors.json` (the vectors `test/slip39_test.dart` and
  the key core's `src/slip39.rs` tests read)
- **Source:** [trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic)
- **Licence:** MIT. Copyright 2019 SatoshiLabs.
- **Licence text:** [`LICENSES/MIT-python-shamir-mnemonic.txt`](LICENSES/MIT-python-shamir-mnemonic.txt)

The word list is part of the SLIP-39 format: a share is written in exactly
these 1,024 words, so it is reproduced rather than rewritten. The vectors hold
the implementation to SatoshiLabs' own answers — valid shares, invalid shares,
identifiers, indexes and digest failures.

## Unicode normalization test cases

- **In:** `test/fixtures/unicode/normalization_vectors.txt`
- **Source:** [`NormalizationTest.txt`](https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt),
  Unicode 17.0.0, published by the Unicode Consortium. The file here is a
  subset — parts 0, 3 and 5 whole, parts 1, 2 and 4 every 25th case — as its
  header says.
- **Licence:** Unicode License v3. Copyright © 1991-2026 Unicode, Inc.
- **Licence text:** [`LICENSES/Unicode-3.0.txt`](LICENSES/Unicode-3.0.txt)

Every password, PIN and backup passphrase is normalised to NFC before a key is
derived from it, so the normaliser decides which bytes a secret becomes. These
cases hold it to the Unicode Consortium's own conformance data.

## Test vectors in the key core

- **In:** `native/key_core/src/vectors.rs`, written by
  `native/key_core/tool/generate_vectors.py` (whose docstring names each file
  and its SHA-256), and a few vectors written out in
  `native/key_core/src/tests.rs`. Compiled into the tests only
  (`#[cfg(test)]`); nothing below is in a built library.

The key core is held to answers it did not write. Each set is taken from
the source below, which keeps its own licence:

| Vectors | Taken from | Licence of the source |
|---|---|---|
| BIP-39 seeds and master keys | [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic)'s English vectors, as the Dart `bip39` 1.0.6 package ships them | MIT, Copyright (c) 2013-2016 Pavol Rusnak; the package BSD-3-Clause, Copyright 2018 anicdh |
| BIP-32 keys | [bitcoinjs/bip32](https://github.com/bitcoinjs/bip32)'s `fixtures.json`, as the Dart `bip32` 2.0.0 package ships it | MIT, Copyright (c) 2011-2018 bitcoinjs-lib contributors; the package MIT, Copyright (c) 2018 anicdh |
| BIP-340 signatures | RustCrypto's `k256` 0.14.0, `src/schnorr.rs` | Apache-2.0 OR MIT |
| SLIP-10 ed25519 | [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), test vectors 1 and 2 | CC BY-SA 4.0, SatoshiLabs |
| RFC 8032 Ed25519 | Cryspen's `libcrux-ed25519` 0.0.9, `tests/ed25519.rs` (RFC 8032 §7.1) | Apache-2.0 |
| Cardano master keys | [CIP-0003](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0003), its Ledger and Icarus vectors | CC BY 4.0, the CIP's authors |
| BIP32-Ed25519 child and signature | `ed25519-bip32` 0.5.0, `src/tests.rs` | MIT OR Apache-2.0 |
| BIP-143 signature hashes | `bitcoin` 0.32.102, `src/crypto/sighash.rs` (BIP-143's own examples) | CC0-1.0 |
| BIP-341 key-path spends | [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)'s `wallet-test-vectors.json` | BSD-3-Clause, the BIP's authors |
| Legacy signature hashes | Bitcoin Core's `src/test/data/sighash.json`, every fifth case | MIT, Copyright (c) 2009-2026 The Bitcoin Core developers, Copyright (c) 2009-2026 Bitcoin Developers |
| Bitcoin Cash signature hashes | Bitcoin Cash Node's `src/test/data/sighash.json`, every fifth and tenth case | MIT, Copyright (c) 2009-2025 The Bitcoin developers, Copyright (c) 2009-2017 The Bitcoin Core developers |
| EIP-712 typed data | `alloy-dyn-abi` 1.7.3, `src/eip712/typed_data.rs` | MIT OR Apache-2.0 |
| EIP-191 hash and signature | `alloy-primitives` 1.7.3 and `alloy-signer-local` 2.5.0, quoting web3.js's documentation | MIT OR Apache-2.0 |
| Stark keys by EIP-2645 paths, and the grind | StarkWare's [starkex-resources](https://github.com/starkware-libs/starkex-resources), `crypto/starkware/crypto/signature/test/key_derivation_test.js` | Apache-2.0, Copyright 2019 StarkWare Industries Ltd. |
| A Stark public key | `starknet-crypto` 0.8.1, `src/ecdsa.rs` (`test_get_public_key_1`) | MIT OR Apache-2.0 |
| Stark curve RFC 6979 nonces | [starknet-rs](https://github.com/xJonathanLEI/starknet-rs)'s `starknet-crypto/test-data/rfc6979_padded.json` and `rfc6979_not_padded.json` at the tag `starknet-crypto/v0.8.1`, generated from cairo-lang | MIT OR Apache-2.0 |
| A transparent Zcash address and its TEX form | [ZIP-320](https://zips.z.cash/zip-0320)'s reference pair | MIT, the ZIP's owners (Daira-Emma Hopwood, Kris Nuttycombe) |
| Zcash signature digests and transaction ids | Six transparent version 5 transactions from Zcash's mainnet (heights 3,576,097 to 3,576,132) and the coins they spend, as zec.rocks' lightwalletd served them on 15 November 2026 — the network's own record, verified by the signatures in them | Public blockchain data |

## Dependencies

The packages named in `pubspec.yaml` are fetched by `flutter pub get` and are
not redistributed in this repository. Each keeps its own licence, and
`flutter pub deps` lists them. The same holds for the key core's crates: Cargo
fetches them at the versions `native/key_core/Cargo.lock` locks, and none is
copied here but one. A build that ships the key core carries their notices —
the Smartable app lists them on its licence page.

The one copied: **`native/key_core/vendor/starknet-crypto`** is
`starknet-crypto` 0.8.1 by Jonathan LEI
([starknet-rs](https://github.com/xJonathanLEI/starknet-rs), MIT OR
Apache-2.0, used here under Apache-2.0), with its RFC 6979 module, that
module's benchmark and the five dependencies only it used removed; the key
core makes the nonce itself. `SMARTABLE.md` beside it says what changed and
why (RUSTSEC-2026-0387).

One is named here although the others are not: **`unorm_dart`** (MIT,
Copyright 2018 Yasuhiro Shimizu, a Dart port of
[walling/unorm](https://github.com/walling/unorm)) normalises every secret
before PBKDF2 sees it. A reviewer reading `crypto_utils.dart` should not have
to resolve a package to learn whose code that is. It is pinned to an exact
version for the same reason.
