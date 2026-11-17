# Changelog

All notable changes to Smartable Wallet Core are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as [docs/releasing.md](docs/releasing.md#version-numbers) applies it to this
code. Each version names the Smartable Wallet release its files were exported
from.

## [2.0.0] - 2026-11-17

Exported from Smartable Wallet 3.0.0 (build 23).

The recovery phrase's seed and every key derived from it now live in the key
core, a Rust library published here for the first time: once a wallet is
open, the Dart code holds a session with the core, not the phrase. This is
the same move from one implementation to another that a wallet core makes
when it rewrites its key handling in a lower-level language, and it is why
this is a major version. **1.0.0 and 1.0.1 are superseded by 2.0.0.** Every
record they wrote — a sealed phrase, a PIN, a device-key record, a split
backup's shares — is read and opened by this version; new work should build
on 2.0.0, and 1.0.x receives no further changes.

### Added

- The key core, `native/key_core/`: the Rust crate that holds the recovery
  phrase's seed and every key derived from it, opens the sealed phrase, and
  signs a transaction or a message only after reading it itself; its C
  interface (`include/key_core.h`), its Dart binding over `dart:ffi`
  (`dart/`), whose build hook compiles the crate offline at the pinned
  toolchain, and its tests against published vectors (THIRD_PARTY_NOTICES.md
  names each source).
- The split backup in the key core: SLIP-39 split, checked and recombined
  there, each share sealed with Argon2id (`argon2` 0.5.3) and AES-256-GCM in
  the same format the Dart code writes; a restore opens a wallet in the core
  from the shares, so the phrase is never text on the way.
- A phrase made or typed into the app is sealed in the core
  (`kc_seal_phrase`), and an imported private key is opened there from its
  record.
- Zcash's transparent keys, addresses and ZIP-244 signatures, held to six
  mainnet version 5 transactions and ZIP-320's reference addresses.
- CI runs the key core's `cargo test`, debug and release.

### Changed

- **BREAKING:** `VaultKeeper.loadSeed`, `unlockWithPin` and
  `unlockWithDeviceKey` open the wallet and return nothing; they used to
  return the recovery phrase. A caller that shows the words — for a backup —
  asks `revealPhrase(password)`, which reads them from the stored record
  behind the password.
- **BREAKING:** `VaultHost.opened` and `VaultHost.switched` receive the vault
  key, from which the host opens its key-core session, instead of the phrase.
- The `lib/core/`, `test/` and `native/` files are those of the app's
  current source. Among them: the password's PBKDF2 runs off the main
  isolate and writes over the typed secret's bytes when done
  (`crypto_utils.dart`); the vault keeper stores a phrase the key core
  sealed, for a first wallet and one added beside others, under a vault key
  it draws (`vault_keeper.dart`); the share-sealing parameters
  are read in one place, which the key core is handed
  (`sealed_share.dart`).
- The GitHub address in the README and the workflows is
  github.com/getsmartableapp/core; the repository's home stays
  gitlab.com/getsmartable-app/core.

### Security

- After an unlock the phrase is no longer kept in the app's memory as text:
  the seed is derived and every key used inside the key core, which signs a
  transaction or a message only after reading it itself. What remains of a
  typed secret is the text the platform's keyboard and text field held.
- The password's PBKDF2 runs off the main isolate and overwrites the bytes of
  the typed secret when it is done.

## [1.0.1] - 2026-10-20

Exported from Smartable Wallet 2.2.0 (build 22).

No code changed: every file under `lib/`, `native/` and `test/`, and
`pubspec.lock`, is the same as in 1.0.0. This version changes the
documentation only.

### Changed

- The repository's home is gitlab.com/getsmartable-app/core: the README's
  badges, links and clone address, the `repository` in `pubspec.yaml` and the
  address on the banner point there.
- While GitHub Actions is not running for this repository, a version is
  checked locally before it is published — `flutter analyze` and the full test
  suite on macOS — and its archive and `SHA256SUMS` are made with
  `git archive` from the tag. This version carries no provenance attestation.
- A vulnerability is reported by email only; GitHub's private vulnerability
  reporting is not available here. Bug reports and proposed changes also go by
  email.

### Fixed

- The README and the 1.0.0 entry below said every split-backup share is
  sealed under the wallet password. Shares kept on the phone and in cloud
  accounts are; a share written on paper is its own words and is not sealed.

## [1.0.0] - 2026-10-16

Exported from Smartable Wallet 2.2.0 (build 21).

### Added

- The code that keeps Smartable Wallet non-custodial on the device, published
  for the first time:
  - one form for every typed secret, Unicode NFC, then PBKDF2-HMAC-SHA256
    at 600,000 rounds — or, for a split-backup share, Argon2id with 64 MiB
    of memory per guess;
  - encrypted-only secret storage that reports a secret it cannot decrypt
    instead of deleting it;
  - each recovery phrase sealed under a random key of its own, which the
    password only wraps, and every way one is opened: the password, the PIN
    and biometric unlock;
  - the rule a password meets before anything is sealed under it: at least
    twelve characters, and not mostly a run, a repeat, a year or a common
    word;
  - the platform keys the wallet is sealed under: Android Keystore, StrongBox
    first, and the iOS Secure Enclave;
  - the app PIN: every guess a key-store operation on the phone, then sealed
    by a device key that on Android 15 and later works only while the phone is
    unlocked;
  - biometric unlock bound to a key released once per use;
  - one lockout for every password and PIN check, measured on the boot clock;
  - SLIP-39 split backup, 2-of-3 and 3-of-5, each share sealed under a key
    derived from the wallet password; a share written on paper leaves only a
    note on the phone, never its words.

[2.0.0]: https://gitlab.com/getsmartable-app/core/-/releases/v2.0.0
[1.0.1]: https://gitlab.com/getsmartable-app/core/-/releases/v1.0.1
[1.0.0]: https://gitlab.com/getsmartable-app/core/-/releases/v1.0.0
