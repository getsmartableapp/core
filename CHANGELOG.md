# Changelog

All notable changes to Smartable Wallet Core are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as [docs/releasing.md](docs/releasing.md#version-numbers) applies it to this
code. Each version names the Smartable Wallet release its files were exported
from.

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

[1.0.1]: https://gitlab.com/getsmartable-app/core/-/releases/v1.0.1
[1.0.0]: https://gitlab.com/getsmartable-app/core/-/releases/v1.0.0
