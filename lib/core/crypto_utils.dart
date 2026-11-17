import 'dart:convert';
import 'dart:isolate' show Isolate;
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg show SecretKey;
import 'package:cryptography/dart.dart' as cg show DartArgon2id;
import 'package:meta/meta.dart' show visibleForTesting;
import 'package:pointycastle/export.dart';
import 'package:webcrypto/webcrypto.dart';

import 'unicode_nfc.dart';

class CryptoUtils {
  static final _secureRandom = Random.secure();

  /// The canonical bytes of something a person typed.
  ///
  /// **The one place a typed secret becomes bytes, and the reason it is one
  /// place.** `é` written as U+00E9 and `é` written as `e` plus a combining
  /// acute are the same character on every screen and different bytes in every
  /// encoder — so without this they are different keys, and which one a
  /// keyboard produces is the keyboard's business rather than the person's.
  /// See [toNfc] for why the answer is NFC and not trimming, case folding or
  /// NFKC, each of which would merge characters somebody chose on purpose.
  ///
  /// Every password, PIN and backup passphrase in this app reaches PBKDF2
  /// through [deriveKey], or Argon2id through [deriveKeyArgon2id] for a
  /// split-backup share, and both take it from here, which is why normalising
  /// here covers creation, unlock, import, recovery, a password change, the
  /// sealed SLIP-39 shares and the account key without any caller having to
  /// remember to.
  static Uint8List canonicalSecretBytes(String secret) =>
      Uint8List.fromList(utf8.encode(toNfc(secret)));

  /// Whether two typed secrets open the same thing.
  ///
  /// **What a confirmation field is actually asking.** Not "did you press the
  /// same keys twice" but "will this open your wallet tomorrow" — and that is
  /// decided by [canonicalSecretBytes], so the comparison has to be made on
  /// the same form. Raw `==` would refuse two spellings of `é` that derive one
  /// key, and would say the passwords do not match while showing two fields
  /// that look identical, which is unanswerable.
  ///
  /// It is not a weakening: every character somebody chose is still there.
  /// Case, spaces and width all still make two secrets different.
  static bool sameSecret(String a, String b) => toNfc(a) == toNfc(b);

  /// Derive a 256-bit key from [password] and [salt] using PBKDF2-HMAC-SHA256.
  /// Uses package:webcrypto, which wraps the native Web Crypto API on web
  /// (hardware-accelerated) and BoringSSL on mobile/desktop.
  ///
  /// [password] is normalised by [canonicalSecretBytes] first. ASCII passes
  /// through unchanged, byte for byte, which is what makes this safe to add:
  /// no wallet whose password is ASCII derives a different key than it did
  /// before.
  ///
  /// **Off the calling isolate** (the owner, 14 November 2026: moving the
  /// password's PBKDF2 off the main thread — "it is needed"). BoringSSL runs
  /// the 600,000 rounds synchronously, and Dart runs on Android's main
  /// thread. Measured on the Mac's test VM that day: the first derivation in a
  /// process 0.44–1.32 s, the library being loaded with it, and each one after
  /// it about 36 ms (SHA-256 in hardware); a phone was not measured. An ANR was
  /// recorded on the emulator 7.5 s after a password was typed
  /// (`STATUS_DETAILS.md#unlock-history-warmup-anr`); that this was its cause
  /// is not shown. A background isolate runs it now; the bytes it was handed
  /// are overwritten there, and this side's copy here.
  static Future<Uint8List> deriveKey(String password, List<int> salt) async {
    final secret = canonicalSecretBytes(password);
    final saltBytes = Uint8List.fromList(salt);
    try {
      if (!deriveOffThisIsolate) return await _pbkdf2Sha256(secret, saltBytes);
      final key = await Isolate.run(() async {
        try {
          return await _pbkdf2Sha256(secret, saltBytes);
        } finally {
          secret.fillRange(0, secret.length, 0);
        }
      });
      derivedOffThisIsolate++;
      return key;
    } finally {
      secret.fillRange(0, secret.length, 0);
    }
  }

  /// Whether [deriveKey] runs on a background isolate — and the unlock's
  /// open of a sealed phrase in the key core with it (`WalletProvider`): true
  /// everywhere but in a widget test, whose fake clock never delivers an
  /// isolate's answer (`test/flutter_test_config.dart` turns it off;
  /// `crypto_utils_kdf_isolate_test` and `key_core_open_off_isolate_test` run
  /// with it on, with the real clock).
  static bool deriveOffThisIsolate = true;

  /// How many keys [deriveKey] has had worked out on another isolate. Only
  /// the test that holds it there reads it: a key is the same bytes wherever
  /// it is computed, and a warm derivation is too short for a stalled
  /// heartbeat to tell the two apart.
  @visibleForTesting
  static int derivedOffThisIsolate = 0;

  static Future<Uint8List> _pbkdf2Sha256(Uint8List secret, Uint8List salt) async {
    final pbkdf2Key = await Pbkdf2SecretKey.importRawKey(secret);
    return pbkdf2Key.deriveBits(256, Hash.sha256, salt, 600000);
  }

  /// Argon2id of [password] and [salt]: a 256-bit key that costs memory, not
  /// only time, to guess.
  ///
  /// **Why a second key derivation exists.** PBKDF2 ([deriveKey]) asks for
  /// arithmetic and nothing else, so a guessing rig spreads it across
  /// thousands of graphics-card cores. Argon2id asks each guess for
  /// [memoryKiB] of memory, written and read in an order the password decides,
  /// and that is what a graphics card has least of per core. It is used where
  /// the guessing happens away from this phone and nothing on it can slow it
  /// down: the shares of a split backup (`sealed_share.dart`).
  ///
  /// [password] is normalised by [canonicalSecretBytes], as everywhere.
  ///
  /// **`DartArgon2id` named outright**, not the package's factory, so that the
  /// implementation is the one that was measured against RFC 9106's test
  /// vector (`crypto_utils_argon2id_test`) and does not change with whatever
  /// plugin is registered. With [parallelism] above one it computes the lanes
  /// in isolates of its own, over memory shared through FFI, so the derivation
  /// does not hold the UI thread: 0.18–0.24 s for 64 MiB, three passes and four
  /// lanes, AOT on an Apple M-series laptop, measured 11 October 2026; a phone
  /// is slower and was not measured.
  static Future<Uint8List> deriveKeyArgon2id(
    String password,
    List<int> salt, {
    required int memoryKiB,
    required int iterations,
    required int parallelism,
  }) async {
    final algorithm = cg.DartArgon2id(
      parallelism: parallelism,
      memory: memoryKiB,
      iterations: iterations,
      hashLength: 32,
    );
    final key = await algorithm.deriveKey(
      secretKey: cg.SecretKey(canonicalSecretBytes(password)),
      nonce: salt,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  /// PBKDF2-HMAC-SHA512 with parameters somebody else chose.
  ///
  /// **Separate from [deriveKey], and the parameters are arguments rather than
  /// constants for one reason**: this one derives a key for a *third party's*
  /// account, where the round count, the hash and the length are theirs and
  /// changing any of them produces a login that fails. [deriveKey]'s numbers
  /// are ours and must not become negotiable by accident.
  ///
  /// It is here so the one place in this app that touches `webcrypto` stays
  /// the one place. The alternative was 550ms of pure-Dart hashing on the UI
  /// thread per sign-in, measured AOT on a desktop — seconds on a phone.
  ///
  /// **And it does not normalise, deliberately.** [canonicalSecretBytes] is
  /// this wallet's rule for this wallet's secrets. The password here is a
  /// MEGA account's, checked by MEGA's servers against bytes MEGA's own
  /// clients produced; imposing our canonical form on it would fail the login
  /// of anybody whose MEGA password is not ASCII and report it as a wrong
  /// password. Nothing derived here ever unlocks a vault.
  static Future<Uint8List> pbkdf2Sha512({
    required String password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) async {
    final key = await Pbkdf2SecretKey.importRawKey(utf8.encode(password));
    return key.deriveBits(length * 8, Hash.sha512, salt, iterations);
  }

  /// [length] bytes from the platform's secure random.
  ///
  /// Exposed because SLIP-39 needs shares and a set identifier of sizes other
  /// than 32, and a second `Random.secure()` elsewhere would be a second place
  /// somebody could quietly make deterministic.
  static Uint8List randomBytes(int length) => Uint8List.fromList(
      List<int>.generate(length, (_) => _secureRandom.nextInt(256)));

  /// A fresh 256-bit key, from the platform's secure random.
  ///
  /// This is the key a vault is actually encrypted with. It is not derived
  /// from anything a person types, which is the whole point: what somebody
  /// types can be guessed offline, and a key that exists only as bytes cannot
  /// be. The password's job becomes wrapping this, and later the phone's own
  /// secure element will hold a copy so a six-digit PIN can release it without
  /// weakening anything — six digits are safe exactly when there is nothing to
  /// brute-force offline.
  static Uint8List randomKey() => Uint8List.fromList(
      List<int>.generate(32, (_) => _secureRandom.nextInt(256)));

  /// [vaultKey] under [wrappingKey], base64, ready to store beside the vault.
  ///
  /// Wrapping rather than re-encrypting is what makes changing a password
  /// cheap: today it means decrypting every phrase and encrypting it again,
  /// so a wallet with three recovery phrases pays 600k PBKDF2 rounds three
  /// times and rewrites all of them, and a failure halfway leaves one
  /// half-openable. With the key wrapped, a password change touches 32 bytes
  /// per vault and the phrases are never decrypted at all.
  static String wrapKey(Uint8List vaultKey, Uint8List wrappingKey) =>
      base64Encode(encrypt(base64Encode(vaultKey), wrappingKey));

  static Uint8List unwrapKey(String wrapped, Uint8List wrappingKey) =>
      Uint8List.fromList(base64Decode(decrypt(base64Decode(wrapped), wrappingKey)));

  static Uint8List encrypt(String plaintext, Uint8List key) {
    final input = Uint8List.fromList(utf8.encode(plaintext));
    return encryptBytes(input, key);
  }

  static String decrypt(List<int> encryptedData, Uint8List key) {
    final plain = decryptBytes(encryptedData, key);
    try {
      return utf8.decode(plain);
    } finally {
      plain.fillRange(0, plain.length, 0);
    }
  }

  /// [encrypt] for bytes: AES-256-GCM, a fresh 12-byte nonce in front.
  ///
  /// **For a secret that must never become a `String`** — an imported key,
  /// sealed on its own (`docs/RUST_KEY_CORE_DESIGN.md#phase-5b`): a `String`
  /// cannot be written over, and [encrypt]'s argument already is one. The
  /// cipher's own output buffer is written over once it has been copied.
  static Uint8List encryptBytes(Uint8List plain, Uint8List key) {
    final nonce = Uint8List.fromList(
        List<int>.generate(12, (i) => _secureRandom.nextInt(256)));
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
    final out = Uint8List(cipher.getOutputSize(plain.length));
    var len = cipher.processBytes(plain, 0, plain.length, out, 0);
    len += cipher.doFinal(out, len);
    return Uint8List.fromList(nonce + out.sublist(0, len));
  }

  /// [decrypt] for bytes: what [encryptBytes] sealed, as bytes the caller
  /// writes over when done. Throws when [key] is not the one it was sealed
  /// under, or the data was changed.
  static Uint8List decryptBytes(List<int> encryptedData, Uint8List key) {
    final nonce = Uint8List.fromList(encryptedData.sublist(0, 12));
    final ciphertext = Uint8List.fromList(encryptedData.sublist(12));
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
    final out = Uint8List(cipher.getOutputSize(ciphertext.length));
    try {
      var len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
      len += cipher.doFinal(out, len);
      return Uint8List.fromList(out.sublist(0, len));
    } finally {
      out.fillRange(0, out.length, 0);
    }
  }
}
