import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/crypto_utils.dart';
import 'package:smartable_wallet_core/core/hardware_key.dart';
import 'package:smartable_wallet_core/core/password_recovery.dart';
import 'package:smartable_wallet_core/core/pin_lock.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';
import 'package:smartable_wallet_core/core/seed_vault.dart';
import 'package:smartable_wallet_core/core/vault_keeper.dart';
import 'package:smartable_wallet_core/core/wallet_doors.dart';

import 'support/fake_pin_pepper.dart';

/// The keeper on its own, with no wallet in front of it.
///
/// **Why a file of its own when the wallet's tests already go through it.**
/// Those tests reach the keeper through `WalletProvider`, which the published
/// core does not carry — so in the core they do not exist, and the code that
/// seals a phrase would be published with nothing there running it. These are
/// the same properties asked of the keeper directly, through a host that does
/// nothing but record what it was told.
void main() {
  useFakePinPepper();
  TestWidgetsFlutterBinding.ensureInitialized();

  const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
      'abandon abandon abandon abandon about';
  const otherPhrase =
      'legal winner thank year wave sausage worth useful legal winner thank '
      'yellow';
  const password = 'correct horse battery';
  const next = 'a different long password';
  const pin = '246813';

  const deviceChannel = MethodChannel('test.vault_keeper_device_key');
  DeviceKey.channel = deviceChannel;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    resetWalletDoorsForTest();
    var alive = true;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(deviceChannel, (call) async {
      final bytes = call.arguments?['bytes'] as Uint8List?;
      switch (call.method) {
        case 'isSupported':
          return true;
        case 'wrap':
          return Uint8List.fromList([9, ...bytes!]);
        case 'unwrap':
          if (!alive) throw PlatformException(code: 'key_gone');
          return Uint8List.fromList(bytes!.sublist(1));
        case 'forget':
          alive = false;
          return null;
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(deviceChannel, null);
  });

  Future<SeedVault> storedVault() async =>
      SeedVault.decode(await SecureStorage.getSeedVaults()).single;

  /// A wallet saved under [password] and then dropped from memory, which is
  /// how the create flow leaves it.
  Future<void> sealed() async {
    final host = _Host()..phrase = phrase;
    await VaultKeeper(host).saveSeed(phrase, password,
        accountSpan: 1, derivedCount: 1, backedUp: false);
  }

  /// The phrase a fresh keeper's wallet is opened on through [door], as the
  /// host decrypts it from the record and key it is handed (phase 6b: an
  /// unlock returns no phrase).
  Future<String?> openedBy(Future<void> Function(VaultKeeper keeper) door) async {
    final host = _Host();
    await door(VaultKeeper(host));
    return host.phrase;
  }

  /// [sealed], then opened by the password, as an unlock leaves it.
  Future<(VaultKeeper, _Host)> opened() async {
    await sealed();
    final host = _Host();
    final keeper = VaultKeeper(host);
    await keeper.loadSeed(password);
    return (keeper, host);
  }

  group('a phrase is sealed under a key nobody typed', () {
    test('the password unwraps that key, and opens nothing by itself', () async {
      await sealed();
      final vault = await storedVault();
      final derived =
          await CryptoUtils.deriveKey(password, base64Decode(vault.salt));

      expect(vault.wrappedKey, isNotNull);
      expect(
          () => CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), derived),
          throwsA(anything),
          reason: 'a phrase under the password is a phrase guessable offline');
      final vaultKey = CryptoUtils.unwrapKey(vault.wrappedKey!, derived);
      expect(CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), vaultKey),
          phrase);
      expect(await SecureStorage.getEncryptedSeed(), isNull,
          reason: 'no copy is kept under the password for an older build');
    });

    test('saving drops the keys and what the wallet derived', () async {
      final host = _Host()..phrase = phrase;
      final keeper = VaultKeeper(host);
      await keeper.saveSeed(phrase, password,
          accountSpan: 1, derivedCount: 1, backedUp: false);

      expect(host.forgets, 1);
      expect(host.phrase, isNull);
      expect(keeper.holdsAccountKey, isFalse);
      expect(keeper.canArmQuickUnlock, isFalse);
      expect(keeper.vaults, hasLength(1),
          reason: 'the records stay; only what they open goes');
    });

    test('a password too short is refused before anything is stored',
        () async {
      expect(() => VaultKeeper.requireSealablePassword('short'),
          throwsException);
      await expectLater(
          VaultKeeper(_Host()..phrase = phrase).saveSeed(phrase, 'short',
              accountSpan: 1, derivedCount: 1, backedUp: false),
          throwsException);
      expect(await SecureStorage.getSeedVaults(), isNull);
    });
  });

  group('the password opens it, and nothing else does', () {
    test('the right one opens the phrase and hands it to the wallet', () async {
      final (keeper, host) = await opened();

      expect(host.openedOn.single, ('primary', phrase));
      expect(keeper.activeVaultId, 'primary');
      expect(keeper.holdsAccountKey, isTrue);
      expect(await keeper.verifyPassword(password), isTrue);
      expect(await keeper.verifyPassword('not the password'), isFalse);
    });

    test('a wrong one is WrongPassword, and the wallet is told nothing',
        () async {
      await sealed();
      final host = _Host();
      await expectLater(VaultKeeper(host).loadSeed('not the password'),
          throwsA(isA<WrongPassword>()));
      expect(host.openedOn, isEmpty);
    });
  });

  group('changing the password', () {
    test('re-wraps the vault key and never touches the phrase', () async {
      final (keeper, _) = await opened();
      final before = await storedVault();

      await keeper.changePassword(password, next);
      final after = await storedVault();

      expect(after.encryptedSeed, before.encryptedSeed,
          reason: 'the vault key is kept; only its wrapper changes');
      expect(after.salt, isNot(before.salt));
      await expectLater(VaultKeeper(_Host()).loadSeed(password),
          throwsA(isA<WrongPassword>()));
      expect(await openedBy((k) => k.loadSeed(next)), phrase);
    });

    test('a wrong current password is counted as one and writes nothing',
        () async {
      final (keeper, _) = await opened();
      final before = await SecureStorage.getSeedVaults();

      await expectLater(keeper.changePassword('not the password', next),
          throwsA(isA<WrongPassword>()));
      expect(await SecureStorage.getSeedVaults(), before);
    });

    test('the account key survives it, so imported keys still open', () async {
      final (keeper, _) = await opened();
      final imported = keeper.encryptWithAccountKey('imported keys');

      await keeper.changePassword(password, next);
      final again = VaultKeeper(_Host());
      await again.loadSeed(next);

      expect(again.decryptWithAccountKey(imported), 'imported keys');
    });
  });

  group('several phrases, one password', () {
    test('every phrase opens with it, and switching asks for nothing',
        () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);

      await keeper.switchVault(second.id);
      expect(host.switchedTo.single, (second.id, otherPhrase));

      // The next unlock opens on the wallet used last, and the other is a
      // switch away.
      final nextHost = _Host();
      final nextKeeper = VaultKeeper(nextHost);
      await nextKeeper.loadSeed(password);
      expect(nextHost.phrase, otherPhrase);
      await nextKeeper.switchVault('primary');
      expect(nextHost.switchedTo.single, ('primary', phrase));
    });

    test('the same phrase twice is refused', () async {
      final (keeper, _) = await opened();
      await expectLater(keeper.addVault(phrase, password), throwsException);
      expect(keeper.vaults, hasLength(1));
    });

    test('removing the open one lands on another, and the last one stays',
        () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);

      await keeper.removeVault('primary');
      expect(keeper.vaults.map((v) => v.id), [second.id]);
      expect(host.switchedTo.single, (second.id, otherPhrase));

      await expectLater(keeper.removeVault(second.id), throwsException);
      expect(keeper.vaults, hasLength(1));
    });
  });

  group('the host is handed the key to the record it opens', () {
    // Phase 6a (`docs/RUST_KEY_CORE_DESIGN.md#phase-6`): a build that signs
    // in the key core opens the phrase from the vault's record and this key,
    // so on every door the key must open that record to that phrase.
    void expectKeysOpenTheirRecords(_Host host, int count) {
      expect(host.handed, hasLength(count));
      for (final (vault, mnemonic, key) in host.handed) {
        expect(CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), key),
            mnemonic,
            reason: vault.id);
      }
    }

    test('by the password, and on a switch to a wallet it opened', () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.switchVault(second.id);
      await keeper.switchVault('primary');
      expectKeysOpenTheirRecords(host, 3);
      expect(host.handed.map((h) => h.$2),
          [phrase, otherPhrase, phrase]);
    });

    test('by the PIN, the device key, and the password for one more wallet',
        () async {
      // The secure element, standing in: the same sealing-by-a-byte the PIN's
      // device key gets above.
      final platform = HardwareKey.channel;
      HardwareKey.channel = deviceChannel;
      addTearDown(() => HardwareKey.channel = platform);
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      expect(await keeper.armPinUnlock(pin), isTrue);
      expect(await keeper.armDeviceUnlock(), isTrue);

      final byPin = _Host();
      final pinKeeper = VaultKeeper(byPin);
      await pinKeeper.unlockWithPin(pin);
      await pinKeeper.openVaultWithPassword(second.id, password);
      expectKeysOpenTheirRecords(byPin, 2);

      final byDevice = _Host();
      await VaultKeeper(byDevice).unlockWithDeviceKey();
      expectKeysOpenTheirRecords(byDevice, 1);
    });
  });

  group('the PIN', () {
    test('seals the two keys and never the phrase', () async {
      final (keeper, _) = await opened();
      expect(await keeper.armPinUnlock(pin), isTrue);
      expect(pinArmedAsObserved, isTrue);

      final plain = utf8.decode(
          await PinLock.open((await SecureStorage.getPinBlob())!, pin));
      final payload = jsonDecode(plain) as Map<String, dynamic>;
      expect(payload.keys.toSet(), {'vault', 'key', 'enc'});
      expect(payload['vault'], 'primary');
      expect(plain, isNot(contains('abandon')));
    });

    test('opens the same wallet the password opens, imported keys and all',
        () async {
      final (keeper, _) = await opened();
      final imported = keeper.encryptWithAccountKey('imported keys');
      await keeper.armPinUnlock(pin);

      final host = _Host();
      final byPin = VaultKeeper(host);
      await byPin.unlockWithPin(pin);
      expect(host.openedOn.single, ('primary', phrase));
      expect(byPin.decryptWithAccountKey(imported), 'imported keys');
      await expectLater(VaultKeeper(_Host()).unlockWithPin('000000'),
          throwsA(isA<WrongPin>()));
    });

    test('opens one wallet, not every wallet', () async {
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.armPinUnlock(pin);

      final host = _Host();
      final byPin = VaultKeeper(host);
      await byPin.unlockWithPin(pin);

      await expectLater(
          byPin.switchVault(second.id), throwsA(isA<VaultLocked>()));
      await expectLater(byPin.openVaultWithPassword(second.id, 'nope'),
          throwsA(isA<WrongPassword>()));
      await byPin.openVaultWithPassword(second.id, password);
      expect(host.switchedTo.single, (second.id, otherPhrase));
    });

    test('disarmed, it opens nothing', () async {
      final (keeper, _) = await opened();
      await keeper.armPinUnlock(pin);

      await keeper.disarmPinUnlock();
      expect(await keeper.hasPin(), isFalse);
      expect(pinArmedAsObserved, isFalse);
      await expectLater(VaultKeeper(_Host()).unlockWithPin(pin),
          throwsA(isA<HardwareKeyUnavailable>()));
    });
  });

  group('a forgotten password, replaced by the PIN', () {
    test('is offered only when this device can finish the job', () async {
      final (keeper, host) = await opened();
      await keeper.addVault(otherPhrase, password);
      expect(await keeper.passwordRecoveryOffer(), PasswordRecoveryOffer.none,
          reason: 'no quick unlock to prove anything with');

      await keeper.armPinUnlock(pin);
      expect(await keeper.passwordRecoveryOffer(),
          PasswordRecoveryOffer.available);

      host.phraseAccount = false;
      expect(await keeper.passwordRecoveryOffer(), PasswordRecoveryOffer.none,
          reason: 'a watched or imported account is not the phrase');

      // After a PIN unlock only that wallet's phrase is open.
      final byPin = VaultKeeper(_Host());
      await byPin.unlockWithPin(pin);
      expect(await byPin.passwordRecoveryOffer(),
          PasswordRecoveryOffer.otherWalletsClosed);
    });

    test('is bound to the wallet the PIN opens', () async {
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.armPinUnlock(pin);

      await keeper.switchVault(second.id);
      await expectLater(
          keeper.resetPasswordWithPin(pin, next),
          throwsA(predicate((e) => '$e'.contains('different wallet'))),
          reason: 'six digits armed on one wallet must not reseal another');

      await keeper.switchVault('primary');
      await keeper.resetPasswordWithPin(pin, next);
      expect(await openedBy((k) => k.loadSeed(next)), phrase);
    });
  });

  group('a wallet with no password yet', () {
    test('is opened by the PIN until it is given one', () async {
      final host = _Host()..phrase = phrase;
      final keeper = VaultKeeper(host);
      await keeper.saveSeedWithoutPassword(phrase,
          accountSpan: 1, derivedCount: 1, backedUp: false);

      expect(keeper.hasPassword, isFalse);
      expect(await VaultKeeper.storedWalletHasPassword(), isFalse);
      expect(await keeper.armPinUnlock(pin), isTrue);

      await keeper.setPassword(password);
      expect(await VaultKeeper.storedWalletHasPassword(), isTrue);
      expect(await openedBy((k) => k.loadSeed(password)), phrase);
      expect(await openedBy((k) => k.unlockWithPin(pin)), phrase);
    });
  });

  group('records', () {
    test('a change to a record may not touch its seal', () async {
      final (keeper, _) = await opened();
      final before = await SecureStorage.getSeedVaults();

      await expectLater(
          keeper.updateVault('primary', (v) => v.copyWith(salt: 'AAAA')),
          throwsArgumentError);
      expect(await SecureStorage.getSeedVaults(), before);

      await keeper.updateVault('primary', (v) => v.copyWith(label: 'Savings'));
      expect((await storedVault()).label, 'Savings');
    });
  });

  group('locking', () {
    test('forgets every key, every phrase and which vaults exist', () async {
      final (keeper, host) = await opened();

      keeper.lock();

      expect(keeper.vaults, isEmpty);
      expect(keeper.activeVaultId, isNull);
      expect(keeper.holdsAccountKey, isFalse);
      expect(keeper.canArmQuickUnlock, isFalse);
      expect(host.forgets, 1);
      expect(await keeper.armPinUnlock(pin), isFalse,
          reason: 'nothing is held to seal');
    });
  });

  group('no phrase in the keeper (phase 6b)', () {
    // `docs/RUST_KEY_CORE_DESIGN.md#phase-6b`: the keeper holds keys, hands
    // the host a record and its key, and decrypts a phrase only for the two
    // screens that show or split it.
    bool zero(Uint8List key) => key.every((b) => b == 0);

    test('a wrapped vault is proved by its key, the record not opened',
        () async {
      final (keeper, host) = await opened();
      expect(host.sealOpensAsked, 0, reason: 'the unlock');
      expect(await keeper.verifyPassword(password), isTrue);
      expect(await keeper.verifyPassword('not the password'), isFalse);
      await keeper.changePassword(password, next);
      expect(host.sealOpensAsked, 0, reason: 'the gates and the change');
    });

    test('a vault sealed before wrapping is proved by the host', () async {
      final salt = List<int>.generate(16, (i) => i + 3);
      final derived = await CryptoUtils.deriveKey(password, salt);
      await SecureStorage.saveSeedVaults(SeedVault.encode([
        SeedVault(
          id: 'primary',
          encryptedSeed: base64Encode(CryptoUtils.encrypt(phrase, derived)),
          salt: base64Encode(salt),
        ),
      ]));
      final host = _Host();
      final keeper = VaultKeeper(host);
      await keeper.loadSeed(password);
      expect(host.phrase, phrase);
      expect(host.sealOpensAsked, 1);
      expect(await keeper.verifyPassword('not the password'), isFalse);
      expect(host.sealOpensAsked, 2);

      // O31: re-wrapped, its key and its record kept.
      await keeper.changePassword(password, next);
      final after = await storedVault();
      expect(after.wrappedKey, isNotNull);
      expect(CryptoUtils.unwrapKey(after.wrappedKey!,
              await CryptoUtils.deriveKey(next, base64Decode(after.salt))),
          derived);
      expect(await openedBy((k) => k.loadSeed(next)), phrase);
    });

    test('the phrase is revealed for the password, and nothing is opened',
        () async {
      final (keeper, host) = await opened();
      expect(await keeper.revealPhrase(password), phrase);
      await expectLater(keeper.revealPhrase('not the password'),
          throwsA(isA<WrongPassword>()));
      expect(host.openedOn, hasLength(1), reason: 'only the unlock');
      // The password is the gate, not an open wallet — as the unlock was.
      keeper.lock();
      expect(await keeper.revealPhrase(password), phrase);
      expect(host.openedOn, hasLength(1));
    });

    test('a lock writes over every key it held', () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.switchVault(second.id);
      expect(host.keysAsHanded.any(zero), isFalse);
      keeper.lock();
      expect(host.keysAsHanded.every(zero), isTrue);
    });
  });

  group('only the active wallet open (O28)', () {
    // A build that keeps the phrase in the key core.
    Future<(VaultKeeper, _Host, SeedVault)> twoWallets() async {
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.armPinUnlock(pin);
      final host = _Host();
      final strict = VaultKeeper(host, opensActiveOnly: true);
      await strict.loadSeed(password);
      return (strict, host, second);
    }

    test('an unlock opens the active wallet and no other', () async {
      final (keeper, host, second) = await twoWallets();
      expect(host.openedOn.single, ('primary', phrase));
      await expectLater(
          keeper.switchVault(second.id), throwsA(isA<VaultLocked>()));
      expect(await keeper.passwordRecoveryOffer(),
          PasswordRecoveryOffer.otherWalletsClosed);
    });

    test('a switch asks for the password, and closes the wallet left',
        () async {
      final (keeper, host, second) = await twoWallets();
      await expectLater(keeper.openVaultWithPassword(second.id, 'nope'),
          throwsA(isA<WrongPassword>()));
      await keeper.openVaultWithPassword(second.id, password);
      expect(host.switchedTo.single, (second.id, otherPhrase));
      expect(host.keysAsHanded.first.every((b) => b == 0), isTrue,
          reason: "the first wallet's key, written over");
      await expectLater(
          keeper.switchVault('primary'), throwsA(isA<VaultLocked>()));
    });

    test('or for the PIN, for the wallet it opens and no other', () async {
      final (keeper, host, second) = await twoWallets();
      await keeper.openVaultWithPassword(second.id, password);
      await expectLater(keeper.openVaultWithPin(second.id, pin),
          throwsA(isA<VaultLocked>()),
          reason: 'the PIN was armed on the first wallet');
      await expectLater(keeper.openVaultWithPin('primary', '000000'),
          throwsA(isA<WrongPin>()));
      await keeper.openVaultWithPin('primary', pin);
      expect(host.switchedTo.last, ('primary', phrase));
    });

    test('the password changes for every wallet, opening none', () async {
      final (keeper, host, second) = await twoWallets();
      await keeper.changePassword(password, next);
      await expectLater(
          keeper.switchVault(second.id), throwsA(isA<VaultLocked>()));
      expect(host.openedOn, hasLength(1));
      await keeper.openVaultWithPassword(second.id, next);
      expect(host.phrase, otherPhrase);
      expect(await openedBy((k) => k.loadSeed(next)), otherPhrase);
    });

    test('a phrase already stored is refused though its wallet is closed',
        () async {
      final (keeper, host, _) = await twoWallets();
      await expectLater(keeper.addVault(otherPhrase, password),
          throwsA(predicate((e) => '$e'.contains('already in this wallet'))));
      expect(host.sealHoldsAsked, greaterThanOrEqualTo(2));
      expect(keeper.vaults, hasLength(2));
    });

    test('removing the open one asks to open the one it lands on', () async {
      final (keeper, host, second) = await twoWallets();
      await expectLater(
          keeper.removeVault('primary'), throwsA(isA<VaultLocked>()));
      expect(keeper.vaults, hasLength(2), reason: 'nothing removed yet');
      await keeper.openVaultWithPassword(second.id, password);
      await keeper.removeVault('primary');
      expect(keeper.vaults.map((v) => v.id), [second.id]);
      expect(host.phrase, otherPhrase);
    });
  });
}

/// A wallet that opens what it is handed as a build without the key core
/// does — the record, decrypted with its key — and records it.
class _Host implements VaultHost {
  String? phrase;
  bool phraseAccount = true;
  int forgets = 0;
  final List<(String, String)> openedOn = [];
  final List<(String, String)> switchedTo = [];

  /// How many times the keeper asked whether a key opens a record, and
  /// whether a record holds a phrase.
  int sealOpensAsked = 0;
  int sealHoldsAsked = 0;

  /// Every vault, the phrase its record opened to, and the vault key handed
  /// over, opened or switched to.
  final List<(SeedVault, String, Uint8List)> handed = [];

  /// The key objects themselves, as handed: what the keeper writes over when
  /// it closes a wallet.
  final List<Uint8List> keysAsHanded = [];

  String _open(SeedVault vault, Uint8List key) =>
      CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), key);

  @override
  Future<void> opened(SeedVault vault, Uint8List vaultKey) async {
    final mnemonic = _open(vault, vaultKey);
    phrase = mnemonic;
    openedOn.add((vault.id, mnemonic));
    handed.add((vault, mnemonic, Uint8List.fromList(vaultKey)));
    keysAsHanded.add(vaultKey);
  }

  @override
  Future<void> switched(SeedVault vault, Uint8List vaultKey) async {
    final mnemonic = _open(vault, vaultKey);
    phrase = mnemonic;
    switchedTo.add((vault.id, mnemonic));
    handed.add((vault, mnemonic, Uint8List.fromList(vaultKey)));
    keysAsHanded.add(vaultKey);
  }

  @override
  bool sealOpens(SeedVault vault, Uint8List key) {
    sealOpensAsked++;
    try {
      _open(vault, key);
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  bool sealHolds(SeedVault vault, Uint8List key, String phrase) {
    sealHoldsAsked++;
    try {
      return _open(vault, key) == phrase;
    } catch (_) {
      return false;
    }
  }

  @override
  void forget() {
    phrase = null;
    forgets++;
  }

  @override
  bool get phraseOpen => phrase != null;

  @override
  bool get phraseAccountSelected => phraseAccount;
}
