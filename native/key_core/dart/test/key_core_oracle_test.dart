import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:key_core/key_core.dart';
import 'package:test/test.dart';

/// The core held to the wallet's own libraries, byte for byte.
///
/// **The Dart implementation is the oracle** (`docs/RUST_KEY_CORE_DESIGN.md`,
/// Proving it): the calls below are the ones the wallet makes today, written
/// out rather than imported from `lib/` — that is a Flutter package, and this
/// check runs on plain Dart so it needs neither Flutter's native-asset build
/// nor a device.
///
/// - seed: `WalletProvider._seedBytes`;
/// - derivation: `WalletProvider._buildAccount` and `Secp256k1Derivation`;
/// - signature: `signEvmDigest` in `lib/core/evm_key.dart`, before its `+ 27`.
///
/// Runs against the library `hook/build.dart` built and `dart test` bundled
/// ([KeyCore.bundled]), or the file `KEY_CORE_LIBRARY` names. A missing
/// library fails here; it is not a skip.
void main() {
  final named = Platform.environment['KEY_CORE_LIBRARY'];
  final core = named != null && named.isNotEmpty
      ? KeyCore.at(named)
      : KeyCore.bundled();

  Uint8List dartSeed(String phrase) => Uint8List.fromList(
      Bip39SeedGenerator(Mnemonic.fromString(phrase)).generate());

  Bip32Base dartChild(Uint8List seed, String path) =>
      Bip32Slip10Secp256k1.fromSeed(seed).derivePath(path);

  group('the pinned phrases', () {
    // `test/derivation_vectors_test.dart` pins these for the wallet: the first
    // address is BIP-39's canonical vector, which every Ethereum tool derives.
    const pinned = <String, List<(String address, String key)>>{
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon about': [
        (
          '0x9858effd232b4033e47d90003d41ec34ecaeda94',
          '1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727'
        ),
        (
          '0x6fac4d18c912343bf86fa7049364dd4e424ab9c0',
          '9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6'
        ),
        (
          '0xb6716976a3ebe8d39aceb04372f22ff8e6802d7a',
          '5b824bd1104617939cd07c117ddc4301eb5beeca0904f964158963d69ab9d831'
        ),
      ],
      'legal winner thank year wave sausage worth useful legal winner thank '
          'yellow': [
        (
          '0x58a57ed9d8d624cbd12e2c467d34787555bb1b25',
          '33fa40f84e854b941c2b0436dd4a256e1df1cb41b9c1c0ccc8446408c19b8bf9'
        ),
        (
          '0x0d3eb21b6b21833a4939cfff4810e9ae0758e12c',
          '5e4f6a62c67d2b8735d3cda66e37854d7a80f59aab639c3a4bed7e2c7432a4e4'
        ),
        (
          '0xe42f4612e154153b68e241e8fde337e0c4dd6bbd',
          'd46507376b3a8a4af4f1f934375df25213a09857a3ed1086ba284c82d387904b'
        ),
      ],
    };

    pinned.forEach((phrase, accounts) {
      final label = phrase.split(' ').take(2).join(' ');
      test('$label… gives the addresses and keys the wallet pins', () {
        final session = core.open(phrase);
        addTearDown(session.close);
        for (var i = 0; i < accounts.length; i++) {
          final path = "m/44'/60'/0'/0/$i";
          final public = session.secp256k1PublicKey(path, compressed: false);
          expect(EthAddrEncoder().encodeKey(public).toLowerCase(),
              accounts[i].$1,
              reason: 'account $i');
          expect(BytesUtils.toHexString(session.exportSecp256k1PrivateKey(path)),
              accounts[i].$2,
              reason: 'account $i');
        }
      });
    });
  });

  group('the same as blockchain_utils', () {
    // Fixed seed: a difference has to be reproducible, and a random one that
    // shows once in ten thousand runs is a flaky test, not a finding.
    final random = Random(20261027);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    // Every length the wallet accepts, eight phrases each.
    final phrases = [
      for (final entropyBytes in [16, 20, 24, 28, 32])
        for (var i = 0; i < 8; i++)
          Bip39MnemonicGenerator().fromEntropy(bytes(entropyBytes)).toStr(),
    ];

    String randomPath() {
      final depth = 1 + random.nextInt(6);
      final levels = [
        for (var i = 0; i < depth; i++)
          '${random.nextInt(1 << 31)}${random.nextBool() ? "'" : ''}'
      ];
      return 'm/${levels.join('/')}';
    }

    test('on keys and public keys, over ${5 * 8} phrases', () {
      for (final phrase in phrases) {
        final seed = dartSeed(phrase);
        final session = core.open(phrase);
        try {
          final paths = [
            "m/44'/60'/0'/0/0",
            "m/44'/60'/0'/0/${random.nextInt(1000)}",
            "m/44'/60'/0'/0/${random.nextInt(1 << 31)}",
            "m/84'/0'/0'/0/${random.nextInt(1000)}",
            randomPath(),
            randomPath(),
          ];
          for (final path in paths) {
            final child = dartChild(seed, path);
            final why = '${phrase.split(' ').length} words at $path';
            expect(session.exportSecp256k1PrivateKey(path),
                child.privateKey.raw,
                reason: why);
            expect(session.secp256k1PublicKey(path), child.publicKey.compressed,
                reason: why);
            expect(session.secp256k1PublicKey(path, compressed: false),
                child.publicKey.uncompressed,
                reason: why);
          }
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('on signatures: r, s and the recovery id, over 300 digests', () {
      final order = Curves.generatorSecp256k1.order!;
      for (var i = 0; i < 300; i++) {
        final phrase = phrases[i % phrases.length];
        // Paths no network uses: EVM's keys sign no bare digest since O43,
        // and TRON's and the Cosmos zones', where this tested in turn, only
        // what the core read since O58.
        final path = i.isEven ? "m/1'/2'/3'/4/${i % 7}" : randomPath();
        Uint8List digest;
        do {
          digest = bytes(32);
        } while (BigintUtils.fromBytes(digest) == BigInt.zero ||
            BigintUtils.fromBytes(digest) >= order);

        final key = dartChild(dartSeed(phrase), path).privateKey.raw;
        final (expected, recoveryId) =
            Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(digest: digest);

        final session = core.open(phrase);
        try {
          final signature = session.signSecp256k1Digest(path, digest);
          final why = 'pair $i at $path';
          expect(BigintUtils.fromBytes(signature.r), expected.r, reason: why);
          expect(BigintUtils.fromBytes(signature.s), expected.s, reason: why);
          expect(signature.recoveryId, recoveryId, reason: why);
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('the same as blockchain_utils on Bitcoin inputs', () {
    final random = Random(20261028);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    final phrases = [
      for (final entropyBytes in [16, 32])
        for (var i = 0; i < 10; i++)
          Bip39MnemonicGenerator().fromEntropy(bytes(entropyBytes)).toStr(),
    ];

    // What signs a taproot input in the app today: `PsbtDefaultSigner` hands
    // `ECPrivate.signBip340` the input's tap tweak hash, which ends in
    // `BitcoinKeySigner.signBip340Const` with no `aux`.
    test('signatures, tweaked as BIP-341 and not, over 300 digests', () {
      for (var i = 0; i < 300; i++) {
        final phrase = phrases[i % phrases.length];
        // Outside the Bitcoin family, whose keys sign no bare digest since
        // O37 — the primitive is what `src/bitcoin.rs` signs taproot with.
        final path = i.isEven
            ? "m/86'/111111'/0'/${i % 2}/${i % 11}"
            : "m/86'/111111'/${random.nextInt(4)}'/0/${random.nextInt(1 << 31)}";
        final digest = bytes(32);
        final child = dartChild(dartSeed(phrase), path);
        // Untweaked; the key's own TapTweak, as a key-path spend has it; and
        // arbitrary bytes, as a script tree's merkle root would make them.
        final List<int>? tweak = switch (i % 3) {
          0 => null,
          1 => P2TRUtils.calculateTweek(
              child.publicKey.point as ProjectiveECCPoint),
          _ => bytes(32),
        };
        final expected = BitcoinKeySigner.fromKeyBytes(child.privateKey.raw)
            .signBip340Const(digest: digest, tapTweakHash: tweak);

        final session = core.open(phrase);
        try {
          expect(session.signSchnorr(path, digest, tweak: tweak), expected,
              reason: 'pair $i at $path, ${tweak == null ? 'untweaked' : 'tweaked'}');
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    // What signs every other input: `PsbtDefaultSigner` and `BitcoinKeySpend`
    // reach `ECPrivate.signECDSA`, which ends in `signECDSADerConst`.
    test('ECDSA for an input, low R, DER byte for byte, over 300 digests', () {
      final order = Curves.generatorSecp256k1.order!;
      var ground = 0;
      for (var i = 0; i < 300; i++) {
        final phrase = phrases[i % phrases.length];
        // Outside the Bitcoin family, as above: the grind is what every
        // Bitcoin input is signed with, through the reader.
        final path =
            "m/84'/111111'/${i % 3}'/${i % 2}/${random.nextInt(1 << 20)}";
        Uint8List digest;
        do {
          digest = bytes(32);
        } while (BigintUtils.fromBytes(digest) == BigInt.zero ||
            BigintUtils.fromBytes(digest) >= order);
        final key = dartChild(dartSeed(phrase), path).privateKey.raw;
        final expected =
            BitcoinKeySigner.fromKeyBytes(key).signECDSADerConst(digest);
        final plain = Secp256k1SigningKey.fromBytes(keyBytes: key)
            .signConst(digest: digest)
            .$1;
        if (plain.r.bitLength == 256) ground++;

        final session = core.open(phrase);
        try {
          final got = session.signSecp256k1DigestLowR(path, digest);
          expect(
              CryptoSignatureUtils.toDer([
                BigintUtils.fromBytes(got.sublist(0, 32)),
                BigintUtils.fromBytes(got.sublist(32)),
              ]),
              expected,
              reason: 'pair $i at $path');
        } finally {
          session.close();
        }
      }
      // About half need a second signature; a run where none did would prove
      // nothing about the grind.
      expect(ground, inInclusiveRange(100, 200));
    }, timeout: const Timeout(Duration(minutes: 5)));

    // An account's xpub, assembled from the core's chain code and public
    // key rather than from a root in Dart.
    test('an xpub built from the core\'s parts is blockchain_utils\' xpub', () {
      for (final phrase in phrases) {
        final root = Bip32Slip10Secp256k1.fromSeed(dartSeed(phrase));
        final session = core.open(phrase);
        try {
          for (final (path, parent, index) in [
            ("m/84'/0'/0'", "m/84'/0'", 0x80000000),
          ]) {
            final parts = session.secp256k1ExtendedPublicKey(path);
            final parentKey = session.secp256k1PublicKey(parent);
            final built = Bip32Slip10Secp256k1.fromPublicKey(
              parts.publicKey,
              keyData: Bip32KeyData(
                depth: Bip32Depth(path.split('/').length - 1),
                index: Bip32KeyIndex(index),
                chainCode: Bip32ChainCode(parts.chainCode),
                fingerPrint: Bip32FingerPrint(
                    QuickCrypto.hash160(parentKey).sublist(0, 4)),
              ),
            );
            expect(built.publicKey.toExtended,
                root.derivePath(path).publicKey.toExtended,
                reason: path);
          }
        } finally {
          session.close();
        }
      }
    });

    test('a tweak of another length is refused, not padded', () {
      final session = core.open(phrases.first);
      try {
        for (final length in [1, 31, 33]) {
          expect(
              () => session.signSchnorr("m/86'/0'/0'/0/0", bytes(32),
                  tweak: bytes(length)),
              throwsA(isA<KeyCoreException>().having(
                  (e) => e.refusal, 'refusal', KeyCoreRefusal.argument)),
              reason: '$length bytes');
        }
      } finally {
        session.close();
      }
    });
  });

  group('the same as blockchain_utils on ed25519', () {
    // Phase 4: what `Ed25519Derivation` (`chain_crypto`) and `Slip10Ed25519`
    // (`ed25519_chains`) derive and sign with for the networks on SLIP-10.
    final random = Random(20261028 + 25519);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    final phrases = [
      for (final entropyBytes in [16, 24, 32])
        for (var i = 0; i < 4; i++)
          Bip39MnemonicGenerator().fromEntropy(bytes(entropyBytes)).toStr(),
    ];

    // Account [i]'s path in each module.
    List<String> modulePaths(int i) => [
          "m/44'/501'/$i'/0'", // Solana
          "m/44'/607'/$i'", // TON
          "m/44'/397'/$i'", // NEAR
          "m/44'/148'/$i'", // Stellar
          "m/44'/283'/$i'/0'/0'", // Algorand
          "m/44'/1729'/$i'/0'", // Tezos
          "m/44'/508'/0'/0'/$i'", // MultiversX
          "m/44'/637'/$i'/0'/0'", // Aptos, Movement
          "m/44'/784'/$i'/0'/0'", // Sui
          "m/44'/354'/$i'/0'/0'", // Polkadot
        ];

    String randomHardenedPath() {
      final depth = random.nextInt(7);
      return [
        'm',
        for (var i = 0; i < depth; i++) "${random.nextInt(1 << 31)}'",
      ].join('/');
    }

    Bip32Slip10Ed25519 dartNode(Uint8List seed, String path) =>
        Bip32Slip10Ed25519.fromSeed(seed).derivePath(path);

    test('on keys, public keys and signatures, over ${3 * 4} phrases', () {
      for (final phrase in phrases) {
        final seed = dartSeed(phrase);
        final session = core.open(phrase);
        try {
          for (var i = 0; i < 2; i++) {
            final paths = [
              ...modulePaths(i),
              randomHardenedPath(),
              randomHardenedPath(),
            ];
            for (final path in paths) {
              final node = dartNode(seed, path);
              final secret = node.privateKey.raw;
              final why = '${phrase.split(' ').length} words at $path';
              expect(session.exportEd25519PrivateKey(path), secret,
                  reason: why);
              // blockchain_utils' 33 bytes are a 00, then the key.
              expect(node.publicKey.compressed.first, 0, reason: why);
              expect(session.ed25519PublicKey(path),
                  node.publicKey.compressed.sublist(1),
                  reason: why);
              // A Solana key signs only a message read for a screen, and a
              // Stellar or a NEAR key only a transaction's hash read (O58):
              // 'a Solana key signs only a message read for a screen' below,
              // and the Stellar and NEAR groups.
              if (path.startsWith("m/44'/501'") ||
                  path.startsWith("m/44'/148'") ||
                  path.startsWith("m/44'/397'") ||
                  path.startsWith("m/44'/637'") ||
                  path.startsWith("m/44'/784'") ||
                  path.startsWith("m/44'/283'") ||
                  path.startsWith("m/44'/1729'") ||
                  path.startsWith("m/44'/508'") ||
                  path.startsWith("m/44'/354'") ||
                  path.startsWith("m/44'/607'")) {
                expect(() => session.signEd25519(path, bytes(10)),
                    throwsA(isA<KeyCoreException>().having(
                        (e) => e.refusal, 'refusal', KeyCoreRefusal.unshown)),
                    reason: why);
                continue;
              }
              for (final length in [0, 1, 32, 100, 1 + random.nextInt(2000)]) {
                final message = bytes(length);
                expect(session.signEd25519(path, message),
                    Ed25519Signer.fromKeyBytes(secret).sign(message),
                    reason: '$why, $length bytes');
              }
            }
          }
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the key tool/so_smoke.c pins on the device', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/44'/501'/0'/0'";
      const pinned =
          'f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7';
      final session = core.open(phrase);
      addTearDown(session.close);
      final dart = dartNode(dartSeed(phrase), path).publicKey.compressed;
      expect(BytesUtils.toHexString(dart.sublist(1)), pinned);
      expect(BytesUtils.toHexString(session.ed25519PublicKey(path)), pinned);
      // Solana's address for it.
      expect(Base58Encoder.encode(session.ed25519PublicKey(path)),
          'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk');
    });

    test('a level that is not hardened is refused, as Dart refuses it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final bad in ["m/44'/501'/0'/0", 'm/0', "m/44'/501'/0/0'"]) {
        final refusedAsPath = throwsA(isA<KeyCoreException>()
            .having((e) => e.refusal, 'refusal', KeyCoreRefusal.path));
        expect(() => session.ed25519PublicKey(bad), refusedAsPath,
            reason: bad);
        expect(() => session.signEd25519(bad, [1, 2, 3]), refusedAsPath,
            reason: bad);
        expect(() => session.exportEd25519PrivateKey(bad), refusedAsPath,
            reason: bad);
      }
    });

    test('a Solana key signs only a message read for a screen, once (O58)',
        () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/44'/501'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      final payer = session.ed25519PublicKey(path);
      // A System transfer of 1,000,000 lamports, a message of its own.
      final message = <int>[
        1, 0, 1, 3, ...payer, ...List.filled(32, 0x25), ...List.filled(32, 0),
        ...List.filled(32, 0x0b), 1, 2, 2, 0, 1, 12,
        2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0,
      ];
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, message), unshown);
      final reading = jsonDecode(core.readSolanaMessage(message)) as Map;
      expect(reading['feePayer'], Base58Encoder.encode(payer));
      final transfer =
          (reading['instructions'] as List).single['decoded'] as Map;
      expect(transfer['kind'], 'systemTransfer');
      expect(transfer['lamports'], '1000000');
      final secret = dartNode(dartSeed(phrase), path).privateKey.raw;
      expect(session.signEd25519(path, message),
          Ed25519Signer.fromKeyBytes(secret).sign(message));
      expect(() => session.signEd25519(path, message), unshown,
          reason: 'once');
      // An imported Solana key, opened as one, the same.
      final imported = core.openKey(KeyCoreCurve.solana, secret);
      addTearDown(imported.close);
      expect(() => imported.signEd25519('m', message), unshown);
      core.readSolanaMessage(message);
      expect(imported.signEd25519('m', message),
          Ed25519Signer.fromKeyBytes(secret).sign(message));
      expect(
          () => core.readSolanaMessage([0x81, 1, 0, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });

    test('a closed session derives and signs nothing', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/44'/501'/0'/0'";
      final session = core.open(phrase);
      session.close();
      final refusedAsClosed = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.handle));
      expect(() => session.ed25519PublicKey(path), refusedAsClosed);
      expect(() => session.signEd25519(path, [1]), refusedAsClosed);
      expect(() => session.exportEd25519PrivateKey(path), refusedAsClosed);
    });
  });

  group('the same as blockchain_utils on Cardano', () {
    // `Cip1852.fromSeed(seed, Cip1852Coins.cardanoLedger)` — the Ledger scheme
    // the Cardano module derives with — and `CardanoSigner`, which signs its
    // witnesses.
    final random = Random(20261028 + 1852);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    final phrases = [
      for (final entropyBytes in [16, 24, 32])
        for (var i = 0; i < 3; i++)
          Bip39MnemonicGenerator().fromEntropy(bytes(entropyBytes)).toStr(),
    ];

    String randomPath() {
      final depth = random.nextInt(6);
      return [
        'm',
        for (var i = 0; i < depth; i++)
          '${random.nextInt(1 << 31)}${random.nextBool() ? "'" : ''}',
      ].join('/');
    }

    Bip32Base dartNode(Uint8List seed, String path) =>
        Cip1852.fromSeed(seed, Cip1852Coins.cardanoLedger)
            .bip32Object
            .derivePath(path);

    test('on keys, chain codes and signatures, over ${3 * 3} phrases', () {
      for (final phrase in phrases) {
        final seed = dartSeed(phrase);
        final session = core.open(phrase);
        try {
          final paths = [
            for (var account = 0; account < 2; account++)
              for (final (role, index) in [(0, 0), (0, 7), (1, 0), (2, 0)])
                "m/1852'/1815'/$account'/$role/$index",
            randomPath(),
            randomPath(),
          ];
          for (final path in paths) {
            final node = dartNode(seed, path);
            final why = '${phrase.split(' ').length} words at $path';
            expect(session.exportCardanoPrivateKey(path),
                [...node.privateKey.raw, ...node.chainCode.toBytes()],
                reason: why);
            expect(session.cardanoPublicKey(path),
                node.publicKey.compressed.sublist(1),
                reason: why);
            // A key at the module's path signs only the hash of a body
            // read (O58): 'a Cardano key signs only a body read for a
            // screen' below.
            if (path.startsWith("m/1852'/1815'")) {
              expect(() => session.signCardano(path, bytes(32)),
                  throwsA(isA<KeyCoreException>().having(
                      (e) => e.refusal, 'refusal', KeyCoreRefusal.unshown)),
                  reason: why);
              continue;
            }
            for (final length in [0, 32, 1 + random.nextInt(1000)]) {
              final message = bytes(length);
              expect(session.signCardano(path, message),
                  CardanoSigner.fromKeyBytes(node.privateKey.raw).sign(message),
                  reason: '$why, $length bytes');
            }
          }
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the key tool/so_smoke.c pins on the device', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/1852'/1815'/0'/0/0";
      const pinned =
          'cd2b047d1a803eee059769cffb3dfd0a4b9327e55bc78aa962d9bd4f720db0b2';
      final session = core.open(phrase);
      addTearDown(session.close);
      expect(
          BytesUtils.toHexString(
              dartNode(dartSeed(phrase), path).publicKey.compressed.sublist(1)),
          pinned);
      expect(BytesUtils.toHexString(session.cardanoPublicKey(path)), pinned);
    });

    test('a Cardano key signs only the hash of a body read for a screen with '
        'it among the signers, once, as CardanoSigner signs it', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/1852'/1815'/0'/0/0";
      final session = core.open(phrase);
      addTearDown(session.close);
      // The module's body: one input, one output, at a time to live of its
      // own (5,000,077).
      final body = BytesUtils.fromHexString(
          'a400d90102818258201111111111111111111111111111111111111111111111'
          '111111111111111111000181a200581d61616161616161616161616161616161'
          '61616161616161616161616161011a000f4240021a00029810031a004c4b4d');
      final reading =
          jsonDecode(session.readCardanoTransaction(body, [path])) as Map;
      expect(reading['ttl'], '5000013');
      // The signer's payment key hash: BLAKE2b-224 of its public key.
      expect(reading['witnesses'], [
        BytesUtils.toHexString(
            QuickCrypto.blake2b224Hash(session.cardanoPublicKey(path))),
      ]);
      final hash = BytesUtils.fromHexString(reading['hash'] as String);
      expect(hash, QuickCrypto.blake2b256Hash(body));
      final secret = dartNode(dartSeed(phrase), path).privateKey.raw;
      expect(session.signCardano(path, hash),
          CardanoSigner.fromKeyBytes(secret).sign(hash));
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signCardano(path, hash), unshown,
          reason: 'a signer once');
      final refusedTransaction = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.transaction));
      expect(() => session.readCardanoTransaction(body, [path, path]),
          refusedTransaction,
          reason: 'one witness per payment key');
      expect(() => session.signCardano(path, hash), unshown,
          reason: 'nothing kept by a refused reading');
      session.readCardanoTransaction(body, ["m/1852'/1815'/0'/1/0"]);
      expect(() => session.signCardano(path, hash), unshown,
          reason: 'a key the reading did not name');
      expect(() => session.readCardanoTransaction([...body, 0], [path]),
          refusedTransaction);
    });

    test('a closed session derives and signs nothing', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/1852'/1815'/0'/0/0";
      final session = core.open(phrase);
      session.close();
      final refusedAsClosed = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.handle));
      expect(() => session.cardanoPublicKey(path), refusedAsClosed);
      expect(() => session.signCardano(path, [1]), refusedAsClosed);
      expect(() => session.exportCardanoPrivateKey(path), refusedAsClosed);
    });
  });

  group('the same as blockchain_utils on Icarus, and the comparison', () {
    // Phase 6c: `Cip1852.fromSeed(entropy, Cip1852Coins.cardanoIcarus)` — the
    // other-paths question's derivation in Dart until now — and
    // `WalletProvider.matchesCurrentSeed`'s question, asked of the session.
    final random = Random(20261030 + 3);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    final entropies = [
      for (final length in [16, 20, 24, 28, 32])
        for (var i = 0; i < 2; i++) bytes(length),
    ];

    String randomPath() {
      final depth = random.nextInt(6);
      return [
        'm',
        for (var i = 0; i < depth; i++)
          '${random.nextInt(1 << 31)}${random.nextBool() ? "'" : ''}',
      ].join('/');
    }

    Matcher refused(KeyCoreRefusal why) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', why));

    test('on Icarus keys, over ${entropies.length} phrases of every length',
        () {
      for (final entropy in entropies) {
        final phrase = Bip39MnemonicGenerator().fromEntropy(entropy).toStr();
        final root = Cip1852.fromSeed(entropy, Cip1852Coins.cardanoIcarus)
            .bip32Object;
        final session = core.open(phrase);
        try {
          final paths = [
            'm',
            for (var account = 0; account < 2; account++)
              for (final (role, index) in [(0, 0), (0, 7), (1, 0), (2, 0)])
                "m/1852'/1815'/$account'/$role/$index",
            randomPath(),
            randomPath(),
          ];
          for (final path in paths) {
            final why = '${phrase.split(' ').length} words at $path';
            final icarus = session.cardanoIcarusPublicKey(path);
            expect(icarus, root.derivePath(path).publicKey.compressed.sublist(1),
                reason: why);
            expect(icarus, isNot(session.cardanoPublicKey(path)),
                reason: '$why: Icarus is not the Ledger scheme');
          }
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the Icarus key tool/so_smoke.c pins on the device', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/1852'/1815'/0'/0/0";
      const pinned =
          '7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a';
      final entropy = Bip39MnemonicDecoder().decode(phrase);
      final session = core.open(phrase);
      addTearDown(session.close);
      expect(
          BytesUtils.toHexString(Cip1852.fromSeed(
                  entropy, Cip1852Coins.cardanoIcarus)
              .bip32Object
              .derivePath(path)
              .publicKey
              .compressed
              .sublist(1)),
          pinned);
      expect(BytesUtils.toHexString(session.cardanoIcarusPublicKey(path)),
          pinned);
    });

    test('a phrase matches its own session and no other', () {
      final phrases = [
        for (final entropy in entropies)
          Bip39MnemonicGenerator().fromEntropy(entropy).toStr(),
      ];
      for (var i = 0; i < phrases.length; i++) {
        final session = core.open(phrases[i]);
        try {
          for (var j = 0; j < phrases.length; j++) {
            expect(session.matchesPhrase(phrases[j]), i == j,
                reason: '$i and $j');
          }
        } finally {
          session.close();
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a candidate not in the stored form is refused, not answered', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final text in [
        phrase.toUpperCase(),
        ' $phrase',
        phrase.replaceFirst(' ', '  '),
        List.filled(12, 'abandon').join(' '),
        '',
      ]) {
        expect(() => session.matchesPhrase(text),
            refused(KeyCoreRefusal.phrase),
            reason: '"$text"');
      }
    });

    test('an imported key and a closed session answer neither', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/1852'/1815'/0'/0/0";
      final imported = core.openKey(KeyCoreCurve.ed25519, List.filled(32, 2));
      addTearDown(imported.close);
      expect(() => imported.matchesPhrase(phrase), refused(KeyCoreRefusal.kind));
      expect(() => imported.cardanoIcarusPublicKey('m'),
          refused(KeyCoreRefusal.kind));
      final session = core.open(phrase);
      session.close();
      expect(() => session.matchesPhrase(phrase),
          refused(KeyCoreRefusal.handle));
      expect(() => session.cardanoIcarusPublicKey(path),
          refused(KeyCoreRefusal.handle));
    });
  });

  group('an imported key, opened on its own', () {
    // The owner's decision O22: one imported key in the core, answering at
    // `m` alone, as blockchain_utils answers for the same 32 bytes.
    final random = Random(20261029);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    final order = BigInt.parse(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
        radix: 16);
    Uint8List scalar() {
      while (true) {
        final candidate = bytes(32);
        final n = BigintUtils.fromBytes(candidate);
        if (n != BigInt.zero && n < order) return candidate;
      }
    }

    Matcher refused(KeyCoreRefusal why) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', why));

    test('a secp256k1 key: public keys, signatures and export at m', () {
      for (var i = 0; i < 40; i++) {
        final secret = scalar();
        final digest = scalar();
        final session = core.openKey(KeyCoreCurve.secp256k1, secret);
        try {
          final dart = Secp256k1PrivateKey.fromBytes(secret).publicKey;
          expect(session.secp256k1PublicKey('m'), dart.compressed);
          expect(session.secp256k1PublicKey('m', compressed: false),
              dart.uncompressed);
          final (expected, recoveryId) =
              Secp256k1SigningKey.fromBytes(keyBytes: secret)
                  .signConst(digest: digest);
          final signature = session.signSecp256k1Digest('m', digest);
          expect(BigintUtils.fromBytes(signature.r), expected.r);
          expect(BigintUtils.fromBytes(signature.s), expected.s);
          expect(signature.recoveryId, recoveryId);
          expect(session.exportSecp256k1PrivateKey('m'), secret);
        } finally {
          session.close();
        }
      }
    });

    test('an ed25519 key: public key, signatures and export at m', () {
      for (var i = 0; i < 20; i++) {
        final secret = bytes(32);
        final session = core.openKey(KeyCoreCurve.ed25519, secret);
        try {
          expect(session.ed25519PublicKey('m'),
              Ed25519PrivateKey.fromBytes(secret).publicKey.compressed.sublist(1));
          for (final length in [0, 32, 1 + random.nextInt(500)]) {
            final message = bytes(length);
            expect(session.signEd25519('m', message),
                Ed25519Signer.fromKeyBytes(secret).sign(message));
          }
          expect(session.exportEd25519PrivateKey('m'), secret);
        } finally {
          session.close();
        }
      }
    });

    test('refused: another path, the other curve, a phrase\'s call, no key',
        () {
      final secp = core.openKey(KeyCoreCurve.secp256k1, scalar());
      final ed = core.openKey(KeyCoreCurve.ed25519, bytes(32));
      expect(() => secp.secp256k1PublicKey("m/44'/60'/0'/0/0"),
          refused(KeyCoreRefusal.path));
      expect(() => secp.ed25519PublicKey('m'), refused(KeyCoreRefusal.kind));
      expect(() => secp.secp256k1ExtendedPublicKey('m'),
          refused(KeyCoreRefusal.kind));
      expect(() => secp.cardanoPublicKey("m/1852'/1815'/0'/0/0"),
          refused(KeyCoreRefusal.kind));
      expect(() => secp.starknetPublicKey("m/44'/9004'/0'/0/0"),
          refused(KeyCoreRefusal.kind));
      expect(() => ed.secp256k1PublicKey('m'), refused(KeyCoreRefusal.kind));
      expect(() => ed.ed25519PublicKey("m/44'/501'/0'/0'"),
          refused(KeyCoreRefusal.path));
      final orderBytes = BigintUtils.toBytes(order, length: 32);
      for (final notAKey in [List.filled(32, 0), List.filled(32, 0xff), orderBytes]) {
        expect(() => core.openKey(KeyCoreCurve.secp256k1, notAKey),
            refused(KeyCoreRefusal.key));
      }
      expect(() => core.openKey(KeyCoreCurve.ed25519, bytes(31)),
          refused(KeyCoreRefusal.argument));
      secp.close();
      ed.close();
      expect(() => secp.signSecp256k1Digest('m', scalar()),
          refused(KeyCoreRefusal.handle));
      expect(() => ed.signEd25519('m', [1]), refused(KeyCoreRefusal.handle));
    });
  });

  group('an EVM transaction, signed only as built (2c)', () {
    // "Sign what you see": the core reads the bytes it signs and holds them
    // to the transaction the app built. The signature itself is the one
    // `signEvmDigest` makes over the Keccak-256 of the same bytes.
    final random = Random(20261030);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    const path = "m/44'/60'/0'/0/0";

    // RLP as the Yellow Paper defines it, written out: the oracle must not be
    // the reader it checks.
    List<int> rlpLength(int length, int offset) {
      if (length < 56) return [offset + length];
      final be = BigintUtils.toBytes(BigInt.from(length),
          length: BigintUtils.bitlengthInBytes(BigInt.from(length)));
      return [offset + 55 + be.length, ...be];
    }

    List<int> rlpString(List<int> value) =>
        value.length == 1 && value[0] < 0x80
            ? value
            : [...rlpLength(value.length, 0x80), ...value];
    List<int> rlpList(List<List<int>> items) {
      final body = [for (final item in items) ...item];
      return [...rlpLength(body.length, 0xc0), ...body];
    }

    List<int> minimal(BigInt n) => n == BigInt.zero
        ? const []
        : BigintUtils.toBytes(n, length: BigintUtils.bitlengthInBytes(n));
    List<int> word(BigInt n) => BigintUtils.toBytes(n, length: 32);
    BigInt number(int maxBytes) =>
        BigintUtils.fromBytes(bytes(random.nextInt(maxBytes + 1)));

    ({List<int> unsigned, List<int> expected}) transaction(
        {required bool eip1559,
        BigInt? chainId,
        List<int>? to,
        BigInt? value,
        BigInt? gas,
        BigInt? fee,
        BigInt? maxFee,
        List<int>? data}) {
      chainId ??= BigInt.from(1 + random.nextInt(1 << 30));
      to ??= random.nextInt(8) == 0 ? const [] : bytes(20);
      value ??= number(32);
      gas ??= number(4);
      fee ??= number(12);
      maxFee = eip1559 ? (maxFee ?? number(12)) : BigInt.zero;
      data ??= bytes(random.nextInt(4) == 0 ? 0 : random.nextInt(600));
      final nonce = number(8);
      final unsigned = eip1559
          ? [
              2,
              ...rlpList([
                rlpString(minimal(chainId)),
                rlpString(minimal(nonce)),
                rlpString(minimal(fee)),
                rlpString(minimal(maxFee)),
                rlpString(minimal(gas)),
                rlpString(to),
                rlpString(minimal(value)),
                rlpString(data),
                rlpList(const []),
              ])
            ]
          : rlpList([
              rlpString(minimal(nonce)),
              rlpString(minimal(fee)),
              rlpString(minimal(gas)),
              rlpString(to),
              rlpString(minimal(value)),
              rlpString(data),
              rlpString(minimal(chainId)),
              rlpString(const []),
              rlpString(const []),
            ]);
      final expected = [
        eip1559 ? 2 : 0,
        ...word(chainId),
        to.isEmpty ? 0 : 1,
        ...(to.isEmpty ? List.filled(20, 0) : to),
        ...word(value),
        ...word(gas),
        ...word(fee),
        ...word(maxFee),
        ...data,
      ];
      return (unsigned: unsigned, expected: expected);
    }

    Matcher refused(KeyCoreRefusal why) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', why));

    test('both forms, 200 transactions: the signature over their Keccak-256',
        () {
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final session = core.open(phrase);
      addTearDown(session.close);
      for (var i = 0; i < 200; i++) {
        final tx = transaction(eip1559: i.isEven);
        final (expected, recoveryId) =
            Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(
                digest: QuickCrypto.keccack256Hash(tx.unsigned));
        // Read for a screen first, as the app does (2f-1b).
        session.readEvmTransaction(path, tx.expected);
        final signature =
            session.signEvmTransaction(path, tx.unsigned, tx.expected);
        final why = 'transaction $i, ${tx.unsigned.length} bytes';
        expect(BigintUtils.fromBytes(signature.r), expected.r, reason: why);
        expect(BigintUtils.fromBytes(signature.s), expected.s, reason: why);
        expect(signature.recoveryId, recoveryId, reason: why);
      }
    });

    test('a transaction other than the one built is refused, field by field',
        () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final eip1559 in [false, true]) {
        final base = (
          chainId: BigInt.from(8453),
          to: bytes(20),
          value: number(32),
          gas: BigInt.from(21000 + random.nextInt(1 << 20)),
          fee: number(12),
          maxFee: number(12),
          data: bytes(68),
        );
        // The built transaction with one field changed; the nonce differs
        // between any two calls, and is not held to anything.
        ({List<int> unsigned, List<int> expected}) differing(
                {bool? form,
                BigInt? chainId,
                List<int>? to,
                BigInt? value,
                BigInt? gas,
                BigInt? fee,
                BigInt? maxFee,
                List<int>? data}) =>
            transaction(
                eip1559: form ?? eip1559,
                chainId: chainId ?? base.chainId,
                to: to ?? base.to,
                value: value ?? base.value,
                gas: gas ?? base.gas,
                fee: fee ?? base.fee,
                maxFee: maxFee ?? base.maxFee,
                data: data ?? base.data);
        final built = differing();
        session.readEvmTransaction(path, built.expected);
        BigInt plusOne(BigInt n) => n + BigInt.one;
        final changed = {
          'network': differing(chainId: BigInt.from(1)),
          'recipient': differing(to: [...base.to]..[19] ^= 1),
          'creation': differing(to: const []),
          'value': differing(value: plusOne(base.value)),
          'gas limit': differing(gas: plusOne(base.gas)),
          'fee': differing(fee: plusOne(base.fee)),
          if (eip1559) 'maximum fee': differing(maxFee: plusOne(base.maxFee)),
          'call data': differing(data: [...base.data]..[67] ^= 1),
          'call data a byte longer': differing(data: [...base.data, 0]),
          'form': differing(form: !eip1559),
        };
        expect(
            session
                .signEvmTransaction(path, differing().unsigned, built.expected)
                .r,
            hasLength(32),
            reason: 'another nonce, all else the same');
        for (final entry in changed.entries) {
          expect(
              () => session.signEvmTransaction(
                  path, entry.value.unsigned, built.expected),
              refused(KeyCoreRefusal.transaction),
              reason: '${entry.key}, EIP-1559 $eip1559');
        }
      }
    });

    test('bytes the app does not write are refused', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      final tx = transaction(eip1559: true);
      final legacy = transaction(eip1559: false);
      final unreadable = {
        'an EIP-2930 type': [1, ...tx.unsigned.sublist(1)],
        'a byte after it': [...tx.unsigned, 0],
        'a byte short': tx.unsigned.sublist(0, tx.unsigned.length - 1),
        'nothing': <int>[],
        'a personal message': [0x19, ...tx.unsigned],
        'a legacy one without EIP-155': rlpList([
          for (var i = 0; i < 6; i++) rlpString(const []),
        ]),
        'a legacy one a field long': [
          ...rlpLength(legacy.unsigned.length - 1, 0xc0),
          ...legacy.unsigned.sublist(1),
        ],
      };
      for (final entry in unreadable.entries) {
        expect(
            () => session.signEvmTransaction(path, entry.value, tx.expected),
            refused(KeyCoreRefusal.transaction),
            reason: entry.key);
      }
    });

    test("the app's side in another layout is an argument, not a verdict", () {
      final session = core.open(phrase);
      addTearDown(session.close);
      final tx = transaction(eip1559: true, to: bytes(20));
      final wrong = {
        'short': tx.expected.sublist(0, 181),
        'kind 1': [1, ...tx.expected.sublist(1)],
        'presence 2': [...tx.expected]..[33] = 2,
        'absent with an address': [...tx.expected]..[33] = 0,
      };
      for (final entry in wrong.entries) {
        expect(() => session.signEvmTransaction(path, tx.unsigned, entry.value),
            refused(KeyCoreRefusal.argument),
            reason: entry.key);
      }
      session.close();
      expect(() => session.readEvmTransaction(path, tx.expected),
          refused(KeyCoreRefusal.handle));
      expect(() => session.signEvmTransaction(path, tx.unsigned, tx.expected),
          refused(KeyCoreRefusal.handle));
    });
  });

  group('a Bitcoin transaction, signed only as built (2d)', () {
    final random = Random(20261031);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    List<int> le(int value, int width) =>
        [for (var i = 0; i < width; i++) (value >> (8 * i)) & 0xff];
    List<int> le64(BigInt value) => [
          for (var i = 0; i < 8; i++)
            ((value >> (8 * i)) & BigInt.from(0xff)).toInt()
        ];
    List<int> compact(int n) => n < 0xfd ? [n] : [0xfd, ...le(n, 2)];
    List<int> short(List<int> b) => [...le(b.length, 2), ...b];
    List<int> p2wpkh(List<int> key) => [0x00, 0x14, ...QuickCrypto.hash160(key)];
    List<int> p2pkhCode(List<int> key) =>
        [0x76, 0xa9, 0x14, ...QuickCrypto.hash160(key), 0x88, 0xac];

    // BIP-143's sighash for SIGHASH_ALL, written out here: a third
    // implementation beside the core's and bitcoin_base's.
    List<int> bip143(
        {required List<List<int>> outpoints,
        required List<List<int>> sequences,
        required List<List<int>> outputs,
        required int index,
        required List<int> scriptCode,
        required BigInt amount}) {
      final preimage = [
        ...le(2, 4),
        ...QuickCrypto.sha256DoubleHash([for (final o in outpoints) ...o]),
        ...QuickCrypto.sha256DoubleHash([for (final q in sequences) ...q]),
        ...outpoints[index],
        ...compact(scriptCode.length),
        ...scriptCode,
        ...le64(amount),
        ...sequences[index],
        ...QuickCrypto.sha256DoubleHash([for (final o in outputs) ...o]),
        ...le(0, 4),
        ...le(1, 4),
      ];
      return QuickCrypto.sha256DoubleHash(preimage);
    }

    test("BIP-143's second example: its own sighash, and another fee refused",
        () {
      final request = BytesUtils.fromHexString(
          '00770000000100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb6'
          '6092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457'
          'b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd'
          '270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac9204000000ca9a3b00000000'
          '1700a9144733f37cf4db86fbc2efed2500b4f4e49f31202387020100'
          '6d00000000000002' '00b8b4eb0b000000001900'
          '76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388acff00000000'
          '0008af2f000000001900'
          '76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88acff00000000'
          '480d000000000000');
      final session = core.openKey(KeyCoreCurve.secp256k1,
          BytesUtils.fromHexString('eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf'));
      addTearDown(session.close);
      // Signed only once a screen was given its reading (2f-3), and once.
      expect(
          () => session.signBitcoinTransaction(request, 1),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.unshown)));
      final reading = jsonDecode(session.readBitcoinTransaction(request))
          as Map<String, dynamic>;
      expect(reading['flavour'], 'bitcoin');
      expect(reading['fee'], '3400');
      expect((reading['inputs'] as List).single['kind'], 'p2shP2wpkh');
      expect([for (final o in reading['outputs'] as List) o['change']],
          [false, false]);
      final signed = session.signBitcoinTransaction(request, 1).single;
      expect(BytesUtils.toHexString(signed.sighash),
          '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6');
      expect(
          () => session.signBitcoinTransaction(request, 1),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.unshown)),
          reason: 'once');
      final changed = Uint8List.fromList(request)..[request.length - 8] ^= 1;
      expect(
          () => session.readBitcoinTransaction(changed),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });

    test('60 segwit sends: the sighash BIP-143 gives, signed as the app signs',
        () {
      final seed = dartSeed(phrase);
      final session = core.open(phrase);
      addTearDown(session.close);
      for (var t = 0; t < 60; t++) {
        final count = 1 + random.nextInt(3);
        final paths = [
          for (var i = 0; i < count; i++)
            "m/84'/0'/0'/0/${random.nextInt(1000)}"
        ];
        final keys = [for (final p in paths) dartChild(seed, p)];
        final amounts = [
          for (var i = 0; i < count; i++)
            BigInt.from(10000 + random.nextInt(1 << 30))
        ];
        final outpoints = [for (var i = 0; i < count; i++) bytes(36)];
        final sequences = [
          for (var i = 0; i < count; i++) le(0xfffffffd, 4)
        ];
        final total = amounts.fold(BigInt.zero, (a, b) => a + b);
        final fee = BigInt.from(500 + random.nextInt(5000));
        final pay = total ~/ BigInt.two;
        const changePath = "m/84'/0'/0'/1/3";
        final changeKey = dartChild(seed, changePath).publicKey.compressed;
        final scripts = [p2wpkh(bytes(20).sublist(0, 20)), p2wpkh(changeKey)];
        final values = [pay, total - pay - fee];
        final outputs = [
          for (var o = 0; o < 2; o++)
            [...le64(values[o]), ...compact(scripts[o].length), ...scripts[o]]
        ];
        final unsigned = [
          ...le(2, 4),
          ...compact(count),
          for (var i = 0; i < count; i++) ...[...outpoints[i], 0, ...sequences[i]],
          ...compact(2),
          for (final o in outputs) ...o,
          ...le(0, 4),
        ];
        final request = [
          0,
          ...le(unsigned.length, 4),
          ...unsigned,
          for (var i = 0; i < count; i++) ...[
            ...le64(amounts[i]),
            ...short(p2wpkh(keys[i].publicKey.compressed)),
            3,
            ...short(utf8.encode(paths[i])),
            ...short(const []),
            ...le(0, 4),
          ],
          ...le(2, 2),
          ...le64(values[0]), ...short(scripts[0]), 0xff, ...short(const []),
          ...short(const []),
          ...le64(values[1]), ...short(scripts[1]), 3,
          ...short(utf8.encode(changePath)), ...short(const []),
          ...le64(fee),
        ];
        // Read for a screen first, as every door does (2f-3): its change is
        // the core's finding, its fee the inputs less the outputs.
        final reading = jsonDecode(session.readBitcoinTransaction(request))
            as Map<String, dynamic>;
        expect([for (final o in reading['outputs'] as List) o['change']],
            [false, true], reason: 'send $t');
        expect(reading['fee'], fee.toString(), reason: 'send $t');
        final signed = session.signBitcoinTransaction(request, count);
        for (var i = 0; i < count; i++) {
          final sighash = bip143(
              outpoints: outpoints,
              sequences: sequences,
              outputs: outputs,
              index: i,
              scriptCode: p2pkhCode(keys[i].publicKey.compressed),
              amount: amounts[i]);
          expect(signed[i].sighash, sighash, reason: 'send $t, input $i');
          expect(
              CryptoSignatureUtils.toDer([
                BigintUtils.fromBytes(signed[i].signature.sublist(0, 32)),
                BigintUtils.fromBytes(signed[i].signature.sublist(32)),
              ]),
              BitcoinKeySigner.fromKeyBytes(keys[i].privateKey.raw)
                  .signECDSADerConst(sighash),
              reason: 'send $t, input $i');
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a request in another layout is an argument; a closed session, a handle',
        () {
      final session = core.open(phrase);
      expect(
          () => session.signBitcoinTransaction([9], 1),
          throwsA(isA<KeyCoreException>()
              .having((e) => e.refusal, 'refusal', KeyCoreRefusal.argument)));
      session.close();
      expect(
          () => session.signBitcoinTransaction([0], 1),
          throwsA(isA<KeyCoreException>()
              .having((e) => e.refusal, 'refusal', KeyCoreRefusal.argument)),
          reason: 'the request is read before the handle is looked up');
    });
  });

  group("the Bitcoin family's digest call, closed (O37)", () {
    Matcher onlyTransactions() => throwsA(isA<KeyCoreException>().having(
        (e) => e.refusal, 'refusal', KeyCoreRefusal.transactionOnly));
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    final digest = List<int>.filled(32, 0x5a);

    test("a phrase's key at every family path signs no bare digest", () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final path in [
        "m/44'/0'/0'/0/0",
        "m/49'/0'/0'/0/0",
        "m/84'/0'/0'/0/0",
        "m/86'/0'/0'/0/0",
        "m/84'/2'/0'/0/0",
        "m/44'/3'/0'/0/0",
        "m/44'/145'/0'/0/0",
      ]) {
        expect(() => session.signSecp256k1Digest(path, digest),
            onlyTransactions(), reason: path);
        expect(() => session.signSecp256k1DigestLowR(path, digest),
            onlyTransactions(), reason: path);
        expect(() => session.signSchnorr(path, digest), onlyTransactions(),
            reason: path);
        expect(session.secp256k1PublicKey(path), hasLength(33), reason: path);
      }
      expect(session.signSchnorr("m/86'/111111'/0'/0/0", digest), hasLength(64),
          reason: "Kaspa's coin is not of the family");
      expect(() => session.signSchnorr("m/44'/111111'/0'/0/0", digest),
          onlyTransactions(),
          reason: "and Kaspa's own keys sign only a send read, since 2f-20");
    });

    test('a key opened as a Bitcoin key signs no bare digest', () {
      final secret = List<int>.filled(32, 0x46);
      final bitcoin = core.openKey(KeyCoreCurve.bitcoin, secret);
      final plain = core.openKey(KeyCoreCurve.secp256k1, secret);
      addTearDown(bitcoin.close);
      addTearDown(plain.close);
      expect(bitcoin.secp256k1PublicKey('m'), plain.secp256k1PublicKey('m'));
      expect(() => bitcoin.signSecp256k1Digest('m', digest), onlyTransactions());
      expect(() => bitcoin.signSecp256k1DigestLowR('m', digest),
          onlyTransactions());
      expect(() => bitcoin.signSchnorr('m', digest), onlyTransactions());
      expect(plain.signSecp256k1DigestLowR('m', digest), hasLength(64));
    });
  });

  group("Starknet's transaction, only as read (O58)", () {
    test('a Starknet key signs only the hash of a transaction read for it, '
        'once', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/9004'/0'/0/0";
      final session = core.open(phrase);
      addTearDown(session.close);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      // The module's transfer of one STRK from the phrase's first account, at
      // nonce 7, with its hash as the module computes it. The binding reads
      // it at a nonce of its own: the core's tests read this one.
      final transfer = (jsonDecode(r'''{"type":"INVOKE","version":"0x3","sender_address":"0x2acb16b67ee6426b29eb415ab2ff53e729760a8e5442561d90da7d3b0fc2035","calldata":["0x1","0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x123456789abcdef","0xde0b6b3a7640000","0x0"],"signature":[],"nonce":"0x7","resource_bounds":{"l1_gas":{"max_amount":"0x0","max_price_per_unit":"0x11c37937e08000"},"l2_gas":{"max_amount":"0x16e360","max_price_per_unit":"0x3b9aca000"},"l1_data_gas":{"max_amount":"0x1f4","max_price_per_unit":"0x7d0"}},"tip":"0x0","paymaster_data":[],"account_deployment_data":[],"nonce_data_availability_mode":"L1","fee_data_availability_mode":"L1"}''') as Map)
        ..['nonce'] = '0x8';
      final bytes = utf8.encode(jsonEncode(transfer));
      final reading =
          jsonDecode(session.readStarknetTransaction(path, bytes)) as Map;
      expect(reading['kind'], 'invoke');
      expect(reading['nonce'], '8');
      expect(reading['amount'], '1000000000000000000');
      final hash = BytesUtils.fromHexString(reading['hash'] as String);
      expect(() => session.signStarknet("m/44'/9004'/0'/0/1", hash), unshown,
          reason: 'another key');
      expect(session.signStarknet(path, hash), hasLength(64));
      expect(() => session.signStarknet(path, hash), unshown, reason: 'once');
      expect(
          () => session.readStarknetTransaction(path, [...bytes, 0x20, 0x7b]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
      expect(
          () => session.readStarknetTransaction("m/1'/2'/3'/4/9", bytes),
          throwsA(isA<KeyCoreException>()
              .having((e) => e.refusal, 'refusal', KeyCoreRefusal.path)));
    });
  });

  group("Kaspa's send, only as read (O58)", () {
    test('a Kaspa key signs only a send read for a screen, once, as the Dart '
        'key signs it', () {
      const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon about';
      const path = "m/44'/111111'/0'/0/0";
      final session = core.open(phrase);
      addTearDown(session.close);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      // The module's send: two inputs, `55…55:3` and `66…66:0`, of 90,000 and
      // 60,000 sompi; 100,000 to the key `22…22` and 45,000 back, a fee of
      // 5,000. Its own: the binding's tests share no reading with the core's.
      List<int> le(int value, int bytes) =>
          [for (var i = 0; i < bytes; i++) (value >> (8 * i)) & 0xff];
      final own = BytesUtils.fromHexString(
          '1bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058');
      List<int> script(List<int> key) => [...le(34, 2), 0x20, ...key, 0xac];
      List<int> request(String at) => [
            ...le(at.length, 2), ...utf8.encode(at), ...le(0, 2),
            ...le(2, 2),
            ...List.filled(32, 0x55), ...le(3, 4), ...le(90000, 8), ...le(0, 2),
            ...script(own), ...List.filled(8, 0xff), 1,
            ...List.filled(32, 0x66), ...le(0, 4), ...le(60000, 8), ...le(0, 2),
            ...script(own), ...List.filled(8, 0xff), 1,
            ...le(2, 2),
            ...le(100000, 8), ...le(0, 2), ...script(List.filled(32, 0x22)),
            ...le(45000, 8), ...le(0, 2), ...script(own),
            ...le(0, 8), ...List.filled(20, 0), ...le(0, 8), ...le(5000, 8),
          ];
      final send = request(path);
      expect(() => session.signKaspaTransaction(send, 2), unshown);
      final reading = jsonDecode(session.readKaspaTransaction(send)) as Map;
      expect(reading['fee'], '5000');
      expect(reading['sent'], '100000');
      expect((reading['outputs'] as List)[1]['address'],
          'kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh');
      final signed = session.signKaspaTransaction(send, 2);
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      for (var i = 0; i < 2; i++) {
        expect(BytesUtils.toHexString(signed[i].sighash),
            (reading['sighashes'] as List)[i]);
        expect(
            signed[i].signature,
            BitcoinKeySigner.fromKeyBytes(key)
                .signBip340(digest: signed[i].sighash),
            reason: 'input $i');
      }
      expect(() => session.signKaspaTransaction(send, 2), unshown,
          reason: 'once');
      expect(() => session.signSchnorr(path, signed[0].sighash),
          throwsA(isA<KeyCoreException>().having((e) => e.refusal, 'refusal',
              KeyCoreRefusal.transactionOnly)));
      final imported = core.openKey(KeyCoreCurve.kaspa, key);
      addTearDown(imported.close);
      final atRoot = request('m');
      expect(() => imported.signKaspaTransaction(atRoot, 2), unshown);
      imported.readKaspaTransaction(atRoot);
      expect(imported.signKaspaTransaction(atRoot, 2).first.signature,
          signed.first.signature);
      expect(
          () => session.readKaspaTransaction([...send, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.argument)));
    });
  });

  group("ICP's digest, only as read (O58)", () {
    test('an ICP key signs only the digest of a call read for a screen, '
        'once, as the Dart key signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/223'/0'/0/0";
      final session = core.open(phrase);
      addTearDown(session.close);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      // The module's call: one ICP to `80459651 22…22`, with its request id
      // and digest as the module computes them.
      final content = BytesUtils.fromHexString(
          'a66c726571756573745f747970656463616c6c6b63616e69737465725f69644a'
          '000000000000000201016b6d6574686f645f6e616d65687472616e7366657263'
          '61726758824449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c'
          '06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca8'
          '0d01010520804596512222222222222222222222222222222222222222222222'
          '222222222210270000000000000068e5cf8b010000000100002a36fe9c971700'
          'e1f505000000006673656e646572581df1faf000dcb4a48342b3babf4c1685e5'
          'c5984f979a8a2e0ddc124912026e696e67726573735f6578706972791b17979d'
          '3617476000');
      final digest = BytesUtils.fromHexString(
          'd37e71ef3ad17acb3eab159726d4af97784e29299d32ff6da969de366b150016');
      expect(() => session.signSecp256k1Digest(path, digest), unshown);
      final reading = jsonDecode(core.readIcpCall(content)) as Map;
      expect(reading['requestId'],
          '50deafe62c63f261c600203c91cc96d0331adbb91cfaa058e9bcf04b5a1bad5a');
      expect(reading['hash'], '0x${BytesUtils.toHexString(digest)}');
      expect(reading['amount'], '100000000');
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final (expected, recoveryId) =
          Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(digest: digest);
      final signature = session.signSecp256k1Digest(path, digest);
      expect(BigintUtils.fromBytes(signature.r), expected.r);
      expect(BigintUtils.fromBytes(signature.s), expected.s);
      expect(signature.recoveryId, recoveryId);
      expect(() => session.signSecp256k1Digest(path, digest), unshown,
          reason: 'once');
      final imported = core.openKey(KeyCoreCurve.icp, key);
      addTearDown(imported.close);
      expect(() => imported.signSecp256k1Digest('m', digest), unshown);
      core.readIcpCall(content);
      expect(imported.signSecp256k1Digest('m', digest).r, signature.r);
      expect(
          () => core.readIcpCall([...content, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("Filecoin's digest, only as read (O58)", () {
    test('a Filecoin key signs only the digest of a message read for a '
        'screen, once, as the Dart key signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/461'/0'/0/0";
      final session = core.open(phrase);
      addTearDown(session.close);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      // The module's message: one attoFIL, at a nonce of its own (77).
      final message = BytesUtils.fromHexString(
          '8a005501c4bb08204821c4c5ee4fffb9860438995bb83811550100537285faff2e'
          'f1c04fa030ab28a1e6dcc4ba60184d4200011a000927c0420064400040');
      final digest = QuickCrypto.blake2b256Hash([
        0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20,
        ...QuickCrypto.blake2b256Hash(message),
      ]);
      expect(() => session.signSecp256k1Digest(path, digest), unshown);
      final reading = jsonDecode(core.readFilecoinMessage(message)) as Map;
      expect(reading['nonce'], '77');
      expect(reading['to'], 'f1ys5qqiciehcml3sp764ymbbytfn3qoar5fo3iwy');
      expect(reading['hash'], '0x${BytesUtils.toHexString(digest)}');
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final (expected, recoveryId) =
          Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(digest: digest);
      final signature = session.signSecp256k1Digest(path, digest);
      expect(BigintUtils.fromBytes(signature.r), expected.r);
      expect(BigintUtils.fromBytes(signature.s), expected.s);
      expect(signature.recoveryId, recoveryId);
      expect(() => session.signSecp256k1Digest(path, digest), unshown,
          reason: 'once');
      // An imported Filecoin key, opened as one, the same.
      final imported = core.openKey(KeyCoreCurve.filecoin, key);
      addTearDown(imported.close);
      expect(() => imported.signSecp256k1Digest('m', digest), unshown);
      core.readFilecoinMessage(message);
      expect(imported.signSecp256k1Digest('m', digest).r, signature.r);
      expect(
          () => core.readFilecoinMessage([...message, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("TRON's digest, only as read (O58)", () {
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    const path = "m/44'/195'/0'/0/0";
    final unshown = throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));

    List<int> varint(int n) {
      final out = <int>[];
      do {
        final byte = n & 0x7f;
        n >>= 7;
        out.add(n == 0 ? byte : byte | 0x80);
      } while (n != 0);
      return out;
    }

    List<int> field(int number, List<int> bytes) =>
        [...varint(number << 3 | 2), ...varint(bytes.length), ...bytes];
    List<int> number(int number, int value) =>
        [...varint(number << 3), ...varint(value)];

    /// A TRX transfer's `raw_data` from [from] to `41 55…55`, as a node
    /// writes one.
    List<int> transfer(List<int> from, int amount) {
      final value = [
        ...field(1, from),
        ...field(2, [0x41, ...List.filled(20, 0x55)]),
        ...number(3, amount),
      ];
      final any = [
        ...field(1, utf8.encode('type.googleapis.com/protocol.TransferContract')),
        ...field(2, value),
      ];
      return [
        ...field(1, [0xab, 0xcd]),
        ...field(4, List.filled(8, 0x11)),
        ...number(8, 1700000060000),
        ...field(11, [...number(1, 1), ...field(2, any)]),
        ...number(14, 1700000000000),
      ];
    }

    test('a TRON key signs only the SHA-256 of a transaction read for a '
        'screen, once, as the Dart key signs it', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final from = [0x41, ...List.filled(20, 0x66)];
      final raw = transfer(from, 1500000);
      final digest = QuickCrypto.sha256Hash(raw);
      expect(() => session.signSecp256k1Digest(path, digest), unshown);
      final reading = jsonDecode(core.readTronTransaction(raw)) as Map;
      expect(reading['txid'], BytesUtils.toHexString(digest));
      final decoded = (reading['contract'] as Map)['decoded'] as Map;
      expect(decoded['kind'], 'trxTransfer');
      expect(decoded['amount'], '1500000');
      final (expected, recoveryId) =
          Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(digest: digest);
      final signature = session.signSecp256k1Digest(path, digest);
      expect(BigintUtils.fromBytes(signature.r), expected.r);
      expect(BigintUtils.fromBytes(signature.s), expected.s);
      expect(signature.recoveryId, recoveryId);
      expect(() => session.signSecp256k1Digest(path, digest), unshown,
          reason: 'once');
      expect(
          () => session.signSecp256k1DigestLowR(path, digest),
          throwsA(isA<KeyCoreException>().having((e) => e.refusal, 'refusal',
              KeyCoreRefusal.transactionOnly)));

      // An imported TRON key, opened as one, the same; a plain one is not.
      final imported = core.openKey(KeyCoreCurve.tron, key);
      addTearDown(imported.close);
      expect(() => imported.signSecp256k1Digest('m', digest), unshown);
      core.readTronTransaction(raw);
      expect(imported.signSecp256k1Digest('m', digest).r, signature.r);
      final plain = core.openKey(KeyCoreCurve.secp256k1, key);
      addTearDown(plain.close);
      expect(plain.signSecp256k1Digest('m', List.filled(32, 7)).r,
          hasLength(32));
      expect(
          () => core.readTronTransaction([...raw, 0x48, 0x01]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)),
          reason: 'a field no transaction of this wallet carries');
    });
  });

  group("a Stellar transaction's hash, only as read (O58)", () {
    test('a Stellar key signs only the hash of a transaction read for a '
        'screen, once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/148'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      final key = session.ed25519PublicKey(path);
      List<int> u32(int n) => [n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff];
      // The public network's payload of one payment of 7 stroops.
      final payload = [
        ...QuickCrypto.sha256Hash(
            utf8.encode('Public Global Stellar Network ; September 2015')),
        ...u32(2),
        ...u32(0), ...key,
        ...u32(100),
        ...u32(0), ...u32(42),
        ...u32(0),
        ...u32(0),
        ...u32(1),
        ...u32(0), ...u32(1), ...u32(0), ...List.filled(32, 0x23), ...u32(0),
        ...u32(0), ...u32(7),
        ...u32(0),
      ];
      final hash = QuickCrypto.sha256Hash(payload);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, hash), unshown);
      final reading = jsonDecode(core.readStellarTransaction(payload)) as Map;
      expect(reading['publicNetwork'], isTrue);
      expect(((reading['operations'] as List).single as Map)['amount'], '7');
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, hash),
          Ed25519Signer.fromKeyBytes(secret).sign(hash));
      expect(() => session.signEd25519(path, hash), unshown, reason: 'once');
      // An imported Stellar key, opened as one, the same.
      final imported = core.openKey(KeyCoreCurve.stellar, secret);
      addTearDown(imported.close);
      expect(() => imported.signEd25519('m', hash), unshown);
      core.readStellarTransaction(payload);
      expect(imported.signEd25519('m', hash),
          Ed25519Signer.fromKeyBytes(secret).sign(hash));
      expect(
          () => core.readStellarTransaction([...payload, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group('a MultiversX transaction, only as read (O58)', () {
    test('a MultiversX key signs only a transaction read for a screen, once, '
        'as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/508'/0'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      // The module's signing JSON: one EGLD, at a nonce of its own.
      final payload = utf8.encode(
          '{"nonce":77,"value":"1000000000000000000",'
          '"receiver":"erd1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qjfjdy7",'
          '"sender":"erd1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspavcaj",'
          '"gasPrice":1000000000,"gasLimit":50000,"chainID":"1","version":1}');
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, payload), unshown);
      final reading =
          jsonDecode(core.readMultiversxTransaction(payload)) as Map;
      expect(reading['nonce'], '77');
      expect(reading['mainnet'], isTrue);
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, payload),
          Ed25519Signer.fromKeyBytes(secret).sign(payload));
      expect(() => session.signEd25519(path, payload), unshown, reason: 'once');
      expect(
          () => core.readMultiversxTransaction([...payload, 0x20]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("a TON signing message's hash, only as read (O58)", () {
    test('a TON key signs only the hash of a message read for a screen, '
        'once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/607'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      // ton_dart's signing message for one TON, at seqno 5, and its hash.
      final boc = BytesUtils.fromHexString(
          'b5ee9c7241010201004700011c29a9a3176aeb41460000000500010100684200'
          '2776490dcea6ab506ca33b00b6a4e1359cd8ebc80d3f0a9f33019f8a3504437a'
          '21dcd650000000000000000000000000000097d2bead');
      final hash = BytesUtils.fromHexString(
          'c0fddaf2a0857fb719695514998ed359fd5420847cf225fa03ff4ffc244e0940');
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, hash), unshown);
      final reading = jsonDecode(session.readTonTransfer(path, boc)) as Map;
      expect(reading['seqno'], '5');
      expect(reading['hash'], '0x${BytesUtils.toHexString(hash)}');
      final node =
          Bip32Slip10Ed25519.fromSeed(dartSeed(phrase)).derivePath(path);
      // Read for this key, by blockchain_utils' reckoning of it.
      expect(reading['publicKey'],
          '0x${BytesUtils.toHexString(node.publicKey.compressed.sublist(1))}');
      // Another account's key signs nothing this one's reading was of.
      expect(() => session.signEd25519("m/44'/607'/1'", hash), unshown,
          reason: 'read for another key');
      expect(session.signEd25519(path, hash),
          Ed25519Signer.fromKeyBytes(node.privateKey.raw).sign(hash));
      expect(() => session.signEd25519(path, hash), unshown, reason: 'once');
      expect(
          () => session.readTonTransfer(path, [...boc, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
      expect(
          () => session.readTonTransfer("m/44'/354'/0'/0'/0'", boc),
          throwsA(isA<KeyCoreException>()
              .having((e) => e.refusal, 'refusal', KeyCoreRefusal.path)));
    });
  });

  group('a Polkadot payload, only as read (O58)', () {
    test('a Polkadot key signs only a payload read for a screen, once, as '
        'blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/354'/0'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      // The module's Asset Hub signing payload: one DOT, at a nonce of its
      // own (77).
      final payload = BytesUtils.fromHexString(
          '0a0300${'22' * 32}0700e40b54021503${'3501'}00000008981e000f000000'
          '68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f'
          '${'22' * 32}00');
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, payload), unshown);
      final reading =
          jsonDecode(session.readPolkadotTransaction(path, payload)) as Map;
      expect(reading['nonce'], '77');
      expect(reading['amount'], '10000000000');
      expect(reading['assetHub'], isTrue);
      final node =
          Bip32Slip10Ed25519.fromSeed(dartSeed(phrase)).derivePath(path);
      // Read for this key, by blockchain_utils' reckoning of it.
      expect(reading['signer'],
          '0x${BytesUtils.toHexString(node.publicKey.compressed.sublist(1))}');
      // Another account's key signs nothing this one's reading was of.
      expect(() => session.signEd25519("m/44'/354'/1'/0'/0'", payload), unshown,
          reason: 'read for another key');
      expect(session.signEd25519(path, payload),
          Ed25519Signer.fromKeyBytes(node.privateKey.raw).sign(payload));
      expect(() => session.signEd25519(path, payload), unshown, reason: 'once');
      expect(
          () => session.readPolkadotTransaction(path, [...payload, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
      final imported = core.openKey(KeyCoreCurve.ed25519, List.filled(32, 7));
      addTearDown(imported.close);
      expect(
          () => imported.readPolkadotTransaction(path, payload),
          throwsA(isA<KeyCoreException>()
              .having((e) => e.refusal, 'refusal', KeyCoreRefusal.kind)));
    });
  });

  group("a Tezos group's digest, only as read (O58)", () {
    test('a Tezos key signs only the digest of a group read for a screen, '
        'once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/1729'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      // The module's forger's bytes: a reveal and a transfer of one tez, at a
      // branch of its own.
      final forged = BytesUtils.fromHexString(
          '4545454545454545454545454545454545454545454545454545454545454545'
          '6b007d1c05728fa017919cba7ccf7ff007eacfee7d55900308e8070000111111'
          '1111111111111111111111111111111111111111111111111111111111006c00'
          '7d1c05728fa017919cba7ccf7ff007eacfee7d55e80709dc0b8102c0843d0000'
          '222222222222222222222222222222222222222200');
      final digest = QuickCrypto.blake2b256Hash([0x03, ...forged]);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, digest), unshown);
      final reading = jsonDecode(core.readTezosOperation(forged)) as Map;
      final ops = (reading['operations'] as List).cast<Map>();
      expect(ops.map((o) => o['kind']), ['reveal', 'transaction']);
      expect(ops.last['amount'], '1000000');
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, digest),
          Ed25519Signer.fromKeyBytes(secret).sign(digest));
      expect(() => session.signEd25519(path, digest), unshown, reason: 'once');
      final imported = core.openKey(KeyCoreCurve.tezos, secret);
      addTearDown(imported.close);
      expect(() => imported.signEd25519('m', digest), unshown);
      core.readTezosOperation(forged);
      expect(imported.signEd25519('m', digest),
          Ed25519Signer.fromKeyBytes(secret).sign(digest));
      expect(
          () => core.readTezosOperation([...forged, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group('an Algorand transaction, only as read (O58)', () {
    test('an Algorand key signs only a transaction read for a screen, once, '
        'as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/283'/0'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      List<int> text(String s) => [0xa0 | s.length, ...utf8.encode(s)];
      List<int> bytes(List<int> b) => [0xc4, b.length, ...b];
      // A payment of 7 microAlgos, canonical: its keys in order.
      final message = [
        ...'TX'.codeUnits,
        0x85,
        ...text('amt'), 7,
        ...text('fee'), 0xcd, 0x03, 0xe8,
        ...text('rcv'), ...bytes(List.filled(32, 0x22)),
        ...text('snd'), ...bytes(session.ed25519PublicKey(path)),
        ...text('type'), ...text('pay'),
      ];
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, message), unshown);
      final reading = jsonDecode(core.readAlgorandTransaction(message)) as Map;
      expect(((reading['transaction'] as Map)['map'] as Map)['amt'], {'uint': '7'});
      expect(reading['mainnet'], isFalse);
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, message),
          Ed25519Signer.fromKeyBytes(secret).sign(message));
      expect(() => session.signEd25519(path, message), unshown, reason: 'once');
      final imported = core.openKey(KeyCoreCurve.algorand, secret);
      addTearDown(imported.close);
      expect(() => imported.signEd25519('m', message), unshown);
      core.readAlgorandTransaction(message);
      expect(imported.signEd25519('m', message),
          Ed25519Signer.fromKeyBytes(secret).sign(message));
      expect(
          () => core.readAlgorandTransaction([...message, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("a Sui intent message's digest, only as read (O58)", () {
    test('a Sui key signs only the digest of a message read for a screen, '
        'once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/784'/0'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      List<int> u64(int n) => [for (var i = 0; i < 8; i++) n >> (8 * i) & 0xff];
      final sender = List.filled(32, 0x11);
      // 1,000 MIST split off the gas coin and handed to 0x22…22.
      final message = [
        0, 0, 0, 0, 0, 2, 0, 8, ...u64(1000), 0, 32, ...List.filled(32, 0x22),
        2, 2, 0, 1, 1, 0, 0, 1, 1, 3, 0, 0, 0, 0, 1, 1, 0,
        ...sender,
        1, ...List.filled(32, 0x33), ...u64(5), 32, ...List.filled(32, 0x44),
        ...sender, ...u64(750), ...u64(5000000),
        0,
      ];
      final digest = QuickCrypto.blake2b256Hash(message);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, digest), unshown);
      final reading = jsonDecode(core.readSuiTransaction(message)) as Map;
      expect(reading['amount'], '1000');
      expect(reading['recipient'], '0x${'22' * 32}');
      expect(reading['transactionDigest'],
          Base58Encoder.encode(QuickCrypto.blake2b256Hash(
              [...utf8.encode('TransactionData::'), ...message.sublist(3)])));
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, digest),
          Ed25519Signer.fromKeyBytes(secret).sign(digest));
      expect(() => session.signEd25519(path, digest), unshown, reason: 'once');
      // An imported Sui key, opened as one, the same.
      final imported = core.openKey(KeyCoreCurve.sui, secret);
      addTearDown(imported.close);
      expect(() => imported.signEd25519('m', digest), unshown);
      core.readSuiTransaction(message);
      expect(imported.signEd25519('m', digest),
          Ed25519Signer.fromKeyBytes(secret).sign(digest));
      expect(
          () => core.readSuiTransaction([...message, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group('an Aptos signing message, only as read (O58)', () {
    test('an Aptos or Movement key signs only a message read for a screen, '
        'once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/637'/0'/0'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      List<int> u64(int n) => [for (var i = 0; i < 8; i++) n >> (8 * i) & 0xff];
      // One transfer of 7 octas to 0x23…23 on Movement, chain 126.
      final message = [
        ...QuickCrypto.sha3256Hash(utf8.encode('APTOS::RawTransaction')),
        ...List.filled(32, 0x44),
        ...u64(42),
        2, ...List.filled(31, 0), 1,
        13, ...utf8.encode('aptos_account'),
        8, ...utf8.encode('transfer'),
        0, 2, 32, ...List.filled(32, 0x23), 8, ...u64(7),
        ...u64(2000), ...u64(100), ...u64(1700000060),
        126,
      ];
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, message), unshown);
      final reading = jsonDecode(core.readAptosTransaction(message)) as Map;
      expect(reading['amount'], '7');
      expect(reading['chainId'], 126);
      expect(reading['recipient'], '0x${'23' * 32}');
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, message),
          Ed25519Signer.fromKeyBytes(secret).sign(message));
      expect(() => session.signEd25519(path, message), unshown, reason: 'once');
      expect(
          () => core.readAptosTransaction([...message, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("a NEAR transaction's hash, only as read (O58)", () {
    test('a NEAR key signs only the hash of a transaction read for a '
        'screen, once, as blockchain_utils signs it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/44'/397'/0'";
      final session = core.open(phrase);
      addTearDown(session.close);
      final key = session.ed25519PublicKey(path);
      List<int> u32(int n) => [n & 0xff, n >> 8 & 0xff, n >> 16 & 0xff, n >> 24 & 0xff];
      List<int> text(String s) => [...u32(s.length), ...utf8.encode(s)];
      final signer = key.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      // One transfer of 7 yoctoNEAR to bob.near, at nonce 42.
      final transaction = [
        ...text(signer),
        0, ...key,
        42, 0, 0, 0, 0, 0, 0, 0,
        ...text('bob.near'),
        ...List.filled(32, 9),
        ...u32(1),
        3, 7, ...List.filled(15, 0),
      ];
      final hash = QuickCrypto.sha256Hash(transaction);
      final unshown = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => session.signEd25519(path, hash), unshown);
      final reading = jsonDecode(core.readNearTransaction(transaction)) as Map;
      expect(reading['signerId'], signer);
      expect(reading['receiverId'], 'bob.near');
      expect(reading['nonce'], '42');
      expect(((reading['actions'] as List).single as Map)['deposit'], '7');
      expect(reading['hash'], Base58Encoder.encode(hash));
      final secret = Bip32Slip10Ed25519.fromSeed(dartSeed(phrase))
          .derivePath(path)
          .privateKey
          .raw;
      expect(session.signEd25519(path, hash),
          Ed25519Signer.fromKeyBytes(secret).sign(hash));
      expect(() => session.signEd25519(path, hash), unshown, reason: 'once');
      expect(
          () => core.readNearTransaction([...transaction, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.transaction)));
    });
  });

  group("a Cosmos zone's SignDoc, only as read (O58)", () {
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    Matcher refused(KeyCoreRefusal refusal) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', refusal));
    List<int> varint(int n) {
      final out = <int>[];
      do {
        final byte = n & 0x7f;
        n >>= 7;
        out.add(n == 0 ? byte : byte | 0x80);
      } while (n != 0);
      return out;
    }

    List<int> field(int number, List<int> bytes) =>
        [...varint(number << 3 | 2), ...varint(bytes.length), ...bytes];

    test("a zone's key signs only the SHA-256 of a SignDoc read for a "
        'screen, once, as blockchain_utils signs it', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final path in ["m/44'/118'/0'/0/0", "m/44'/459'/0'/0/0"]) {
        final key = dartChild(dartSeed(phrase), path).privateKey.raw;
        // A transfer's SignDoc of this path's own, so each is read anew.
        final send = [
          ...field(1, utf8.encode('cosmos1from')),
          ...field(2, utf8.encode(path)),
        ];
        final body = field(1, [
          ...field(1, utf8.encode('/cosmos.bank.v1beta1.MsgSend')),
          ...field(2, send),
        ]);
        final doc = [...field(1, body), ...field(3, utf8.encode('cosmoshub-4'))];
        final digest = QuickCrypto.sha256Hash(doc);
        expect(() => session.signSecp256k1Digest(path, digest),
            refused(KeyCoreRefusal.unshown), reason: path);
        final reading = jsonDecode(core.readCosmosSignDoc(doc)) as Map;
        expect(reading['chainId'], 'cosmoshub-4');
        expect(((reading['messages'] as List).single as Map)['decoded']['to'],
            path);
        final (expected, recoveryId) = Secp256k1SigningKey.fromBytes(keyBytes: key)
            .signConst(digest: digest);
        final signature = session.signSecp256k1Digest(path, digest);
        expect(BigintUtils.fromBytes(signature.r), expected.r, reason: path);
        expect(BigintUtils.fromBytes(signature.s), expected.s, reason: path);
        expect(signature.recoveryId, recoveryId, reason: path);
        expect(() => session.signSecp256k1Digest(path, digest),
            refused(KeyCoreRefusal.unshown), reason: '$path, once');
        // An imported zone's key, opened as one, the same.
        final imported = core.openKey(KeyCoreCurve.cosmos, key);
        addTearDown(imported.close);
        expect(() => imported.signSecp256k1Digest('m', digest),
            refused(KeyCoreRefusal.unshown));
        core.readCosmosSignDoc(doc);
        expect(imported.signSecp256k1Digest('m', digest).r, signature.r);
      }
      expect(() => core.readCosmosSignDoc([...field(5, [1])]),
          refused(KeyCoreRefusal.transaction));
    });
  });

  group('an XRP payment, only as read, its expiry aside (O59)', () {
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    const path = "m/44'/144'/0'/0/0";
    // xrpl_dart's signing serialisation of a payment of 1 XRP whose
    // LastLedgerSequence is 104 (`src/tests.rs` holds the same).
    final payment = BytesUtils.fromHexString(
        '1200002400000005201b000000686140000000000f424068400000000000000c7321'
        '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f81'
        '14a3c6b1ee4a49d9f2af3b3802974744fba924164a8314b5f762798a53d543a014ca'
        'f8b297cff8f2f937e8');
    Matcher refused(KeyCoreRefusal refusal) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', refusal));

    test('an XRP key signs only a payment read for a screen, once, its '
        'expiry set at the signature, as blockchain_utils signs it', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      final secret = dartChild(dartSeed(phrase), path).privateKey.raw;
      final moved = Uint8List.fromList(payment)..[13] = 0x6c;
      expect(() => session.signXrplTransaction(path, moved),
          refused(KeyCoreRefusal.unshown));
      final reading = jsonDecode(core.readXrplTransaction(payment)) as Map;
      expect(reading['destination'], 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
      expect(reading['amount'], '1000000');
      expect(reading['lastLedgerSequence'], 104);
      final digest = QuickCrypto.sha512HashHalves(
          [...'STX'.codeUnits, 0, ...moved]).$1;
      expect(session.signXrplTransaction(path, moved),
          Secp256k1Signer.fromKeyBytes(secret)
              .signConst(digest, hashMessage: false));
      expect(() => session.signXrplTransaction(path, moved),
          refused(KeyCoreRefusal.unshown),
          reason: 'once');
      expect(() => session.signSecp256k1Digest(path, digest),
          refused(KeyCoreRefusal.transactionOnly));

      // An imported XRP key, opened as one, the same.
      final imported = core.openKey(KeyCoreCurve.xrp, secret);
      addTearDown(imported.close);
      expect(() => imported.signXrplTransaction('m', moved),
          refused(KeyCoreRefusal.unshown));
      core.readXrplTransaction(payment);
      expect(imported.signXrplTransaction('m', moved),
          Secp256k1Signer.fromKeyBytes(secret)
              .signConst(digest, hashMessage: false));
      expect(() => core.readXrplTransaction([...payment, 0]),
          refused(KeyCoreRefusal.transaction));
    });
  });

  group("EVM's digest call, closed (O43)", () {
    Matcher onlyWhatIsRead() => throwsA(isA<KeyCoreException>().having(
        (e) => e.refusal, 'refusal', KeyCoreRefusal.transactionOnly));
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    final digest = List<int>.filled(32, 0x5a);

    test("a phrase's key at an EVM path signs no bare digest", () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final path in [
        "m/44'/60'/0'/0/0",
        "m/44'/60'/0'/0/9",
        "m/44'/60'/4'/0/0",
      ]) {
        expect(() => session.signSecp256k1Digest(path, digest),
            onlyWhatIsRead(), reason: path);
        expect(() => session.signSecp256k1DigestLowR(path, digest),
            onlyWhatIsRead(), reason: path);
        expect(() => session.signSchnorr(path, digest), onlyWhatIsRead(),
            reason: path);
        expect(session.secp256k1PublicKey(path), hasLength(33), reason: path);
        expect(session.signEvmPersonalMessage(path, [1, 2]).r, hasLength(32),
            reason: path);
      }
      expect(session.signSecp256k1Digest("m/1'/2'/3'/4/5", digest).r,
          hasLength(32), reason: "a key at no network's path is not EVM's");
    });

    test('a key opened as an EVM key signs no bare digest, and its messages '
        'as the plain key', () {
      final secret = List<int>.filled(32, 0x46);
      final evm = core.openKey(KeyCoreCurve.evm, secret);
      final plain = core.openKey(KeyCoreCurve.secp256k1, secret);
      addTearDown(evm.close);
      addTearDown(plain.close);
      expect(evm.secp256k1PublicKey('m'), plain.secp256k1PublicKey('m'));
      expect(evm.exportSecp256k1PrivateKey('m'),
          plain.exportSecp256k1PrivateKey('m'));
      expect(() => evm.signSecp256k1Digest('m', digest), onlyWhatIsRead());
      expect(() => evm.signSecp256k1DigestLowR('m', digest), onlyWhatIsRead());
      expect(() => evm.signSchnorr('m', digest), onlyWhatIsRead());
      final message = utf8.encode('Some data');
      final a = evm.signEvmPersonalMessage('m', message);
      final b = plain.signEvmPersonalMessage('m', message);
      expect(a.r, b.r);
      expect(a.s, b.s);
      expect(a.recoveryId, b.recoveryId);
    });
  });

  group('EVM messages, hashed in the core (2e)', () {
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    const path = "m/44'/60'/0'/0/0";
    Matcher refused(KeyCoreRefusal why) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', why));
    // EIP-712's own example, and the digest the EIP publishes for it.
    final mail = jsonEncode({
      'types': {
        'EIP712Domain': [
          {'name': 'name', 'type': 'string'},
          {'name': 'version', 'type': 'string'},
          {'name': 'chainId', 'type': 'uint256'},
          {'name': 'verifyingContract', 'type': 'address'},
        ],
        'Person': [
          {'name': 'name', 'type': 'string'},
          {'name': 'wallet', 'type': 'address'},
        ],
        'Mail': [
          {'name': 'from', 'type': 'Person'},
          {'name': 'to', 'type': 'Person'},
          {'name': 'contents', 'type': 'string'},
        ],
      },
      'primaryType': 'Mail',
      'domain': {
        'name': 'Ether Mail',
        'version': '1',
        'chainId': 1,
        'verifyingContract': '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      'message': {
        'from': {
          'name': 'Cow',
          'wallet': '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        'to': {
          'name': 'Bob',
          'wallet': '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        'contents': 'Hello, Bob!',
      },
    });
    final mailDigest = BytesUtils.fromHexString(
        'be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2');

    void sameAs(Secp256k1Signature signature, List<int> key, List<int> digest,
        String why) {
      final (expected, recoveryId) =
          Secp256k1SigningKey.fromBytes(keyBytes: key).signConst(digest: digest);
      expect(BigintUtils.fromBytes(signature.r), expected.r, reason: why);
      expect(BigintUtils.fromBytes(signature.s), expected.s, reason: why);
      expect(signature.recoveryId, recoveryId, reason: why);
    }

    test('200 personal messages: the signature over EIP-191 of each', () {
      final random = Random(20261031);
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final session = core.open(phrase);
      addTearDown(session.close);
      for (var i = 0; i < 200; i++) {
        final message = List.generate(
            i < 3 ? i * 50 : random.nextInt(2000), (_) => random.nextInt(256));
        final digest = QuickCrypto.keccack256Hash([
          ...utf8.encode('\u0019Ethereum Signed Message:\n${message.length}'),
          ...message,
        ]);
        sameAs(session.signEvmPersonalMessage(path, message), key, digest,
            'message $i, ${message.length} bytes');
      }
    });

    test("EIP-712's example: the signature over the digest it publishes", () {
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final session = core.open(phrase);
      addTearDown(session.close);
      // Read for a screen first, as every door does (2f-2, O54).
      session.readEvmTypedData(path, mail);
      sameAs(session.signEvmTypedData(path, mail), key, mailDigest, 'the spec');
      final imported = core.openKey(KeyCoreCurve.secp256k1, key);
      addTearDown(imported.close);
      imported.readEvmTypedData('m', mail);
      sameAs(imported.signEvmTypedData('m', mail), key, mailDigest,
          'imported');
    });

    test('refused: typed data that does not read, a key of the Bitcoin '
        'family, another curve', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final json in ['', '{}', mail.replaceFirst('"chainId":1', '"chainId":"+1"')]) {
        expect(() => session.signEvmTypedData(path, json),
            refused(KeyCoreRefusal.typedData), reason: json);
      }
      // Read, so each refusal below is the key's.
      session.readEvmTypedData(path, mail);
      for (final at in ["m/84'/0'/0'/0/0", "m/44'/2'/0'/0/0", "m/44'/3'/0'/0/0"]) {
        expect(() => session.signEvmTypedData(at, mail),
            refused(KeyCoreRefusal.transactionOnly), reason: at);
        expect(() => session.signEvmPersonalMessage(at, [1]),
            refused(KeyCoreRefusal.transactionOnly), reason: at);
      }
      final bitcoin =
          core.openKey(KeyCoreCurve.bitcoin, List.filled(32, 0x46));
      addTearDown(bitcoin.close);
      expect(() => bitcoin.signEvmPersonalMessage('m', [1]),
          refused(KeyCoreRefusal.transactionOnly));
      final ed = core.openKey(KeyCoreCurve.ed25519, List.filled(32, 7));
      addTearDown(ed.close);
      expect(() => ed.signEvmTypedData('m', mail), refused(KeyCoreRefusal.kind));
    });

    test('2f-2: what is signed, through the length-first protocol; signed once, '
        'and only once read', () {
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final session = core.open(phrase);
      addTearDown(session.close);
      // A document of its own, so no other test's reading stands for it.
      final own = mail.replaceFirst('Hello, Bob!', 'Hello, 2f-2!');
      expect(() => session.signEvmTypedData(path, own),
          refused(KeyCoreRefusal.unshown));
      final reading = jsonDecode(session.readEvmTypedData(path, own))
          as Map<String, dynamic>;
      // Read for this key: its account, by blockchain_utils' reckoning.
      final account = EthAddrEncoder().encodeKey(
          dartChild(dartSeed(phrase), path).publicKey.compressed,
          skipChecksum: true);
      expect(reading['signer'], '0x$account');
      expect(() => session.signEvmTypedData("m/44'/60'/0'/0/1", own),
          refused(KeyCoreRefusal.unshown),
          reason: 'read for another key');
      expect(reading['primaryType'], 'Mail');
      expect(reading['domainOnly'], isFalse);
      final from = (reading['message'] as List).first as Map;
      expect(from['name'], 'from');
      expect(((from['value'] as List)[1] as Map)['value'],
          '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826');
      expect(reading['unsigned'], isEmpty);
      expect(reading['permit'], isNull);
      final signature = session.signEvmTypedData(path, own);
      sameAs(signature, key, BytesUtils.fromHexString(reading['digest'] as String),
          'over the digest it read');
      expect(() => session.signEvmTypedData(path, own),
          refused(KeyCoreRefusal.unshown));
      expect(() => session.readEvmTypedData(path, '{}'),
          refused(KeyCoreRefusal.typedData));
    });
  });

  group('an EVM transaction read for the screen (2f-1)', () {
    test('its facts and its call, through the length-first protocol', () {
      // An approval of 2^256 − 1 to 0x11…11 on chain 1, as the app writes
      // the layout `kc_secp256k1_sign_evm_transaction` reads.
      List<int> word(int n) => List.filled(32, 0)..[31] = n;
      final data = [
        0x09, 0x5e, 0xa7, 0xb3,
        ...List.filled(12, 0), ...List.filled(20, 0x11),
        ...List.filled(32, 0xff),
      ];
      final expected = [
        2, ...word(1), 1, ...List.filled(20, 0x22),
        ...word(0), ...word(0x52), ...word(1), ...word(2),
        ...data,
      ];
      final session = core.openKey(KeyCoreCurve.secp256k1, List.filled(32, 0x46));
      addTearDown(session.close);
      final reading = jsonDecode(session.readEvmTransaction('m', expected))
          as Map<String, dynamic>;
      // EIP-155's example sender: the account of the key 0x4646…46.
      expect(reading['from'], '0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f');
      expect(reading['to'], '0x${'22' * 20}');
      final call = reading['call'] as Map<String, dynamic>;
      expect(call['reading'], 'decoded');
      expect(call['selector'], '0x095ea7b3');
      final approve = call['call'] as Map<String, dynamic>;
      expect(approve['kind'], 'approve');
      expect(approve['spender'], '0x${'11' * 20}');
      expect(approve['unlimited'], isTrue);
      expect(() => session.readEvmTransaction('m', [2, 0, 0]),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.argument)));
    });

    test('a transaction is signed only once read for a screen, once (2f-1b)',
        () {
      // EIP-155's example, signed by the key 0x4646…46: its signing data, and
      // the transaction as the app writes it.
      final unsigned = BytesUtils.fromHexString(
          'ec098504a817c800825208943535353535353535353535353535353535353535880de0b6'
          'b3a764000080018080');
      List<int> word(BigInt n) => BigintUtils.toBytes(n, length: 32);
      final expected = [
        0, ...word(BigInt.one), 1, ...List.filled(20, 0x35),
        ...word(BigInt.from(10).pow(18)), ...word(BigInt.from(21000)),
        ...word(BigInt.from(20000000000)), ...word(BigInt.zero),
      ];
      final key = core.openKey(KeyCoreCurve.secp256k1, List.filled(32, 0x46));
      addTearDown(key.close);
      Matcher unshown() => throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.unshown));
      expect(() => key.signEvmTransaction('m', unsigned, expected), unshown());
      // Read for another key, it signs nothing for this one.
      final other = core.openKey(KeyCoreCurve.secp256k1, List.filled(32, 0x47));
      addTearDown(other.close);
      other.readEvmTransaction('m', expected);
      expect(() => key.signEvmTransaction('m', unsigned, expected), unshown(),
          reason: 'read for another key');
      key.readEvmTransaction('m', expected);
      expect(key.signEvmTransaction('m', unsigned, expected).recoveryId, 0);
      expect(() => key.signEvmTransaction('m', unsigned, expected), unshown(),
          reason: 'one reading signs once');
    });
  });

  group('a phrase opened from its seal', () {
    // The record `src/tests.rs` and `tool/so_smoke.c` hold: the canonical
    // phrase sealed by pointycastle's AES-GCM, as `CryptoUtils.encryptBytes`
    // calls it, under the key 01 02 … 20 with the nonce a0 a1 … ab. The app's
    // `test/key_core_sealed_test.dart` seals thousands more through
    // `CryptoUtils` itself.
    final key = List<int>.generate(32, (i) => i + 1);
    final sealed = BytesUtils.fromHexString(
        'a0a1a2a3a4a5a6a7a8a9aaabd8b35c0899da34241e6cc30595ea4ea436b5d1773c07'
        '0ea44639b4933621b61550b3f8a68bbdde144c14a1f7c259200778d411aaa8f490f5'
        '2986e29ea6596948cd20c28aca4422d1bbf2279a66b595ffacfd77251c993c56a890'
        'a94f933502bfe7efb90e57e9e5f4b30022347a');
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon about';
    Matcher refused(KeyCoreRefusal why) => throwsA(isA<KeyCoreException>()
        .having((e) => e.refusal, 'refusal', why));

    test('is the wallet the phrase is, and the key the wallet pins', () {
      final fromSeal = core.openSealed(sealed, key);
      addTearDown(fromSeal.close);
      final fromPhrase = core.open(phrase);
      addTearDown(fromPhrase.close);
      const path = "m/44'/60'/0'/0/0";
      expect(BytesUtils.toHexString(fromSeal.exportSecp256k1PrivateKey(path)),
          '1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727');
      expect(fromSeal.secp256k1PublicKey(path),
          fromPhrase.secp256k1PublicKey(path));
      expect(fromSeal.ed25519PublicKey("m/44'/501'/0'/0'"),
          fromPhrase.ed25519PublicKey("m/44'/501'/0'/0'"));
    });

    test('refuses a changed byte, another key and a short record as a seal',
        () {
      for (var i = 0; i < sealed.length; i += 7) {
        final changed = [...sealed]..[i] ^= 1;
        expect(() => core.openSealed(changed, key),
            refused(KeyCoreRefusal.seal),
            reason: 'byte $i');
      }
      expect(() => core.openSealed(sealed, [...key]..[0] ^= 1),
          refused(KeyCoreRefusal.seal));
      expect(() => core.openSealed(sealed.sublist(0, 27), key),
          refused(KeyCoreRefusal.seal));
      expect(() => core.openSealed(sealed, key.sublist(0, 31)),
          refused(KeyCoreRefusal.argument));
    });
  });

  group('a session borrowed by other isolates', () {
    // What a background isolate does in a core build: it borrows the main
    // isolate's session by its handle and asks the core itself. Two isolates
    // at once, every curve, the main isolate's answers to compare with.
    const phrase = 'legal winner thank year wave sausage worth useful legal '
        'winner thank yellow';
    const evm = "m/44'/60'/0'/0/0";
    // A path no network uses, and Stellar's: TRON's, the Cosmos zones' and
    // Solana's keys sign only what a screen was given the reading of (O58).
    const cosmos = "m/1'/2'/3'/4/5";
    const solana = "m/1'/2'/3'";
    // And a Cardano key at a path no module writes: one at m/1852'/1815'
    // signs only a body read (O58).
    const cardano = "m/1'/2'/3'/4/5";
    // And a Stark key at a path no module writes: one at m/44'/9004' signs
    // only the hash of a transaction read (O58).
    const starknet = "m/1'/2'/3'/4/9";
    final hash = Uint8List(32)..fillRange(1, 32, 0x5a);

    List<List<int>> answers(KeyCoreSession s) => [
          s.secp256k1PublicKey(evm),
          s.signSecp256k1DigestLowR(cosmos, List.filled(32, 3)),
          s.signEd25519(solana, [1, 2, 3]),
          s.signCardano(cardano, [4, 5, 6]),
          s.signStarknet(starknet, hash),
        ];

    test('answers in two isolates at once as on the main one', () async {
      final session = core.open(phrase);
      addTearDown(session.close);
      final expected = answers(session);
      final named = Platform.environment['KEY_CORE_LIBRARY'];
      final handle = session.handle;
      final fromIsolates = await Future.wait([
        for (var i = 0; i < 2; i++)
          Isolate.run(() {
            final inside = named != null && named.isNotEmpty
                ? KeyCore.at(named)
                : KeyCore.bundled();
            final borrowed = inside.borrow(handle);
            final all = <List<List<int>>>[];
            for (var n = 0; n < 20; n++) {
              all.add(answers(borrowed));
            }
            borrowed.close(); // borrowed: closes nothing
            return all;
          }),
      ]);
      for (final run in fromIsolates) {
        for (final one in run) {
          expect(one, expected);
        }
      }
      // The isolates' close() left the session open.
      expect(session.secp256k1PublicKey(evm), expected.first);
    });

    test('is refused once the main isolate closes it', () async {
      final session = core.open(phrase);
      final handle = session.handle;
      session.close();
      final named = Platform.environment['KEY_CORE_LIBRARY'];
      final refusal = await Isolate.run(() {
        final inside = named != null && named.isNotEmpty
            ? KeyCore.at(named)
            : KeyCore.bundled();
        try {
          inside.borrow(handle).secp256k1PublicKey(evm);
          return null;
        } on KeyCoreException catch (e) {
          return e.refusal;
        }
      });
      expect(refusal, KeyCoreRefusal.handle);
    });
  });

  group('both sides refuse', () {
    test('a phrase whose checksum fails', () {
      final phrase = List.filled(12, 'abandon').join(' ');
      expect(() => dartSeed(phrase), throwsA(anything));
      expect(() => core.open(phrase),
          throwsA(isA<KeyCoreException>().having(
              (e) => e.refusal, 'refusal', KeyCoreRefusal.phrase)));
    });

    test('a digest of zero, the order, or above it', () {
      const phrase = 'legal winner thank year wave sausage worth useful legal '
          'winner thank yellow';
      const path = "m/1'/2'/3'/4/5";
      final key = dartChild(dartSeed(phrase), path).privateKey.raw;
      final order = BigintUtils.toBytes(Curves.generatorSecp256k1.order!,
          length: 32);
      final above = Uint8List.fromList(order)..[31] += 1;
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final digest in [Uint8List(32), Uint8List.fromList(order), above]) {
        expect(
            () => Secp256k1SigningKey.fromBytes(keyBytes: key)
                .signConst(digest: digest),
            throwsA(anything));
        expect(() => session.signSecp256k1Digest(path, digest),
            throwsA(isA<KeyCoreException>().having(
                (e) => e.refusal, 'refusal', KeyCoreRefusal.digest)));
      }
    });
  });

  group('a session', () {
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon about';
    const path = "m/44'/60'/0'/0/0";

    test('signs nothing once closed', () {
      final session = core.open(phrase);
      session.close();
      final refusedAsClosed = throwsA(isA<KeyCoreException>()
          .having((e) => e.refusal, 'refusal', KeyCoreRefusal.handle));
      expect(() => session.signSecp256k1Digest(path, List.filled(32, 7)),
          refusedAsClosed);
      expect(() => session.secp256k1PublicKey(path), refusedAsClosed);
      expect(() => session.exportSecp256k1PrivateKey(path), refusedAsClosed);
      session.close(); // closed already: not an error
    });

    test('is closed by closeAll, which is what the lock would call', () {
      final a = core.open(phrase);
      final b = core.open(phrase);
      expect(core.closeAll(), greaterThanOrEqualTo(2));
      for (final session in [a, b]) {
        expect(
            () => session.exportSecp256k1PrivateKey(path),
            throwsA(isA<KeyCoreException>()
                .having((e) => e.refusal, 'refusal', KeyCoreRefusal.handle)));
        session.close();
      }
    });

    test('refuses a path the wallet does not write', () {
      final session = core.open(phrase);
      addTearDown(session.close);
      for (final bad in ["m/44h/60h", "44'/60'", 'm/+1', 'm/2147483648']) {
        expect(
            () => session.exportSecp256k1PrivateKey(bad),
            throwsA(isA<KeyCoreException>()
                .having((e) => e.refusal, 'refusal', KeyCoreRefusal.path)),
            reason: bad);
      }
    });
  });
}
