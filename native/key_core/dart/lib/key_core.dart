/// The Dart side of the Smartable key core, `native/key_core`.
///
/// **Not wired into the app.** Phase 1 of `docs/RUST_KEY_CORE_DESIGN.md`: the
/// binding, and its checks against the libraries the wallet signs with today.
///
/// A phrase goes in once — or the record it is sealed in, with its key
/// ([KeyCore.openSealed]) — and a [KeyCoreSession] comes back; keys are asked
/// of the session by path and are never held on this side. The exceptions are
/// [KeyCoreSession.exportSecp256k1PrivateKey],
/// [KeyCoreSession.exportEd25519PrivateKey],
/// [KeyCoreSession.exportCardanoPrivateKey] and
/// [KeyCoreSession.exportStarknetPrivateKey], for the export screens.
///
/// Since phase 6c the session also answers the two questions that read the
/// phrase's text in Dart: whether a phrase is this one
/// ([KeyCoreSession.matchesPhrase]) and Cardano's Icarus key
/// ([KeyCoreSession.cardanoIcarusPublicKey]).
///
/// The declarations below are the second copy of `include/key_core.h`; each
/// function's rules are documented once, in `src/lib.rs`.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// The ABI this binding was written against: `KC_ABI_VERSION`.
const int keyCoreAbiVersion = 41;

/// Why the core refused: one value per `KC_ERR_*` code.
enum KeyCoreRefusal {
  /// A null pointer or a buffer of the wrong length — a defect in this file.
  argument(1),

  /// The session was closed, by [KeyCoreSession.close] or [KeyCore.closeAll].
  handle(2),

  /// Not a checksum-valid English phrase in the form the wallet stores.
  phrase(3),

  /// Not a path in the form the wallet writes, or, for ed25519, one with a
  /// level that is not hardened.
  path(4),

  /// A digest of zero, or one not below the curve's order; for Starknet, a
  /// hash at or above 2^251.
  digest(5),

  /// A BIP-32 or BIP32-Ed25519 child that does not exist.
  derivation(6),

  /// A panic in the core, caught, or a signature that failed its own check.
  internal(7),

  /// A call this session's kind does not answer: an imported key asked for a
  /// chain code, a Cardano or Starknet key, or a key on the other curve.
  kind(8),

  /// For [KeyCore.openKey], 32 bytes that are not a key on the curve: a
  /// secp256k1 scalar of zero, or not below the order.
  key(9),

  /// For [KeyCore.openSealed], a record this key does not open: a wrong key,
  /// a changed byte, or fewer bytes than a nonce and a tag.
  seal(10),

  /// For [KeyCoreSession.signEvmTransaction],
  /// [KeyCoreSession.signBitcoinTransaction],
  /// [KeyCoreSession.signKaspaTransaction] and
  /// [KeyCoreSession.signZcashTransaction], bytes that are not a
  /// transaction in a form the app writes, or not the transaction it built.
  transaction(11),

  /// A bare digest asked of a key that signs only what the core reads: a key
  /// of the Bitcoin family — a phrase's key at a Bitcoin, Litecoin, Dogecoin
  /// or Bitcoin Cash path, or a key opened as [KeyCoreCurve.bitcoin] — signs
  /// only a transaction, and no EVM message either (O37); an EVM key — a
  /// phrase's key at `m/44'/60'`, or a key opened as [KeyCoreCurve.evm] —
  /// only a transaction, a personal message or typed data (O43).
  transactionOnly(12),

  /// For [KeyCoreSession.signEvmTypedData], a document that is not EIP-712
  /// typed data the app's validator takes: over 512 KiB, JSON that does not
  /// parse, a type or value refused, a limit passed, or a value in any but
  /// its one canonical spelling (O42, O44).
  typedData(13),

  /// An output buffer shorter than the reading — a defect in this file, which
  /// asks for the length first.
  buffer(14),

  /// For [KeyCoreSession.signEvmTransaction], a transaction no screen was
  /// shown: no reading [KeyCoreSession.readEvmTransaction] gave for this key
  /// and no signature has used has its kind, network, recipient, value and
  /// call data at a fee within its cap (the owner's decision O53). For
  /// [KeyCoreSession.signEvmTypedData], a document no unused reading of
  /// [KeyCoreSession.readEvmTypedData] for this key has the digest of (O54).
  /// For
  /// [KeyCoreSession.signBitcoinTransaction], a request no unused reading of
  /// [KeyCoreSession.readBitcoinTransaction] was of, byte for byte (2f-3).
  /// For [KeyCoreSession.signEd25519] by a Solana key, a message no unused
  /// reading of [KeyCore.readSolanaMessage] was of (O58). For
  /// [KeyCoreSession.signSecp256k1Digest] by a TRON key, a digest that is no
  /// unused reading's of [KeyCore.readTronTransaction] (O58). For
  /// [KeyCoreSession.signXrplTransaction], a payment no unused reading of
  /// [KeyCore.readXrplTransaction] was of, its expiry aside (O59). For
  /// [KeyCoreSession.signSecp256k1Digest] by a Cosmos zone's key, a digest
  /// that is no unused reading's of [KeyCore.readCosmosSignDoc] (O58); by a
  /// Filecoin key, one no unused reading of [KeyCore.readFilecoinMessage]
  /// was of; by an ICP key, one no unused reading of [KeyCore.readIcpCall]
  /// was of (O58). For [KeyCoreSession.signKaspaTransaction], a request no
  /// unused reading of [KeyCoreSession.readKaspaTransaction] was of, byte
  /// for byte (O58). For [KeyCoreSession.signZcashTransaction], a request no
  /// unused reading of [KeyCoreSession.readZcashTransaction] was of, byte
  /// for byte. For
  /// [KeyCoreSession.signEd25519] by a Stellar key, a message that is not the
  /// hash of a transaction an unused reading of
  /// [KeyCore.readStellarTransaction] was of (O58); by a NEAR key, one that
  /// is not the hash of a transaction an unused reading of
  /// [KeyCore.readNearTransaction] was of (O58); by an Aptos or Movement
  /// key, a message no unused reading of [KeyCore.readAptosTransaction] was
  /// of; by a Sui key, one that is not the BLAKE2b-256 of an intent message an
  /// unused reading of [KeyCore.readSuiTransaction] was of; by an Algorand
  /// key, a message no unused reading of [KeyCore.readAlgorandTransaction]
  /// was of; by a Tezos key, one that is not the watermarked BLAKE2b-256 of
  /// a group an unused reading of [KeyCore.readTezosOperation] was of; by a
  /// MultiversX key, a message no unused reading of
  /// [KeyCore.readMultiversxTransaction] was of; by a Polkadot key, a
  /// message no unused reading of [KeyCoreSession.readPolkadotTransaction]
  /// for this key was of; by a TON key, one that is not the hash of a signing
  /// message an unused reading of [KeyCoreSession.readTonTransfer] for this
  /// key was of; [KeyCoreSession.signCardano]
  /// by a key at `m/1852'/1815'`, one that is not the hash of a body an
  /// unused reading of [KeyCoreSession.readCardanoTransaction] was of with
  /// that key among its signers (O58).
  unshown(15),

  /// [KeyCore.slip39Restore]: too few shares, and the stores' copies did not
  /// open under the password.
  sharePassword(16),

  /// [KeyCore.slip39Restore]: too few shares, and a copy that opened says
  /// another backup than its labels — a file edited.
  shareAltered(17),

  /// [KeyCore.slip39Restore]: shares that give no wallet back — too few, or
  /// no set of them recombining to a phrase.
  share(18);

  const KeyCoreRefusal(this.code);

  final int code;
}

/// The curve of a key [KeyCore.openKey] opens: `KC_CURVE_*`.
enum KeyCoreCurve {
  /// A 32-byte secp256k1 scalar.
  secp256k1(0),

  /// A 32-byte ed25519 seed, RFC 8032's private key.
  ed25519(1),

  /// A 32-byte secp256k1 scalar of the Bitcoin family — an imported Bitcoin,
  /// Litecoin, Dogecoin or Bitcoin Cash key — which signs only a transaction
  /// the core reads ([KeyCoreSession.signBitcoinTransaction]) and no bare
  /// digest (the owner's decision O37).
  bitcoin(2),

  /// A 32-byte secp256k1 scalar of an imported EVM key, which signs only a
  /// transaction ([KeyCoreSession.signEvmTransaction]), a personal message
  /// or typed data the core reads — no bare digest, and no Bitcoin
  /// transaction (O43).
  evm(3),

  /// A 32-byte ed25519 seed of an imported Solana key, which signs only a
  /// message [KeyCore.readSolanaMessage] read for a screen, once (O58).
  solana(4),

  /// A 32-byte secp256k1 scalar of an imported TRON key, which signs only the
  /// SHA-256 of a transaction [KeyCore.readTronTransaction] read for a screen,
  /// once ([KeyCoreSession.signSecp256k1Digest]), and no Bitcoin or EVM
  /// transaction (O58).
  tron(5),

  /// A 32-byte secp256k1 scalar of an imported XRP Ledger key, which signs
  /// only a payment [KeyCore.readXrplTransaction] read for a screen, once
  /// ([KeyCoreSession.signXrplTransaction]) — no digest, and no Bitcoin or
  /// EVM transaction (O59).
  xrp(6),

  /// A 32-byte secp256k1 scalar of an imported Cosmos zone's key, which signs
  /// only the SHA-256 of a `SignDoc` [KeyCore.readCosmosSignDoc] read for a
  /// screen, once ([KeyCoreSession.signSecp256k1Digest]), and no Bitcoin or
  /// EVM transaction (O58).
  cosmos(7),

  /// A 32-byte ed25519 seed of an imported Stellar key, which signs only the
  /// hash of a transaction [KeyCore.readStellarTransaction] read for a
  /// screen, once (O58).
  stellar(8),

  /// A 32-byte ed25519 seed of an imported Sui key, which signs only the
  /// BLAKE2b-256 of an intent message [KeyCore.readSuiTransaction] read for a
  /// screen, once (O58).
  sui(9),

  /// A 32-byte ed25519 seed of an imported Algorand key, which signs only a
  /// transaction [KeyCore.readAlgorandTransaction] read for a screen, once
  /// (O58).
  algorand(10),

  /// A 32-byte ed25519 seed of an imported Tezos key, which signs only the
  /// watermarked BLAKE2b-256 of a group [KeyCore.readTezosOperation] read for
  /// a screen, once (O58).
  tezos(11),

  /// A 32-byte secp256k1 scalar of an imported Filecoin key, which signs only
  /// the digest of a message [KeyCore.readFilecoinMessage] read for a screen,
  /// once ([KeyCoreSession.signSecp256k1Digest]), and no Bitcoin or EVM
  /// transaction (O58).
  filecoin(12),

  /// A 32-byte secp256k1 scalar of an imported ICP key, which signs only the
  /// digest of a call [KeyCore.readIcpCall] read for a screen, once
  /// ([KeyCoreSession.signSecp256k1Digest]), and no Bitcoin or EVM
  /// transaction (O58).
  icp(13),

  /// A 32-byte secp256k1 scalar of an imported Kaspa key, which signs only a
  /// send [KeyCoreSession.readKaspaTransaction] read for a screen, once
  /// ([KeyCoreSession.signKaspaTransaction]), and no bare digest, message,
  /// Bitcoin or EVM transaction (O58).
  kaspa(14),

  /// A 32-byte secp256k1 scalar of an imported Zcash transparent key, which
  /// signs only a send [KeyCoreSession.readZcashTransaction] read for a
  /// screen, once ([KeyCoreSession.signZcashTransaction]), and no bare
  /// digest, message, Bitcoin or EVM transaction.
  zcash(15);

  const KeyCoreCurve(this.code);

  final int code;
}

class KeyCoreException implements Exception {
  const KeyCoreException(this.refusal);

  /// A code this binding does not know is [KeyCoreRefusal.internal]: a newer
  /// library is refused at [KeyCore]'s construction, so this is a defect.
  factory KeyCoreException.fromCode(int code) => KeyCoreException(
        KeyCoreRefusal.values.firstWhere((r) => r.code == code,
            orElse: () => KeyCoreRefusal.internal),
      );

  final KeyCoreRefusal refusal;

  @override
  String toString() => 'KeyCoreException(${refusal.name})';
}

/// A recoverable secp256k1 signature: [r] and [s] as 32 big-endian bytes,
/// [recoveryId] from 0 to 3.
final class Secp256k1Signature {
  const Secp256k1Signature._(this.r, this.s, this.recoveryId);

  final Uint8List r;
  final Uint8List s;
  final int recoveryId;
}

typedef _AbiVersionC = Uint32 Function();
typedef _AbiVersion = int Function();
typedef _OpenC = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint64>);
typedef _Open = int Function(Pointer<Uint8>, int, Pointer<Uint64>);
typedef _OpenKeyC = Int32 Function(
    Int32, Pointer<Uint8>, Size, Pointer<Uint64>);
typedef _OpenKey = int Function(int, Pointer<Uint8>, int, Pointer<Uint64>);
typedef _OpenSealedC = Int32 Function(
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint64>);
typedef _OpenSealed = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint64>);
typedef _MatchesPhraseC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _MatchesPhrase = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>);
typedef _Slip39BackupC = Int32 Function(Uint64, Uint8, Uint8, Uint8,
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _Slip39Backup = int Function(int, int, int, int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _Slip39RestoreC = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>,
    Size, Uint8, Pointer<Uint8>, Size, Pointer<Uint64>, Pointer<Uint8>, Pointer<Uint8>);
typedef _Slip39Restore = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
    int, Pointer<Uint8>, int, Pointer<Uint64>, Pointer<Uint8>, Pointer<Uint8>);
typedef _MatchesSessionC = Int32 Function(Uint64, Uint64, Pointer<Uint8>);
typedef _MatchesSession = int Function(int, int, Pointer<Uint8>);
typedef _OpenSealedKeyC = Int32 Function(
    Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint64>);
typedef _OpenSealedKey = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint64>);
typedef _SealPhraseC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _SealPhrase = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _Slip39CheckC = Int32 Function(Uint64, Pointer<Uint8>, Size,
    Pointer<Uint8>, Size, Uint8, Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _Slip39Check = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>,
    int, int, Pointer<Uint8>, int, Pointer<Uint8>);
typedef _CloseC = Int32 Function(Uint64);
typedef _Close = int Function(int);
typedef _CloseAllC = Uint64 Function();
typedef _ReadEvmTransactionC = Int32 Function(
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _ReadEvmTransaction = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _CloseAll = int Function();
typedef _PublicKeyC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Int32, Pointer<Uint8>, Size);
typedef _PublicKey = int Function(
    int, Pointer<Uint8>, int, int, Pointer<Uint8>, int);
typedef _SignC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Sign = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ExportC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Export = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ExtendedC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Extended = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _LowRC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _LowR = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _SchnorrC = Int32 Function(Uint64, Pointer<Uint8>, Size, Pointer<Uint8>,
    Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Schnorr = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _SignEvmTransactionC = Int32 Function(Uint64, Pointer<Uint8>, Size,
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _SignEvmTransaction = int Function(int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _SignEvmMessageC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _SignEvmMessage = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ReadCardanoTransactionC = Int32 Function(Uint64, Pointer<Uint8>, Size,
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _ReadCardanoTransaction = int Function(int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _SignBitcoinTransactionC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _SignBitcoinTransaction = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ReadBitcoinTransactionC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _ReadBitcoinTransaction = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _Ed25519PublicKeyC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Ed25519PublicKey = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _Ed25519SignC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Ed25519Sign = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _Ed25519ExportC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _Ed25519Export = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _CardanoPublicKeyC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _CardanoPublicKey = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _CardanoSignC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _CardanoSign = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _CardanoExportC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _CardanoExport = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _StarknetPublicKeyC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _StarknetPublicKey = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _StarknetSignC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _StarknetSign = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _StarknetExportC = Int32 Function(
    Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _StarknetExport = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int);

/// The code asset `hook/build.dart` builds and the Dart or Flutter build
/// bundles.
const String keyCoreAssetId = 'package:key_core/key_core.dart';

@Native<_AbiVersionC>(symbol: 'kc_abi_version', assetId: keyCoreAssetId)
external int _bundledAbiVersion();
@Native<_OpenC>(symbol: 'kc_open', assetId: keyCoreAssetId)
external int _bundledOpen(Pointer<Uint8> phrase, int length, Pointer<Uint64> out);

@Native<_OpenSealedC>(symbol: 'kc_open_sealed', assetId: keyCoreAssetId)
external int _bundledOpenSealed(Pointer<Uint8> sealed, int sealedLength,
    Pointer<Uint8> key, int keyLength, Pointer<Uint64> out);

@Native<_OpenKeyC>(symbol: 'kc_open_key', assetId: keyCoreAssetId)
external int _bundledOpenKey(
    int curve, Pointer<Uint8> secret, int length, Pointer<Uint64> out);
@Native<_MatchesPhraseC>(symbol: 'kc_matches_phrase', assetId: keyCoreAssetId)
external int _bundledMatchesPhrase(
    int handle, Pointer<Uint8> candidate, int length, Pointer<Uint8> out);
@Native<_Slip39BackupC>(symbol: 'kc_slip39_backup', assetId: keyCoreAssetId)
external int _bundledSlip39Backup(
    int handle,
    int threshold,
    int count,
    int paperIndex,
    Pointer<Uint8> password,
    int passwordLength,
    Pointer<Uint8> labels,
    int labelsLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_Slip39RestoreC>(symbol: 'kc_slip39_restore', assetId: keyCoreAssetId)
external int _bundledSlip39Restore(
    Pointer<Uint8> shares,
    int sharesLength,
    Pointer<Uint8> extra,
    int extraLength,
    int minThreshold,
    Pointer<Uint8> password,
    int passwordLength,
    Pointer<Uint64> handle,
    Pointer<Uint8> needed,
    Pointer<Uint8> read);
@Native<_MatchesSessionC>(symbol: 'kc_matches_session', assetId: keyCoreAssetId)
external int _bundledMatchesSession(int handle, int other, Pointer<Uint8> out);
@Native<_OpenSealedKeyC>(symbol: 'kc_open_sealed_key', assetId: keyCoreAssetId)
external int _bundledOpenSealedKey(int curve, Pointer<Uint8> sealed,
    int sealedLength, Pointer<Uint8> key, int keyLength, Pointer<Uint64> handle);
@Native<_SealPhraseC>(symbol: 'kc_seal_phrase', assetId: keyCoreAssetId)
external int _bundledSealPhrase(int handle, Pointer<Uint8> key, int keyLength,
    Pointer<Uint8> out, int outCapacity, Pointer<Size> outLength);
@Native<_Slip39CheckC>(symbol: 'kc_slip39_check', assetId: keyCoreAssetId)
external int _bundledSlip39Check(
    int handle,
    Pointer<Uint8> shares,
    int sharesLength,
    Pointer<Uint8> paper,
    int paperLength,
    int threshold,
    Pointer<Uint8> password,
    int passwordLength,
    Pointer<Uint8> out);
@Native<_CloseC>(symbol: 'kc_close', assetId: keyCoreAssetId)
external int _bundledClose(int handle);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_evm_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadEvmTransaction(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> expected,
    int expectedLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_evm_read_typed_data', assetId: keyCoreAssetId)
external int _bundledReadEvmTypedData(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> json,
    int jsonLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_solana_read_message', assetId: keyCoreAssetId)
external int _bundledReadSolanaMessage(Pointer<Uint8> message,
    int messageLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_tron_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadTronTransaction(Pointer<Uint8> raw, int rawLength,
    Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_xrpl_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadXrplTransaction(Pointer<Uint8> blob, int blobLength,
    Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_Ed25519SignC>(
    symbol: 'kc_xrpl_sign_transaction', assetId: keyCoreAssetId)
external int _bundledXrplSign(int handle, Pointer<Uint8> path, int pathLength,
    Pointer<Uint8> blob, int blobLength, Pointer<Uint8> out, int outLength);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_cosmos_read_sign_doc', assetId: keyCoreAssetId)
external int _bundledReadCosmosSignDoc(Pointer<Uint8> signDoc,
    int signDocLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_stellar_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadStellarTransaction(Pointer<Uint8> payload,
    int payloadLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_multiversx_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadMultiversxTransaction(Pointer<Uint8> payload,
    int payloadLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_icp_read_call', assetId: keyCoreAssetId)
external int _bundledReadIcpCall(Pointer<Uint8> content, int contentLength,
    Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_filecoin_read_message', assetId: keyCoreAssetId)
external int _bundledReadFilecoinMessage(Pointer<Uint8> message,
    int messageLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_cardano_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadCardanoTransaction(
    int handle,
    Pointer<Uint8> body,
    int bodyLength,
    Pointer<Uint8> signers,
    int signersLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_ton_read_transfer', assetId: keyCoreAssetId)
external int _bundledReadTonTransfer(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> boc,
    int bocLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_polkadot_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadPolkadotTransaction(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> payload,
    int payloadLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_tezos_read_operation', assetId: keyCoreAssetId)
external int _bundledReadTezosOperation(Pointer<Uint8> forged,
    int forgedLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_algorand_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadAlgorandTransaction(Pointer<Uint8> message,
    int messageLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_sui_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadSuiTransaction(Pointer<Uint8> message,
    int messageLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_aptos_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadAptosTransaction(Pointer<Uint8> message,
    int messageLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_ReadEvmTransactionC>(
    symbol: 'kc_near_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadNearTransaction(Pointer<Uint8> transaction,
    int transactionLength, Pointer<Uint8> out, int capacity,
    Pointer<Size> length);
@Native<_CloseAllC>(symbol: 'kc_close_all', assetId: keyCoreAssetId)
external int _bundledCloseAll();
@Native<_PublicKeyC>(symbol: 'kc_secp256k1_public_key', assetId: keyCoreAssetId)
external int _bundledPublicKey(int handle, Pointer<Uint8> path, int pathLength,
    int format, Pointer<Uint8> out, int outLength);
@Native<_SignC>(symbol: 'kc_secp256k1_sign_digest', assetId: keyCoreAssetId)
external int _bundledSign(int handle, Pointer<Uint8> path, int pathLength,
    Pointer<Uint8> digest, int digestLength, Pointer<Uint8> out, int outLength);
@Native<_ExportC>(
    symbol: 'kc_secp256k1_export_private_key', assetId: keyCoreAssetId)
external int _bundledExport(int handle, Pointer<Uint8> path, int pathLength,
    Pointer<Uint8> out, int outLength);
@Native<_ExtendedC>(
    symbol: 'kc_secp256k1_extended_public_key', assetId: keyCoreAssetId)
external int _bundledExtended(int handle, Pointer<Uint8> path, int pathLength,
    Pointer<Uint8> out, int outLength);
@Native<_LowRC>(
    symbol: 'kc_secp256k1_sign_digest_low_r', assetId: keyCoreAssetId)
external int _bundledLowR(int handle, Pointer<Uint8> path, int pathLength,
    Pointer<Uint8> digest, int digestLength, Pointer<Uint8> out, int outLength);
@Native<_SchnorrC>(symbol: 'kc_secp256k1_schnorr_sign', assetId: keyCoreAssetId)
external int _bundledSchnorr(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> digest,
    int digestLength,
    Pointer<Uint8> tweak,
    int tweakLength,
    Pointer<Uint8> out,
    int outLength);
@Native<_SignEvmTransactionC>(
    symbol: 'kc_secp256k1_sign_evm_transaction', assetId: keyCoreAssetId)
external int _bundledSignEvmTransaction(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> unsigned,
    int unsignedLength,
    Pointer<Uint8> expected,
    int expectedLength,
    Pointer<Uint8> out,
    int outLength);
@Native<_SignEvmMessageC>(
    symbol: 'kc_evm_sign_personal_message', assetId: keyCoreAssetId)
external int _bundledSignPersonalMessage(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> message, int messageLength,
    Pointer<Uint8> out, int outLength);
@Native<_SignEvmMessageC>(
    symbol: 'kc_evm_sign_typed_data', assetId: keyCoreAssetId)
external int _bundledSignTypedData(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> json, int jsonLength, Pointer<Uint8> out,
    int outLength);
@Native<_SignBitcoinTransactionC>(
    symbol: 'kc_bitcoin_sign_transaction', assetId: keyCoreAssetId)
external int _bundledSignBitcoinTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int outLength);
@Native<_ReadBitcoinTransactionC>(
    symbol: 'kc_bitcoin_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadBitcoinTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_SignBitcoinTransactionC>(
    symbol: 'kc_kaspa_sign_transaction', assetId: keyCoreAssetId)
external int _bundledSignKaspaTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int outLength);
@Native<_ReadBitcoinTransactionC>(
    symbol: 'kc_kaspa_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadKaspaTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_SignBitcoinTransactionC>(
    symbol: 'kc_zcash_sign_transaction', assetId: keyCoreAssetId)
external int _bundledSignZcashTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int outLength);
@Native<_ReadBitcoinTransactionC>(
    symbol: 'kc_zcash_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadZcashTransaction(int handle, Pointer<Uint8> request,
    int requestLength, Pointer<Uint8> out, int capacity, Pointer<Size> length);
@Native<_Ed25519PublicKeyC>(
    symbol: 'kc_ed25519_public_key', assetId: keyCoreAssetId)
external int _bundledEd25519PublicKey(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_Ed25519SignC>(symbol: 'kc_ed25519_sign', assetId: keyCoreAssetId)
external int _bundledEd25519Sign(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> message,
    int messageLength,
    Pointer<Uint8> out,
    int outLength);
@Native<_Ed25519ExportC>(
    symbol: 'kc_ed25519_export_private_key', assetId: keyCoreAssetId)
external int _bundledEd25519Export(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_CardanoPublicKeyC>(
    symbol: 'kc_cardano_public_key', assetId: keyCoreAssetId)
external int _bundledCardanoPublicKey(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_CardanoPublicKeyC>(
    symbol: 'kc_cardano_icarus_public_key', assetId: keyCoreAssetId)
external int _bundledCardanoIcarusPublicKey(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_CardanoSignC>(symbol: 'kc_cardano_sign', assetId: keyCoreAssetId)
external int _bundledCardanoSign(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> message,
    int messageLength,
    Pointer<Uint8> out,
    int outLength);
@Native<_CardanoExportC>(
    symbol: 'kc_cardano_export_private_key', assetId: keyCoreAssetId)
external int _bundledCardanoExport(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_StarknetPublicKeyC>(
    symbol: 'kc_starknet_public_key', assetId: keyCoreAssetId)
external int _bundledStarknetPublicKey(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);
@Native<_ReadCardanoTransactionC>(
    symbol: 'kc_starknet_read_transaction', assetId: keyCoreAssetId)
external int _bundledReadStarknetTransaction(
    int handle,
    Pointer<Uint8> path,
    int pathLength,
    Pointer<Uint8> transaction,
    int transactionLength,
    Pointer<Uint8> out,
    int capacity,
    Pointer<Size> length);
@Native<_StarknetSignC>(symbol: 'kc_starknet_sign', assetId: keyCoreAssetId)
external int _bundledStarknetSign(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> hash, int hashLength, Pointer<Uint8> out,
    int outLength);
@Native<_StarknetExportC>(
    symbol: 'kc_starknet_export_private_key', assetId: keyCoreAssetId)
external int _bundledStarknetExport(int handle, Pointer<Uint8> path,
    int pathLength, Pointer<Uint8> out, int outLength);

/// The loaded core.
final class KeyCore {
  /// Binds [library], refusing one whose ABI is not [keyCoreAbiVersion]:
  /// a code or an argument that changed meaning would be read wrongly here.
  ///
  /// For a library at a path of the caller's choosing — a check of one
  /// particular file. The app uses [KeyCore.bundled].
  KeyCore(DynamicLibrary library)
      : this._(
          abiVersion: library
              .lookupFunction<_AbiVersionC, _AbiVersion>('kc_abi_version'),
          open: library.lookupFunction<_OpenC, _Open>('kc_open'),
          openSealed: library
              .lookupFunction<_OpenSealedC, _OpenSealed>('kc_open_sealed'),
          openKey: library.lookupFunction<_OpenKeyC, _OpenKey>('kc_open_key'),
          matchesPhrase: library.lookupFunction<_MatchesPhraseC,
              _MatchesPhrase>('kc_matches_phrase'),
          slip39Backup: library
              .lookupFunction<_Slip39BackupC, _Slip39Backup>('kc_slip39_backup'),
          slip39Check: library
              .lookupFunction<_Slip39CheckC, _Slip39Check>('kc_slip39_check'),
          slip39Restore: library.lookupFunction<_Slip39RestoreC, _Slip39Restore>(
              'kc_slip39_restore'),
          matchesSession: library.lookupFunction<_MatchesSessionC,
              _MatchesSession>('kc_matches_session'),
          sealPhrase: library
              .lookupFunction<_SealPhraseC, _SealPhrase>('kc_seal_phrase'),
          openSealedKey: library.lookupFunction<_OpenSealedKeyC, _OpenSealedKey>(
              'kc_open_sealed_key'),
          close: library.lookupFunction<_CloseC, _Close>('kc_close'),
          closeAll:
              library.lookupFunction<_CloseAllC, _CloseAll>('kc_close_all'),
          readEvmTransaction: library.lookupFunction<_ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_evm_read_transaction'),
          readEvmTypedData: library.lookupFunction<_ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_evm_read_typed_data'),
          readSolanaMessage: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_solana_read_message'),
          readTronTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_tron_read_transaction'),
          readXrplTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_xrpl_read_transaction'),
          readCosmosSignDoc: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_cosmos_read_sign_doc'),
          readStellarTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_stellar_read_transaction'),
          readNearTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_near_read_transaction'),
          readAptosTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_aptos_read_transaction'),
          readSuiTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_sui_read_transaction'),
          readAlgorandTransaction: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_algorand_read_transaction'),
          readTezosOperation: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_tezos_read_operation'),
          readMultiversxTransaction: library.lookupFunction<
              _ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_multiversx_read_transaction'),
          readPolkadotTransaction: library.lookupFunction<
              _ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_polkadot_read_transaction'),
          readTonTransfer: library.lookupFunction<_ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_ton_read_transfer'),
          readCardanoTransaction: library.lookupFunction<
              _ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_cardano_read_transaction'),
          readFilecoinMessage: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_filecoin_read_message'),
          readIcpCall: library.lookupFunction<_ReadEvmTransactionC,
              _ReadEvmTransaction>('kc_icp_read_call'),
          xrplSign: library.lookupFunction<_Ed25519SignC, _Ed25519Sign>(
              'kc_xrpl_sign_transaction'),
          publicKey: library.lookupFunction<_PublicKeyC, _PublicKey>(
              'kc_secp256k1_public_key'),
          sign: library
              .lookupFunction<_SignC, _Sign>('kc_secp256k1_sign_digest'),
          export: library.lookupFunction<_ExportC, _Export>(
              'kc_secp256k1_export_private_key'),
          extended: library.lookupFunction<_ExtendedC, _Extended>(
              'kc_secp256k1_extended_public_key'),
          lowR: library.lookupFunction<_LowRC, _LowR>(
              'kc_secp256k1_sign_digest_low_r'),
          schnorr: library.lookupFunction<_SchnorrC, _Schnorr>(
              'kc_secp256k1_schnorr_sign'),
          signEvmTransaction:
              library.lookupFunction<_SignEvmTransactionC, _SignEvmTransaction>(
                  'kc_secp256k1_sign_evm_transaction'),
          signPersonalMessage:
              library.lookupFunction<_SignEvmMessageC, _SignEvmMessage>(
                  'kc_evm_sign_personal_message'),
          signTypedData:
              library.lookupFunction<_SignEvmMessageC, _SignEvmMessage>(
                  'kc_evm_sign_typed_data'),
          signBitcoinTransaction: library.lookupFunction<
              _SignBitcoinTransactionC,
              _SignBitcoinTransaction>('kc_bitcoin_sign_transaction'),
          readBitcoinTransaction: library.lookupFunction<
              _ReadBitcoinTransactionC,
              _ReadBitcoinTransaction>('kc_bitcoin_read_transaction'),
          signKaspaTransaction: library.lookupFunction<
              _SignBitcoinTransactionC,
              _SignBitcoinTransaction>('kc_kaspa_sign_transaction'),
          readKaspaTransaction: library.lookupFunction<
              _ReadBitcoinTransactionC,
              _ReadBitcoinTransaction>('kc_kaspa_read_transaction'),
          signZcashTransaction: library.lookupFunction<
              _SignBitcoinTransactionC,
              _SignBitcoinTransaction>('kc_zcash_sign_transaction'),
          readZcashTransaction: library.lookupFunction<
              _ReadBitcoinTransactionC,
              _ReadBitcoinTransaction>('kc_zcash_read_transaction'),
          ed25519PublicKey:
              library.lookupFunction<_Ed25519PublicKeyC, _Ed25519PublicKey>(
                  'kc_ed25519_public_key'),
          ed25519Sign: library
              .lookupFunction<_Ed25519SignC, _Ed25519Sign>('kc_ed25519_sign'),
          ed25519Export:
              library.lookupFunction<_Ed25519ExportC, _Ed25519Export>(
                  'kc_ed25519_export_private_key'),
          cardanoPublicKey:
              library.lookupFunction<_CardanoPublicKeyC, _CardanoPublicKey>(
                  'kc_cardano_public_key'),
          cardanoIcarusPublicKey:
              library.lookupFunction<_CardanoPublicKeyC, _CardanoPublicKey>(
                  'kc_cardano_icarus_public_key'),
          cardanoSign: library
              .lookupFunction<_CardanoSignC, _CardanoSign>('kc_cardano_sign'),
          cardanoExport:
              library.lookupFunction<_CardanoExportC, _CardanoExport>(
                  'kc_cardano_export_private_key'),
          starknetPublicKey:
              library.lookupFunction<_StarknetPublicKeyC, _StarknetPublicKey>(
                  'kc_starknet_public_key'),
          starknetSign: library
              .lookupFunction<_StarknetSignC, _StarknetSign>('kc_starknet_sign'),
          readStarknetTransaction: library.lookupFunction<
              _ReadCardanoTransactionC,
              _ReadCardanoTransaction>('kc_starknet_read_transaction'),
          starknetExport:
              library.lookupFunction<_StarknetExportC, _StarknetExport>(
                  'kc_starknet_export_private_key'),
        );

  /// The library at [path].
  factory KeyCore.at(String path) => KeyCore(DynamicLibrary.open(path));

  /// The library `hook/build.dart` built for this target and the build
  /// bundled, as [keyCoreAssetId].
  KeyCore.bundled()
      : this._(
          abiVersion: _bundledAbiVersion,
          open: _bundledOpen,
          openSealed: _bundledOpenSealed,
          openKey: _bundledOpenKey,
          matchesPhrase: _bundledMatchesPhrase,
          slip39Backup: _bundledSlip39Backup,
          slip39Check: _bundledSlip39Check,
          slip39Restore: _bundledSlip39Restore,
          matchesSession: _bundledMatchesSession,
          sealPhrase: _bundledSealPhrase,
          openSealedKey: _bundledOpenSealedKey,
          close: _bundledClose,
          closeAll: _bundledCloseAll,
          readEvmTransaction: _bundledReadEvmTransaction,
          readEvmTypedData: _bundledReadEvmTypedData,
          readSolanaMessage: _bundledReadSolanaMessage,
          readTronTransaction: _bundledReadTronTransaction,
          readXrplTransaction: _bundledReadXrplTransaction,
          readCosmosSignDoc: _bundledReadCosmosSignDoc,
          readStellarTransaction: _bundledReadStellarTransaction,
          readNearTransaction: _bundledReadNearTransaction,
          readAptosTransaction: _bundledReadAptosTransaction,
          readSuiTransaction: _bundledReadSuiTransaction,
          readAlgorandTransaction: _bundledReadAlgorandTransaction,
          readTezosOperation: _bundledReadTezosOperation,
          readMultiversxTransaction: _bundledReadMultiversxTransaction,
          readPolkadotTransaction: _bundledReadPolkadotTransaction,
          readTonTransfer: _bundledReadTonTransfer,
          readCardanoTransaction: _bundledReadCardanoTransaction,
          readFilecoinMessage: _bundledReadFilecoinMessage,
          readIcpCall: _bundledReadIcpCall,
          xrplSign: _bundledXrplSign,
          publicKey: _bundledPublicKey,
          sign: _bundledSign,
          export: _bundledExport,
          extended: _bundledExtended,
          lowR: _bundledLowR,
          schnorr: _bundledSchnorr,
          signEvmTransaction: _bundledSignEvmTransaction,
          signPersonalMessage: _bundledSignPersonalMessage,
          signTypedData: _bundledSignTypedData,
          signBitcoinTransaction: _bundledSignBitcoinTransaction,
          readBitcoinTransaction: _bundledReadBitcoinTransaction,
          signKaspaTransaction: _bundledSignKaspaTransaction,
          readKaspaTransaction: _bundledReadKaspaTransaction,
          signZcashTransaction: _bundledSignZcashTransaction,
          readZcashTransaction: _bundledReadZcashTransaction,
          ed25519PublicKey: _bundledEd25519PublicKey,
          ed25519Sign: _bundledEd25519Sign,
          ed25519Export: _bundledEd25519Export,
          cardanoPublicKey: _bundledCardanoPublicKey,
          cardanoIcarusPublicKey: _bundledCardanoIcarusPublicKey,
          cardanoSign: _bundledCardanoSign,
          cardanoExport: _bundledCardanoExport,
          starknetPublicKey: _bundledStarknetPublicKey,
          starknetSign: _bundledStarknetSign,
          readStarknetTransaction: _bundledReadStarknetTransaction,
          starknetExport: _bundledStarknetExport,
        );

  KeyCore._({
    required _AbiVersion abiVersion,
    required _Open open,
    required _OpenSealed openSealed,
    required _OpenKey openKey,
    required _MatchesPhrase matchesPhrase,
    required _Slip39Backup slip39Backup,
    required _Slip39Check slip39Check,
    required _Slip39Restore slip39Restore,
    required _MatchesSession matchesSession,
    required _SealPhrase sealPhrase,
    required _OpenSealedKey openSealedKey,
    required _Close close,
    required _CloseAll closeAll,
    required _ReadCardanoTransaction readEvmTransaction,
    required _ReadCardanoTransaction readEvmTypedData,
    required _ReadEvmTransaction readSolanaMessage,
    required _ReadEvmTransaction readTronTransaction,
    required _ReadEvmTransaction readXrplTransaction,
    required _ReadEvmTransaction readCosmosSignDoc,
    required _ReadEvmTransaction readStellarTransaction,
    required _ReadEvmTransaction readNearTransaction,
    required _ReadEvmTransaction readAptosTransaction,
    required _ReadEvmTransaction readSuiTransaction,
    required _ReadEvmTransaction readAlgorandTransaction,
    required _ReadEvmTransaction readTezosOperation,
    required _ReadEvmTransaction readMultiversxTransaction,
    required _ReadCardanoTransaction readPolkadotTransaction,
    required _ReadCardanoTransaction readTonTransfer,
    required _ReadCardanoTransaction readCardanoTransaction,
    required _ReadEvmTransaction readFilecoinMessage,
    required _ReadEvmTransaction readIcpCall,
    required _Ed25519Sign xrplSign,
    required _PublicKey publicKey,
    required _Sign sign,
    required _Export export,
    required _Extended extended,
    required _LowR lowR,
    required _Schnorr schnorr,
    required _SignEvmTransaction signEvmTransaction,
    required _SignEvmMessage signPersonalMessage,
    required _SignEvmMessage signTypedData,
    required _SignBitcoinTransaction signBitcoinTransaction,
    required _ReadBitcoinTransaction readBitcoinTransaction,
    required _SignBitcoinTransaction signKaspaTransaction,
    required _ReadBitcoinTransaction readKaspaTransaction,
    required _SignBitcoinTransaction signZcashTransaction,
    required _ReadBitcoinTransaction readZcashTransaction,
    required _Ed25519PublicKey ed25519PublicKey,
    required _Ed25519Sign ed25519Sign,
    required _Ed25519Export ed25519Export,
    required _CardanoPublicKey cardanoPublicKey,
    required _CardanoPublicKey cardanoIcarusPublicKey,
    required _CardanoSign cardanoSign,
    required _CardanoExport cardanoExport,
    required _StarknetPublicKey starknetPublicKey,
    required _StarknetSign starknetSign,
    required _ReadCardanoTransaction readStarknetTransaction,
    required _StarknetExport starknetExport,
  })  : _open = open,
        _openSealed = openSealed,
        _openKey = openKey,
        _matchesPhrase = matchesPhrase,
        _slip39Backup = slip39Backup,
        _slip39Check = slip39Check,
        _slip39Restore = slip39Restore,
        _matchesSession = matchesSession,
        _sealPhrase = sealPhrase,
        _openSealedKey = openSealedKey,
        _close = close,
        _closeAll = closeAll,
        _readEvmTransaction = readEvmTransaction,
        _readEvmTypedData = readEvmTypedData,
        _readSolanaMessage = readSolanaMessage,
        _readTronTransaction = readTronTransaction,
        _readXrplTransaction = readXrplTransaction,
        _readCosmosSignDoc = readCosmosSignDoc,
        _readStellarTransaction = readStellarTransaction,
        _readNearTransaction = readNearTransaction,
        _readAptosTransaction = readAptosTransaction,
        _readSuiTransaction = readSuiTransaction,
        _readAlgorandTransaction = readAlgorandTransaction,
        _readTezosOperation = readTezosOperation,
        _readMultiversxTransaction = readMultiversxTransaction,
        _readPolkadotTransaction = readPolkadotTransaction,
        _readTonTransfer = readTonTransfer,
        _readCardanoTransaction = readCardanoTransaction,
        _readFilecoinMessage = readFilecoinMessage,
        _readIcpCall = readIcpCall,
        _xrplSign = xrplSign,
        _publicKey = publicKey,
        _sign = sign,
        _export = export,
        _extended = extended,
        _lowR = lowR,
        _schnorr = schnorr,
        _signEvmTransaction = signEvmTransaction,
        _signPersonalMessage = signPersonalMessage,
        _signTypedData = signTypedData,
        _signBitcoinTransaction = signBitcoinTransaction,
        _readBitcoinTransaction = readBitcoinTransaction,
        _signKaspaTransaction = signKaspaTransaction,
        _readKaspaTransaction = readKaspaTransaction,
        _signZcashTransaction = signZcashTransaction,
        _readZcashTransaction = readZcashTransaction,
        _ed25519PublicKey = ed25519PublicKey,
        _ed25519Sign = ed25519Sign,
        _ed25519Export = ed25519Export,
        _cardanoPublicKey = cardanoPublicKey,
        _cardanoIcarusPublicKey = cardanoIcarusPublicKey,
        _cardanoSign = cardanoSign,
        _cardanoExport = cardanoExport,
        _starknetPublicKey = starknetPublicKey,
        _starknetSign = starknetSign,
        _readStarknetTransaction = readStarknetTransaction,
        _starknetExport = starknetExport {
    final version = abiVersion();
    if (version != keyCoreAbiVersion) {
      throw StateError('key core ABI $version, this binding is for '
          '$keyCoreAbiVersion');
    }
  }

  final _Open _open;
  final _OpenSealed _openSealed;
  final _OpenKey _openKey;
  final _MatchesPhrase _matchesPhrase;
  final _Slip39Backup _slip39Backup;
  final _Slip39Check _slip39Check;
  final _Slip39Restore _slip39Restore;
  final _MatchesSession _matchesSession;
  final _SealPhrase _sealPhrase;
  final _OpenSealedKey _openSealedKey;
  final _Close _close;
  final _CloseAll _closeAll;
  final _ReadCardanoTransaction _readEvmTransaction;
  final _ReadCardanoTransaction _readEvmTypedData;
  final _ReadEvmTransaction _readSolanaMessage;
  final _ReadEvmTransaction _readTronTransaction;
  final _ReadEvmTransaction _readXrplTransaction;
  final _ReadEvmTransaction _readCosmosSignDoc;
  final _ReadEvmTransaction _readStellarTransaction;
  final _ReadEvmTransaction _readNearTransaction;
  final _ReadEvmTransaction _readAptosTransaction;
  final _ReadEvmTransaction _readSuiTransaction;
  final _ReadEvmTransaction _readAlgorandTransaction;
  final _ReadEvmTransaction _readTezosOperation;
  final _ReadEvmTransaction _readMultiversxTransaction;
  final _ReadCardanoTransaction _readPolkadotTransaction;
  final _ReadCardanoTransaction _readTonTransfer;
  final _ReadCardanoTransaction _readCardanoTransaction;
  final _ReadEvmTransaction _readFilecoinMessage;
  final _ReadEvmTransaction _readIcpCall;
  final _Ed25519Sign _xrplSign;
  final _PublicKey _publicKey;
  final _Sign _sign;
  final _Export _export;
  final _Extended _extended;
  final _LowR _lowR;
  final _Schnorr _schnorr;
  final _SignEvmTransaction _signEvmTransaction;
  final _SignEvmMessage _signPersonalMessage;
  final _SignEvmMessage _signTypedData;
  final _SignBitcoinTransaction _signBitcoinTransaction;
  final _ReadBitcoinTransaction _readBitcoinTransaction;
  final _SignBitcoinTransaction _signKaspaTransaction;
  final _ReadBitcoinTransaction _readKaspaTransaction;
  final _SignBitcoinTransaction _signZcashTransaction;
  final _ReadBitcoinTransaction _readZcashTransaction;
  final _Ed25519PublicKey _ed25519PublicKey;
  final _Ed25519Sign _ed25519Sign;
  final _Ed25519Export _ed25519Export;
  final _CardanoPublicKey _cardanoPublicKey;
  final _CardanoPublicKey _cardanoIcarusPublicKey;
  final _CardanoSign _cardanoSign;
  final _CardanoExport _cardanoExport;
  final _StarknetPublicKey _starknetPublicKey;
  final _StarknetSign _starknetSign;
  final _ReadCardanoTransaction _readStarknetTransaction;
  final _StarknetExport _starknetExport;

  /// Opens [phrase] and returns its session.
  ///
  /// **This copy of the phrase is the last one this side makes.** Its UTF-8
  /// bytes are overwritten here, on the Dart heap and in native memory, once
  /// the core has read them; the [String] itself is immutable and outlives
  /// this call, which is what Tier 2 is for.
  KeyCoreSession open(String phrase) {
    final bytes = utf8.encode(phrase);
    final native = _copyIn(bytes);
    final handle = calloc<Uint64>();
    try {
      _check(_open(native, bytes.length, handle));
      return KeyCoreSession._(this, handle.value);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
      _release(native, bytes.length);
      calloc.free(handle);
    }
  }

  /// A split backup restored in the core — phase 7b
  /// (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`): the sealed bodies in [shares]
  /// (a JSON list) and the typed shares in [extra], opened under [password]
  /// (its NFC UTF-8 bytes, overwritten here once read), and a session on the
  /// phrase they give back. **The phrase never comes to this side.**
  ///
  /// A refusal the backup's own fault — [KeyCoreRefusal.sharePassword],
  /// [KeyCoreRefusal.shareAltered] or [KeyCoreRefusal.share] — comes back in
  /// the record with how many shares were [needed] and how many distinct ones
  /// were [read], for the sentence it is said with; any other is thrown.
  ({KeyCoreSession? session, KeyCoreRefusal? refusal, int needed, int read})
      slip39Restore({
    required String shares,
    List<String> extra = const [],
    int minThreshold = 0,
    required List<int> password,
  }) {
    final shareBytes = utf8.encode(shares);
    final extraBytes = utf8.encode(jsonEncode(extra));
    final nativeShares = _copyIn(shareBytes);
    final nativeExtra = _copyIn(extraBytes);
    final nativePassword = _copyIn(password);
    final handle = calloc<Uint64>();
    final needed = calloc<Uint8>();
    final read = calloc<Uint8>();
    try {
      final code = _slip39Restore(nativeShares, shareBytes.length, nativeExtra,
          extraBytes.length, minThreshold, nativePassword, password.length,
          handle, needed, read);
      final refusal = KeyCoreRefusal.values.where((r) => r.code == code).firstOrNull;
      if (refusal == KeyCoreRefusal.sharePassword ||
          refusal == KeyCoreRefusal.shareAltered ||
          refusal == KeyCoreRefusal.share) {
        return (session: null, refusal: refusal, needed: needed.value, read: read.value);
      }
      _check(code);
      return (
        session: KeyCoreSession._(this, handle.value),
        refusal: null,
        needed: needed.value,
        read: read.value
      );
    } finally {
      password.fillRange(0, password.length, 0);
      extraBytes.fillRange(0, extraBytes.length, 0);
      _release(nativePassword, password.length);
      _release(nativeExtra, extraBytes.length);
      _release(nativeShares, shareBytes.length);
      calloc.free(handle);
      calloc.free(needed);
      calloc.free(read);
    }
  }

  /// Opens the phrase sealed in [sealed] under [key] and returns its session
  /// — phase 6a (`docs/RUST_KEY_CORE_DESIGN.md#phase-6`).
  ///
  /// [sealed] is the record as the wallet stores it (`CryptoUtils.encryptBytes`:
  /// the 12-byte nonce, the ciphertext, the 16-byte tag), [key] the 32 bytes it
  /// is sealed under. **The phrase is opened in the core and never comes to
  /// this side**: no [String] of it, no bytes. A wrong key, a changed byte or
  /// a record too short is [KeyCoreRefusal.seal]; a record that opens to
  /// something other than a phrase in the stored form is
  /// [KeyCoreRefusal.phrase], as [open] refuses it.
  ///
  /// [key] is the caller's to erase; the native copy this call makes of it is
  /// overwritten here once the core has read it. The record is ciphertext and
  /// is copied as it is.
  KeyCoreSession openSealed(List<int> sealed, List<int> key) {
    final nativeSealed = _copyIn(sealed);
    final nativeKey = _copyIn(key);
    final handle = calloc<Uint64>();
    try {
      _check(_openSealed(
          nativeSealed, sealed.length, nativeKey, key.length, handle));
      return KeyCoreSession._(this, handle.value);
    } finally {
      _release(nativeKey, key.length);
      _release(nativeSealed, sealed.length);
      calloc.free(handle);
    }
  }

  /// Opens one imported key — [secret], 32 bytes on [curve] — and returns its
  /// session (the owner's decision O22).
  ///
  /// Every call for its curve answers at the path `m` alone, as the key
  /// itself: another path is [KeyCoreRefusal.path], and a call for the other
  /// curve, a chain code, Cardano or Starknet is [KeyCoreRefusal.kind]. A
  /// secp256k1 scalar of zero or not below the order is [KeyCoreRefusal.key].
  ///
  /// [secret] is the caller's to erase; the native copy this call makes is
  /// overwritten here once the core has read it.
  /// [openKey] for a key this wallet already holds: its record [sealed]
  /// under [key], the account key, opened in the core — **the key's bytes
  /// never come to this side** (14 November 2026). A record [key] does not
  /// open is [KeyCoreRefusal.seal]; bytes not a key of [curve] refuse as
  /// [openKey] does. The caller's [key] is not written over: it is the
  /// account key, held while the wallet is open.
  KeyCoreSession openSealedKey(
      KeyCoreCurve curve, List<int> sealed, Uint8List key) {
    final nativeSealed = _copyIn(sealed);
    final nativeKey = _copyIn(key);
    final handle = calloc<Uint64>();
    try {
      _check(_openSealedKey(
          curve.code, nativeSealed, sealed.length, nativeKey, key.length, handle));
      return KeyCoreSession._(this, handle.value);
    } finally {
      _release(nativeKey, key.length);
      _release(nativeSealed, sealed.length);
      calloc.free(handle);
    }
  }

  KeyCoreSession openKey(KeyCoreCurve curve, List<int> secret) {
    final native = _copyIn(secret);
    final handle = calloc<Uint64>();
    try {
      _check(_openKey(curve.code, native, secret.length, handle));
      return KeyCoreSession._(this, handle.value);
    } finally {
      _release(native, secret.length);
      calloc.free(handle);
    }
  }

  /// Closes every session the core holds, this binding's or not, and returns
  /// how many there were. For the lock.
  int closeAll() => _closeAll();

  /// [message] — a Solana message, the bytes after a transaction's signature
  /// table, which an ed25519 signature on Solana is over — as the core reads
  /// it for the review screen (O52, O58): its header, accounts, fee payer,
  /// blockhash, every instruction and what it does where the program is one
  /// a send of this wallet's uses, and its lookup tables, as the JSON
  /// `kc_solana_read_message` writes. Kept by the core, so that one signature
  /// of exactly this message by a Solana key may be made. A message the
  /// app's reader refuses is [KeyCoreRefusal.transaction]. Asks no session.
  String readSolanaMessage(List<int> message) =>
      _reading(_readSolanaMessage, message);

  /// [raw] — a TRON transaction's `raw_data`, whose SHA-256 is its id and what
  /// its signature is over — as the core reads it for the review screen
  /// (O58): the id, reference block, expiry, timestamp, fee limit and memo,
  /// and its one contract, decoded where it is a TRX transfer or a contract
  /// call, a TRC-20 `transfer` named — the JSON `kc_tron_read_transaction`
  /// writes. Kept by the core, so that one signature of exactly its SHA-256
  /// by a TRON key may be made. Bytes the app's reader refuses, or a field no
  /// transaction of this wallet carries, are [KeyCoreRefusal.transaction].
  /// Asks no session.
  String readTronTransaction(List<int> raw) =>
      _reading(_readTronTransaction, raw);

  /// [blob] — an XRP Ledger payment's signing serialisation, the bytes after
  /// `STX\0` its signature is over — as the core reads it for the review
  /// screen (O58, O59): the account, destination and tag, amount and fee in
  /// drops, sequence, expiry, flags, signing key and memos, as the JSON
  /// `kc_xrpl_read_transaction` writes. Kept by the core, its
  /// `LastLedgerSequence` aside, so that one signature of this payment by an
  /// XRP key may be made ([KeyCoreSession.signXrplTransaction]). Bytes that
  /// are not a payment of XRP in the fields the module writes are
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readXrplTransaction(List<int> blob) =>
      _reading(_readXrplTransaction, blob);

  /// [signDoc] — a Cosmos SDK `SignDoc`, whose SHA-256 a `SIGN_MODE_DIRECT`
  /// signature is over — as the core reads it for the review screen (O58):
  /// the chain, account number, every message (a bank `MsgSend` decoded),
  /// memo, timeout height, each signer's key, mode and sequence, and the fee,
  /// as the JSON `kc_cosmos_read_sign_doc` writes. Kept by the core, so that
  /// one signature of exactly its SHA-256 by a Cosmos zone's key may be made.
  /// Bytes the app's reader refuses, or a field no transaction of this wallet
  /// carries, are [KeyCoreRefusal.transaction]. Asks no session.
  String readCosmosSignDoc(List<int> signDoc) =>
      _reading(_readCosmosSignDoc, signDoc);

  /// [payload] — a Stellar `TransactionSignaturePayload`: the network's id,
  /// the envelope type and the transaction in XDR, whose SHA-256 is its id
  /// and what its signature is over — as the core reads it for the review
  /// screen (O58): the network, source, fee, sequence, time window, memo and
  /// every operation, as the JSON `kc_stellar_read_transaction` writes. Kept
  /// by the core, so that one signature of exactly its hash by a Stellar key
  /// may be made. A payload no transaction of this wallet is, is
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readStellarTransaction(List<int> payload) =>
      _reading(_readStellarTransaction, payload);

  /// [transaction] — a NEAR `Transaction`'s Borsh bytes, whose SHA-256 is its
  /// id and what its signature is over — as the core reads it for the review
  /// screen (O58): the signer, its key, the nonce, the receiver, the block,
  /// every transfer's deposit and the hash, as the JSON
  /// `kc_near_read_transaction` writes. Kept by the core, so that one
  /// signature of exactly its hash by a NEAR key may be made. Bytes no
  /// transaction of this wallet is are [KeyCoreRefusal.transaction]. Asks no
  /// session.
  String readNearTransaction(List<int> transaction) =>
      _reading(_readNearTransaction, transaction);

  /// [message] — an Aptos `RawTransaction`'s signing message, SHA3-256 of
  /// `APTOS::RawTransaction` and then its BCS, which an Aptos or Movement
  /// signature is over — as the core reads it for the review screen (O58):
  /// the sender, sequence number, function, recipient, amount, gas ceiling
  /// and price, expiry and chain id, as the JSON `kc_aptos_read_transaction`
  /// writes. Kept by the core, so that one signature of exactly [message] by
  /// an Aptos or Movement key may be made. A message no transaction of this
  /// wallet is, is [KeyCoreRefusal.transaction]. Asks no session.
  String readAptosTransaction(List<int> message) =>
      _reading(_readAptosTransaction, message);

  /// [message] — a Sui intent message, the intent's three bytes and then the
  /// `TransactionData`'s BCS, whose BLAKE2b-256 a Sui signature is over — as
  /// the core reads it for the review screen (O58, O60): the sender,
  /// recipient, amount, gas coins, owner, price and budget, and the
  /// transaction's digest, as the JSON `kc_sui_read_transaction` writes. Kept
  /// by the core, so that one signature of exactly its BLAKE2b-256 by a Sui
  /// key may be made. A message no transaction of this wallet is, is
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readSuiTransaction(List<int> message) =>
      _reading(_readSuiTransaction, message);

  /// [message] — `TX` and an Algorand transaction's canonical msgpack, which
  /// its signature is over — as the core reads it for the review screen
  /// (O58): the id, whether the genesis is mainnet's, and every field tagged
  /// with its kind, as the JSON `kc_algorand_read_transaction` writes. Kept
  /// by the core, so that one signature of exactly [message] by an Algorand
  /// key may be made. A message that is not canonical msgpack as the module
  /// writes it, or that rekeys or closes, is [KeyCoreRefusal.transaction].
  /// Asks no session.
  String readAlgorandTransaction(List<int> message) =>
      _reading(_readAlgorandTransaction, message);

  /// [forged] — a Tezos operation group as this wallet's forger writes it,
  /// whose BLAKE2b-256 after the watermark `0x03` its signature is over — as
  /// the core reads it for the review screen (O58, O60): the branch and every
  /// reveal and transaction, as the JSON `kc_tezos_read_operation` writes.
  /// Kept by the core, so that one signature of exactly its watermarked
  /// digest by a Tezos key may be made. A group the forger never writes is
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readTezosOperation(List<int> forged) =>
      _reading(_readTezosOperation, forged);

  /// [payload] — a MultiversX transaction's signing JSON, which its
  /// signature is over — as the core reads it for the review screen (O58):
  /// the nonce, value, receiver, sender, gas, data and chain, as the JSON
  /// `kc_multiversx_read_transaction` writes. Kept by the core, so that one
  /// signature of exactly [payload] by a MultiversX key may be made. JSON in
  /// any spelling but the module's is [KeyCoreRefusal.transaction]. Asks no
  /// session.
  String readMultiversxTransaction(List<int> payload) =>
      _reading(_readMultiversxTransaction, payload);

  /// [message] — a Filecoin message's CBOR, whose CID's BLAKE2b-256 its
  /// signature is over — as the core reads it for the review screen (O58):
  /// both addresses as `f1`, the nonce, the value, the gas and the premium,
  /// the CID and the digest, as the JSON `kc_filecoin_read_message` writes.
  /// Kept by the core, so that one signature of exactly that digest by a
  /// Filecoin key may be made. A message the module never writes is
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readFilecoinMessage(List<int> message) =>
      _reading(_readFilecoinMessage, message);

  /// [content] — an ICP call's content map as CBOR, whose request id's
  /// domain-separated SHA-256 its signature is over — as the core reads it
  /// for the review screen (O58): the ledger's transfer, the sender, the
  /// expiry, the request id and the digest, as the JSON `kc_icp_read_call`
  /// writes. Kept by the core, so that one signature of exactly that digest
  /// by an ICP key may be made. A call the module never makes is
  /// [KeyCoreRefusal.transaction]. Asks no session.
  String readIcpCall(List<int> content) => _reading(_readIcpCall, content);

  /// [input] read by [entry], through the protocol both readings share: the
  /// length first, then the reading into a buffer that holds it.
  String _reading(_ReadEvmTransaction entry, List<int> input) {
    final nativeInput = _copyIn(input);
    final length = calloc<Size>();
    try {
      final code = entry(nativeInput, input.length, nullptr, 0, length);
      if (code != KeyCoreRefusal.buffer.code) _check(code);
      final needed = length.value;
      final out = calloc<Uint8>(needed == 0 ? 1 : needed);
      try {
        _check(entry(nativeInput, input.length, out, needed, length));
        return utf8.decode(out.asTypedList(length.value));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(length);
      _release(nativeInput, input.length);
    }
  }

  /// The session another isolate opened, by its [KeyCoreSession.handle] — the
  /// core's table is the process's, so a background isolate asks the same
  /// session the main one holds. **Borrowed:** its [KeyCoreSession.close]
  /// closes nothing; the isolate that opened it closes it, and after that
  /// every call here is [KeyCoreRefusal.handle].
  ///
  /// Safe from several isolates at once: each call takes the core's one lock
  /// for the whole of its derivation and signature (`src/lib.rs`).
  KeyCoreSession borrow(int handle) =>
      KeyCoreSession._(this, handle, borrowed: true);

  /// Takes the session [handle] for this isolate — **one a background isolate
  /// opened and handed over by its number** ([slip39Restore] run off the main
  /// isolate, phase 7b): unlike [borrow], [KeyCoreSession.close] closes it.
  /// The isolate that opened it must not close it too.
  KeyCoreSession adopt(int handle) => KeyCoreSession._(this, handle);
}

/// One opened phrase, or one imported key ([KeyCore.openKey]), by its handle.
final class KeyCoreSession {
  KeyCoreSession._(this._core, this._handle, {bool borrowed = false})
      : _borrowed = borrowed;

  final KeyCore _core;
  final int _handle;
  final bool _borrowed;

  /// The core's number for this session, for [KeyCore.borrow] on another
  /// isolate. A number, not a key: it means something only inside this
  /// process, and only until the session closes.
  int get handle => _handle;

  /// The public key at [path]: 33 bytes, or 65 when not [compressed].
  Uint8List secp256k1PublicKey(String path, {bool compressed = true}) {
    final length = compressed ? 33 : 65;
    return _withPath(path, length, secret: false, (p, pathLength, out) {
      return _core._publicKey(
          _handle, p, pathLength, compressed ? 0 : 1, out, length);
    });
  }

  /// A recoverable signature over the 32-byte [digest] with the key at [path].
  /// A TRON key — a phrase's at `m/44'/195'`, or one opened as
  /// [KeyCoreCurve.tron] — signs only the SHA-256 of a transaction
  /// [readTronTransaction] read for a screen, once, and a Cosmos zone's — at
  /// `m/44'/118'` or `m/44'/459'`, or opened as [KeyCoreCurve.cosmos] — only
  /// the SHA-256 of a `SignDoc` [readCosmosSignDoc] read, once; or
  /// [KeyCoreRefusal.unshown] (O58).
  Secp256k1Signature signSecp256k1Digest(String path, List<int> digest) {
    final nativeDigest = _copyIn(digest);
    try {
      final out = _withPath(path, 65, secret: false, (p, pathLength, out) {
        return _core._sign(
            _handle, p, pathLength, nativeDigest, digest.length, out, 65);
      });
      return Secp256k1Signature._(
          out.sublist(0, 32), out.sublist(32, 64), out[64]);
    } finally {
      _release(nativeDigest, digest.length);
    }
  }

  /// The chain code (32 bytes) and the compressed public key (33) at [path]:
  /// what an account's xpub is made of.
  ({Uint8List chainCode, Uint8List publicKey}) secp256k1ExtendedPublicKey(
      String path) {
    final out = _withPath(path, 65, secret: false, (p, pathLength, out) {
      return _core._extended(_handle, p, pathLength, out, 65);
    });
    return (chainCode: out.sublist(0, 32), publicKey: out.sublist(32));
  }

  /// An ECDSA signature for a Bitcoin input over the 32-byte [digest] with the
  /// key at [path]: `r` then `s`, 32 bytes each, low `s`, and `r` ground below
  /// 2^255 the way `blockchain_utils`' `signECDSADerConst` grinds it, so the
  /// DER form is that method's byte for byte. See `src/keys.rs`.
  Uint8List signSecp256k1DigestLowR(String path, List<int> digest) {
    final nativeDigest = _copyIn(digest);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._lowR(
            _handle, p, pathLength, nativeDigest, digest.length, out, 64);
      });
    } finally {
      _release(nativeDigest, digest.length);
    }
  }

  /// A BIP-340 Schnorr signature (64 bytes) over the 32-byte [digest] with the
  /// key at [path], tweaked first by the 32-byte [tweak] when one is given —
  /// BIP-341's key-path spend, as `PsbtDefaultSigner` passes a taproot input's
  /// tap tweak hash. Byte for byte what `blockchain_utils`'
  /// `signBip340Const` makes with no `aux` given; see `src/keys.rs`.
  Uint8List signSchnorr(String path, List<int> digest, {List<int>? tweak}) {
    final nativeDigest = _copyIn(digest);
    final tweakLength = tweak?.length ?? 0;
    final nativeTweak = tweak == null ? nullptr : _copyIn(tweak);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._schnorr(_handle, p, pathLength, nativeDigest,
            digest.length, nativeTweak, tweakLength, out, 64);
      });
    } finally {
      _release(nativeDigest, digest.length);
      if (tweak != null) _release(nativeTweak, tweakLength);
    }
  }

  /// A recoverable signature over an EVM transaction with the key at [path] —
  /// "sign what you see", step 2c — made only once the core has read
  /// [unsigned] and found it to be [expected].
  ///
  /// [unsigned] is what web3dart encoded for the signature: a legacy
  /// transaction under EIP-155 or an EIP-1559 one. [expected] is the same
  /// transaction as the app built it, in the layout `src/lib.rs` documents
  /// for `kc_secp256k1_sign_evm_transaction`. A difference in the network,
  /// recipient, value, gas limit, a fee or the call data, or bytes in any
  /// other form, is [KeyCoreRefusal.transaction]; the core takes the
  /// Keccak-256 itself, so nothing hashed on this side is signed. And only a
  /// transaction [readEvmTransaction] read for a screen for this key, once:
  /// the same facts at a fee within the cap it showed, or
  /// [KeyCoreRefusal.unshown] (2f-1b, O53).
  Secp256k1Signature signEvmTransaction(
      String path, List<int> unsigned, List<int> expected) {
    final nativeUnsigned = _copyIn(unsigned);
    final nativeExpected = _copyIn(expected);
    try {
      final out = _withPath(path, 65, secret: false, (p, pathLength, out) {
        return _core._signEvmTransaction(_handle, p, pathLength,
            nativeUnsigned, unsigned.length, nativeExpected, expected.length,
            out, 65);
      });
      return Secp256k1Signature._(
          out.sublist(0, 32), out.sublist(32, 64), out[64]);
    } finally {
      _release(nativeExpected, expected.length);
      _release(nativeUnsigned, unsigned.length);
    }
  }

  /// [expected] — an EVM transaction in the layout `src/lib.rs` documents for
  /// `kc_secp256k1_sign_evm_transaction` — as the core reads it for the
  /// review screen ("the screen shows what the core read", 2f-1) **for the
  /// key at [path]**: that key's address as `from`, the facts, the fee cap and
  /// the call data's reading, as the JSON `kc_evm_read_transaction` writes —
  /// and kept by the core with that address, so that one signature of a
  /// transaction it covers by that key may be made ([signEvmTransaction]),
  /// and by no other key. A key that signs no EVM transaction is
  /// [KeyCoreRefusal.kind].
  String readEvmTransaction(String path, List<int> expected) =>
      _readFor(_core._readEvmTransaction, path, expected);

  /// [json] — EIP-712 typed data, as [signEvmTypedData] takes it — as the
  /// core reads it for the review screen ("the screen shows what the core
  /// read", 2f-2) **for the key at [path]**: that key's address as `signer`;
  /// what is signed, the declared fields of the domain and the message as
  /// hashed; the places of the values the page sent that are not signed; the
  /// digest; and the permit, when the document is one of the six standard
  /// permits exactly (O55) — as the JSON `kc_evm_read_typed_data` writes.
  /// Kept by the core with that address, so that one signature of a document
  /// with its digest by that key may be made (O54), and by no other key. A
  /// document the signature would refuse is [KeyCoreRefusal.typedData], and
  /// a key it would refuse is refused as it would be.
  String readEvmTypedData(String path, String json) =>
      _readFor(_core._readEvmTypedData, path, utf8.encode(json));

  /// [KeyCore.readSolanaMessage], through this session's core: the reading a
  /// review screen shows, kept so a Solana key may then sign the message.
  String readSolanaMessage(List<int> message) =>
      _core.readSolanaMessage(message);

  /// [KeyCore.readTronTransaction], through this session's core: the reading
  /// a review screen shows, kept so a TRON key may then sign the transaction.
  String readTronTransaction(List<int> raw) => _core.readTronTransaction(raw);

  /// [KeyCore.readXrplTransaction], through this session's core: the reading
  /// a review screen shows, kept so an XRP key may then sign the payment.
  String readXrplTransaction(List<int> blob) => _core.readXrplTransaction(blob);

  /// [KeyCore.readCosmosSignDoc], through this session's core: the reading a
  /// review screen shows, kept so a Cosmos zone's key may then sign it.
  String readCosmosSignDoc(List<int> signDoc) =>
      _core.readCosmosSignDoc(signDoc);

  /// [KeyCore.readStellarTransaction], through this session's core: the
  /// reading a review screen shows, kept so a Stellar key may then sign the
  /// transaction's hash.
  String readStellarTransaction(List<int> payload) =>
      _core.readStellarTransaction(payload);

  /// [KeyCore.readNearTransaction], through this session's core: the reading
  /// a review screen shows, kept so a NEAR key may then sign the
  /// transaction's hash.
  String readNearTransaction(List<int> transaction) =>
      _core.readNearTransaction(transaction);

  /// [KeyCore.readAptosTransaction], through this session's core: the
  /// reading a review screen shows, kept so an Aptos or Movement key may then
  /// sign the message.
  String readAptosTransaction(List<int> message) =>
      _core.readAptosTransaction(message);

  /// [KeyCore.readSuiTransaction], through this session's core: the reading a
  /// review screen shows, kept so a Sui key may then sign its digest.
  String readSuiTransaction(List<int> message) =>
      _core.readSuiTransaction(message);

  /// [KeyCore.readAlgorandTransaction], through this session's core: the
  /// reading a review screen shows, kept so an Algorand key may then sign it.
  String readAlgorandTransaction(List<int> message) =>
      _core.readAlgorandTransaction(message);

  /// [KeyCore.readTezosOperation], through this session's core: the reading
  /// a review screen shows, kept so a Tezos key may then sign its digest.
  String readTezosOperation(List<int> forged) =>
      _core.readTezosOperation(forged);

  /// [KeyCore.readMultiversxTransaction], through this session's core: the
  /// reading a review screen shows, kept so a MultiversX key may then sign
  /// it.
  String readMultiversxTransaction(List<int> payload) =>
      _core.readMultiversxTransaction(payload);

  /// [payload] — a Polkadot Asset Hub extrinsic's signing payload, which its
  /// signature is over — as the core reads it for the review screen (O58)
  /// **for the Polkadot key at [path]** (`m/44'/354'/…`): that key's public
  /// half as `signer`, the destination, the amount, the era, the nonce, the
  /// tip, the runtime's versions, the genesis and the era's block, as the
  /// JSON `kc_polkadot_read_transaction` writes. Kept by the core with that
  /// key, so that one signature of exactly [payload] by it may be made, and
  /// by no other key. A payload the module never writes — another call, an
  /// immortal era, an asset paying the fee, a metadata hash, a compact not in
  /// its shortest form — is [KeyCoreRefusal.transaction]; a path not
  /// Polkadot's [KeyCoreRefusal.path]; an imported key's session
  /// [KeyCoreRefusal.kind].
  String readPolkadotTransaction(String path, List<int> payload) =>
      _readFor(_core._readPolkadotTransaction, path, payload);

  /// [boc] — a TON wallet v4R2 signing message as a bag of cells, whose
  /// root's representation hash a TON signature is over — as the core reads
  /// it for the review screen (O58) **for the TON key at [path]**
  /// (`m/44'/607'/…`): that key's public half as `publicKey`, the subwallet,
  /// the expiry, the seqno, every message and its body, and the hash the core
  /// takes, as the JSON `kc_ton_read_transfer` writes. Kept by the core with
  /// that key, so that one signature of exactly that hash by it may be made,
  /// and by no other key. A bag the module never writes is
  /// [KeyCoreRefusal.transaction]; a path not TON's [KeyCoreRefusal.path]; an
  /// imported key's session [KeyCoreRefusal.kind].
  String readTonTransfer(String path, List<int> boc) =>
      _readFor(_core._readTonTransfer, path, boc);

  /// [input] read by [entry] for the key at [path], through the protocol
  /// every reading shares: the length first, then the reading into a buffer
  /// that holds it.
  String _readFor(_ReadCardanoTransaction entry, String path, List<int> input) {
    final pathBytes = utf8.encode(path);
    final nativePath = _copyIn(pathBytes);
    final nativeInput = _copyIn(input);
    final length = calloc<Size>();
    try {
      final code = entry(_handle, nativePath, pathBytes.length, nativeInput,
          input.length, nullptr, 0, length);
      if (code != KeyCoreRefusal.buffer.code) _check(code);
      final needed = length.value;
      final out = calloc<Uint8>(needed == 0 ? 1 : needed);
      try {
        _check(entry(_handle, nativePath, pathBytes.length, nativeInput,
            input.length, out, needed, length));
        return utf8.decode(out.asTypedList(length.value));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(length);
      _release(nativeInput, input.length);
      _release(nativePath, pathBytes.length);
    }
  }

  /// [body] — a Cardano transaction body's CBOR, whose BLAKE2b-256 every
  /// witness signs — as the core reads it for the review screen (O58), with
  /// the keys at [signers] that will sign it: the inputs, the outputs, the
  /// fee, the time to live, the hash and the signers' payment key hashes, as
  /// the JSON `kc_cardano_read_transaction` writes. **One witness per payment
  /// key**: two signers of one key hash are [KeyCoreRefusal.transaction] and
  /// nothing is kept (the owner's decision of 5 November 2026). Otherwise
  /// **kept for each signer**: each may then sign that hash once
  /// ([signCardano]), and no other key may. A body the module never writes
  /// is [KeyCoreRefusal.transaction].
  String readCardanoTransaction(List<int> body, List<String> signers) {
    final layout = BytesBuilder()
      ..add(_le16(signers.length));
    for (final path in signers) {
      final bytes = utf8.encode(path);
      layout
        ..add(_le16(bytes.length))
        ..add(bytes);
    }
    final signerBytes = layout.takeBytes();
    final nativeBody = _copyIn(body);
    final nativeSigners = _copyIn(signerBytes);
    final length = calloc<Size>();
    try {
      final code = _core._readCardanoTransaction(_handle, nativeBody,
          body.length, nativeSigners, signerBytes.length, nullptr, 0, length);
      if (code != KeyCoreRefusal.buffer.code) _check(code);
      final needed = length.value;
      final out = calloc<Uint8>(needed == 0 ? 1 : needed);
      try {
        _check(_core._readCardanoTransaction(_handle, nativeBody, body.length,
            nativeSigners, signerBytes.length, out, needed, length));
        return utf8.decode(out.asTypedList(length.value));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(length);
      _release(nativeSigners, signerBytes.length);
      _release(nativeBody, body.length);
    }
  }

  static List<int> _le16(int value) => [value & 0xff, value >> 8 & 0xff];

  /// [KeyCore.readFilecoinMessage], through this session's core: the reading
  /// a review screen shows, kept so a Filecoin key may then sign its digest.
  String readFilecoinMessage(List<int> message) =>
      _core.readFilecoinMessage(message);

  /// [KeyCore.readIcpCall], through this session's core: the reading a
  /// review screen shows, kept so an ICP key may then sign its digest.
  String readIcpCall(List<int> content) => _core.readIcpCall(content);

  /// `r ‖ s`, 64 bytes, low `s`: the XRP key at [path]'s signature of [blob]
  /// — a payment's signing serialisation — over the SHA-512 half of `STX\0`
  /// and [blob], which the core takes itself. Only of a payment an unused
  /// reading of [readXrplTransaction] was of in every field but its
  /// `LastLedgerSequence`, which it must carry, once — or
  /// [KeyCoreRefusal.unshown] — and only by an XRP key: a phrase's at
  /// `m/44'/144'`, or one opened as [KeyCoreCurve.xrp] (O59).
  Uint8List signXrplTransaction(String path, List<int> blob) {
    final nativeBlob = _copyIn(blob);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._xrplSign(
            _handle, p, pathLength, nativeBlob, blob.length, out, 64);
      });
    } finally {
      _release(nativeBlob, blob.length);
    }
  }

  /// A recoverable signature over [message] as an EVM personal message
  /// (EIP-191, version `E`) with the key at [path] — "sign what you see",
  /// step 2e. [message] is the bytes the review showed; the core puts the
  /// prefix and the length before them and takes the Keccak-256 itself.
  Secp256k1Signature signEvmPersonalMessage(String path, List<int> message) =>
      _signEvmMessage(_core._signPersonalMessage, path, message);

  /// A recoverable signature over EIP-712 typed data with the key at [path]
  /// — "sign what you see", step 2e. [json] is the document the review read,
  /// as JSON; the core reads it and computes `keccak256(0x19 0x01 ‖
  /// domainSeparator ‖ hashStruct(message))` itself. A document the app's
  /// validator would refuse, or one past its limits, is
  /// [KeyCoreRefusal.typedData]; one no screen was shown — no unused reading
  /// of [readEvmTypedData] for this key has its digest — is
  /// [KeyCoreRefusal.unshown] (2f-2, O54).
  Secp256k1Signature signEvmTypedData(String path, String json) =>
      _signEvmMessage(_core._signTypedData, path, utf8.encode(json));

  Secp256k1Signature _signEvmMessage(
      _SignEvmMessage entry, String path, List<int> data) {
    final nativeData = _copyIn(data);
    try {
      final out = _withPath(path, 65, secret: false, (p, pathLength, out) {
        return entry(_handle, p, pathLength, nativeData, data.length, out, 65);
      });
      return Secp256k1Signature._(
          out.sublist(0, 32), out.sublist(32, 64), out[64]);
    } finally {
      _release(nativeData, data.length);
    }
  }

  /// Every input of a Bitcoin, Litecoin, Dogecoin or Bitcoin Cash
  /// transaction signed — "sign what you see", step 2d — once the core has
  /// read [request] and found its transaction to be the one the app built.
  ///
  /// [request] is in the layout `src/lib.rs` documents for
  /// `kc_bitcoin_sign_transaction`, and names [inputs] inputs. Each answer is
  /// the sighash the core computed and the signature over it: `r ‖ s` (64
  /// bytes, low `s`, `r` ground low) for ECDSA, or a BIP-340 signature with
  /// BIP-86's tweak for a taproot key path. A transaction other than the one
  /// described is [KeyCoreRefusal.transaction]; one no screen was shown — no
  /// unused reading of [readBitcoinTransaction] was of this request — is
  /// [KeyCoreRefusal.unshown] (2f-3).
  List<({Uint8List sighash, Uint8List signature})> signBitcoinTransaction(
          List<int> request, int inputs) =>
      _signTransaction(_core._signBitcoinTransaction, request, inputs);

  /// [request] — in [signBitcoinTransaction]'s layout — held as the
  /// signature would hold it and read for the review screen ("the screen
  /// shows what the core read", 2f-3), as the JSON
  /// `kc_bitcoin_read_transaction` writes: the flavour, the txid, the inputs,
  /// the outputs with whether each is the wallet's change — the core's
  /// finding, by this session's keys — the sum spent and the fee. Kept by the
  /// core, so that one signature of exactly this request may be made. A
  /// transaction other than the one described is
  /// [KeyCoreRefusal.transaction].
  String readBitcoinTransaction(List<int> request) =>
      _readTransaction(_core._readBitcoinTransaction, request);

  /// Every input of a Kaspa send signed by BIP-340 (O58) once the core has
  /// read [request] — in the layout `src/lib.rs` documents for
  /// `kc_kaspa_sign_transaction`, naming [inputs] inputs — and found every
  /// input this session's key's own coin. Each answer is the sighash the core
  /// computed, BLAKE2b-256 keyed by `TransactionSigningHash`, and the
  /// signature over it. A send the module does not write is
  /// [KeyCoreRefusal.transaction]; one no screen was shown — no unused
  /// reading of [readKaspaTransaction] was of this request — is
  /// [KeyCoreRefusal.unshown].
  List<({Uint8List sighash, Uint8List signature})> signKaspaTransaction(
          List<int> request, int inputs) =>
      _signTransaction(_core._signKaspaTransaction, request, inputs);

  /// [request] — in [signKaspaTransaction]'s layout — held as the signature
  /// would hold it and read for the review screen, as the JSON
  /// `kc_kaspa_read_transaction` writes: the inputs, the outputs with the
  /// addresses the core spells and whether each is change — the core's
  /// finding, by this session's key — the sum sent, the sum spent, the fee
  /// and the sighashes. Kept by the core, so that one signature of exactly
  /// this request may be made. A send the module does not write is
  /// [KeyCoreRefusal.transaction].
  String readKaspaTransaction(List<int> request) =>
      _readTransaction(_core._readKaspaTransaction, request);

  /// Every input of a transparent Zcash send signed by ECDSA once the core
  /// has read [request] — in the layout `src/lib.rs` documents for
  /// `kc_zcash_sign_transaction`, naming [inputs] inputs — and found every
  /// input this session's key's own coin. Each answer is the ZIP-244
  /// signature digest the core computed under `SIGHASH_ALL` and the
  /// signature over it, `r` then `s`, low R and low s. A send the module does
  /// not write is [KeyCoreRefusal.transaction]; one no screen was shown — no
  /// unused reading of [readZcashTransaction] was of this request — is
  /// [KeyCoreRefusal.unshown].
  List<({Uint8List sighash, Uint8List signature})> signZcashTransaction(
          List<int> request, int inputs) =>
      _signTransaction(_core._signZcashTransaction, request, inputs);

  /// [request] — in [signZcashTransaction]'s layout — held as the signature
  /// would hold it and read for the review screen, as the JSON
  /// `kc_zcash_read_transaction` writes: the inputs, the outputs with the
  /// `t1`, `t3` or `tex1` addresses the core spells and whether each is
  /// change — the core's finding, by this session's key — the sum sent, the
  /// sum spent, the fee, the expiry height, the transaction id and the
  /// signature digests. Kept by the core, so that one signature of exactly
  /// this request may be made. A send the module does not write is
  /// [KeyCoreRefusal.transaction].
  String readZcashTransaction(List<int> request) =>
      _readTransaction(_core._readZcashTransaction, request);

  List<({Uint8List sighash, Uint8List signature})> _signTransaction(
      _SignBitcoinTransaction entry, List<int> request, int inputs) {
    final nativeRequest = _copyIn(request);
    final length = inputs * 96;
    final out = calloc<Uint8>(length == 0 ? 1 : length);
    try {
      _check(entry(_handle, nativeRequest, request.length, out, length));
      final bytes = Uint8List.fromList(out.asTypedList(length));
      return [
        for (var i = 0; i < inputs; i++)
          (
            sighash: bytes.sublist(i * 96, i * 96 + 32),
            signature: bytes.sublist(i * 96 + 32, i * 96 + 96),
          ),
      ];
    } finally {
      calloc.free(out);
      _release(nativeRequest, request.length);
    }
  }

  String _readTransaction(_ReadBitcoinTransaction entry, List<int> request) {
    final nativeRequest = _copyIn(request);
    final length = calloc<Size>();
    try {
      final code =
          entry(_handle, nativeRequest, request.length, nullptr, 0, length);
      if (code != KeyCoreRefusal.buffer.code) _check(code);
      final needed = length.value;
      final out = calloc<Uint8>(needed == 0 ? 1 : needed);
      try {
        _check(entry(_handle, nativeRequest, request.length, out, needed, length));
        return utf8.decode(out.asTypedList(length.value));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(length);
      _release(nativeRequest, request.length);
    }
  }

  /// The 32-byte private key at [path], **for the export screens only**.
  ///
  /// The returned list is the caller's to overwrite when the screen closes;
  /// the native buffer it came through is overwritten here.
  Uint8List exportSecp256k1PrivateKey(String path) =>
      _withPath(path, 32, secret: true, (p, pathLength, out) {
        return _core._export(_handle, p, pathLength, out, 32);
      });

  /// The 32-byte ed25519 public key at [path], by SLIP-10 — the bare key,
  /// without the `00` `blockchain_utils` puts before its compressed form.
  /// Every level of [path] must be hardened.
  Uint8List ed25519PublicKey(String path) =>
      _withPath(path, 32, secret: false, (p, pathLength, out) {
        return _core._ed25519PublicKey(_handle, p, pathLength, out, 32);
      });

  /// An Ed25519 signature (64 bytes, RFC 8032) over [message] — the message
  /// itself, of any length, not a digest of it — with the key at [path].
  /// Ed25519 is deterministic: byte for byte what `blockchain_utils`'
  /// `Ed25519Signer` makes with the same key. **A Solana key** — the phrase's
  /// at `m/44'/501'`, or one opened as [KeyCoreCurve.solana] — signs only a
  /// message [KeyCore.readSolanaMessage] read for a screen, once, or
  /// [KeyCoreRefusal.unshown] (O58).
  Uint8List signEd25519(String path, List<int> message) {
    final nativeMessage = _copyIn(message);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._ed25519Sign(
            _handle, p, pathLength, nativeMessage, message.length, out, 64);
      });
    } finally {
      _release(nativeMessage, message.length);
    }
  }

  /// The 32-byte ed25519 private key at [path] — SLIP-10's key, what every
  /// export format is made from — **for the export screens only**, as
  /// [exportSecp256k1PrivateKey] is.
  Uint8List exportEd25519PrivateKey(String path) =>
      _withPath(path, 32, secret: true, (p, pathLength, out) {
        return _core._ed25519Export(_handle, p, pathLength, out, 32);
      });

  /// The 32-byte Cardano public key at [path]: BIP32-Ed25519 from the Ledger
  /// scheme's master key, as `Cip1852.fromSeed(seed,
  /// Cip1852Coins.cardanoLedger)` derives it. Normal levels are allowed.
  Uint8List cardanoPublicKey(String path) =>
      _withPath(path, 32, secret: false, (p, pathLength, out) {
        return _core._cardanoPublicKey(_handle, p, pathLength, out, 32);
      });

  /// The 32-byte Cardano public key at [path] by **the Icarus scheme** — the
  /// master key Yoroi, Eternl and Daedalus build from the phrase's entropy
  /// (CIP-0003), as `Cip1852.fromSeed(entropy, Cip1852Coins.cardanoIcarus)`
  /// derives it — phase 6c. Normal levels are allowed. A public key and
  /// nothing else: no call signs or exports under Icarus. An imported key's
  /// session is [KeyCoreRefusal.kind].
  Uint8List cardanoIcarusPublicKey(String path) =>
      _withPath(path, 32, secret: false, (p, pathLength, out) {
        return _core._cardanoIcarusPublicKey(_handle, p, pathLength, out, 32);
      });

  /// A Cardano signature (64 bytes) over [message] — the message itself —
  /// with the extended key at [path]: byte for byte `CardanoSigner`'s, which
  /// signs every Cardano witness the app makes today. **A key at
  /// `m/1852'/1815'` signs only the 32-byte hash of a body
  /// [readCardanoTransaction] read with it among the signers**, once
  /// ([KeyCoreRefusal.unshown], O58).
  Uint8List signCardano(String path, List<int> message) {
    final nativeMessage = _copyIn(message);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._cardanoSign(
            _handle, p, pathLength, nativeMessage, message.length, out, 64);
      });
    } finally {
      _release(nativeMessage, message.length);
    }
  }

  /// The 96 bytes of the Cardano node at [path] — the extended key `kL ‖ kR`
  /// and the chain code, what the export screen shows — **for the export
  /// screens only**.
  Uint8List exportCardanoPrivateKey(String path) =>
      _withPath(path, 96, secret: true, (p, pathLength, out) {
        return _core._cardanoExport(_handle, p, pathLength, out, 96);
      });

  /// The 32-byte Stark public key (`x`, big-endian) of the Starknet key at
  /// [path] — Argent's derivation: [path] is in the second tree
  /// (`m/44'/9004'/0'/0/{i}`), which the key at `m/44'/60'/0'/0/0` seeds, as
  /// the Starknet module's `ArgentAccount` derives it.
  Uint8List starknetPublicKey(String path) =>
      _withPath(path, 32, secret: false, (p, pathLength, out) {
        return _core._starknetPublicKey(_handle, p, pathLength, out, 32);
      });

  /// A Stark signature over the 32-byte big-endian [hash] (a felt below
  /// 2^251) with the key at [path]: `r` then `s`, 32 bytes each, big-endian
  /// — the `starknet` package's `starknetSign`, RFC 6979 nonce. **A key at
  /// `m/44'/9004'` signs only the hash of a transaction
  /// [readStarknetTransaction] read for it**, once ([KeyCoreRefusal.unshown],
  /// O58).
  Uint8List signStarknet(String path, List<int> hash) {
    final nativeHash = _copyIn(hash);
    try {
      return _withPath(path, 64, secret: false, (p, pathLength, out) {
        return _core._starknetSign(
            _handle, p, pathLength, nativeHash, hash.length, out, 64);
      });
    } finally {
      _release(nativeHash, hash.length);
    }
  }

  /// [transaction] — a v3 Starknet transaction's JSON body as the module
  /// sends it, unsigned — as the core reads it for the review screen (O58),
  /// held to the Stark key at [path]: the kind, the query flag, the network,
  /// the bounds and the most they cost, the transfer or the deployment, and
  /// the hash, which the core takes. **Kept with the key**, so that one
  /// signature of that hash by it may be made ([signStarknet]). A
  /// transaction the module never sends, or one not this key's, is
  /// [KeyCoreRefusal.transaction].
  String readStarknetTransaction(String path, List<int> transaction) {
    final pathBytes = utf8.encode(path);
    final nativePath = _copyIn(pathBytes);
    final nativeTransaction = _copyIn(transaction);
    final length = calloc<Size>();
    try {
      final code = _core._readStarknetTransaction(_handle, nativePath,
          pathBytes.length, nativeTransaction, transaction.length, nullptr, 0,
          length);
      if (code != KeyCoreRefusal.buffer.code) _check(code);
      final needed = length.value;
      final out = calloc<Uint8>(needed == 0 ? 1 : needed);
      try {
        _check(_core._readStarknetTransaction(_handle, nativePath,
            pathBytes.length, nativeTransaction, transaction.length, out,
            needed, length));
        return utf8.decode(out.asTypedList(length.value));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(length);
      _release(nativeTransaction, transaction.length);
      _release(nativePath, pathBytes.length);
    }
  }

  /// The 32-byte ground Stark private key at [path], big-endian — **for the
  /// export screens only**.
  Uint8List exportStarknetPrivateKey(String path) =>
      _withPath(path, 32, secret: true, (p, pathLength, out) {
        return _core._starknetExport(_handle, p, pathLength, out, 32);
      });

  /// Whether [candidate] is the phrase this session was opened on — phase 6c,
  /// the question a split backup's restore asks of the open wallet.
  ///
  /// **The core compares the seeds, in constant time**, and keeps nothing of
  /// [candidate]; one bit comes back. [candidate] must be in the form the
  /// wallet stores a phrase — lower case, one space between words — or it is
  /// [KeyCoreRefusal.phrase]; normalising it is the caller's. An imported
  /// key's session is [KeyCoreRefusal.kind].
  ///
  /// Its UTF-8 bytes are overwritten here, on the Dart heap and in native
  /// memory, once the core has read them, as [KeyCore.open] overwrites its
  /// phrase's; the [String] itself is the caller's.
  bool matchesPhrase(String candidate) {
    final bytes = utf8.encode(candidate);
    final native = _copyIn(bytes);
    final out = calloc<Uint8>();
    try {
      _check(_core._matchesPhrase(_handle, native, bytes.length, out));
      return out.value == 1;
    } finally {
      bytes.fillRange(0, bytes.length, 0);
      _release(native, bytes.length);
      calloc.free(out);
    }
  }

  /// Whether [other] holds the same phrase as this session — by their seeds,
  /// in constant time, in the core (phase 7b): "is this backup this wallet's",
  /// with no phrase on either side. A one-key session is
  /// [KeyCoreRefusal.kind].
  bool matchesSession(KeyCoreSession other) {
    final out = calloc<Uint8>();
    try {
      _check(_core._matchesSession(_handle, other._handle, out));
      return out.value == 1;
    } finally {
      calloc.free(out);
    }
  }

  /// This session's phrase sealed under [key] (the vault's 32-byte key) as
  /// the wallet stores a phrase — the record [KeyCore.openSealed] opens —
  /// phase 7b: the vault's record of a wallet a split backup gave back in the
  /// core, made there, so the phrase is never a string on this side. The
  /// record is ciphertext and the caller's; the native buffer is cleared.
  /// A one-key session is [KeyCoreRefusal.kind].
  Uint8List sealPhrase(Uint8List key) {
    const capacity = 256;
    final nativeKey = _copyIn(key);
    final out = calloc<Uint8>(capacity);
    final length = calloc<Size>();
    try {
      _check(_core._sealPhrase(_handle, nativeKey, key.length, out, capacity, length));
      return Uint8List.fromList(out.asTypedList(length.value));
    } finally {
      _release(nativeKey, key.length);
      out.asTypedList(capacity).fillRange(0, capacity, 0);
      calloc.free(out);
      calloc.free(length);
    }
  }

  /// A split backup of this session's phrase, made and sealed in the core —
  /// phase 7a (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`).
  ///
  /// [count] SLIP-39 shares of the phrase's entropy, [threshold] of which
  /// restore it, each sealed under [password] — its NFC UTF-8 bytes, which
  /// are overwritten here once the core has read them — as `SealedShare`
  /// version 4 seals one, with [labels] (`bid`, `at`, and Argon2id's `m`,
  /// `t`, `p`) as JSON. The answer is the core's JSON: per share `set`,
  /// `g`, `m`, `t`, `salt`, `ct`, and — for the share at [paperIndex] alone —
  /// its words under `w`, which a person writes down. The native buffer it
  /// came through is overwritten here; the returned [String] is the caller's.
  ///
  /// Argon2id at the app's numbers takes a while for each share: call it off
  /// the main isolate ([KeyCore.borrow] there).
  String slip39Backup({
    required int threshold,
    required int count,
    int? paperIndex,
    required List<int> password,
    required String labels,
  }) {
    const capacity = 64 * 1024;
    final labelBytes = utf8.encode(labels);
    final nativePassword = _copyIn(password);
    final nativeLabels = _copyIn(labelBytes);
    final out = calloc<Uint8>(capacity);
    final length = calloc<Size>();
    try {
      _check(_core._slip39Backup(_handle, threshold, count, paperIndex ?? 255,
          nativePassword, password.length, nativeLabels, labelBytes.length,
          out, capacity, length));
      return utf8.decode(out.asTypedList(length.value));
    } finally {
      password.fillRange(0, password.length, 0);
      _release(nativePassword, password.length);
      _release(nativeLabels, labelBytes.length);
      out.asTypedList(capacity).fillRange(0, capacity, 0);
      calloc.free(out);
      calloc.free(length);
    }
  }

  /// Whether the sealed bodies in [shares] (a JSON list, as the stores hold
  /// them) and the typed [paper] words give back this session's phrase from
  /// every set of [threshold], opened under [password] in the core — the
  /// check a backup owes a person before it tells them they are safe
  /// (phase 7a). One bit comes back; nothing opened leaves the core.
  /// [password] and [paper]'s bytes are overwritten here.
  bool slip39Check({
    required String shares,
    String? paper,
    required int threshold,
    required List<int> password,
  }) {
    final shareBytes = utf8.encode(shares);
    final paperBytes = paper == null ? null : utf8.encode(paper);
    final nativeShares = _copyIn(shareBytes);
    final nativePaper = paperBytes == null ? nullptr : _copyIn(paperBytes);
    final nativePassword = _copyIn(password);
    final out = calloc<Uint8>();
    try {
      _check(_core._slip39Check(
          _handle,
          nativeShares,
          shareBytes.length,
          nativePaper,
          paperBytes?.length ?? 0,
          threshold,
          nativePassword,
          password.length,
          out));
      return out.value == 1;
    } finally {
      password.fillRange(0, password.length, 0);
      _release(nativePassword, password.length);
      _release(nativeShares, shareBytes.length);
      if (paperBytes != null) {
        paperBytes.fillRange(0, paperBytes.length, 0);
        _release(nativePaper, paperBytes.length);
      }
      calloc.free(out);
    }
  }

  /// Closes the session: the core overwrites its seed with zeros and frees it.
  ///
  /// A session [KeyCore.closeAll] already closed is closed; that is not an
  /// error here. Anything asked of a closed session is
  /// [KeyCoreRefusal.handle]. A [KeyCore.borrow]ed session closes nothing.
  void close() {
    if (_borrowed) return;
    final code = _core._close(_handle);
    if (code != 0 && code != KeyCoreRefusal.handle.code) _check(code);
  }

  Uint8List _withPath(
    String path,
    int outLength,
    int Function(Pointer<Uint8> path, int pathLength, Pointer<Uint8> out) call, {
    required bool secret,
  }) {
    final pathBytes = utf8.encode(path);
    final nativePath = _copyIn(pathBytes);
    final out = calloc<Uint8>(outLength);
    try {
      _check(call(nativePath, pathBytes.length, out));
      return Uint8List.fromList(out.asTypedList(outLength));
    } finally {
      _release(nativePath, pathBytes.length);
      if (secret) {
        _release(out, outLength);
      } else {
        calloc.free(out);
      }
    }
  }
}

void _check(int code) {
  if (code != 0) throw KeyCoreException.fromCode(code);
}

/// [bytes] in native memory, for [_release].
Pointer<Uint8> _copyIn(List<int> bytes) {
  final native = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  native.asTypedList(bytes.length).setAll(0, bytes);
  return native;
}

/// Writes zeros over [length] bytes at [native], then frees it.
void _release(Pointer<Uint8> native, int length) {
  native.asTypedList(length).fillRange(0, length, 0);
  calloc.free(native);
}
