//! Smartable key core: the recovery phrase's seed, and every key derived from
//! it, live here and nowhere else.
//!
//! **Handles, not bytes** (`docs/RUST_KEY_CORE_DESIGN.md#boundary`). [`kc_open`]
//! turns a phrase into a handle; everything after that is asked of the handle,
//! and nothing secret crosses back over the C ABI except through
//! [`kc_secp256k1_export_private_key`], [`kc_ed25519_export_private_key`],
//! [`kc_cardano_export_private_key`] and [`kc_starknet_export_private_key`],
//! which exist for the export screens.
//! A handle is a number into a table this crate owns, never reused, so a closed
//! or unknown one is a refusal and cannot reach another wallet's seed.
//!
//! **Phase 1:** English BIP-39 phrases with no passphrase, secp256k1 BIP-32
//! derivation and recoverable ECDSA — what the EVM accounts use. **Phase 2**
//! adds what Bitcoin's inputs need — low-R ECDSA, and BIP-340 Schnorr with
//! BIP-341's tweak for taproot — and wires the core into the app behind a
//! build flag. **Phase 4** adds ed25519 by SLIP-10, for Solana, TON, NEAR and
//! the other networks on that curve, Cardano's BIP32-Ed25519 by the Ledger
//! scheme, and Starknet's Stark key by Argent's derivation. **Phase 6a**
//! opens the sealed phrase here ([`kc_open_sealed`]), so an unlock hands the
//! core a record and its key rather than a phrase; **6c** answers the two
//! questions that read the phrase's text in Dart — whether a phrase is the
//! open one ([`kc_matches_phrase`]) and Cardano's Icarus key
//! ([`kc_cardano_icarus_public_key`]). **2c** signs an EVM transaction only
//! after reading it ([`kc_secp256k1_sign_evm_transaction`]): the core holds the
//! bytes to be signed to the transaction the app built, and hashes them
//! itself. **2e** does the same for an EVM message: a personal message
//! ([`kc_evm_sign_personal_message`]) and EIP-712 typed data
//! ([`kc_evm_sign_typed_data`]) are hashed here from what the app's review
//! read, not handed in as a digest; and the EVM keys then sign no bare
//! digest (2e-3). The C declarations are `include/key_core.h`; the Dart binding is
//! `dart/lib/key_core.dart`.
//!
//! Every entry point returns one of the `KC_*` codes, writes its output only on
//! success, turns a panic into [`KC_ERR_INTERNAL`] instead of unwinding into
//! the caller, and writes zeros over the stack it used before returning
//! ([`scrub`]).

// The owner's decision O14: curve25519-dalek's formally verified `fiat`
// backend, which `.cargo/config.toml` selects. A build that lost the flag — a
// `RUSTFLAGS` in the environment replaces that file's — would fall back to
// another backend without a word, so it does not build at all.
#[cfg(not(curve25519_dalek_backend = "fiat"))]
compile_error!(
    "key_core needs curve25519-dalek's fiat backend: build from native/key_core \
     (its .cargo/config.toml) and without RUSTFLAGS (docs/RUST_KEY_CORE_DESIGN.md, O14)"
);

mod algorand;
mod aptos;
mod bitcoin;
mod calldata;
mod cardano;
mod cosmos;
mod eip712;
mod evm;
mod filecoin;
mod icp;
mod kaspa;
mod keys;
mod multiversx;
mod near;
mod polkadot;
mod scrub;
mod seal;
mod share_seal;
mod slip39;
mod slip39_wordlist;
mod solana;
mod starknet;
mod stellar;
mod sui;
mod tezos;
mod ton;
mod tron;
mod xrpl;
mod zcash;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

use std::collections::{BTreeMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use bip32::DerivationPath;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Bumped whenever a function, an argument or a code below changes meaning; the
/// Dart binding refuses a library whose number is not the one it was written
/// against.
pub const KC_ABI_VERSION: u32 = 41;

pub const KC_OK: i32 = 0;
/// A null pointer, or a buffer whose length is not the one the call writes.
pub const KC_ERR_ARGUMENT: i32 = 1;
/// A handle that was closed or never opened.
pub const KC_ERR_HANDLE: i32 = 2;
/// Not a checksum-valid English phrase in the form the wallet stores.
pub const KC_ERR_PHRASE: i32 = 3;
/// Not a path in the form the wallet writes, or, for ed25519, one with a level
/// that is not hardened.
pub const KC_ERR_PATH: i32 = 4;
/// A digest of zero, or one not below the curve's order; for Starknet, a hash
/// at or above 2^251.
pub const KC_ERR_DIGEST: i32 = 5;
/// A BIP-32 child that does not exist (about 2^-127 per level), or a
/// BIP32-Ed25519 one whose key is zero modulo the group order.
pub const KC_ERR_DERIVATION: i32 = 6;
/// A panic, caught, or a signature that failed its own check.
pub const KC_ERR_INTERNAL: i32 = 7;
/// A call this session's kind does not answer: a one-key session asked for a
/// chain code, a Cardano or Starknet key, or a key on the other curve.
pub const KC_ERR_KIND: i32 = 8;
/// For [`kc_open_key`], 32 bytes that are not a key on the curve: a secp256k1
/// scalar of zero, or not below the order.
pub const KC_ERR_KEY: i32 = 9;
/// For [`kc_open_sealed`], a record this key does not open: a wrong key, a
/// changed byte, or fewer bytes than a nonce and a tag.
pub const KC_ERR_SEAL: i32 = 10;
/// For [`kc_secp256k1_sign_evm_transaction`], bytes that are not an EVM
/// transaction in a form the app writes, or not the transaction it built; for
/// the reading entries, bytes they do not read.
pub const KC_ERR_TRANSACTION: i32 = 11;
/// A bare digest asked of a key that signs only what the core has read. A key
/// of the Bitcoin family — a phrase's key at a Bitcoin, Litecoin, Dogecoin or
/// Bitcoin Cash path, or a key opened as [`KC_CURVE_SECP256K1_BITCOIN`] —
/// signs only a transaction (`kc_bitcoin_sign_transaction`; the owner's
/// decision O37), and no EVM message either. An EVM key — a phrase's key at
/// `m/44'/60'`, or a key opened as [`KC_CURVE_SECP256K1_EVM`] — signs only a
/// transaction, a personal message or typed data (O43). A TRON key — a
/// phrase's key at `m/44'/195'`, or a key opened as
/// [`KC_CURVE_SECP256K1_TRON`] — signs only the SHA-256 of a transaction
/// [`kc_tron_read_transaction`] read, through [`kc_secp256k1_sign_digest`]
/// (O58): no low-R or Schnorr digest, no EVM message; a Cosmos zone's key —
/// a phrase's at `m/44'/118'` or `m/44'/459'`, or a key opened as
/// [`KC_CURVE_SECP256K1_COSMOS`] — the same, of a `SignDoc`
/// [`kc_cosmos_read_sign_doc`] read (O58). An XRP Ledger key — a
/// phrase's key at `m/44'/144'`, or a key opened as
/// [`KC_CURVE_SECP256K1_XRP`] — signs only a payment, through
/// [`kc_xrpl_sign_transaction`] (O59): no digest at all.
pub const KC_ERR_TRANSACTION_ONLY: i32 = 12;
/// For [`kc_evm_sign_typed_data`], a document that is not EIP-712 typed data
/// the app's validator takes: more than 512 KiB, JSON that does not parse,
/// a type or value it refuses, a limit passed, or a value spelled in any but
/// its one canonical form (the owner's decisions O42 and O44).
pub const KC_ERR_TYPED_DATA: i32 = 13;
/// For [`kc_evm_read_transaction`], [`kc_evm_read_typed_data`],
/// [`kc_bitcoin_read_transaction`], [`kc_solana_read_message`],
/// [`kc_tron_read_transaction`], [`kc_xrpl_read_transaction`],
/// [`kc_cosmos_read_sign_doc`], [`kc_stellar_read_transaction`],
/// [`kc_near_read_transaction`], [`kc_aptos_read_transaction`],
/// [`kc_sui_read_transaction`], [`kc_algorand_read_transaction`],
/// [`kc_tezos_read_operation`], [`kc_multiversx_read_transaction`],
/// [`kc_polkadot_read_transaction`], [`kc_ton_read_transfer`],
/// [`kc_cardano_read_transaction`], [`kc_filecoin_read_message`] and
/// [`kc_icp_read_call`], an output
/// buffer shorter than the reading, or none: the length it needs is written,
/// and nothing else.
pub const KC_ERR_BUFFER: i32 = 14;
/// For [`kc_secp256k1_sign_evm_transaction`], a transaction no reading showed:
/// none of the readings [`kc_evm_read_transaction`] gave and no signature has
/// used has its kind, network, recipient, value and call data at a fee within
/// its cap (the owner's decision O53). For [`kc_evm_sign_typed_data`], a
/// document no unused reading of [`kc_evm_read_typed_data`] has the digest of
/// (O54). For [`kc_bitcoin_sign_transaction`], a request no unused reading of
/// [`kc_bitcoin_read_transaction`] was of, byte for byte (2f-3). For
/// [`kc_ed25519_sign`] by a Solana key, a message no unused reading of
/// [`kc_solana_read_message`] was of (O58). For [`kc_secp256k1_sign_digest`]
/// by a TRON key, a digest that is not the SHA-256 of a transaction an unused
/// reading of [`kc_tron_read_transaction`] was of (O58). For
/// [`kc_xrpl_sign_transaction`], a payment no unused reading of
/// [`kc_xrpl_read_transaction`] was of, its expiry aside (O59). For
/// [`kc_secp256k1_sign_digest`] by a Cosmos zone's key, a digest that is not
/// the SHA-256 of a `SignDoc` an unused reading of
/// [`kc_cosmos_read_sign_doc`] was of (O58). For [`kc_ed25519_sign`] by a
/// Stellar key, a message that is not the hash of a transaction an unused
/// reading of [`kc_stellar_read_transaction`] was of (O58); by a NEAR key,
/// one that is not the hash of a transaction an unused reading of
/// [`kc_near_read_transaction`] was of (O58); by an Aptos or Movement key,
/// a message no unused reading of [`kc_aptos_read_transaction`] was of; by a
/// Sui key, a message that is not the BLAKE2b-256 of an intent message an
/// unused reading of [`kc_sui_read_transaction`] was of; by an Algorand key,
/// a message no unused reading of [`kc_algorand_read_transaction`] was of;
/// by a Tezos key, a message that is not the watermarked BLAKE2b-256 of a
/// group an unused reading of [`kc_tezos_read_operation`] was of; by a
/// MultiversX key, a message no unused reading of
/// [`kc_multiversx_read_transaction`] was of; by a Polkadot key, a message
/// no unused reading of [`kc_polkadot_read_transaction`] was of; by a TON
/// key, one that is not the hash of a signing message an unused reading of
/// [`kc_ton_read_transfer`] was of; [`kc_cardano_sign`] by a key at
/// `m/1852'/1815'`, one that is not the hash of a body an unused reading of
/// [`kc_cardano_read_transaction`] was of with that key among its signers;
/// [`kc_secp256k1_sign_digest`] by a
/// Filecoin key, a digest no unused reading of [`kc_filecoin_read_message`]
/// was of; by an ICP key, one no unused reading of [`kc_icp_read_call`] was
/// of (O58).
pub const KC_ERR_UNSHOWN: i32 = 15;
/// For [`kc_slip39_restore`], too few shares, and the stores' copies did not
/// open under the password: `ShareBackup.restore`'s "That password does not
/// open this backup".
pub const KC_ERR_SHARE_PASSWORD: i32 = 16;
/// For [`kc_slip39_restore`], too few shares, and a copy that opened under the
/// password says another backup than its labels: a file edited.
pub const KC_ERR_SHARE_ALTERED: i32 = 17;
/// For [`kc_slip39_restore`], shares that do not give a wallet back: too few,
/// none of a set, or a set that does not recombine to a phrase's entropy.
pub const KC_ERR_SHARE: i32 = 18;

/// [`kc_open_key`]'s curves.
pub const KC_CURVE_SECP256K1: i32 = 0;
pub const KC_CURVE_ED25519: i32 = 1;
/// A secp256k1 key of the Bitcoin family, imported: as
/// [`KC_CURVE_SECP256K1`], except that it signs only a transaction the core
/// has read — no bare digest (O37).
pub const KC_CURVE_SECP256K1_BITCOIN: i32 = 2;
/// An EVM key, imported: as [`KC_CURVE_SECP256K1`], except that it signs only
/// a transaction, a personal message or typed data the core has read — no
/// bare digest — and no Bitcoin transaction (O43).
pub const KC_CURVE_SECP256K1_EVM: i32 = 3;
/// A Solana key, imported: as [`KC_CURVE_ED25519`], except that it signs only
/// a message [`kc_solana_read_message`] read for a screen, once (O58).
pub const KC_CURVE_ED25519_SOLANA: i32 = 4;
/// A TRON key, imported: as [`KC_CURVE_SECP256K1`], except that it signs
/// only the SHA-256 of a transaction [`kc_tron_read_transaction`] read for a
/// screen, once (O58), and no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_TRON: i32 = 5;
/// An XRP Ledger key, imported: as [`KC_CURVE_SECP256K1`], except that it
/// signs only a payment [`kc_xrpl_read_transaction`] read for a screen, once
/// (O59) — no digest, and no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_XRP: i32 = 6;
/// A Cosmos zone's key, imported: as [`KC_CURVE_SECP256K1`], except that it
/// signs only the SHA-256 of a `SignDoc` [`kc_cosmos_read_sign_doc`] read for
/// a screen, once (O58), and no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_COSMOS: i32 = 7;
/// A Stellar key, imported: as [`KC_CURVE_ED25519`], except that it signs
/// only the hash of a transaction [`kc_stellar_read_transaction`] read for a
/// screen, once (O58).
pub const KC_CURVE_ED25519_STELLAR: i32 = 8;
/// A Sui key, imported: as [`KC_CURVE_ED25519`], except that it signs only
/// the BLAKE2b-256 of an intent message [`kc_sui_read_transaction`] read for a
/// screen, once (O58).
pub const KC_CURVE_ED25519_SUI: i32 = 9;
/// An Algorand key, imported: as [`KC_CURVE_ED25519`], except that it signs
/// only a transaction [`kc_algorand_read_transaction`] read for a screen,
/// once (O58).
pub const KC_CURVE_ED25519_ALGORAND: i32 = 10;
/// A Tezos key, imported: as [`KC_CURVE_ED25519`], except that it signs only
/// the watermarked BLAKE2b-256 of an operation group
/// [`kc_tezos_read_operation`] read for a screen, once (O58).
pub const KC_CURVE_ED25519_TEZOS: i32 = 11;
/// A Filecoin key, imported: as [`KC_CURVE_SECP256K1`], except that it signs
/// only the digest of a message [`kc_filecoin_read_message`] read for a
/// screen, once (O58), and no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_FILECOIN: i32 = 12;
/// An ICP key, imported: as [`KC_CURVE_SECP256K1`], except that it signs only
/// the digest of a call [`kc_icp_read_call`] read for a screen, once (O58),
/// and no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_ICP: i32 = 13;
/// A Kaspa key, imported: as [`KC_CURVE_SECP256K1`], except that it signs
/// only a send [`kc_kaspa_read_transaction`] read for a screen, once, through
/// [`kc_kaspa_sign_transaction`] (O58) — no bare digest, no message, no
/// Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_KASPA: i32 = 14;
/// A Zcash transparent key, imported: as [`KC_CURVE_SECP256K1`], except that
/// it signs only a send [`kc_zcash_read_transaction`] read for a screen,
/// once, through [`kc_zcash_sign_transaction`] — no bare digest, no message,
/// no Bitcoin or EVM transaction.
pub const KC_CURVE_SECP256K1_ZCASH: i32 = 15;

/// 33 bytes, `02`/`03` and x.
pub const KC_PUBLIC_KEY_COMPRESSED: i32 = 0;
/// 65 bytes, `04`, x and y.
pub const KC_PUBLIC_KEY_UNCOMPRESSED: i32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Argument,
    Handle,
    Phrase,
    Path,
    Digest,
    Derivation,
    Internal,
    Kind,
    Key,
    Seal,
    Transaction,
    TransactionOnly,
    TypedData,
    Buffer,
    Unshown,
    SharePassword,
    ShareAltered,
    Share,
}

impl Refusal {
    fn code(self) -> i32 {
        match self {
            Refusal::Argument => KC_ERR_ARGUMENT,
            Refusal::Handle => KC_ERR_HANDLE,
            Refusal::Phrase => KC_ERR_PHRASE,
            Refusal::Path => KC_ERR_PATH,
            Refusal::Digest => KC_ERR_DIGEST,
            Refusal::Derivation => KC_ERR_DERIVATION,
            Refusal::Internal => KC_ERR_INTERNAL,
            Refusal::Kind => KC_ERR_KIND,
            Refusal::Key => KC_ERR_KEY,
            Refusal::Seal => KC_ERR_SEAL,
            Refusal::TransactionOnly => KC_ERR_TRANSACTION_ONLY,
            Refusal::Transaction => KC_ERR_TRANSACTION,
            Refusal::TypedData => KC_ERR_TYPED_DATA,
            Refusal::Buffer => KC_ERR_BUFFER,
            Refusal::Unshown => KC_ERR_UNSHOWN,
            Refusal::SharePassword => KC_ERR_SHARE_PASSWORD,
            Refusal::ShareAltered => KC_ERR_SHARE_ALTERED,
            Refusal::Share => KC_ERR_SHARE,
        }
    }
}

/// One opened phrase, or one imported key.
///
/// What it holds is boxed so it has one address for its whole life: a map
/// moves its values when it rebalances, and a moved array leaves its old
/// bytes behind. `Zeroizing` writes zeros over it before the box is freed.
struct Session {
    held: Held,
}

enum Held {
    /// A phrase, from [`kc_open`] or [`kc_open_sealed`].
    Seed(Box<Phrase>),
    /// One imported secp256k1 key, from [`kc_open_key`] (O22).
    Secp256k1(Box<Zeroizing<[u8; 32]>>),
    /// One imported secp256k1 key of the Bitcoin family, which signs only a
    /// transaction the core has read (O37).
    BitcoinKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported EVM key, which signs only a transaction, a message or
    /// typed data the core has read (O43).
    EvmKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported ed25519 key, its 32-byte seed, from [`kc_open_key`].
    Ed25519(Box<Zeroizing<[u8; 32]>>),
    /// One imported Solana key, its 32-byte seed, which signs only a message
    /// the core read for a screen (O58).
    SolanaKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported TRON key, which signs only the SHA-256 of a transaction
    /// the core read for a screen (O58).
    TronKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Filecoin key, which signs only the digest of a message
    /// the core read for a screen (O58).
    FilecoinKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported ICP key, which signs only the digest of a call the core
    /// read for a screen (O58).
    IcpKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Kaspa key, which signs only a send the core read for a
    /// screen (O58).
    KaspaKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Zcash transparent key, which signs only a send the core
    /// read for a screen.
    ZcashKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported XRP Ledger key, which signs only a payment the core read
    /// for a screen (O59).
    XrplKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Cosmos zone's key, which signs only the SHA-256 of a
    /// `SignDoc` the core read for a screen (O58).
    CosmosKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Stellar key, its 32-byte seed, which signs only the hash
    /// of a transaction the core read for a screen (O58).
    StellarKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Sui key, its 32-byte seed, which signs only the digest of
    /// an intent message the core read for a screen (O58).
    SuiKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Algorand key, its 32-byte seed, which signs only a
    /// transaction the core read for a screen (O58).
    AlgorandKey(Box<Zeroizing<[u8; 32]>>),
    /// One imported Tezos key, its 32-byte seed, which signs only the digest
    /// of an operation group the core read for a screen (O58).
    TezosKey(Box<Zeroizing<[u8; 32]>>),
}

/// What an opened phrase leaves here: its BIP-39 seed, and since phase 6c its
/// entropy, for Icarus (O29) — the phrase itself in another form, so it is
/// held as the seed is, and erased with it.
struct Phrase {
    seed: Zeroizing<[u8; 64]>,
    entropy: keys::Entropy,
}

static SESSIONS: Mutex<BTreeMap<u64, Session>> = Mutex::new(BTreeMap::new());

/// The EVM readings [`kc_evm_read_transaction`] gave a screen and no
/// signature has used, oldest first (2f-1b, O53), **each with the address of
/// the key it was read for**: what [`kc_secp256k1_sign_evm_transaction`]
/// holds a transaction to, and by which key. One reading signs once; reading
/// the same facts again does not make two.
static SHOWN: Mutex<VecDeque<evm::Shown>> = Mutex::new(VecDeque::new());

/// How many readings are kept unused; the oldest goes first. Far more than
/// a screen shows at once.
const MAX_SHOWN: usize = 64;

fn shown() -> MutexGuard<'static, VecDeque<evm::Shown>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The digests of the EIP-712 documents [`kc_evm_read_typed_data`] gave a
/// screen and no signature has used, oldest first (2f-2, O54), **each with
/// the address of the key it was read for**: what [`kc_evm_sign_typed_data`]
/// holds a document to — exactly, by that key, and once. At most
/// [`MAX_SHOWN`], as the transactions'.
static SHOWN_TYPED: Mutex<VecDeque<([u8; 32], [u8; 20])>> = Mutex::new(VecDeque::new());

fn shown_typed() -> MutexGuard<'static, VecDeque<([u8; 32], [u8; 20])>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_TYPED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Bitcoin-family request [`kc_bitcoin_read_transaction`]
/// gave a screen the reading of and no signature has used, oldest first
/// (2f-3): what [`kc_bitcoin_sign_transaction`] holds a request to — byte for
/// byte, and once. At most [`MAX_SHOWN`], as the others.
static SHOWN_BITCOIN: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_bitcoin() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_BITCOIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Solana message [`kc_solana_read_message`] gave a
/// screen the reading of and no signature has used, oldest first (O58): what
/// [`kc_ed25519_sign`] holds a Solana key's signature to — exactly, and once.
static SHOWN_SOLANA: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_solana() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_SOLANA.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every TRON `raw_data` [`kc_tron_read_transaction`] gave a
/// screen the reading of and no signature has used, oldest first (O58): the
/// digests [`kc_secp256k1_sign_digest`] signs by a TRON key — exactly, and
/// once. The digest is the transaction's id, so it names the bytes read.
static SHOWN_TRON: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_tron() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_TRON.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every `SignDoc` [`kc_cosmos_read_sign_doc`] gave a screen
/// the reading of and no signature has used, oldest first (O58): the digests
/// [`kc_secp256k1_sign_digest`] signs by a Cosmos zone's key — exactly, and
/// once.
static SHOWN_COSMOS: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_cosmos() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_COSMOS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What [`kc_xrpl_read_transaction`] gave a screen of each payment and no
/// signature has used, oldest first (O59): the SHA-256 of its signing
/// serialisation without its expiry — what [`kc_xrpl_sign_transaction`] holds
/// a payment to, every other field exactly, and once.
static SHOWN_XRPL: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_xrpl() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_XRPL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The hash of every Stellar transaction [`kc_stellar_read_transaction`] gave
/// a screen the reading of and no signature has used, oldest first (O58): the
/// 32 bytes [`kc_ed25519_sign`] signs by a Stellar key — exactly, and once.
static SHOWN_STELLAR: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_stellar() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_STELLAR.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The representation hash of every wallet v4R2 signing message
/// [`kc_ton_read_transfer`] gave a screen the reading of, **with the public
/// key it was read for**, no signature having used it, oldest first (O58):
/// [`kc_ed25519_sign`] signs by a TON key only such a hash, by that key —
/// exactly, and once.
static SHOWN_TON: Mutex<VecDeque<([u8; 32], [u8; 32])>> = Mutex::new(VecDeque::new());

fn shown_ton() -> MutexGuard<'static, VecDeque<([u8; 32], [u8; 32])>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_TON.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The digest of every ICP call [`kc_icp_read_call`] gave a screen the
/// reading of and no signature has used, oldest first (O58):
/// [`kc_secp256k1_sign_digest`] signs by an ICP key only such a digest —
/// exactly, and once.
static SHOWN_ICP: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_icp() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_ICP.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Kaspa request [`kc_kaspa_read_transaction`] gave a
/// screen the reading of and no signature has used, oldest first (O58):
/// [`kc_kaspa_sign_transaction`] signs only such a request — exactly, and
/// once.
static SHOWN_KASPA: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_kaspa() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_KASPA.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Zcash request [`kc_zcash_read_transaction`] gave a
/// screen the reading of and no signature has used, oldest first:
/// [`kc_zcash_sign_transaction`] signs only such a request — exactly, and
/// once.
static SHOWN_ZCASH: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_zcash() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_ZCASH.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The BLAKE2b-256 of the CID of every Filecoin message
/// [`kc_filecoin_read_message`] gave a screen the reading of and no signature
/// has used, oldest first (O58): [`kc_secp256k1_sign_digest`] signs by a
/// Filecoin key only such a digest — exactly, and once.
static SHOWN_FILECOIN: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_filecoin() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_FILECOIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Asset Hub signing payload
/// [`kc_polkadot_read_transaction`] gave a screen the reading of, **with the
/// public key it was read for**, no signature having used it, oldest first
/// (O58): [`kc_ed25519_sign`] signs by a Polkadot key only a message one of
/// them is of, by that key — exactly, and once.
static SHOWN_POLKADOT: Mutex<VecDeque<([u8; 32], [u8; 32])>> = Mutex::new(VecDeque::new());

fn shown_polkadot() -> MutexGuard<'static, VecDeque<([u8; 32], [u8; 32])>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_POLKADOT.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every MultiversX signing JSON
/// [`kc_multiversx_read_transaction`] gave a screen the reading of and no
/// signature has used, oldest first (O58): [`kc_ed25519_sign`] signs by a
/// MultiversX key only a message one of them is of — exactly, and once.
static SHOWN_MULTIVERSX: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_multiversx() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_MULTIVERSX.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The watermarked BLAKE2b-256 of every Tezos operation group
/// [`kc_tezos_read_operation`] gave a screen the reading of and no signature
/// has used, oldest first (O58): the 32 bytes [`kc_ed25519_sign`] signs by a
/// Tezos key — exactly, and once.
static SHOWN_TEZOS: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_tezos() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_TEZOS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Algorand transaction message
/// [`kc_algorand_read_transaction`] gave a screen the reading of and no
/// signature has used, oldest first (O58): [`kc_ed25519_sign`] signs by an
/// Algorand key only a message one of them is of — exactly, and once.
static SHOWN_ALGORAND: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_algorand() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_ALGORAND.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The BLAKE2b-256 of every Sui intent message [`kc_sui_read_transaction`]
/// gave a screen the reading of and no signature has used, oldest first
/// (O58): the 32 bytes [`kc_ed25519_sign`] signs by a Sui key — exactly, and
/// once.
static SHOWN_SUI: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_sui() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_SUI.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SHA-256 of every Aptos or Movement signing message
/// [`kc_aptos_read_transaction`] gave a screen the reading of and no
/// signature has used, oldest first (O58): [`kc_ed25519_sign`] signs by such a
/// key only a message one of them is of — exactly, and once.
static SHOWN_APTOS: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_aptos() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_APTOS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The hash of every NEAR transaction [`kc_near_read_transaction`] gave a
/// screen the reading of and no signature has used, oldest first (O58): the
/// 32 bytes [`kc_ed25519_sign`] signs by a NEAR key — exactly, and once.
static SHOWN_NEAR: Mutex<VecDeque<[u8; 32]>> = Mutex::new(VecDeque::new());

fn shown_near() -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_NEAR.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The hash of every Starknet transaction [`kc_starknet_read_transaction`]
/// gave a screen the reading of, with the Stark public key it was held to,
/// no signature having used it, oldest first (O58): [`kc_starknet_sign`]
/// signs by a key at `m/44'/9004'` only such a hash, by that key, once.
static SHOWN_STARKNET: Mutex<VecDeque<([u8; 32], [u8; 32])>> = Mutex::new(VecDeque::new());

fn shown_starknet() -> MutexGuard<'static, VecDeque<([u8; 32], [u8; 32])>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_STARKNET.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The BLAKE2b-256 of every Cardano transaction body
/// [`kc_cardano_read_transaction`] gave a screen the reading of, **with each
/// payment key hash the reading named as a signer**, one entry a signer, no
/// signature having used it, oldest first (O58): [`kc_cardano_sign`] signs by
/// a key at `m/1852'/1815'` only such a hash, and only as a signer named for
/// it — once (the owner's decision of 5 November 2026).
static SHOWN_CARDANO: Mutex<VecDeque<([u8; 32], [u8; 28])>> = Mutex::new(VecDeque::new());

fn shown_cardano() -> MutexGuard<'static, VecDeque<([u8; 32], [u8; 28])>> {
    // Only pushes, a removal and a reinsertion, none of which panics.
    SHOWN_CARDANO.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Keeps [entry] in [table] as given to a screen: once, the oldest dropped
/// when it is full.
fn keep_shown<T: PartialEq>(table: &mut VecDeque<T>, entry: T) {
    table.retain(|kept| *kept != entry);
    if table.len() == MAX_SHOWN {
        table.pop_front();
    }
    table.push_back(entry);
}

/// Starts at 1 and only counts up: 0 is never a handle, and a closed handle is
/// never issued again.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn sessions() -> MutexGuard<'static, BTreeMap<u64, Session>> {
    // A panic while the lock was held cannot have left the table half-changed:
    // its only writes are one insert, one remove and a clear, none of which
    // panics, and the code that can panic only reads a seed. So a poisoned
    // lock is taken anyway — refusing would also refuse `kc_close`, which is
    // what erases a seed.
    SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs [use_seed] over [handle]'s seed **with the table's lock held for the
/// whole of it** — the derivation and the signature, or the derivation of an
/// export, a comparison or Icarus's master — in every one of the twenty
/// calls that read what a session holds.
///
/// That is the lock model (`docs/RUST_KEY_CORE_DESIGN.md#phase-5a`): a
/// `kc_close` that arrives mid-call waits for the call, so once it has
/// returned nothing is still using the seed it erased, and no seed is copied
/// out of the table to be used after the lock is let go. Calls from several
/// threads — two Dart isolates — take turns, one call at a time.
fn with_held<T>(
    handle: u64,
    use_held: impl FnOnce(&Held) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    let sessions = sessions();
    let session = sessions.get(&handle).ok_or(Refusal::Handle)?;
    #[cfg(test)]
    tests::inside_the_lock();
    use_held(&session.held)
}

/// [`with_held`] for a call only a phrase answers: Cardano, Starknet and a
/// chain code. A one-key session is [`Refusal::Kind`].
fn with_seed<T>(
    handle: u64,
    use_seed: impl FnOnce(&[u8]) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_phrase(handle, |phrase| use_seed(&phrase.seed[..]))
}

/// [`with_held`] for a call only a phrase answers, given the whole of it — the
/// seed and the entropy.
fn with_phrase<T>(
    handle: u64,
    use_phrase: impl FnOnce(&Phrase) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_held(handle, |held| match held {
        Held::Seed(phrase) => use_phrase(phrase),
        Held::Secp256k1(_)
        | Held::BitcoinKey(_)
        | Held::EvmKey(_)
        | Held::Ed25519(_)
        | Held::SolanaKey(_)
        | Held::StellarKey(_)
        | Held::SuiKey(_)
        | Held::AlgorandKey(_)
        | Held::TezosKey(_)
        | Held::TronKey(_)
        | Held::FilecoinKey(_)
        | Held::IcpKey(_)
        | Held::KaspaKey(_)
        | Held::ZcashKey(_)
        | Held::XrplKey(_)
        | Held::CosmosKey(_) => Err(Refusal::Kind),
    })
}

/// A one-key session is read at `m` alone, as its key itself (O22): any
/// other path is [`Refusal::Path`], so no path can be taken for a
/// derivation that did not happen.
fn at_root(path: &DerivationPath) -> Result<(), Refusal> {
    if path.iter().next().is_none() { Ok(()) } else { Err(Refusal::Path) }
}

/// The secp256k1 key at [path] in [handle]'s session: derived from its seed,
/// or a one-key session's own key at `m`.
fn with_secp256k1<T>(
    handle: u64,
    path: &DerivationPath,
    use_key: impl FnOnce(&keys::DerivedKey) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_held(handle, |held| use_key(&secp256k1_at(held, path)?))
}

/// The secp256k1 key at [path] in [held], inside [`with_held`]'s lock.
fn secp256k1_at(held: &Held, path: &DerivationPath) -> Result<keys::DerivedKey, Refusal> {
    match held {
        Held::Seed(phrase) => keys::derive(&phrase.seed[..], path),
        Held::Secp256k1(key)
        | Held::BitcoinKey(key)
        | Held::EvmKey(key)
        | Held::TronKey(key)
        | Held::FilecoinKey(key)
        | Held::IcpKey(key)
        | Held::KaspaKey(key)
        | Held::ZcashKey(key)
        | Held::XrplKey(key)
        | Held::CosmosKey(key) => {
            at_root(path)?;
            keys::secp256k1_key(key)
        }
        Held::Ed25519(_)
        | Held::SolanaKey(_)
        | Held::StellarKey(_)
        | Held::SuiKey(_)
        | Held::AlgorandKey(_)
        | Held::TezosKey(_) => Err(Refusal::Kind),
    }
}

/// [`with_secp256k1`] for a bare digest's signature, which neither a key of
/// the Bitcoin family (O37), an EVM key (O43), a TRON key (O58) nor an XRP
/// Ledger key (O59) gives: a phrase's key at a Bitcoin, Litecoin, Dogecoin or
/// Bitcoin Cash path ([`keys::is_bitcoin_family`]), at an EVM path
/// ([`keys::is_evm`]), a TRON path ([`keys::is_tron`]), an XRP path
/// ([`keys::is_xrpl`]), a Cosmos zone's ([`keys::is_cosmos`]) or Kaspa's
/// ([`keys::is_kaspa`]), or a key opened as any of them, or a Zcash path
/// ([`keys::is_zcash`]), is [`Refusal::TransactionOnly`] — such a key signs
/// only through the entries that read what they sign; a TRON or a Cosmos
/// zone's key through [`kc_secp256k1_sign_digest`]'s own gate, a Kaspa key
/// through [`kc_kaspa_sign_transaction`], a Zcash key through
/// [`kc_zcash_sign_transaction`].
fn with_digest_key<T>(
    handle: u64,
    path: &DerivationPath,
    use_key: impl FnOnce(&keys::DerivedKey) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_held(handle, |held| {
        digest_key_allowed(held, path)?;
        use_key(&secp256k1_at(held, path)?)
    })
}

/// [`with_digest_key`]'s refusal, inside [`with_held`]'s lock: a key that
/// signs no bare digest is [`Refusal::TransactionOnly`].
fn digest_key_allowed(held: &Held, path: &DerivationPath) -> Result<(), Refusal> {
    {
        match held {
            Held::BitcoinKey(_)
            | Held::EvmKey(_)
            | Held::TronKey(_)
            | Held::FilecoinKey(_)
            | Held::IcpKey(_)
            | Held::KaspaKey(_)
            | Held::ZcashKey(_)
            | Held::XrplKey(_)
            | Held::CosmosKey(_) => {
                return Err(Refusal::TransactionOnly);
            }
            Held::Seed(_)
                if keys::is_bitcoin_family(path)
                    || keys::is_evm(path)
                    || keys::is_tron(path)
                    || keys::is_filecoin(path)
                    || keys::is_icp(path)
                    || keys::is_kaspa(path)
                    || keys::is_zcash(path)
                    || keys::is_xrpl(path)
                    || keys::is_cosmos(path) =>
            {
                return Err(Refusal::TransactionOnly);
            }
            _ => {}
        }
        Ok(())
    }
}

/// [`with_secp256k1`] for an EVM message's signature (2e): the key the
/// message entries sign with. A key of the Bitcoin family signs no message
/// either, as [`with_digest_key`] refuses it (O37), and no TRON key (O58).
fn with_message_key<T>(
    handle: u64,
    path: &DerivationPath,
    use_key: impl FnOnce(&keys::DerivedKey) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_held(handle, |held| {
        match held {
            Held::BitcoinKey(_)
            | Held::TronKey(_)
            | Held::FilecoinKey(_)
            | Held::IcpKey(_)
            | Held::KaspaKey(_)
            | Held::ZcashKey(_)
            | Held::XrplKey(_)
            | Held::CosmosKey(_) => {
                return Err(Refusal::TransactionOnly);
            }
            Held::Seed(_)
                if keys::is_bitcoin_family(path)
                    || keys::is_tron(path)
                    || keys::is_filecoin(path)
                    || keys::is_icp(path)
                    || keys::is_kaspa(path)
                    || keys::is_zcash(path)
                    || keys::is_xrpl(path)
                    || keys::is_cosmos(path) =>
            {
                return Err(Refusal::TransactionOnly);
            }
            _ => {}
        }
        use_key(&secp256k1_at(held, path)?)
    })
}

/// The key at [path] in [held] that signs an EVM transaction, inside
/// [`with_held`]'s lock: a key of the Bitcoin family is not an EVM key (O37),
/// nor is a TRON, a Filecoin, an ICP, a Kaspa, an XRP Ledger or a Cosmos
/// zone's key opened as one (O58) — [`Refusal::Kind`]. The reading
/// [`kc_evm_read_transaction`] gives is held to this key's address, and
/// [`kc_secp256k1_sign_evm_transaction`] signs by it.
fn evm_transaction_key(held: &Held, path: &DerivationPath) -> Result<keys::DerivedKey, Refusal> {
    match held {
        Held::BitcoinKey(_)
        | Held::TronKey(_)
        | Held::FilecoinKey(_)
        | Held::IcpKey(_)
        | Held::KaspaKey(_)
        | Held::ZcashKey(_)
        | Held::XrplKey(_)
        | Held::CosmosKey(_) => Err(Refusal::Kind),
        _ => secp256k1_at(held, path),
    }
}

/// The ed25519 key at [path] in [handle]'s session: derived from its seed by
/// SLIP-10, or a one-key session's own key at `m`.
fn with_ed25519<T>(
    handle: u64,
    path: &DerivationPath,
    use_key: impl FnOnce(&keys::Ed25519Key) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    with_held(handle, |held| use_key(&ed25519_at(held, path)?))
}

/// The ed25519 key at [path] in [held], inside [`with_held`]'s lock.
fn ed25519_at(held: &Held, path: &DerivationPath) -> Result<keys::Ed25519Key, Refusal> {
    match held {
        Held::Seed(phrase) => keys::derive_ed25519(&phrase.seed[..], path),
        Held::Ed25519(key)
        | Held::SolanaKey(key)
        | Held::StellarKey(key)
        | Held::SuiKey(key)
        | Held::AlgorandKey(key)
        | Held::TezosKey(key) => {
            at_root(path)?;
            Ok(keys::ed25519_key(key))
        }
        Held::Secp256k1(_)
        | Held::BitcoinKey(_)
        | Held::EvmKey(_)
        | Held::TronKey(_)
        | Held::FilecoinKey(_)
        | Held::IcpKey(_)
        | Held::KaspaKey(_)
        | Held::ZcashKey(_)
        | Held::XrplKey(_)
        | Held::CosmosKey(_) => Err(Refusal::Kind),
    }
}

/// The public half of the ed25519 key at [path] below [handle]'s seed — for a
/// reading held to a key only a phrase has (Polkadot, TON): a one-key session
/// is [`Refusal::Kind`], a level not hardened [`Refusal::Path`].
fn ed25519_public_at_seed(handle: u64, path: &DerivationPath) -> Result<[u8; 32], Refusal> {
    keys::require_hardened(path)?;
    with_seed(handle, |seed| Ok(keys::ed25519_public_key(&keys::derive_ed25519(seed, path)?)))
}

/// The ed25519 keys that sign only what the core read for a screen (O58).
#[derive(Clone, Copy, PartialEq)]
enum Ed25519Gate {
    /// A Solana key — a phrase's at `m/44'/501'`, or one opened as
    /// [`KC_CURVE_ED25519_SOLANA`]: a message read, by its SHA-256.
    Solana,
    /// A Stellar key — a phrase's at `m/44'/148'`, or one opened as
    /// [`KC_CURVE_ED25519_STELLAR`]: a transaction's hash read, itself.
    Stellar,
    /// A NEAR key — a phrase's at `m/44'/397'`: a transaction's hash read,
    /// itself. NEAR has no imported key.
    Near,
    /// An Aptos or Movement key — a phrase's at `m/44'/637'`: a signing
    /// message read, by its SHA-256. Neither network has an imported key.
    Aptos,
    /// A Sui key — a phrase's at `m/44'/784'`, or one opened as
    /// [`KC_CURVE_ED25519_SUI`]: an intent message's BLAKE2b-256 read, itself.
    Sui,
    /// An Algorand key — a phrase's at `m/44'/283'`, or one opened as
    /// [`KC_CURVE_ED25519_ALGORAND`]: a transaction's message read, by its
    /// SHA-256.
    Algorand,
    /// A Tezos key — a phrase's at `m/44'/1729'`, or one opened as
    /// [`KC_CURVE_ED25519_TEZOS`]: a group's watermarked BLAKE2b-256 read,
    /// itself.
    Tezos,
    /// A MultiversX key — a phrase's at `m/44'/508'`: a transaction's signing
    /// JSON read, by its SHA-256. MultiversX has no imported key.
    Multiversx,
    /// A Polkadot key — a phrase's at `m/44'/354'`: an Asset Hub signing
    /// payload read, by its SHA-256. Polkadot has no imported key.
    Polkadot,
    /// A TON key — a phrase's at `m/44'/607'`: the 32-byte representation
    /// hash of a wallet v4R2 signing message read. TON has no imported key.
    Ton,
}

/// A reading [`kc_ed25519_sign`] took from its gate's table, to give back if
/// the signature is not made: the bytes read — with the key they were read
/// for, a Polkadot or a TON reading.
enum Taken {
    Solana([u8; 32]),
    Stellar([u8; 32]),
    Near([u8; 32]),
    Aptos([u8; 32]),
    Sui([u8; 32]),
    Algorand([u8; 32]),
    Tezos([u8; 32]),
    Multiversx([u8; 32]),
    Polkadot(([u8; 32], [u8; 32])),
    Ton(([u8; 32], [u8; 32])),
}

/// The reading [gate]'s table holds of [message] — for a Polkadot or a TON
/// key, of [message] by [key] — taken out for its signature, or
/// [`Refusal::Unshown`]. Inside [`with_held`]'s lock.
fn take_shown(
    gate: Ed25519Gate,
    message: &[u8],
    key: &Result<keys::Ed25519Key, Refusal>,
) -> Result<Taken, Refusal> {
    fn take<T: PartialEq>(mut table: MutexGuard<'static, VecDeque<T>>, entry: T) -> Result<T, Refusal> {
        let at = table.iter().position(|kept| *kept == entry).ok_or(Refusal::Unshown)?;
        table.remove(at);
        Ok(entry)
    }
    // A gate whose reading is a hash signs exactly 32 bytes.
    let hash = || -> Result<[u8; 32], Refusal> { message.try_into().map_err(|_| Refusal::Unshown) };
    let public = || key.as_ref().map(keys::ed25519_public_key).map_err(|refusal| *refusal);
    Ok(match gate {
        Ed25519Gate::Solana => Taken::Solana(take(shown_solana(), solana::message_id(message))?),
        Ed25519Gate::Stellar => Taken::Stellar(take(shown_stellar(), hash()?)?),
        Ed25519Gate::Near => Taken::Near(take(shown_near(), hash()?)?),
        Ed25519Gate::Aptos => Taken::Aptos(take(shown_aptos(), solana::message_id(message))?),
        Ed25519Gate::Sui => Taken::Sui(take(shown_sui(), hash()?)?),
        Ed25519Gate::Algorand => Taken::Algorand(take(shown_algorand(), solana::message_id(message))?),
        Ed25519Gate::Tezos => Taken::Tezos(take(shown_tezos(), hash()?)?),
        Ed25519Gate::Multiversx => Taken::Multiversx(take(shown_multiversx(), solana::message_id(message))?),
        Ed25519Gate::Polkadot => {
            Taken::Polkadot(take(shown_polkadot(), (solana::message_id(message), public()?))?)
        }
        Ed25519Gate::Ton => Taken::Ton(take(shown_ton(), (hash()?, public()?))?),
    })
}

/// [taken] back in its table, first, as a reading no signature used.
fn give_back(taken: Taken) {
    match taken {
        Taken::Solana(id) => shown_solana().push_front(id),
        Taken::Stellar(id) => shown_stellar().push_front(id),
        Taken::Near(id) => shown_near().push_front(id),
        Taken::Aptos(id) => shown_aptos().push_front(id),
        Taken::Sui(id) => shown_sui().push_front(id),
        Taken::Algorand(id) => shown_algorand().push_front(id),
        Taken::Tezos(id) => shown_tezos().push_front(id),
        Taken::Multiversx(id) => shown_multiversx().push_front(id),
        Taken::Polkadot(entry) => shown_polkadot().push_front(entry),
        Taken::Ton(entry) => shown_ton().push_front(entry),
    }
}

/// Which gate [handle]'s ed25519 key at [path] signs through, or None for a
/// key that signs as before.
/// **Decided inside the same hold of the session's lock as the signature**:
/// a close between the two would refuse a call that had already reached the
/// key.
fn ed25519_gate_of(held: &Held, path: &DerivationPath) -> Option<Ed25519Gate> {
    {
        match held {
            Held::SolanaKey(_) => Some(Ed25519Gate::Solana),
            Held::StellarKey(_) => Some(Ed25519Gate::Stellar),
            Held::SuiKey(_) => Some(Ed25519Gate::Sui),
            Held::AlgorandKey(_) => Some(Ed25519Gate::Algorand),
            Held::TezosKey(_) => Some(Ed25519Gate::Tezos),
            Held::Seed(_) if keys::is_solana(path) => Some(Ed25519Gate::Solana),
            Held::Seed(_) if keys::is_stellar(path) => Some(Ed25519Gate::Stellar),
            Held::Seed(_) if keys::is_near(path) => Some(Ed25519Gate::Near),
            Held::Seed(_) if keys::is_aptos(path) => Some(Ed25519Gate::Aptos),
            Held::Seed(_) if keys::is_sui(path) => Some(Ed25519Gate::Sui),
            Held::Seed(_) if keys::is_algorand(path) => Some(Ed25519Gate::Algorand),
            Held::Seed(_) if keys::is_tezos(path) => Some(Ed25519Gate::Tezos),
            Held::Seed(_) if keys::is_multiversx(path) => Some(Ed25519Gate::Multiversx),
            Held::Seed(_) if keys::is_polkadot(path) => Some(Ed25519Gate::Polkadot),
            Held::Seed(_) if keys::is_ton(path) => Some(Ed25519Gate::Ton),
            _ => None,
        }
    }
}

/// A table of readings a screen was given.
type Readings = fn() -> MutexGuard<'static, VecDeque<[u8; 32]>>;

/// The readings [handle]'s key at [path] signs its digests under, where it
/// is a key that signs a digest only of what the core read for a screen (O58):
/// a TRON key's — a phrase's at `m/44'/195'`, or one opened as
/// [`KC_CURVE_SECP256K1_TRON`] — or a Cosmos zone's, a phrase's at
/// `m/44'/118'` or `m/44'/459'` or one opened as
/// [`KC_CURVE_SECP256K1_COSMOS`]. None for any other key.
/// Decided inside the same hold of the session's lock as the signature, as
/// [`ed25519_gate_of`] is.
fn digest_readings_of(held: &Held, path: &DerivationPath) -> Option<Readings> {
    match held {
        Held::TronKey(_) => Some(shown_tron as Readings),
        Held::CosmosKey(_) => Some(shown_cosmos as Readings),
        Held::FilecoinKey(_) => Some(shown_filecoin as Readings),
        Held::IcpKey(_) => Some(shown_icp as Readings),
        Held::Seed(_) if keys::is_tron(path) => Some(shown_tron as Readings),
        Held::Seed(_) if keys::is_filecoin(path) => Some(shown_filecoin as Readings),
        Held::Seed(_) if keys::is_icp(path) => Some(shown_icp as Readings),
        Held::Seed(_) if keys::is_cosmos(path) => Some(shown_cosmos as Readings),
        _ => None,
    }
}

/// Whether [handle]'s key at [path] is an XRP Ledger key — a phrase's at
/// `m/44'/144'`, or one opened as [`KC_CURVE_SECP256K1_XRP`] — the only kind
/// [`kc_xrpl_sign_transaction`] signs with (O59).
fn is_xrpl_key(handle: u64, path: &DerivationPath) -> Result<bool, Refusal> {
    with_held(handle, |held| {
        Ok(match held {
            Held::XrplKey(_) => true,
            Held::Seed(_) => keys::is_xrpl(path),
            _ => false,
        })
    })
}

/// Runs [call] with a panic turned into a code, then writes zeros over the
/// stack it used.
///
/// The zeros are written from this frame, and [call] runs in [`below`]'s, so
/// every secret the call or a library held lies under the zeros.
fn guarded(call: impl FnOnce() -> Result<(), Refusal>) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| below(call)));
    scrub::stack();
    match outcome {
        Ok(Ok(())) => KC_OK,
        Ok(Err(refusal)) => refusal.code(),
        Err(_) => KC_ERR_INTERNAL,
    }
}

/// [call], in a frame of its own under [`guarded`]'s.
///
/// **Not inlined, and that is the whole of it.** An optimised build inlines a
/// `catch_unwind` body into the function that called it, and the entry
/// point's own frame is above the zeros, not under them: a release build of
/// `kc_secp256k1_public_key` left a key of the derivation there, which
/// `tests::sign_public_key_and_export_leave_no_key_on_the_stack` found and a
/// debug build did not show.
#[inline(never)]
fn below(call: impl FnOnce() -> Result<(), Refusal>) -> Result<(), Refusal> {
    call()
}

/// [len] bytes at [data], or a refusal for a null pointer.
///
/// # Safety
/// A non-null [data] must point to [len] readable bytes that stay unchanged
/// for the call.
unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8], Refusal> {
    if data.is_null() || len > isize::MAX as usize {
        return Err(Refusal::Argument);
    }
    Ok(unsafe { core::slice::from_raw_parts(data, len) })
}

/// Refuses an output buffer that is null or not exactly [expected] bytes,
/// before any work is done for it.
fn check_out(out: *mut u8, out_len: usize, expected: usize) -> Result<(), Refusal> {
    if out.is_null() || out_len != expected {
        return Err(Refusal::Argument);
    }
    Ok(())
}

/// Copies [bytes] to [out], already checked by [`check_out`].
///
/// # Safety
/// [out] must point to `bytes.len()` writable bytes. `copy`, not
/// `copy_nonoverlapping`: nothing stops a caller passing one buffer as both an
/// input and the output, and every input has been read by the time this runs.
unsafe fn write_out(out: *mut u8, bytes: &[u8]) {
    unsafe { core::ptr::copy(bytes.as_ptr(), out, bytes.len()) };
}

/// The version of this ABI; see [`KC_ABI_VERSION`].
#[unsafe(no_mangle)]
pub extern "C" fn kc_abi_version() -> u32 {
    KC_ABI_VERSION
}

/// Opens [phrase] (UTF-8, `phrase_len` bytes) and writes its handle to
/// [out_handle].
///
/// The phrase is read, never kept: it becomes the seed, and the seed stays
/// here. [out_handle] is set to 0 before anything else, so a refused phrase
/// leaves no handle — not even one from an earlier call.
///
/// # Safety
/// [phrase] must point to `phrase_len` readable bytes and [out_handle] to a
/// writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_open(
    phrase: *const u8,
    phrase_len: usize,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_handle.write_unaligned(0) };
    guarded(|| {
        let phrase = unsafe { input(phrase, phrase_len) }?;
        let (seed, entropy) = keys::phrase_secrets(phrase)?;
        unsafe { issue_phrase(&seed, entropy, out_handle) };
        Ok(())
    })
}

/// Opens the phrase sealed in [sealed] under [key] and writes its handle to
/// [out_handle] — phase 6a (`docs/RUST_KEY_CORE_DESIGN.md#phase-6`).
///
/// [sealed] is the record as the wallet stores it: AES-256-GCM, the 12-byte
/// nonce in front, then the ciphertext and its 16-byte tag, no associated
/// data. [key] is the 32 bytes it is sealed under.
///
/// **The phrase is opened here and never handed back.** It is decrypted into
/// memory this call owns, read as [`kc_open`] reads a phrase, and written over
/// before the call returns; the seed stays, as from [`kc_open`]. The tag is
/// checked before anything is decrypted. A wrong key, a changed byte or a
/// record too short to hold a nonce and a tag is [`KC_ERR_SEAL`], never read
/// as a phrase; a record that opens to something other than a phrase in the
/// form the wallet stores is [`KC_ERR_PHRASE`], as [`kc_open`] refuses it. A
/// key that is not 32 bytes is [`KC_ERR_ARGUMENT`].
///
/// The caller's key is read where it lies and is the caller's to erase. As
/// with [`kc_open`], [out_handle] is set to 0 before anything else.
///
/// # Safety
/// [sealed] must point to `sealed_len` readable bytes, [key] to `key_len`
/// readable ones and [out_handle] to a writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_open_sealed(
    sealed: *const u8,
    sealed_len: usize,
    key: *const u8,
    key_len: usize,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_handle.write_unaligned(0) };
    guarded(|| {
        let key: &[u8; 32] =
            unsafe { input(key, key_len) }?.try_into().map_err(|_| Refusal::Argument)?;
        let sealed = unsafe { input(sealed, sealed_len) }?;
        let phrase = seal::open(sealed, key)?;
        // A record an older build sealed is read as the Dart code read it (O32).
        let (seed, entropy) = keys::record_phrase_secrets(&phrase)?;
        unsafe { issue_phrase(&seed, entropy, out_handle) };
        Ok(())
    })
}

/// A new session holding [seed] and [entropy], its handle written to
/// [out_handle].
///
/// # Safety
/// [out_handle] must point to a writable `u64`.
unsafe fn issue_phrase(seed: &[u8; 64], entropy: keys::Entropy, out_handle: *mut u64) {
    let mut held = Box::new(Phrase { seed: Zeroizing::new([0u8; 64]), entropy });
    held.seed.copy_from_slice(seed);
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    sessions().insert(handle, Session { held: Held::Seed(held) });
    unsafe { out_handle.write_unaligned(handle) };
}

/// Writes 1 to [out_matches] when [candidate] (UTF-8, `candidate_len` bytes)
/// is the phrase [handle] was opened on, and 0 when it is another — phase 6c,
/// the question a split backup's restore asks of the open wallet.
///
/// **By the seeds, compared in constant time**: the candidate is read as
/// [`kc_open`] reads a phrase, its seed computed and compared with the
/// session's, and nothing of it is kept. A candidate that is not a phrase in
/// the form the wallet stores is [`KC_ERR_PHRASE`], before the session is
/// looked at; a one-key session is [`KC_ERR_KIND`]. [out_matches] is set to 0
/// before anything else.
///
/// # Safety
/// [candidate] must point to `candidate_len` readable bytes and [out_matches]
/// to a writable byte.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_matches_phrase(
    handle: u64,
    candidate: *const u8,
    candidate_len: usize,
    out_matches: *mut u8,
) -> i32 {
    if out_matches.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_matches.write(0) };
    guarded(|| {
        let candidate = unsafe { input(candidate, candidate_len) }?;
        let theirs = keys::seed_from_phrase(candidate, "")?;
        let same = with_phrase(handle, |phrase| {
            Ok(bool::from(phrase.seed[..].ct_eq(&theirs[..])))
        })?;
        unsafe { out_matches.write(u8::from(same)) };
        Ok(())
    })
}

/// The open phrase's entropy, copied out of its session so the session lock
/// is not held through Argon2id: a split backup's master secret (phase 7a).
fn phrase_entropy(handle: u64) -> Result<slip39::Secret, Refusal> {
    with_phrase(handle, |phrase| Ok(Zeroizing::new(phrase.entropy.as_bytes().to_vec())))
}

/// Splits the entropy of the phrase [handle] was opened on into [count]
/// SLIP-39 shares, [threshold] of which restore it, and seals each under
/// [password] — phase 7a (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`).
///
/// **What leaves is sealed.** [out] receives, as JSON, one object per share
/// in member order — `set`, `g`, `m`, `t`, `salt`, `ct`, the body
/// `SealedShare` writes for version 4 (`labelBoundVersion`) less what the
/// caller already holds — and only the share at [paper_index] carries its
/// words, under `w`, for the screen a person writes them down from. 255 is
/// no paper share. [labels] is JSON: `bid` (32 lowercase hex digits, or
/// null), `at` (the date as the app writes it) and Argon2id's `m`, `t` and
/// `p`, within `ShareKdf.fromJson`'s bounds; [password] is its NFC UTF-8
/// bytes. One group, extendable, no SLIP-39 passphrase, as
/// `WalletShares.split` makes them; the coefficients, each salt and each
/// nonce from the operating system (O62).
///
/// An arrangement `ShareBackup` does not offer (a threshold below 2, above
/// [count], or more than 16 shares), a [paper_index] past [count], or labels
/// out of bounds are [`KC_ERR_ARGUMENT`], before anything is split; a
/// one-key session is [`KC_ERR_KIND`]. The JSON's length is written to
/// [out_len]; when [out_cap] is less, [`KC_ERR_BUFFER`] — and the shares made
/// for that call are gone: ask with room for 16 (64 KiB).
///
/// # Safety
/// [password] and [labels] must point to their lengths of readable bytes,
/// [out] to `out_cap` writable ones (or be null) and [out_len] to a writable
/// `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_slip39_backup(
    handle: u64,
    threshold: u8,
    count: u8,
    paper_index: u8,
    password: *const u8,
    password_len: usize,
    labels: *const u8,
    labels_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_len.write_unaligned(0) };
    guarded(|| {
        let password = unsafe { input(password, password_len) }?;
        let labels: serde_json::Value =
            serde_json::from_slice(unsafe { input(labels, labels_len) }?).map_err(|_| Refusal::Argument)?;
        if threshold < 2 || threshold > count || usize::from(count) > slip39::MAX_SHARE_COUNT {
            return Err(Refusal::Argument);
        }
        if paper_index != 255 && paper_index >= count {
            return Err(Refusal::Argument);
        }
        let number = |k: &str| labels.get(k).and_then(serde_json::Value::as_u64).and_then(|n| u32::try_from(n).ok());
        let kdf = share_seal::Kdf::checked(
            number("m").ok_or(Refusal::Argument)?,
            number("t").ok_or(Refusal::Argument)?,
            number("p").ok_or(Refusal::Argument)?,
        )
        .ok_or(Refusal::Argument)?;
        let backup_id = match labels.get("bid") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(id)) => Some(id.as_str()),
            Some(_) => return Err(Refusal::Argument),
        };
        let created_at = labels.get("at").and_then(serde_json::Value::as_str).ok_or(Refusal::Argument)?;
        let labels = share_seal::Labels { backup_id, share_count: count, created_at };
        if !labels.well_formed() {
            return Err(Refusal::Argument);
        }

        let entropy = phrase_entropy(handle)?;
        let mut random = |n| slip39::os_random(n);
        let mut groups = slip39::split_secret(&entropy, 1, &[(threshold, count)], b"", 0, true, &mut random)
            .map_err(|_| Refusal::Internal)?;
        let shares = groups.pop().ok_or(Refusal::Internal)?;
        drop(entropy);

        // Written into one buffer of its final size, since a paper share's
        // words are in it.
        let mut json = Zeroizing::new(String::with_capacity(64 * 1024));
        json.push('[');
        for (i, words) in shares.iter().enumerate() {
            let sealed = share_seal::seal(words, &labels, password, kdf, &mut random).ok_or(Refusal::Internal)?;
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"set":"{}","g":{},"m":{},"t":{},"salt":"{}","ct":"{}""#,
                sealed.set_id, sealed.group_index, sealed.member_index, sealed.threshold, sealed.salt, sealed.ciphertext
            ));
            if usize::from(paper_index) == i {
                json.push_str(r#","w":""#);
                json.push_str(words);
                json.push('"');
            }
            json.push('}');
        }
        json.push(']');
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, json.as_bytes()) };
        Ok(())
    })
}

/// Writes 1 to [out_restores] when the sealed shares in [shares] — a JSON
/// list of the bodies a backup's stores hold, as `SealedShare.toJson` writes
/// them — and the typed words in [paper] (none when `paper_len` is 0) give
/// back the phrase [handle] was opened on **from every set of [threshold]**,
/// and 0 when they do not — the check `ShareBackup` owes a person before it
/// tells them they are safe (phase 7a).
///
/// Each body is opened under [password] (NFC UTF-8): Argon2id with the
/// numbers it states, held to their bounds, then AES-256-GCM, its labels held
/// to the copy sealed beside the words. One copy per member index counts, the
/// first that opens; a body that does not open, or a share that is not one,
/// counts for nothing, as in `ShareBackup._verify`. Fewer than [threshold]
/// counted, or a set that does not recombine to the session's entropy
/// (compared in constant time), is 0. Nothing of what is opened leaves: no
/// words, no entropy. A one-key session is [`KC_ERR_KIND`]; [shares] that are
/// not a JSON list, or a threshold below 2 or above 16, [`KC_ERR_ARGUMENT`].
///
/// # Safety
/// [shares], [paper] and [password] must point to their lengths of readable
/// bytes ([paper] may be null when `paper_len` is 0) and [out_restores] to a
/// writable byte.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_slip39_check(
    handle: u64,
    shares: *const u8,
    shares_len: usize,
    paper: *const u8,
    paper_len: usize,
    threshold: u8,
    password: *const u8,
    password_len: usize,
    out_restores: *mut u8,
) -> i32 {
    if out_restores.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_restores.write(0) };
    guarded(|| {
        if !(2..=slip39::MAX_SHARE_COUNT as u8).contains(&threshold) {
            return Err(Refusal::Argument);
        }
        let password = unsafe { input(password, password_len) }?;
        let bodies: serde_json::Value =
            serde_json::from_slice(unsafe { input(shares, shares_len) }?).map_err(|_| Refusal::Argument)?;
        let bodies = bodies.as_array().ok_or(Refusal::Argument)?;
        let paper = if paper_len == 0 {
            None
        } else {
            Some(core::str::from_utf8(unsafe { input(paper, paper_len) }?).map_err(|_| Refusal::Argument)?)
        };
        let entropy = phrase_entropy(handle)?;

        let mut counted: Vec<(u8, Zeroizing<String>)> = Vec::new();
        for body in bodies {
            let Some(body) = body.as_object() else { continue };
            if let Ok((words, share)) = share_seal::open(body, password) {
                if !counted.iter().any(|(m, _)| *m == share.member_index) {
                    counted.push((share.member_index, words));
                }
            }
        }
        if let Some(words) = paper {
            match slip39::decode_share(words) {
                Ok(share) => {
                    if !counted.iter().any(|(m, _)| *m == share.member_index) {
                        counted.push((share.member_index, Zeroizing::new(words.to_string())));
                    }
                }
                // A paper share that is not one: the backup does not stand.
                Err(_) => return Ok(()),
            }
        }
        let needed = usize::from(threshold);
        if counted.len() < needed {
            return Ok(());
        }
        // Every set of [threshold], not the first: `ShareBackup._verify`'s rule.
        let n = counted.len();
        let mut pick: Vec<usize> = (0..needed).collect();
        loop {
            let set: Vec<&str> = pick.iter().map(|&i| counted[i].1.as_str()).collect();
            let restores = match slip39::recover_secret(&set, b"") {
                Ok(secret) => secret.len() == entropy.len() && bool::from(secret[..].ct_eq(&entropy[..])),
                Err(_) => false,
            };
            if !restores {
                return Ok(());
            }
            // The next combination, in lexicographic order.
            let mut i = needed;
            loop {
                if i == 0 {
                    unsafe { out_restores.write(1) };
                    return Ok(());
                }
                i -= 1;
                if pick[i] < n - needed + i {
                    pick[i] += 1;
                    for j in i + 1..needed {
                        pick[j] = pick[j - 1] + 1;
                    }
                    break;
                }
            }
        }
    })
}

/// Restores a split backup in the core and opens a session on the phrase it
/// gives back, writing its handle to [out_handle] — phase 7b
/// (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`).
///
/// **`ShareBackup.restore`, here.** [shares] is a JSON list of the bodies the
/// stores hold for one backup, any version this app has written; [extra] a
/// JSON list of typed shares' words. Each body is opened under [password] (NFC
/// UTF-8); the words are the typed ones and then those opened, repeats
/// removed. How many are needed: the most any opened body says, at least
/// [min_threshold] (a paper note's), or else what the typed words say, or
/// two. Every set of that many is tried until one recombines to a phrase's
/// entropy (16 or 32 bytes), and the session is opened on it — **the phrase
/// is never text, here or across the ABI**. [out_needed] and [out_read] are
/// written how many were needed and how many distinct shares were read, for
/// the sentence a refusal is said with.
///
/// Too few read is [`KC_ERR_SHARE_PASSWORD`] when a stored copy failed its
/// tag, else [`KC_ERR_SHARE_ALTERED`] when one opened and disagreed with its
/// labels, else [`KC_ERR_SHARE`]; enough read and no set restoring is
/// [`KC_ERR_SHARE`]. A list that is not one is [`KC_ERR_ARGUMENT`].
/// [out_handle] is 0 on any refusal.
///
/// # Safety
/// [shares], [extra] and [password] must point to their lengths of readable
/// bytes, and the three outputs to writable ones.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_slip39_restore(
    shares: *const u8,
    shares_len: usize,
    extra: *const u8,
    extra_len: usize,
    min_threshold: u8,
    password: *const u8,
    password_len: usize,
    out_handle: *mut u64,
    out_needed: *mut u8,
    out_read: *mut u8,
) -> i32 {
    if out_handle.is_null() || out_needed.is_null() || out_read.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe {
        out_handle.write_unaligned(0);
        out_needed.write(0);
        out_read.write(0);
    }
    guarded(|| {
        let password = unsafe { input(password, password_len) }?;
        let bodies: serde_json::Value =
            serde_json::from_slice(unsafe { input(shares, shares_len) }?).map_err(|_| Refusal::Argument)?;
        let bodies = bodies.as_array().ok_or(Refusal::Argument)?;
        let mut typed: serde_json::Value =
            serde_json::from_slice(unsafe { input(extra, extra_len) }?).map_err(|_| Refusal::Argument)?;
        let typed = typed.as_array_mut().ok_or(Refusal::Argument)?;

        let mut words: Vec<Zeroizing<String>> = Vec::new();
        for value in typed.iter_mut() {
            match value {
                serde_json::Value::String(w) => words.push(Zeroizing::new(core::mem::take(w))),
                _ => return Err(Refusal::Argument),
            }
        }
        let typed_count = words.len();
        let mut needed = usize::from(min_threshold);
        let mut wrong_password = false;
        let mut altered = false;
        for body in bodies {
            let Some(body) = body.as_object() else { continue };
            match share_seal::open(body, password) {
                Ok((opened, share)) => {
                    needed = needed.max(usize::from(share.member_threshold));
                    words.push(opened);
                }
                Err(share_seal::OpenError::WrongPassword) => wrong_password = true,
                Err(share_seal::OpenError::Altered) => altered = true,
                Err(share_seal::OpenError::Damaged) => {}
            }
        }
        if needed == 0 {
            needed = words[..typed_count]
                .iter()
                .find_map(|w| slip39::decode_share(w).ok().map(|s| usize::from(s.member_threshold)))
                .unwrap_or(2);
        }
        // One share typed in and also read from a store is one share.
        let mut distinct: Vec<Zeroizing<String>> = Vec::new();
        for w in words {
            let normal = Zeroizing::new(w.split_whitespace().map(str::to_ascii_lowercase).collect::<Vec<_>>().join(" "));
            if !distinct.iter().any(|d| **d == *normal) {
                distinct.push(normal);
            }
        }
        unsafe {
            out_needed.write(u8::try_from(needed).unwrap_or(u8::MAX));
            out_read.write(u8::try_from(distinct.len()).unwrap_or(u8::MAX));
        }
        if needed == 0 || distinct.len() < needed {
            return Err(if wrong_password {
                Refusal::SharePassword
            } else if altered {
                Refusal::ShareAltered
            } else {
                Refusal::Share
            });
        }
        // Every set until one restores, not the first one.
        let n = distinct.len();
        let mut pick: Vec<usize> = (0..needed).collect();
        loop {
            let set: Vec<&str> = pick.iter().map(|&i| distinct[i].as_str()).collect();
            if let Ok(entropy) = slip39::recover_secret(&set, b"") {
                if let Ok((seed, kept)) = keys::entropy_secrets(&entropy) {
                    unsafe { issue_phrase(&seed, kept, out_handle) };
                    return Ok(());
                }
            }
            let mut i = needed;
            loop {
                if i == 0 {
                    return Err(Refusal::Share);
                }
                i -= 1;
                if pick[i] < n - needed + i {
                    pick[i] += 1;
                    for j in i + 1..needed {
                        pick[j] = pick[j - 1] + 1;
                    }
                    break;
                }
            }
        }
    })
}

/// Writes 1 to [out_matches] when the sessions [handle] and [other] hold one
/// phrase — by their seeds, in constant time — and 0 when they do not: phase
/// 7b's "is this backup this wallet's", asked of a session
/// [`kc_slip39_restore`] opened and the open wallet's, with no phrase on either
/// side. A one-key session is [`KC_ERR_KIND`]. [out_matches] is 0 on any
/// refusal.
///
/// # Safety
/// [out_matches] must point to a writable byte.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_matches_session(handle: u64, other: u64, out_matches: *mut u8) -> i32 {
    if out_matches.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_matches.write(0) };
    guarded(|| {
        // One session at a time: the lock is not taken twice.
        let mine = with_phrase(handle, |phrase| Ok(Zeroizing::new(*phrase.seed)))?;
        let same = with_phrase(other, |phrase| Ok(bool::from(phrase.seed[..].ct_eq(&mine[..]))))?;
        unsafe { out_matches.write(u8::from(same)) };
        Ok(())
    })
}

/// Seals the phrase [handle] was opened on under [key] (32 bytes) as the
/// wallet stores one and writes the record to [out] — phase 7b
/// (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`): the vault's record of a wallet a
/// split backup gave back in the core ([`kc_slip39_restore`]), so that phrase
/// is never text outside the core on its way to the vault either.
///
/// **The record [`kc_open_sealed`] opens**: `CryptoUtils.encryptBytes`'s
/// layout (nonce, ciphertext, tag), the phrase in the stored form —
/// lowercase words, single spaces — that the core reads back. The key is the
/// vault's, which Dart holds as it does at every unlock; the phrase is made
/// from the session's entropy here and erased.
///
/// The record's length is written to [out_len] (12 + the phrase + 16); when
/// [out_cap] is less, [`KC_ERR_BUFFER`] (ask with 256 bytes: 24 words are at
/// most 215). A key not of 32 bytes is [`KC_ERR_ARGUMENT`]; a one-key session
/// [`KC_ERR_KIND`].
///
/// # Safety
/// [key] must point to `key_len` readable bytes, [out] to `out_cap` writable
/// ones (or be null with `out_cap` 0), and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_seal_phrase(
    handle: u64,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_len.write_unaligned(0) };
    guarded(|| {
        let key: &[u8; 32] =
            unsafe { input(key, key_len) }?.try_into().map_err(|_| Refusal::Argument)?;
        let entropy = phrase_entropy(handle)?;
        let text = keys::phrase_text(&entropy)?;
        drop(entropy);
        let record = seal::seal(&text, key)?;
        drop(text);
        unsafe { out_len.write_unaligned(record.len()) };
        if out.is_null() || out_cap < record.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &record) };
        Ok(())
    })
}

/// Opens one imported key — [secret], 32 bytes on [curve] — and writes its
/// handle to [out_handle] (the owner's decision O22).
///
/// [`KC_CURVE_SECP256K1`]: the scalar, refused with [`KC_ERR_KEY`] when it is
/// zero or not below the order; [`KC_CURVE_SECP256K1_BITCOIN`] the same, for a
/// key that signs only a transaction the core reads (O37);
/// [`KC_CURVE_SECP256K1_EVM`] the same, for a key that signs only a
/// transaction, a message or typed data the core reads (O43).
/// [`KC_CURVE_ED25519`]: the key's 32-byte seed.
/// The session answers every call for its curve at the path `m` alone, as
/// the key itself; any other path is [`KC_ERR_PATH`], and a call for the
/// other curve, a chain code, Cardano or Starknet is [`KC_ERR_KIND`].
///
/// The caller's bytes are copied and are the caller's to erase. As with
/// [`kc_open`], [out_handle] is set to 0 before anything else.
///
/// # Safety
/// [secret] must point to `secret_len` readable bytes and [out_handle] to a
/// writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_open_key(
    curve: i32,
    secret: *const u8,
    secret_len: usize,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_handle.write_unaligned(0) };
    guarded(|| {
        let bytes = unsafe { input(secret, secret_len) }?;
        unsafe { issue_key(curve, bytes, out_handle) }
    })
}

/// A one-key session on [bytes] (32) for [curve], its handle written to
/// [out_handle] — [`kc_open_key`]'s body, and [`kc_open_sealed_key`]'s once
/// the record is open.
///
/// # Safety
/// [out_handle] must point to a writable `u64`.
unsafe fn issue_key(curve: i32, bytes: &[u8], out_handle: *mut u64) -> Result<(), Refusal> {
    if bytes.len() != 32 {
        return Err(Refusal::Argument);
    }
    let mut key = Box::new(Zeroizing::new([0u8; 32]));
    key.copy_from_slice(bytes);
    let held = match curve {
        KC_CURVE_SECP256K1 => {
            keys::secp256k1_key(&key)?;
            Held::Secp256k1(key)
        }
        KC_CURVE_SECP256K1_BITCOIN => {
            keys::secp256k1_key(&key)?;
            Held::BitcoinKey(key)
        }
        KC_CURVE_SECP256K1_EVM => {
            keys::secp256k1_key(&key)?;
            Held::EvmKey(key)
        }
        KC_CURVE_ED25519 => Held::Ed25519(key),
        KC_CURVE_ED25519_SOLANA => Held::SolanaKey(key),
        KC_CURVE_ED25519_STELLAR => Held::StellarKey(key),
        KC_CURVE_ED25519_SUI => Held::SuiKey(key),
        KC_CURVE_ED25519_ALGORAND => Held::AlgorandKey(key),
        KC_CURVE_ED25519_TEZOS => Held::TezosKey(key),
        KC_CURVE_SECP256K1_FILECOIN => {
            keys::secp256k1_key(&key)?;
            Held::FilecoinKey(key)
        }
        KC_CURVE_SECP256K1_ICP => {
            keys::secp256k1_key(&key)?;
            Held::IcpKey(key)
        }
        KC_CURVE_SECP256K1_KASPA => {
            keys::secp256k1_key(&key)?;
            Held::KaspaKey(key)
        }
        KC_CURVE_SECP256K1_ZCASH => {
            keys::secp256k1_key(&key)?;
            Held::ZcashKey(key)
        }
        KC_CURVE_SECP256K1_TRON => {
            keys::secp256k1_key(&key)?;
            Held::TronKey(key)
        }
        KC_CURVE_SECP256K1_XRP => {
            keys::secp256k1_key(&key)?;
            Held::XrplKey(key)
        }
        KC_CURVE_SECP256K1_COSMOS => {
            keys::secp256k1_key(&key)?;
            Held::CosmosKey(key)
        }
        _ => return Err(Refusal::Argument),
    };
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    sessions().insert(handle, Session { held });
    unsafe { out_handle.write_unaligned(handle) };
    Ok(())
}

/// Opens one imported key from its sealed record — [sealed] under [key], the
/// account key (32 bytes), in the wallet's layout (nonce, ciphertext, tag:
/// `CryptoUtils.encryptBytes`, as `VaultKeeper.sealKeyWithAccountKey` writes
/// it) — and a session on it for [curve], its handle written to [out_handle].
///
/// **The key's bytes never cross the boundary** (14 November 2026, the
/// owner's "no holes"): until now an unlock opened each imported key's record
/// in Dart and handed the bytes over. A record this key does not open, a
/// changed byte or a short record is [`KC_ERR_SEAL`]; bytes that are not a
/// key of [curve], or an unknown curve, refuse as [`kc_open_key`] does. As
/// there, [out_handle] is set to 0 before anything else.
///
/// # Safety
/// [sealed] and [key] must point to their lengths of readable bytes, and
/// [out_handle] to a writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_open_sealed_key(
    curve: i32,
    sealed: *const u8,
    sealed_len: usize,
    key: *const u8,
    key_len: usize,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return KC_ERR_ARGUMENT;
    }
    unsafe { out_handle.write_unaligned(0) };
    guarded(|| {
        let key: &[u8; 32] =
            unsafe { input(key, key_len) }?.try_into().map_err(|_| Refusal::Argument)?;
        let sealed = unsafe { input(sealed, sealed_len) }?;
        let secret = seal::open(sealed, key)?;
        unsafe { issue_key(curve, &secret, out_handle) }
    })
}

/// Closes [handle]: what it holds is overwritten with zeros, then freed.
///
/// Closing a handle that is already closed is [`KC_ERR_HANDLE`], so a caller
/// that thinks it closed something it did not finds out.
#[unsafe(no_mangle)]
pub extern "C" fn kc_close(handle: u64) -> i32 {
    guarded(|| sessions().remove(&handle).map(drop).ok_or(Refusal::Handle))
}

/// Closes every open handle and returns how many there were.
///
/// For the lock: whatever the wallet still holds, nothing is left open here.
#[unsafe(no_mangle)]
pub extern "C" fn kc_close_all() -> u64 {
    let mut sessions = sessions();
    let count = sessions.len() as u64;
    sessions.clear();
    count
}

/// Writes the public key at [path] below [handle]'s seed to [out]: 33 bytes
/// for [`KC_PUBLIC_KEY_COMPRESSED`], 65 for [`KC_PUBLIC_KEY_UNCOMPRESSED`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    format: i32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        let expected = match format {
            KC_PUBLIC_KEY_COMPRESSED => 33,
            KC_PUBLIC_KEY_UNCOMPRESSED => 65,
            _ => return Err(Refusal::Argument),
        };
        check_out(out, out_len, expected)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let public = with_secp256k1(handle, &path, |key| Ok(keys::public_key(key)))?;
        if format == KC_PUBLIC_KEY_COMPRESSED {
            unsafe { write_out(out, &public.serialize()) };
        } else {
            unsafe { write_out(out, &public.serialize_uncompressed()) };
        }
        Ok(())
    })
}

/// Signs the 32-byte [digest] with the key at [path] below [handle]'s seed and
/// writes 65 bytes to [out]: `r`, `s`, then the recovery id (0 to 3).
///
/// RFC 6979, low `s`, and checked by recovery before it is written; see
/// `keys::sign_digest`. A digest of zero or not below the order is
/// [`KC_ERR_DIGEST`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [digest] to `digest_len`
/// readable ones and [out] to `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_sign_digest(
    handle: u64,
    path: *const u8,
    path_len: usize,
    digest: *const u8,
    digest_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 65)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let digest: [u8; 32] = unsafe { input(digest, digest_len) }?
            .try_into()
            .map_err(|_| Refusal::Argument)?;
        // **A TRON key, a Cosmos zone's, a Filecoin or an ICP key signs only
        // the digest of what a screen was given the reading of, once** (O58):
        // taken for this signature, given back if it is not made. That digest
        // names the bytes read — a TRON transaction's id, a `SignDoc`'s hash,
        // the BLAKE2b-256 of a Filecoin message's CID.
        // Decided, taken and signed in one hold of the session's lock, so a
        // close waits for all of it.
        let signature = with_held(handle, |held| {
            if let Some(readings) = digest_readings_of(held, &path) {
                {
                    let mut table = readings();
                    let at = table.iter().position(|entry| *entry == digest).ok_or(Refusal::Unshown)?;
                    table.remove(at);
                }
                secp256k1_at(held, &path)
                    .and_then(|key| keys::sign_digest(&key, &digest))
                    .inspect_err(|_| readings().push_front(digest))
            } else {
                digest_key_allowed(held, &path)?;
                keys::sign_digest(&secp256k1_at(held, &path)?, &digest)
            }
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Reads [raw] — a TRON transaction's `raw_data`, the protobuf bytes whose
/// SHA-256 is its id and what a TRON signature is over — for the review
/// screen ("the screen shows what the core read", O52, O58), and writes the
/// reading to [out] as UTF-8 JSON (`src/tron.rs`): the id, the reference
/// block, the expiry, the timestamp, the fee limit, the memo, and its one
/// contract — its type and bytes, and what it does where it is a TRX transfer
/// or a contract call, a TRC-20 `transfer` named.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// SHA-256 by a TRON key may be made ([`kc_secp256k1_sign_digest`]). Asking
/// its length keeps nothing. Bytes the app's reader refuses, a field no
/// transaction this wallet signs carries, one stated twice, or no contract is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [raw] must point to `raw_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_tron_read_transaction(
    raw: *const u8,
    raw_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let raw = unsafe { input(raw, raw_len) }?;
        let json = serde_json::to_vec(&tron::reading(raw)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_tron(), tron::transaction_id(raw));
        Ok(())
    })
}

/// Reads [sign_doc] — a Cosmos SDK `SignDoc`, whose SHA-256 a
/// `SIGN_MODE_DIRECT` signature is over — for the review screen ("the screen
/// shows what the core read", O52, O58), and writes the reading to [out] as
/// UTF-8 JSON (`src/cosmos.rs`): the chain, the account number, every
/// message — a bank `MsgSend` decoded — the memo, the timeout height, each
/// signer's key, mode and sequence, and the fee.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// SHA-256 by a Cosmos zone's key may be made ([`kc_secp256k1_sign_digest`]).
/// Asking its length keeps nothing. Bytes the app's reader refuses, or a
/// field no transaction of this wallet carries, are [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [sign_doc] must point to `sign_doc_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_cosmos_read_sign_doc(
    sign_doc: *const u8,
    sign_doc_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let sign_doc = unsafe { input(sign_doc, sign_doc_len) }?;
        let json = serde_json::to_vec(&cosmos::reading(sign_doc)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_cosmos(), cosmos::sign_doc_id(sign_doc));
        Ok(())
    })
}

/// Reads [blob] — an XRP Ledger payment's signing serialisation, the bytes
/// after `STX\0` that its signature is over — for the review screen ("the
/// screen shows what the core read", O52, O58, O59), and writes the reading to
/// [out] as UTF-8 JSON (`src/xrpl.rs`): the account, the destination and its
/// tag, the amount and the fee in drops, the sequence, the expiry, the flags,
/// the signing key and the memos.
///
/// **The reading is kept, its expiry aside**: once it is written, one
/// signature by an XRP key of a payment that is [blob] in every field but
/// `LastLedgerSequence` may be made ([`kc_xrpl_sign_transaction`]). Asking its
/// length keeps nothing. Bytes that are not a payment of XRP in the fields
/// the app's module writes, each once and in canonical order, are
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [blob] must point to `blob_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_xrpl_read_transaction(
    blob: *const u8,
    blob_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let blob = unsafe { input(blob, blob_len) }?;
        let payment = xrpl::read(blob)?;
        let json = serde_json::to_vec(&xrpl::reading(&payment)).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_xrpl(), xrpl::shown_id(blob, &payment));
        Ok(())
    })
}

/// Signs [blob] — an XRP Ledger payment's signing serialisation — with the
/// XRP key at [path] below [handle] and writes `r ‖ s`, 64 bytes, low `s`, to
/// [out]: the signature over the SHA-512 half of `STX\0` and [blob], which
/// the core takes itself (O59).
///
/// **Only a payment a screen was given the reading of, once**: one an unused
/// reading of [`kc_xrpl_read_transaction`] was of in every field but
/// `LastLedgerSequence` — the expiry the module sets at the signature, four
/// ledgers ahead — or [`KC_ERR_UNSHOWN`]; and one that has an expiry, or
/// [`KC_ERR_TRANSACTION`]. Only an XRP key — a phrase's at `m/44'/144'`, or
/// one opened as [`KC_CURVE_SECP256K1_XRP`] — signs here, or [`KC_ERR_KIND`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [blob] to `blob_len`
/// readable ones and [out] to `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_xrpl_sign_transaction(
    handle: u64,
    path: *const u8,
    path_len: usize,
    blob: *const u8,
    blob_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let blob = unsafe { input(blob, blob_len) }?;
        let payment = xrpl::read(blob)?;
        if payment.last_ledger.is_none() {
            return Err(Refusal::Transaction);
        }
        if !is_xrpl_key(handle, &path)? {
            return Err(Refusal::Kind);
        }
        // A reading a screen showed, taken for this signature, and given back
        // if the signature is not made.
        let shown = xrpl::shown_id(blob, &payment);
        {
            let mut table = shown_xrpl();
            let at = table.iter().position(|entry| *entry == shown).ok_or(Refusal::Unshown)?;
            table.remove(at);
        }
        let digest = xrpl::signing_digest(blob);
        let signed = with_held(handle, |held| keys::sign_digest(&secp256k1_at(held, &path)?, &digest));
        let signature = match signed {
            Ok(signature) => signature,
            Err(refusal) => {
                shown_xrpl().push_front(shown);
                return Err(refusal);
            }
        };
        unsafe { write_out(out, &signature[..64]) };
        Ok(())
    })
}

/// Signs every input of a Bitcoin, Litecoin, Dogecoin or Bitcoin Cash
/// transaction with keys below [handle] — "sign what you see", step 2d — once
/// the core has read it and found it to be the transaction the app built
/// (`src/bitcoin.rs`, O35–O40). [request], little-endian throughout:
///
/// | Bytes | Field |
/// |---|---|
/// | 1 | flavour: 0 Bitcoin, Litecoin and Dogecoin; 1 Bitcoin Cash (`SIGHASH_FORKID`) |
/// | 4, then that many | the unsigned transaction: no script signatures, no witnesses |
/// | per input, in order | 8 the amount spent; 2 + the spent script; 1 the kind — 0 P2PKH, 1 P2PKH of the uncompressed key, 2 P2SH-P2WPKH, 3 P2WPKH, 4 P2TR key path (BIP-86); 2 + the key's path; 2 + a witness script, always empty; 4 + the previous transaction, or 0 |
/// | 2, then per output | 8 the value; 2 + the script; 1 the change kind, or `0xff` for an output that is not change; 2 + the change key's path; 2 + a witness script, always empty |
/// | 8 | the fee |
///
/// Before any key is touched: the transaction reads whole, in its unsigned
/// form; a legacy input on the Bitcoin flavour has its previous transaction,
/// which hashes to the input's txid and pays the amount to the script named
/// (O38); the outputs are the app's, each once; and the fee is the inputs'
/// sum less the outputs'. Then, under the lock, each change output is the
/// script of the wallet's key at its path, and each input spends its key's
/// script in its kind. A difference is [`KC_ERR_TRANSACTION`]; a layout that
/// does not read, or a field a kind does not take, is [`KC_ERR_ARGUMENT`].
///
/// Writes 96 bytes per input to [out], in input order: the sighash the core
/// computed — legacy `ALL`, BIP-143 `ALL`, Bitcoin Cash's `ALL|FORKID`, or
/// BIP-341 `DEFAULT` — then the signature over it: `r ‖ s` as
/// [`kc_secp256k1_sign_digest_low_r`] writes them, or a BIP-340 signature
/// with BIP-86's tweak. [out_len] must be exactly that.
///
/// **And only a request a screen was shown** (2f-3): [request] must be,
/// byte for byte, one an unused reading of [`kc_bitcoin_read_transaction`]
/// gave, or the call is [`KC_ERR_UNSHOWN`]. The reading is used by the
/// signature, and kept if the signature is refused.
///
/// # Safety
/// [request] must point to `request_len` readable bytes and [out] to
/// `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_bitcoin_sign_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = bitcoin::Request::read(bytes)?;
        check_out(out, out_len, request.inputs.len() * 96)?;
        // A reading a screen showed, taken for this signature, and given back
        // if the signature is not made.
        let shown = bitcoin::request_id(bytes);
        {
            let mut table = shown_bitcoin();
            let at = table.iter().position(|entry| *entry == shown).ok_or(Refusal::Unshown)?;
            table.remove(at);
        }
        let signed = with_held(handle, |held| {
            // An EVM, a TRON, a Filecoin, an XRP or a Cosmos key is not a
            // Bitcoin key (O43, O58).
            if matches!(
                held,
                Held::EvmKey(_)
                    | Held::TronKey(_)
                    | Held::FilecoinKey(_)
                    | Held::IcpKey(_)
                    | Held::KaspaKey(_)
                    | Held::ZcashKey(_)
                    | Held::XrplKey(_)
                    | Held::CosmosKey(_)
            ) {
                return Err(Refusal::Kind);
            }
            let key_at = |path: &[u8]| secp256k1_at(held, &keys::parse_path(path)?);
            bitcoin::sign(&request, &key_at)
        });
        let signed = match signed {
            Ok(signed) => signed,
            Err(refusal) => {
                shown_bitcoin().push_front(shown);
                return Err(refusal);
            }
        };
        unsafe { write_out(out, &signed.concat()) };
        Ok(())
    })
}

/// Reads [request] — in [`kc_bitcoin_sign_transaction`]'s layout — for the
/// review screen ("the screen shows what the core read", 2f-3), and writes the
/// reading to [out] as UTF-8 JSON: the flavour, the transaction's id, every
/// input's outpoint, amount and kind, every output in the transaction's order
/// with its value, its script and whether it is the wallet's change, the sum
/// spent and the fee.
///
/// **Held first, as the signature would hold it**: the transaction is the
/// app's, its legacy inputs' amounts read from their previous transactions,
/// the fee the inputs' sum less the outputs'; and, under the lock, each change
/// output is the script of the wallet's key at its path and each input spends
/// its key's — so "change" on the screen is the core's finding, not a claim.
/// A difference is [`KC_ERR_TRANSACTION`]. **The reading is kept**: once it
/// is written, one signature of exactly this request may be made. Asking its
/// length keeps nothing.
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [request] must point to `request_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_bitcoin_read_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = bitcoin::Request::read(bytes)?;
        with_held(handle, |held| {
            if matches!(
                held,
                Held::EvmKey(_)
                    | Held::TronKey(_)
                    | Held::FilecoinKey(_)
                    | Held::IcpKey(_)
                    | Held::KaspaKey(_)
                    | Held::ZcashKey(_)
                    | Held::XrplKey(_)
                    | Held::CosmosKey(_)
            ) {
                return Err(Refusal::Kind);
            }
            let key_at = |path: &[u8]| secp256k1_at(held, &keys::parse_path(path)?);
            bitcoin::hold_to_keys(&request, &key_at)
        })?;
        let json = serde_json::to_vec(&bitcoin::reading(&request)).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_bitcoin(), bitcoin::request_id(bytes));
        Ok(())
    })
}

/// Signs an EVM transaction with the key at [path] below [handle] — "sign what
/// you see", step 2c — and writes 65 bytes to [out], as
/// [`kc_secp256k1_sign_digest`] writes them: `r`, `s`, then the recovery id.
///
/// [unsigned] is what the signature covers: the bytes the app's transaction
/// library encoded, a legacy transaction under EIP-155 or an EIP-1559 one.
/// [expected] is the same transaction as the app built it, before that
/// library saw it, in this layout:
///
/// | Bytes | Field |
/// |---|---|
/// | 1 | the kind: 0 legacy, 2 EIP-1559 |
/// | 32 | the chain id, big-endian |
/// | 1 + 20 | 1 and the recipient, or 0 and twenty zeros for a contract's creation |
/// | 32 | the value in wei, big-endian |
/// | 32 | the gas limit |
/// | 32 | the gas price (legacy), or the priority fee (EIP-1559) |
/// | 32 | the maximum fee (EIP-1559), or zero (legacy) |
/// | the rest | the call data |
///
/// **The core reads [unsigned] and holds it to [expected] before it hashes or
/// signs anything**: a different kind, chain, recipient, value, gas limit,
/// fee or call data is [`KC_ERR_TRANSACTION`], and so is anything the app's
/// library does not write — another transaction type, non-canonical RLP, a
/// field more or less, an access list, a chain id of zero. The nonce is read
/// for its form and not held to anything: the app does not choose it. The
/// hash is Keccak-256 of [unsigned], taken here. [expected] in another layout
/// is [`KC_ERR_ARGUMENT`].
///
/// **And only a transaction a screen was shown** (2f-1b, O53): [expected] must
/// be covered by a reading [`kc_evm_read_transaction`] gave **for this key**
/// and no signature has used — the same account, kind, network, recipient,
/// value and call data, and a gas limit times price within that reading's
/// cap — or the call is [`KC_ERR_UNSHOWN`]. The key is derived, the reading
/// taken and the digest signed in one hold of the session's lock; the reading
/// is used by the signature, and kept if the signature is refused.
///
/// # Safety
/// [path], [unsigned] and [expected] must point to their lengths of readable
/// bytes, and [out] to `out_len` writable ones.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_secp256k1_sign_evm_transaction(
    handle: u64,
    path: *const u8,
    path_len: usize,
    unsigned: *const u8,
    unsigned_len: usize,
    expected: *const u8,
    expected_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 65)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let expected = evm::Expected::read(unsafe { input(expected, expected_len) }?)?;
        // Read and hashed before the lock: nothing here is secret.
        let digest = evm::transaction_digest(unsafe { input(unsigned, unsigned_len) }?, &expected)?;
        let signature = with_held(handle, |held| {
            let key = evm_transaction_key(held, &path)?;
            // A reading a screen showed for this key's account, taken for this
            // signature (O53), and given back if the signature is not made.
            let from = evm::address(&key);
            let taken = {
                let mut shown = shown();
                let at = shown.iter().position(|entry| entry.covers(&expected, from)).ok_or(Refusal::Unshown)?;
                shown.remove(at).expect("in range")
            };
            keys::sign_digest(&key, &digest).inspect_err(|_| shown().push_front(taken))
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Reads [expected] — an EVM transaction in the layout
/// [`kc_secp256k1_sign_evm_transaction`] holds a signature to — for the review
/// screen ("the screen shows what the core read", 2f-1, O49), **for the key
/// at [path] below [handle]**, and writes the reading to [out] as UTF-8 JSON:
/// `from`, that key's address, then the kind, the chain id, the recipient or
/// `null` for a contract's creation, the value, the gas limit, the fee and the
/// maximum fee, the call data, and the call as `src/calldata.rs` reads it —
/// how far it could be believed, its selector, and the approval, transfer or
/// batch it decodes to, with each call a batch carries — and `feeCap`, the
/// gas limit times the most a unit may cost, 64 bytes.
///
/// **The reading is kept with that address** (2f-1b, O53): once it is
/// written, a signature of a transaction it covers by that key may be made,
/// once ([`kc_secp256k1_sign_evm_transaction`]); no other key's. Asking its
/// length keeps nothing.
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. [expected] in another
/// layout is [`KC_ERR_ARGUMENT`]; a key that signs no EVM transaction is
/// [`KC_ERR_KIND`], as the signature would be.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [expected] to
/// `expected_len` ones, a non-null [out] to `out_cap` writable ones, and
/// [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_evm_read_transaction(
    handle: u64,
    path: *const u8,
    path_len: usize,
    expected: *const u8,
    expected_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let expected = evm::Expected::read(unsafe { input(expected, expected_len) }?)?;
        let from = with_held(handle, |held| Ok(evm::address(&evm_transaction_key(held, &path)?)))?;
        let json = serde_json::to_vec(&evm::reading(&expected, &from)).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown(), evm::Shown::of(&expected, from));
        Ok(())
    })
}

/// Signs [message] as an EVM personal message (EIP-191, version `E`) with the
/// key at [path] below [handle] — "sign what you see", step 2e — and writes
/// 65 bytes to [out], as [`kc_secp256k1_sign_digest`] writes them.
///
/// [message] is the bytes the review showed, as they are. **The core puts
/// the prefix before them and takes the hash itself**: Keccak-256 of
/// `"\x19Ethereum Signed Message:\n"`, the message's length in decimal, and
/// the message — so no digest computed elsewhere is signed on this path. A
/// key of the Bitcoin family is [`KC_ERR_TRANSACTION_ONLY`] (O37).
///
/// # Safety
/// [path] and [message] must point to their lengths of readable bytes, and
/// [out] to `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_evm_sign_personal_message(
    handle: u64,
    path: *const u8,
    path_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 65)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let digest = evm::personal_message_digest(unsafe { input(message, message_len) }?);
        let signature = with_message_key(handle, &path, |key| keys::sign_digest(key, &digest))?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Signs EIP-712 typed data with the key at [path] below [handle] — "sign
/// what you see", step 2e — and writes 65 bytes to [out], as
/// [`kc_secp256k1_sign_digest`] writes them.
///
/// [json] is the typed data the review read, as UTF-8 JSON: `types`,
/// `primaryType`, `domain` and `message`. **The core reads it and computes
/// `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))` itself**
/// (`src/eip712.rs`), with nothing secret in reach until the digest is done.
/// It takes what the app's validator takes, and no more: a document over
/// 512 KiB, or one that does not read as that validator reads it, is
/// [`KC_ERR_TYPED_DATA`] (O42, O44, O45). A key of the Bitcoin family is
/// [`KC_ERR_TRANSACTION_ONLY`] (O37).
///
/// **And only a document a screen was shown** (2f-2, O54): its digest must be
/// one an unused reading of [`kc_evm_read_typed_data`] gave **for this key**,
/// or the call is [`KC_ERR_UNSHOWN`]. The key is derived, the reading taken
/// and the digest signed in one hold of the session's lock; the reading is
/// used by the signature, and kept if the signature is refused.
///
/// # Safety
/// [path] and [json] must point to their lengths of readable bytes, and
/// [out] to `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_evm_sign_typed_data(
    handle: u64,
    path: *const u8,
    path_len: usize,
    json: *const u8,
    json_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 65)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        // Read and hashed before the lock: nothing here is secret.
        let digest = eip712::digest(unsafe { input(json, json_len) }?)?;
        let signature = with_message_key(handle, &path, |key| {
            // A reading a screen showed for this key's account, taken for this
            // signature (O54), and given back if the signature is not made.
            let entry = (digest, evm::address(key));
            {
                let mut shown = shown_typed();
                let at = shown.iter().position(|kept| *kept == entry).ok_or(Refusal::Unshown)?;
                shown.remove(at);
            }
            keys::sign_digest(key, &digest).inspect_err(|_| shown_typed().push_front(entry))
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Reads [json] — EIP-712 typed data, as [`kc_evm_sign_typed_data`] takes it
/// — for the review screen ("the screen shows what the core read", 2f-2,
/// O56), **for the key at [path] below [handle]**, and writes the reading to
/// [out] as UTF-8 JSON: `signer`, that key's address; the primary type,
/// whether the domain alone is signed, the digest, the domain and the
/// message as their declared fields — each its name, its type and its value
/// as hashed, a struct as its own fields — the places of the values the
/// page sent that are not signed (up to twenty, sorted) and their count, and
/// the permit, when the document is one of the six standard permits exactly
/// (O55): its kind, spender, tokens, amounts, whether each is unlimited
/// (2^128 or more), expirations and deadline.
///
/// **The reading is kept with that address** (O54): once it is written, a
/// signature of a document with its digest by that key may be made, once
/// ([`kc_evm_sign_typed_data`]); no other key's. Asking its length keeps
/// nothing.
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. A document
/// [`kc_evm_sign_typed_data`] would refuse is [`KC_ERR_TYPED_DATA`], and a
/// key it would refuse is refused as it would be. The key's address is taken
/// in the session's lock, and the document read after it is let go.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [json] to `json_len` ones,
/// a non-null [out] to `out_cap` writable ones, and [out_len] to a writable
/// `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_evm_read_typed_data(
    handle: u64,
    path: *const u8,
    path_len: usize,
    json: *const u8,
    json_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let signer = with_message_key(handle, &path, |key| Ok(evm::address(key)))?;
        let (reading, digest) = eip712::reading(unsafe { input(json, json_len) }?, &signer)?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_typed(), (digest, signer));
        Ok(())
    })
}

/// Writes the 32-byte private key at [path] below [handle]'s seed to [out].
///
/// **The one call that hands a secret back, and only for the export screens**,
/// where the person has asked to see the key. The caller owns those bytes
/// from here and overwrites them when the screen closes.
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_export_private_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let secret = with_secp256k1(handle, &path, |key| {
            Ok(Zeroizing::new(key.secret().to_secret_bytes()))
        })?;
        unsafe { write_out(out, &secret[..]) };
        Ok(())
    })
}

/// Writes the chain code and the compressed public key at [path] below
/// [handle]'s seed to [out]: 32 bytes, then 33 — what an account's xpub is
/// made of, so its addresses can be found without its keys. See
/// `keys::derive_with_chain_code` for why only beside a public key.
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_extended_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 65)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let extended = with_seed(handle, |seed| {
            let (key, chain_code) = keys::derive_with_chain_code(seed, &path)?;
            let mut extended = [0u8; 65];
            extended[..32].copy_from_slice(&chain_code);
            extended[32..].copy_from_slice(&keys::public_key(&key).serialize());
            Ok(extended)
        })?;
        unsafe { write_out(out, &extended) };
        Ok(())
    })
}

/// Signs the 32-byte [digest] for a Bitcoin input with the key at [path] below
/// [handle]'s seed and writes 64 bytes to [out]: `r` then `s`, low `s`, and
/// `r` ground below 2^255 as `keys::sign_digest_low_r` describes. A digest of
/// zero or not below the order is [`KC_ERR_DIGEST`].
///
/// # Safety
/// As [`kc_secp256k1_sign_digest`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_sign_digest_low_r(
    handle: u64,
    path: *const u8,
    path_len: usize,
    digest: *const u8,
    digest_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let digest: [u8; 32] = unsafe { input(digest, digest_len) }?
            .try_into()
            .map_err(|_| Refusal::Argument)?;
        let signature =
            with_digest_key(handle, &path, |key| keys::sign_digest_low_r(key, &digest))?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Signs the 32-byte [digest] by BIP-340 with the key at [path] below
/// [handle]'s seed and writes the 64-byte signature to [out].
///
/// With `tweak_len` 32 the key is first tweaked by [tweak] as BIP-341's
/// key-path spend asks; with `tweak_len` 0 it signs untweaked and [tweak] is
/// not read (it may be null). Any other length is [`KC_ERR_ARGUMENT`], as is a
/// tweak not below the order. See `keys::schnorr_sign` for the auxiliary bytes
/// and the check made before the signature is written.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [digest] to `digest_len`
/// readable ones, a non-empty [tweak] to `tweak_len` readable ones and [out]
/// to `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_secp256k1_schnorr_sign(
    handle: u64,
    path: *const u8,
    path_len: usize,
    digest: *const u8,
    digest_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let digest: [u8; 32] = unsafe { input(digest, digest_len) }?
            .try_into()
            .map_err(|_| Refusal::Argument)?;
        let tweak: Option<[u8; 32]> = match tweak_len {
            0 => None,
            32 => Some(unsafe { input(tweak, tweak_len) }?.try_into().map_err(|_| Refusal::Argument)?),
            _ => return Err(Refusal::Argument),
        };
        let signature = with_digest_key(handle, &path, |key| {
            keys::schnorr_sign(key, &digest, tweak.as_ref())
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Writes the 32-byte ed25519 public key at [path] below [handle]'s seed, by
/// SLIP-10, to [out]. Every level of [path] must be hardened, or it is
/// [`KC_ERR_PATH`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_ed25519_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        keys::require_hardened(&path)?;
        let public = with_ed25519(handle, &path, |key| Ok(keys::ed25519_public_key(key)))?;
        unsafe { write_out(out, &public) };
        Ok(())
    })
}

/// Signs [message] (`message_len` bytes, any length, the message itself — not
/// a digest of it) by Ed25519 with the key at [path] below [handle]'s seed and
/// writes the 64-byte signature to [out]. Checked against the public key
/// before it is written; see `keys::ed25519_sign`.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [message] to `message_len`
/// readable ones (non-null even when `message_len` is 0) and [out] to
/// `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_ed25519_sign(
    handle: u64,
    path: *const u8,
    path_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        keys::require_hardened(&path)?;
        let message = unsafe { input(message, message_len) }?;
        // **A Solana, a Stellar, a NEAR, an Aptos, a Sui, an Algorand, a
        // Tezos, a MultiversX, a Polkadot or a TON key signs only what a
        // screen was given the reading of, once** (O58) — a Polkadot or a TON
        // key only what it was read for: taken for this signature, given back
        // if it is not made. Every other ed25519 network signs as before,
        // until its reader.
        // Decided, taken and signed in one hold of the session's lock, so a
        // close waits for all of it.
        let signature = with_held(handle, |held| {
            // Derived before the gate, which a Polkadot or a TON reading's key
            // is held at; a refusal of the derivation waits for the gate's.
            let key = ed25519_at(held, &path);
            let taken = match ed25519_gate_of(held, &path) {
                None => None,
                Some(gate) => Some(take_shown(gate, message, &key)?),
            };
            key.and_then(|key| keys::ed25519_sign(&key, message)).inspect_err(|_| {
                if let Some(taken) = taken {
                    give_back(taken);
                }
            })
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Reads [message] — a Solana message, the bytes after a transaction's
/// signature table, which an ed25519 signature on Solana is over — for the
/// review screen ("the screen shows what the core read", O52, O58), and writes
/// the reading to [out] as UTF-8 JSON (`src/solana.rs`): whether it is
/// versioned, its header, its accounts and fee payer, its blockhash, every
/// instruction — its program, accounts and data, and what it does where the
/// program is the System program's, a token program's, the Associated Token
/// Account program's (the account held to the owner and mint it names), the
/// compute budget's or the memo's — and its lookup tables.
///
/// **The reading is kept**: once it is written, one signature of exactly this
/// message by a Solana key may be made ([`kc_ed25519_sign`]). Asking its
/// length keeps nothing. A message the app's reader refuses is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [message] must point to `message_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_solana_read_message(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let message = unsafe { input(message, message_len) }?;
        let json = serde_json::to_vec(&solana::reading(message)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_solana(), solana::message_id(message));
        Ok(())
    })
}

/// Reads [payload] — a Stellar `TransactionSignaturePayload`, the network's
/// id, the envelope type and the transaction in XDR, whose SHA-256 is the
/// transaction's id and what its signature is over — for the review screen
/// ("the screen shows what the core read", O52, O58), and writes the reading
/// to [out] as UTF-8 JSON (`src/stellar.rs`): the network, the source, the
/// fee, the sequence, the time window, the memo and every operation.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// hash by a Stellar key may be made ([`kc_ed25519_sign`]). Asking its length
/// keeps nothing. A payload no transaction of this wallet is — another
/// envelope, a precondition beyond a time window, an operation the module
/// does not write, a Soroban extension, a padding byte that is not zero — is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [payload] must point to `payload_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_stellar_read_transaction(
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let payload = unsafe { input(payload, payload_len) }?;
        let json = serde_json::to_vec(&stellar::reading(payload)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_stellar(), stellar::transaction_hash(payload));
        Ok(())
    })
}

/// Reads [transaction] — a NEAR `Transaction`'s Borsh bytes, whose SHA-256
/// is the transaction's id and what its signature is over — for the review
/// screen ("the screen shows what the core read", O52, O58), and writes the
/// reading to [out] as UTF-8 JSON (`src/near.rs`): the signer, its key, the
/// nonce, the receiver, the block, every transfer's deposit and the hash.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// hash by a NEAR key may be made ([`kc_ed25519_sign`]). Asking its length
/// keeps nothing. Bytes no transaction of this wallet is — an account id
/// NEAR would not take, a key that is not ed25519, no action or one that is
/// not a transfer, a byte after the last action — are [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [transaction] must point to `transaction_len` readable bytes, a non-null
/// [out] to `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_near_read_transaction(
    transaction: *const u8,
    transaction_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let transaction = unsafe { input(transaction, transaction_len) }?;
        let json = serde_json::to_vec(&near::reading(transaction)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_near(), near::transaction_hash(transaction));
        Ok(())
    })
}

/// Reads [message] — an Aptos `RawTransaction`'s signing message, SHA3-256
/// of `APTOS::RawTransaction` and then the transaction's BCS, which an
/// ed25519 signature on Aptos and on Movement is over — for the review screen
/// ("the screen shows what the core read", O52, O58), and writes the reading
/// to [out] as UTF-8 JSON (`src/aptos.rs`): the sender, the sequence number,
/// the function, the recipient, the amount, the gas ceiling and price, the
/// expiry and the chain id.
///
/// **The reading is kept**: once it is written, one signature of exactly
/// [message] by an Aptos or Movement key may be made ([`kc_ed25519_sign`]).
/// Asking its length keeps nothing. A message no transaction of this wallet
/// is — another domain, a payload other than an entry function, an entry
/// function other than `0x1::aptos_account::transfer` with its address and
/// amount, a length not in its shortest form, a byte after the chain id — is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [message] must point to `message_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_aptos_read_transaction(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let message = unsafe { input(message, message_len) }?;
        let json = serde_json::to_vec(&aptos::reading(message)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_aptos(), solana::message_id(message));
        Ok(())
    })
}

/// Reads [message] — a Sui intent message, the intent's three bytes and then
/// the `TransactionData`'s BCS, whose BLAKE2b-256 a Sui signature is over —
/// for the review screen ("the screen shows what the core read", O52, O58,
/// O60), and writes the reading to [out] as UTF-8 JSON (`src/sui.rs`): the
/// sender, the recipient, the amount, the gas coins, owner, price and budget,
/// and the transaction's digest.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// BLAKE2b-256 by a Sui key may be made ([`kc_ed25519_sign`]). Asking its
/// length keeps nothing. A message no transaction of this wallet is — another
/// intent or kind, a programme other than the transfer the module writes, an
/// expiry, a ULEB128 not in its shortest form, a byte after the last field —
/// is [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [message] must point to `message_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_sui_read_transaction(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let message = unsafe { input(message, message_len) }?;
        let json = serde_json::to_vec(&sui::reading(message)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_sui(), sui::signing_digest(message));
        Ok(())
    })
}

/// Reads [message] — `TX` and an Algorand transaction's canonical msgpack,
/// which an ed25519 signature on Algorand is over — for the review screen
/// ("the screen shows what the core read", O52, O58), and writes the reading
/// to [out] as UTF-8 JSON (`src/algorand.rs`): the transaction's id, whether
/// its genesis is mainnet's, and every field, each value tagged with its kind.
///
/// **The reading is kept**: once it is written, one signature of exactly
/// [message] by an Algorand key may be made ([`kc_ed25519_sign`]). Asking its
/// length keeps nothing. A message that is not canonical msgpack as the
/// module writes it, or a transaction with no sender or type, or one that
/// rekeys or closes the account or an asset holding, is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [message] must point to `message_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_algorand_read_transaction(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let message = unsafe { input(message, message_len) }?;
        let json = serde_json::to_vec(&algorand::reading(message)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_algorand(), solana::message_id(message));
        Ok(())
    })
}

/// Reads [forged] — a Tezos operation group as this wallet's forger writes
/// it, the branch and then each operation, whose BLAKE2b-256 after the
/// watermark `0x03` a Tezos signature is over — for the review screen ("the
/// screen shows what the core read", O52, O58, O60), and writes the reading
/// to [out] as UTF-8 JSON (`src/tezos.rs`): the branch and every operation —
/// a reveal's key, a transaction's amount, destination, entrypoint and
/// argument — with its source, fee, counter and limits.
///
/// **The reading is kept**: once it is written, one signature of exactly its
/// watermarked BLAKE2b-256 by a Tezos key may be made ([`kc_ed25519_sign`]).
/// Asking its length keeps nothing. A group the forger never writes — another
/// kind of operation, a key that is not ed25519, a zarith not in its shortest
/// form, a Micheline node it does not write, a byte after the last operation
/// — is [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [forged] must point to `forged_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_tezos_read_operation(
    forged: *const u8,
    forged_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let forged = unsafe { input(forged, forged_len) }?;
        let json = serde_json::to_vec(&tezos::reading(forged)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_tezos(), tezos::signing_digest(forged));
        Ok(())
    })
}

/// Reads [payload] — a MultiversX transaction's signing JSON, which an
/// ed25519 signature on MultiversX is over — for the review screen ("the
/// screen shows what the core read", O52, O58), and writes the reading to
/// [out] as UTF-8 JSON (`src/multiversx.rs`): the nonce, value, receiver,
/// sender, gas price and limit, the data and its text, the chain and whether
/// it is mainnet's.
///
/// **The reading is kept**: once it is written, one signature of exactly
/// [payload] by a MultiversX key may be made ([`kc_ed25519_sign`]). Asking
/// its length keeps nothing. JSON in any spelling but the module's — another
/// key or order, whitespace, an escape, a leading zero, a version other than
/// 1, an address that is not an `erd1` bech32 of 32 bytes, data that is not
/// canonical base64 — is [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [payload] must point to `payload_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_multiversx_read_transaction(
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let payload = unsafe { input(payload, payload_len) }?;
        let json = serde_json::to_vec(&multiversx::reading(payload)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_multiversx(), solana::message_id(payload));
        Ok(())
    })
}

/// Reads [payload] — an Asset Hub extrinsic's signing payload, which an
/// ed25519 signature on Polkadot is over — for the review screen ("the screen
/// shows what the core read", O52, O58), **for the Polkadot key at [path]
/// below [handle]'s seed** (`m/44'/354'/…`), and writes the reading to [out]
/// as UTF-8 JSON (`src/polkadot.rs`): `signer`, that key's public half; the
/// destination, the amount, the era, the nonce, the tip, the runtime's
/// versions, the genesis and the era's block, and whether the genesis is
/// Asset Hub's.
///
/// **The reading is kept with that key**: once it is written, one signature
/// of exactly [payload] by that key may be made ([`kc_ed25519_sign`]); no
/// other key's. Asking its length keeps nothing. A payload the module never
/// writes — another call, an immortal era, an asset paying the fee, a
/// metadata hash, a compact not in its shortest form, a byte after — is
/// [`KC_ERR_TRANSACTION`]; a path not Polkadot's is [`KC_ERR_PATH`], and a
/// one-key session [`KC_ERR_KIND`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [payload] to
/// `payload_len` ones, a non-null [out] to `out_cap` writable ones, and
/// [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_polkadot_read_transaction(
    handle: u64,
    path: *const u8,
    path_len: usize,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        if !keys::is_polkadot(&path) {
            return Err(Refusal::Path);
        }
        let payload = unsafe { input(payload, payload_len) }?;
        let signer = ed25519_public_at_seed(handle, &path)?;
        let json = serde_json::to_vec(&polkadot::reading(payload, &signer)?).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_polkadot(), (solana::message_id(payload), signer));
        Ok(())
    })
}

/// Reads [boc] — a TON wallet v4R2 signing message as a bag of cells, whose
/// root's representation hash a TON signature is over — for the review screen
/// ("the screen shows what the core read", O52, O58), and writes the reading
/// to [out] as UTF-8 JSON (`src/ton.rs`): the subwallet, the expiry, the
/// seqno, every message — its mode, bounce flag, destination, value and body
/// (nothing, a comment, or a jetton transfer whose forward payload is
/// nothing, a comment or a STON.fi swap) — and the hash, which the core takes
/// itself — and `publicKey`, the public half of the TON key at [path] below
/// [handle]'s seed (`m/44'/607'/…`) **it is read for**.
///
/// **The reading is kept with that key**: once it is written, one signature
/// of exactly that hash by that key may be made ([`kc_ed25519_sign`]); no
/// other key's. Asking its length keeps nothing. A bag the module never
/// writes — another root, an exotic cell, a CRC32C wrong, a cell not reached,
/// another wallet's opcode, a state init, an extra currency, a body of
/// another kind, a `Coins` not in its shortest form — is
/// [`KC_ERR_TRANSACTION`]; a path not TON's is [`KC_ERR_PATH`], and a one-key
/// session [`KC_ERR_KIND`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [boc] to `boc_len` ones, a
/// non-null [out] to `out_cap` writable ones, and [out_len] to a writable
/// `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_ton_read_transfer(
    handle: u64,
    path: *const u8,
    path_len: usize,
    boc: *const u8,
    boc_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        if !keys::is_ton(&path) {
            return Err(Refusal::Path);
        }
        let boc = unsafe { input(boc, boc_len) }?;
        let public = ed25519_public_at_seed(handle, &path)?;
        let (reading, hash) = ton::reading(boc, &public)?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_ton(), (hash, public));
        Ok(())
    })
}

/// Reads [message] — a Filecoin message's CBOR, whose CID's BLAKE2b-256 a
/// Filecoin signature is over — for the review screen ("the screen shows what
/// the core read", O52, O58), and writes the reading to [out] as UTF-8 JSON
/// (`src/filecoin.rs`): the recipient and the sender as `f1…`, the nonce, the
/// value, the gas limit, the fee cap, the premium, the CID and the digest,
/// which the core takes itself.
///
/// **The reading is kept**: once it is written, one signature of exactly that
/// digest by a Filecoin key may be made ([`kc_secp256k1_sign_digest`]).
/// Asking its length keeps nothing. A message the module never writes —
/// another version, a method call, parameters, an address other than `f1`, a
/// negative amount, a big integer with a leading zero, a CBOR number not in
/// its shortest form, a byte after — is [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [message] must point to `message_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_filecoin_read_message(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let message = unsafe { input(message, message_len) }?;
        let (reading, digest) = filecoin::reading(message)?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_filecoin(), digest);
        Ok(())
    })
}

/// Reads [content] — an ICP call's content map as CBOR, whose request id's
/// domain-separated SHA-256 an ICP signature is over — for the review screen
/// ("the screen shows what the core read", O52, O58), and writes the reading
/// to [out] as UTF-8 JSON (`src/icp.rs`): the ledger's `transfer` — the
/// recipient's account identifier, the amount, the fee, the memo, the
/// creation time — the sender, the expiry, the request id and the digest,
/// which the core takes itself.
///
/// **The reading is kept**: once it is written, one signature of exactly that
/// digest by an ICP key may be made ([`kc_secp256k1_sign_digest`]). Asking
/// its length keeps nothing. A call the module never makes — another
/// canister, another method, a nonce, a subaccount, no creation time, an
/// account identifier whose checksum is wrong, a type table not the module's,
/// a CBOR head not in its shortest form, a byte after — is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes. No session is asked:
/// nothing secret is read.
///
/// # Safety
/// [content] must point to `content_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_icp_read_call(
    content: *const u8,
    content_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let content = unsafe { input(content, content_len) }?;
        let (reading, digest) = icp::reading(content)?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_icp(), digest);
        Ok(())
    })
}

/// The key a Kaspa request is signed with, inside [`with_held`]'s lock: a
/// phrase's at a Kaspa path ([`keys::is_kaspa`]), or a key opened as
/// [`KC_CURVE_SECP256K1_KASPA`] at `m`. Any other key is [`Refusal::Kind`],
/// another path [`Refusal::Path`]: a Kaspa sighash is signed by a Kaspa key
/// alone.
fn kaspa_key_at(held: &Held, path: &[u8]) -> Result<keys::DerivedKey, Refusal> {
    let path = keys::parse_path(path)?;
    match held {
        Held::Seed(_) if keys::is_kaspa(&path) => secp256k1_at(held, &path),
        Held::Seed(_) => Err(Refusal::Path),
        Held::KaspaKey(_) => secp256k1_at(held, &path),
        _ => Err(Refusal::Kind),
    }
}

/// Signs every input of a Kaspa send by BIP-340 with the key the request
/// names below [handle] (`src/kaspa.rs`, O58), and writes 96 bytes per input
/// to [out], in input order: the sighash the core computed — BIP-143's shape
/// with every hash BLAKE2b-256 keyed by `TransactionSigningHash`, as the
/// module's `KaspaTransaction.signingDigest` writes it — then the signature
/// over it, untweaked, its auxiliary bytes [`kc_secp256k1_schnorr_sign`]'s.
/// [out_len] must be exactly that. [request], little-endian throughout:
///
/// | Bytes | Field |
/// |---|---|
/// | 2 + path | the key every input is signed with: a phrase's at `m/44'/111111'/…`, or `m` for a key opened as [`KC_CURVE_SECP256K1_KASPA`] |
/// | 2 | the transaction's version: 0 |
/// | 2, then per input | 32 the spent output's transaction id, as the indexer writes it; 4 its index; 8 its amount; 2 its script's version, 0; 2 + its script, the key's `0x20 key 0xac`; 8 the sequence, `u64::MAX`; 1 the signature operations, 1 |
/// | 2, then per output | 8 the amount; 2 the script's version, 0; 2 + the script, a Schnorr key's `0x20 key 0xac` |
/// | 8 | the lock time: 0 |
/// | 20 | the subnetwork: zeros, the native one |
/// | 8 | the gas: 0 |
/// | 8 | the fee: the inputs' sum less the outputs' |
///
/// A layout that does not read is [`KC_ERR_ARGUMENT`]. A send the module
/// never writes — another version, no input or output, another script or
/// script version, a sequence, signature count, lock time, subnetwork or gas
/// of its own, an outpoint twice, a fee that is not the difference — is
/// [`KC_ERR_TRANSACTION`], and so, under the lock, is an input that does not
/// spend the signing key's own script. A key that is not Kaspa's is
/// [`KC_ERR_KIND`], a phrase's path that is not Kaspa's [`KC_ERR_PATH`].
///
/// **And only a request a screen was shown** (O58): [request] must be, byte
/// for byte, one an unused reading of [`kc_kaspa_read_transaction`] gave, or
/// the call is [`KC_ERR_UNSHOWN`]. The reading is taken, the key asked and
/// the inputs signed in one hold of the session's lock, and the reading is
/// given back if the signature is refused.
///
/// # Safety
/// [request] must point to `request_len` readable bytes and [out] to
/// `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_kaspa_sign_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = kaspa::Request::read(bytes)?;
        check_out(out, out_len, request.inputs.len() * 96)?;
        let shown = kaspa::request_id(bytes);
        let signed = with_held(handle, |held| {
            let key = kaspa_key_at(held, request.path)?;
            {
                let mut table = shown_kaspa();
                let at = table.iter().position(|entry| *entry == shown).ok_or(Refusal::Unshown)?;
                table.remove(at);
            }
            kaspa::sign(&request, &key).inspect_err(|_| shown_kaspa().push_front(shown))
        })?;
        unsafe { write_out(out, &signed.concat()) };
        Ok(())
    })
}

/// Reads [request] — in [`kc_kaspa_sign_transaction`]'s layout — for the
/// review screen ("the screen shows what the core read", O52, O58), and
/// writes the reading to [out] as UTF-8 JSON (`src/kaspa.rs`): every input's
/// outpoint and amount; every output in order with its address, spelt here
/// as Kaspa's CashAddr, its amount, and whether it is the account's change;
/// the sum sent to others, the sum spent, the fee, and every input's sighash.
///
/// **Held first, as the signature would hold it**: the send is one the module
/// writes and, under the lock, every input spends the signing key's own
/// script — so "change" on the screen is the core's finding, an output that
/// pays that key, not a claim. **The reading is kept**: once it is written,
/// one signature of exactly this request may be made. Asking its length
/// keeps nothing.
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [request] must point to `request_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_kaspa_read_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = kaspa::Request::read(bytes)?;
        let reading = with_held(handle, |held| {
            let own = kaspa::own_script(&kaspa_key_at(held, request.path)?);
            kaspa::hold_to_key(&request, &own)?;
            Ok(kaspa::reading(&request, &own))
        })?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_kaspa(), kaspa::request_id(bytes));
        Ok(())
    })
}

/// The key a Zcash request is signed with, inside [`with_held`]'s lock: a
/// phrase's at a Zcash path ([`keys::is_zcash`]), or a key opened as
/// [`KC_CURVE_SECP256K1_ZCASH`] at `m`. Any other key is [`Refusal::Kind`],
/// another path [`Refusal::Path`]: a Zcash signature digest is signed by a
/// Zcash key alone.
fn zcash_key_at(held: &Held, path: &[u8]) -> Result<keys::DerivedKey, Refusal> {
    let path = keys::parse_path(path)?;
    match held {
        Held::Seed(_) if keys::is_zcash(&path) => secp256k1_at(held, &path),
        Held::Seed(_) => Err(Refusal::Path),
        Held::ZcashKey(_) => secp256k1_at(held, &path),
        _ => Err(Refusal::Kind),
    }
}

/// Signs every input of a transparent Zcash send by ECDSA with the key the
/// request names below [handle] (`src/zcash.rs`), and writes 96 bytes per
/// input to [out], in input order: the ZIP-244 signature digest the core
/// computed under `SIGHASH_ALL`, then the signature over it — `r` then `s`,
/// 32 bytes each, low `R` and low `s` as [`kc_secp256k1_sign_digest_low_r`] signs.
/// [out_len] must be exactly that. [request], little-endian:
///
/// | Bytes | Field |
/// |---|---|
/// | 2 + path | the key every input is signed with: a phrase's at `m/44'/133'/…`, or `m` for a key opened as [`KC_CURVE_SECP256K1_ZCASH`] |
/// | 4 + tx | the unsigned transaction exactly as ZIP-225 serialises it: version 5 under the overwinter flag (`0x80000005`), version group `0x26A7270A`, the consensus branch id, lock time 0, an expiry height above 0 and below 500,000,000; per input its outpoint, an empty `scriptSig` and the sequence `0xFFFFFFFE`; per output an amount above 0 and at most 21 million ZEC and a pay-to-public-key-hash or pay-to-script-hash script; no Sapling spend or output and no Orchard action |
/// | per input | 8 the amount of the coin it spends; 2 + that coin's script, a pay-to-public-key-hash one |
/// | 1 per output | how the person wrote the recipient: 0 the transparent address its script spells, 1 ZIP-320's TEX form (a pay-to-public-key-hash output only) |
/// | 8 | the fee: the inputs' sum less the outputs' |
///
/// A layout that does not read is [`KC_ERR_ARGUMENT`]. A send the module
/// never writes — another version, group, lock time or sequence, no expiry,
/// a `scriptSig`, no input or output, a script of another kind, an amount of
/// zero or above the ceiling, a shielded part, an outpoint twice, a fee that
/// is not the difference — is [`KC_ERR_TRANSACTION`], and so, under the lock,
/// is an input that does not spend the signing key's own script. A key that
/// is not Zcash's is [`KC_ERR_KIND`], a phrase's path that is not Zcash's
/// [`KC_ERR_PATH`].
///
/// **And only a request a screen was shown**: [request] must be, byte for
/// byte, one an unused reading of [`kc_zcash_read_transaction`] gave, or the
/// call is [`KC_ERR_UNSHOWN`]. The reading is taken, the key asked and the
/// inputs signed in one hold of the session's lock, and the reading is given
/// back if the signature is refused.
///
/// # Safety
/// [request] must point to `request_len` readable bytes and [out] to
/// `out_len` writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_zcash_sign_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = zcash::Request::read(bytes)?;
        check_out(out, out_len, request.inputs.len() * 96)?;
        let shown = zcash::request_id(bytes);
        let signed = with_held(handle, |held| {
            let key = zcash_key_at(held, request.path)?;
            {
                let mut table = shown_zcash();
                let at = table.iter().position(|entry| *entry == shown).ok_or(Refusal::Unshown)?;
                table.remove(at);
            }
            zcash::sign(&request, &key).inspect_err(|_| shown_zcash().push_front(shown))
        })?;
        unsafe { write_out(out, &signed.concat()) };
        Ok(())
    })
}

/// Reads [request] — in [`kc_zcash_sign_transaction`]'s layout — for the
/// review screen ("the screen shows what the core read"), and writes the
/// reading to [out] as UTF-8 JSON (`src/zcash.rs`): every input's outpoint
/// (its transaction id as explorers write it) and amount; every output in
/// order with its address, spelt here (`t1…`, `t3…` or `tex1…`), its amount,
/// and whether it is the account's change; the sum sent to others, the sum
/// spent, the fee, the expiry height, the transaction's ZIP-244 id and every
/// input's signature digest.
///
/// **Held first, as the signature would hold it**: the send is one the module
/// writes and, under the lock, every input spends the signing key's own
/// script — so "change" on the screen is the core's finding, an output that
/// pays that key, not a claim. **The reading is kept**: once it is written,
/// one signature of exactly this request may be made. Asking its length
/// keeps nothing.
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [request] must point to `request_len` readable bytes, a non-null [out] to
/// `out_cap` writable ones, and [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_zcash_read_transaction(
    handle: u64,
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let bytes = unsafe { input(request, request_len) }?;
        let request = zcash::Request::read(bytes)?;
        let reading = with_held(handle, |held| {
            let own = zcash::own_script(&zcash_key_at(held, request.path)?);
            zcash::hold_to_key(&request, &own)?;
            Ok(zcash::reading(&request, &own))
        })?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_zcash(), zcash::request_id(bytes));
        Ok(())
    })
}

/// Reads [body] — a Cardano transaction body's CBOR, whose BLAKE2b-256 is the
/// transaction's id and what every witness signs — for the review screen
/// ("the screen shows what the core read", O52, O58), with the keys that will
/// sign it, and writes the reading to [out] as UTF-8 JSON (`src/cardano.rs`):
/// the inputs, the outputs — each address and its lovelace — the fee, the
/// time to live, the hash, and the signers' payment key hashes.
///
/// [signers] names the witnesses' keys below [handle]'s phrase, in this
/// layout, little-endian: two bytes of count, then for each two bytes of
/// length and its path, each at `m/1852'/1815'`. **One witness per payment
/// key** (the owner's decision of 5 November 2026): the core derives each
/// key, takes its BLAKE2b-224 — the payment key hash an address holds — and
/// refuses with [`KC_ERR_TRANSACTION`] a list in which two keys share one,
/// before anything is kept. None, or a layout that does not read, is
/// [`KC_ERR_ARGUMENT`]; a path not Cardano's is [`KC_ERR_PATH`].
///
/// **The reading is kept for each signer it names**: each such key may then
/// sign that hash once ([`kc_cardano_sign`]), and no other key may. Asking
/// its length keeps nothing. A body the module never writes — a certificate,
/// a withdrawal, a mint, metadata, a native asset, a datum, an input twice, a
/// length indefinite, a number not in its shortest form, a byte after — is
/// [`KC_ERR_TRANSACTION`].
///
/// [out_len] receives the reading's length. With [out] null or [out_cap]
/// shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [body] must point to `body_len` readable bytes, [signers] to
/// `signers_len` ones, a non-null [out] to `out_cap` writable ones, and
/// [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_cardano_read_transaction(
    handle: u64,
    body: *const u8,
    body_len: usize,
    signers: *const u8,
    signers_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let body = unsafe { input(body, body_len) }?;
        let (mut reading, hash) = cardano::reading(body)?;
        let mut paths = Vec::new();
        for path in cardano::signer_paths(unsafe { input(signers, signers_len) }?)? {
            let path = keys::parse_path(path)?;
            if !keys::is_cardano(&path) {
                return Err(Refusal::Path);
            }
            paths.push(path);
        }
        let key_hashes = with_seed(handle, |seed| {
            paths
                .iter()
                .map(|path| Ok(cardano::key_hash(&keys::cardano_public_key(&keys::derive_cardano(seed, path)?))))
                .collect::<Result<Vec<_>, Refusal>>()
        })?;
        // A key named twice, or two paths of one payment key: a witness
        // repeated in a set that holds each key once.
        for (i, key_hash) in key_hashes.iter().enumerate() {
            if key_hashes[..i].contains(key_hash) {
                return Err(Refusal::Transaction);
            }
        }
        if let serde_json::Value::Object(map) = &mut reading {
            map.insert(
                "witnesses".into(),
                serde_json::Value::Array(
                    key_hashes
                        .iter()
                        .map(|h| serde_json::Value::String(h.iter().map(|b| format!("{b:02x}")).collect()))
                        .collect(),
                ),
            );
        }
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked — one
        // entry for each signer it names.
        let mut table = shown_cardano();
        for key_hash in key_hashes {
            if table.len() == MAX_SHOWN {
                table.pop_front();
            }
            table.push_back((hash, key_hash));
        }
        Ok(())
    })
}

/// Writes the 32-byte ed25519 private key at [path] below [handle]'s seed to
/// [out] — SLIP-10's key, the seed RFC 8032 expands, which every format the
/// export screens show is made from.
///
/// **For the export screens only**, like [`kc_secp256k1_export_private_key`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_ed25519_export_private_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        keys::require_hardened(&path)?;
        let secret = with_ed25519(handle, &path, |key| Ok(keys::ed25519_secret(key)))?;
        unsafe { write_out(out, &secret[..]) };
        Ok(())
    })
}

/// Writes the 32-byte Cardano public key at [path] below [handle]'s seed to
/// [out]: BIP32-Ed25519 from the Ledger scheme's master key, normal levels
/// allowed (CIP-1852's role and index are); see `keys::derive_cardano`.
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_cardano_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let public = with_seed(handle, |seed| {
            Ok(keys::cardano_public_key(&keys::derive_cardano(seed, &path)?))
        })?;
        unsafe { write_out(out, &public) };
        Ok(())
    })
}

/// Writes the 32-byte Cardano public key at [path] by **the Icarus scheme**
/// to [out]: BIP32-Ed25519 below the master key Yoroi, Eternl and Daedalus
/// build from the phrase's entropy (CIP-0003; the owner's decisions O19 and
/// O29) rather than from its seed — see `keys::cardano_icarus_master`. Normal
/// levels allowed, as for [`kc_cardano_public_key`].
///
/// **A public key and nothing else**: the wallet asks where another wallet
/// would have put this phrase's money, and signs nothing under Icarus. A
/// one-key session is [`KC_ERR_KIND`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_cardano_icarus_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let public = with_phrase(handle, |phrase| {
            Ok(keys::cardano_public_key(&keys::derive_cardano_icarus(
                phrase.entropy.as_bytes(),
                &path,
            )?))
        })?;
        unsafe { write_out(out, &public) };
        Ok(())
    })
}

/// Signs [message] (`message_len` bytes, the message itself) with the
/// extended key at [path] below [handle]'s seed, as a Cardano witness is
/// signed, and writes the 64-byte signature to [out]. Checked against the
/// public key before it is written; see `keys::cardano_sign`.
///
/// **A key at `m/1852'/1815'` signs only the 32-byte hash of a body a screen
/// was given the reading of** ([`kc_cardano_read_transaction`]), **and only
/// as a signer that reading named — once**; anything else is
/// [`KC_ERR_UNSHOWN`], and a refused signature gives its reading back (O58).
///
/// # Safety
/// As [`kc_ed25519_sign`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_cardano_sign(
    handle: u64,
    path: *const u8,
    path_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let message = unsafe { input(message, message_len) }?;
        // Taken and signed in one hold of the session's lock, so a close
        // waits for all of it; a closed handle, or a key's, is said first.
        let signature = with_seed(handle, |seed| {
            let node = keys::derive_cardano(seed, &path)?;
            let kept = if keys::is_cardano(&path) {
                let digest: [u8; 32] = message.try_into().map_err(|_| Refusal::Unshown)?;
                let entry = (digest, cardano::key_hash(&keys::cardano_public_key(&node)));
                let mut table = shown_cardano();
                let at = table.iter().position(|kept| *kept == entry).ok_or(Refusal::Unshown)?;
                table.remove(at);
                Some(entry)
            } else {
                None
            };
            keys::cardano_sign(&node, message).inspect_err(|_| {
                if let Some(entry) = kept {
                    shown_cardano().push_front(entry);
                }
            })
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Writes the 96 bytes of the Cardano node at [path] below [handle]'s seed to
/// [out]: the extended key `kL ‖ kR`, then the chain code — the form Cardano
/// wallets import.
///
/// **For the export screens only**, like [`kc_secp256k1_export_private_key`].
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_cardano_export_private_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 96)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let node = with_seed(handle, |seed| keys::derive_cardano(seed, &path))?;
        unsafe { write_out(out, &node[..]) };
        Ok(())
    })
}

/// Writes the 32-byte Stark public key (big-endian `x`) of the Starknet key
/// at [path] below [handle]'s seed to [out]. [path] names the key in Argent's
/// second tree (`m/44'/9004'/0'/0/{i}`); the first step, the Ethereum key at
/// `m/44'/60'/0'/0/0`, is fixed — see `keys::derive_starknet`.
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_starknet_public_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let public = with_seed(handle, |seed| {
            Ok(keys::starknet_public_key(&*keys::derive_starknet(seed, &path)?))
        })?;
        unsafe { write_out(out, &public) };
        Ok(())
    })
}

/// Signs the 32-byte big-endian [hash] (a felt below 2^251) with the Starknet
/// key at [path] below [handle]'s seed and writes 64 bytes to [out]: `r` then
/// `s`, big-endian. See `keys::starknet_sign` for the nonce and the check.
///
/// **A key at `m/44'/9004'` signs only the hash of a transaction a screen was
/// given the reading of** ([`kc_starknet_read_transaction`]), **held to this
/// key — once**; anything else is [`KC_ERR_UNSHOWN`], and a refused signature
/// gives its reading back (O58). The reading is taken, the key derived and
/// the hash signed in one hold of the session's lock.
///
/// # Safety
/// As [`kc_secp256k1_sign_digest`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_starknet_sign(
    handle: u64,
    path: *const u8,
    path_len: usize,
    hash: *const u8,
    hash_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 64)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let hash: [u8; 32] = unsafe { input(hash, hash_len) }?
            .try_into()
            .map_err(|_| Refusal::Argument)?;
        let signature = with_seed(handle, |seed| {
            let secret = keys::derive_starknet(seed, &path)?;
            let kept = if keys::is_starknet(&path) {
                let entry = (hash, keys::starknet_public_key(&secret));
                let mut table = shown_starknet();
                let at = table.iter().position(|kept| *kept == entry).ok_or(Refusal::Unshown)?;
                table.remove(at);
                Some(entry)
            } else {
                None
            };
            keys::starknet_sign(&secret, &hash).inspect_err(|_| {
                if let Some(entry) = kept {
                    shown_starknet().push_front(entry);
                }
            })
        })?;
        unsafe { write_out(out, &signature) };
        Ok(())
    })
}

/// Reads [transaction] — a v3 Starknet transaction's JSON body as the module
/// sends it, `starknet_addInvokeTransaction`'s or
/// `starknet_addDeployAccountTransaction`'s, with no signature yet — for the
/// review screen ("the screen shows what the core read", O52, O58), held to
/// the Stark key at [path] below [handle]'s seed (`m/44'/9004'/…`), and writes
/// the reading to [out] as UTF-8 JSON (`src/starknet.rs`): the kind, whether
/// it is the query version an estimate is signed at, the network, the
/// bounds and the most they let it cost; an invoke's sender, nonce, token,
/// recipient and amount, a deployment's address, class and key; and the
/// hash, Poseidon over the transaction on mainnet's chain id, which the core
/// takes itself.
///
/// **Held to the key**: an invoke's sender is the key's own Argent account —
/// at 0.4.0's, 0.3.1's or 0.3.0's address for it — and a deployment's class
/// is one of those, its salt and constructor the key's. A transaction the
/// module never sends — another type or version, a signature, a tip,
/// paymaster or account deployment data, data availability other than L1,
/// anything but one ERC-20 `transfer` through `__execute__`, a felt not in
/// the module's spelling or not below the prime, a bound past its width, a
/// key not in its place — is [`KC_ERR_TRANSACTION`]; a path not Starknet's
/// is [`KC_ERR_PATH`].
///
/// **The reading is kept** with the key's public half: one signature of that
/// hash by that key may then be made ([`kc_starknet_sign`]). Asking its length
/// keeps nothing. [out_len] receives the reading's length. With [out] null or
/// [out_cap] shorter than that, nothing else is written and the call is
/// [`KC_ERR_BUFFER`]: ask again with that many bytes.
///
/// # Safety
/// [path] must point to `path_len` readable bytes, [transaction] to
/// `transaction_len` ones, a non-null [out] to `out_cap` writable ones, and
/// [out_len] to a writable `usize`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kc_starknet_read_transaction(
    handle: u64,
    path: *const u8,
    path_len: usize,
    transaction: *const u8,
    transaction_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return KC_ERR_ARGUMENT;
    }
    guarded(|| {
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        if !keys::is_starknet(&path) {
            return Err(Refusal::Path);
        }
        let transaction = unsafe { input(transaction, transaction_len) }?;
        let public = with_seed(handle, |seed| {
            let secret = keys::derive_starknet(seed, &path)?;
            Ok(keys::starknet_public_key(&secret))
        })?;
        let (reading, hash) = starknet::reading(transaction, &public)?;
        let json = serde_json::to_vec(&reading).map_err(|_| Refusal::Internal)?;
        unsafe { out_len.write_unaligned(json.len()) };
        if out.is_null() || out_cap < json.len() {
            return Err(Refusal::Buffer);
        }
        unsafe { write_out(out, &json) };
        // Kept once the reading is given, not when its length is asked.
        keep_shown(&mut shown_starknet(), (hash, public));
        Ok(())
    })
}

/// Writes the 32-byte Stark private key (big-endian, ground) at [path] below
/// [handle]'s seed to [out] — **for the export screens only**.
///
/// # Safety
/// [path] must point to `path_len` readable bytes and [out] to `out_len`
/// writable ones.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_starknet_export_private_key(
    handle: u64,
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| {
        check_out(out, out_len, 32)?;
        let path = keys::parse_path(unsafe { input(path, path_len) }?)?;
        let secret = with_seed(handle, |seed| keys::derive_starknet(seed, &path))?;
        unsafe { write_out(out, &secret[..]) };
        Ok(())
    })
}

