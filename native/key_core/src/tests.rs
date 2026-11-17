//! The core held to published vectors, to its own refusals, and to what it
//! leaves on the stack.
//!
//! The Dart side is the oracle for everything a wallet would notice — the
//! same seed, keys and signatures as `blockchain_utils` on random phrases —
//! and lives in `dart/test/`. These are what the Rust side can say alone.

use std::cell::RefCell;

use bip32::ExtendedPrivateKey;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, XOnlyPublicKey, schnorr};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use super::*;
use crate::keys::{DerivedKey, Ed25519Key};
use crate::vectors::{
    BIP32, BIP39_TREZOR, BIP143, BIP340, BIP341_INPUTS, BIP341_OUTPUTS, BIP341_SPENT,
    BIP341_TRANSACTION, CARDANO_BIP32, CARDANO_ICARUS, CARDANO_LEDGER, EIP191_HASH, EIP191_SIGNED,
    EIP712_DOMAIN_ONLY, EIP712_HASHED, EIP712_REFUSED, FORKID_SIGHASH, LEGACY_SIGHASH, RFC8032,
    SLIP10_ED25519,
};

/// The ABI's table is global and the tests run in parallel; every test that
/// opens, closes or counts holds this — and every one that reads a
/// transaction for a screen, whose readings are kept in a global table too.
static ABI: Mutex<()> = Mutex::new(());

fn abi() -> MutexGuard<'static, ()> {
    ABI.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

thread_local! {
    /// What a test runs inside `with_seed` while the table's lock is held —
    /// on the thread that set it, so the tests running beside it meet none.
    static INSIDE_THE_LOCK: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    /// How many times this thread has entered the table's lock.
    static LOCK_ENTRIES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Called by `with_seed` under the lock, in a test build only.
pub(crate) fn inside_the_lock() {
    LOCK_ENTRIES.with(|n| n.set(n.get() + 1));
    INSIDE_THE_LOCK.with(|hook| {
        if let Some(run) = hook.borrow_mut().as_mut() {
            run();
        }
    });
}

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon about";
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner \
                     thank yellow";
const EVM_0: &str = "m/44'/60'/0'/0/0";
const BTC_TAPROOT_0: &str = "m/86'/0'/0'/0/0";
/// Kaspa's first key, which signs only a send the core read for a screen
/// since 2f-20 (`a_kaspa_key_signs_only_a_send_read_for_a_screen`). The
/// BIP-340 primitive, tested here at this path until then, is tested at
/// [`DIGEST_0`]: Bitcoin's keys sign only transactions the core reads since
/// O37 (`a_bitcoin_family_key_signs_no_bare_digest`).
const KASPA_0: &str = "m/44'/111111'/0'/0/0";
/// A path no network of the wallet's signs at, where the bare-digest
/// primitive is tested: EVM's keys sign only what the core reads since O43
/// (`an_evm_key_signs_no_bare_digest`), and TRON's and the Cosmos zones',
/// where these tests signed in turn, since O58
/// (`a_tron_key_signs_only_a_transaction_read_for_a_screen`,
/// `a_cosmos_key_signs_only_a_sign_doc_read_for_a_screen`).
const DIGEST_0: &str = "m/1'/2'/3'/4/5";
const COSMOS_0: &str = "m/44'/118'/0'/0/0";
const TRON_0: &str = "m/44'/195'/0'/0/0";
const XRP_0: &str = "m/44'/144'/0'/0/0";
const SOLANA_0: &str = "m/44'/501'/0'/0'";
/// A hardened path no network of the wallet's signs at: where the tests sign
/// arbitrary bytes with a phrase's ed25519 key, since a Solana key signs only
/// a message read for a screen and a Stellar key only a transaction's hash
/// read (O58) — Stellar's first account was this path until then.
const ED_0: &str = "m/1'/2'/3'";
const STELLAR_0: &str = "m/44'/148'/0'";
const CARDANO_0: &str = "m/1852'/1815'/0'/0/0";
/// A Cardano key at a path no module writes, which signs bytes as given:
/// only a key at `m/1852'/1815'` signs only a body read (O58).
const CARDANO_FREE: &str = "m/1'/2'/3'/4/5";
const STARKNET_0: &str = "m/44'/9004'/0'/0/0";
/// A path no module writes, where the Stark signature primitive is tested:
/// a key at `m/44'/9004'` signs only the hash of a transaction the core read
/// for a screen since 2f-21 (`a_starknet_key_signs_only_a_transaction_read_for_a_screen`).
/// Argent's derivation reaches it as it reaches the module's path.
const STARKNET_FREE: &str = "m/1'/2'/3'/4/9";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes that look random and are the same on every run, so a failure is
/// reproducible rather than a flake.
fn sequence(seed: u64, count: usize) -> Vec<u8> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn open_key(curve: i32, secret: &[u8]) -> Result<u64, i32> {
    let mut handle = u64::MAX;
    let code = unsafe { kc_open_key(curve, secret.as_ptr(), secret.len(), &mut handle) };
    if code == KC_OK {
        Ok(handle)
    } else {
        assert_eq!(handle, 0, "a refused open left a handle");
        Err(code)
    }
}

fn open(phrase: &[u8]) -> Result<u64, i32> {
    // Not zero, so a refusal that forgot to clear it is seen.
    let mut handle = u64::MAX;
    let code = unsafe { kc_open(phrase.as_ptr(), phrase.len(), &mut handle) };
    if code == KC_OK {
        Ok(handle)
    } else {
        assert_eq!(handle, 0, "a refused open left a handle");
        Err(code)
    }
}

fn open_sealed(sealed: &[u8], key: &[u8]) -> Result<u64, i32> {
    let mut handle = u64::MAX;
    let code = unsafe {
        kc_open_sealed(sealed.as_ptr(), sealed.len(), key.as_ptr(), key.len(), &mut handle)
    };
    if code == KC_OK {
        Ok(handle)
    } else {
        assert_eq!(handle, 0, "a refused open left a handle");
        Err(code)
    }
}

/// [plain] sealed as the wallet seals it (`CryptoUtils.encryptBytes`):
/// [nonce], then the ciphertext and its tag. The nonce is the test's, so the
/// record is the same on every run.
fn seal(plain: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut buffer = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], &mut buffer)
        .unwrap();
    [nonce.as_slice(), &buffer, tag.as_slice()].concat()
}

fn public_key(handle: u64, path: &str, format: i32) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; if format == KC_PUBLIC_KEY_UNCOMPRESSED { 65 } else { 33 }];
    let code = unsafe {
        kc_secp256k1_public_key(
            handle,
            path.as_ptr(),
            path.len(),
            format,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK { Ok(out) } else { Err(code) }
}

fn sign(handle: u64, path: &str, digest: &[u8]) -> Result<[u8; 65], i32> {
    let mut out = [0u8; 65];
    let code = unsafe {
        kc_secp256k1_sign_digest(
            handle,
            path.as_ptr(),
            path.len(),
            digest.as_ptr(),
            digest.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 65], "a refused signature wrote its output");
        Err(code)
    }
}

fn export(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_secp256k1_export_private_key(
            handle,
            path.as_ptr(),
            path.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK { Ok(out) } else { Err(code) }
}

fn sign_low_r(handle: u64, path: &str, digest: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    let code = unsafe {
        kc_secp256k1_sign_digest_low_r(
            handle,
            path.as_ptr(),
            path.len(),
            digest.as_ptr(),
            digest.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 64], "a refused signature wrote its output");
        Err(code)
    }
}

fn schnorr(handle: u64, path: &str, digest: &[u8], tweak: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    let tweak_ptr = if tweak.is_empty() { core::ptr::null() } else { tweak.as_ptr() };
    let code = unsafe {
        kc_secp256k1_schnorr_sign(
            handle,
            path.as_ptr(),
            path.len(),
            digest.as_ptr(),
            digest.len(),
            tweak_ptr,
            tweak.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 64], "a refused signature wrote its output");
        Err(code)
    }
}

fn ed_public_key(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_ed25519_public_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 32], "a refused public key wrote its output");
        Err(code)
    }
}

fn ed_sign(handle: u64, path: &str, message: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    // A message of no bytes still comes through a real pointer, as the binding
    // passes it.
    let byte = 0u8;
    let message_ptr = if message.is_empty() { &byte as *const u8 } else { message.as_ptr() };
    let code = unsafe {
        kc_ed25519_sign(
            handle,
            path.as_ptr(),
            path.len(),
            message_ptr,
            message.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 64], "a refused signature wrote its output");
        Err(code)
    }
}

fn ed_export(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_ed25519_export_private_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 32], "a refused export wrote its output");
        Err(code)
    }
}

fn cd_public_key(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_cardano_public_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 32], "a refused public key wrote its output");
        Err(code)
    }
}

fn cd_sign(handle: u64, path: &str, message: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    let byte = 0u8;
    let message_ptr = if message.is_empty() { &byte as *const u8 } else { message.as_ptr() };
    let code = unsafe {
        kc_cardano_sign(
            handle,
            path.as_ptr(),
            path.len(),
            message_ptr,
            message.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 64], "a refused signature wrote its output");
        Err(code)
    }
}

fn cd_export(handle: u64, path: &str) -> Result<[u8; 96], i32> {
    let mut out = [0u8; 96];
    let code = unsafe {
        kc_cardano_export_private_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 96], "a refused export wrote its output");
        Err(code)
    }
}

fn icarus_public_key(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_cardano_icarus_public_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 32], "a refused Icarus key wrote its output");
        Err(code)
    }
}

/// [`kc_matches_phrase`]'s answer, with its byte started at neither 0 nor 1,
/// so an answer it forgot to write is seen.
fn matches(handle: u64, candidate: &[u8]) -> Result<bool, i32> {
    let mut out = 0xa5u8;
    let code = unsafe { kc_matches_phrase(handle, candidate.as_ptr(), candidate.len(), &mut out) };
    if code == KC_OK {
        assert!(out <= 1, "an answer of {out}");
        Ok(out == 1)
    } else {
        assert_eq!(out, 0, "a refusal left an answer");
        Err(code)
    }
}

fn sk_public_key(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_starknet_public_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK { Ok(out) } else { assert_eq!(out, [0u8; 32]); Err(code) }
}

fn sk_sign(handle: u64, path: &str, hash: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    let code = unsafe {
        kc_starknet_sign(
            handle,
            path.as_ptr(),
            path.len(),
            hash.as_ptr(),
            hash.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK { Ok(out) } else { assert_eq!(out, [0u8; 64], "a refused signature wrote its output"); Err(code) }
}

fn sk_export(handle: u64, path: &str) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let code = unsafe {
        kc_starknet_export_private_key(handle, path.as_ptr(), path.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK { Ok(out) } else { assert_eq!(out, [0u8; 32]); Err(code) }
}

/// A hash below 2^251 that looks random and is the same every run.
fn stark_hash(n: u64) -> [u8; 32] {
    let mut hash: [u8; 32] = sequence(n + 77, 32).try_into().unwrap();
    hash[0] &= 0x07;
    hash
}

fn node96(text: &str) -> keys::CardanoNode {
    zeroize::Zeroizing::new(hex(text).try_into().unwrap())
}

fn bytes32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

/// The x-only key at [at] below [handle]'s seed, tweaked by [tweak] the way
/// BIP-341's `taproot_tweak_pubkey` does — by the library's own call on the
/// public side, which never touches the secret path under test.
fn x_only(handle: u64, at: &str, tweak: Option<&[u8; 32]>) -> XOnlyPublicKey {
    let public = PublicKey::from_slice(&public_key(handle, at, KC_PUBLIC_KEY_COMPRESSED).unwrap())
        .unwrap();
    let (x, _) = public.x_only_public_key();
    match tweak {
        None => x,
        Some(tweak) => x.add_tweak(&Scalar::from_be_bytes(*tweak).unwrap()).unwrap().0,
    }
}

fn path(text: &str) -> bip32::DerivationPath {
    keys::parse_path(text.as_bytes()).unwrap()
}

// --- Published vectors -----------------------------------------------------

#[test]
fn bip39_vectors_give_the_published_seed_and_master_key() {
    for (entropy, phrase, seed, master) in BIP39_TREZOR {
        let got = keys::seed_from_phrase(phrase.as_bytes(), "TREZOR").unwrap();
        assert_eq!(to_hex(&got[..]), seed, "seed of {entropy}");
        let key = keys::derive(&got[..], &path("m")).unwrap();
        assert_eq!(to_hex(&key.secret().to_secret_bytes()), master, "master of {entropy}");
    }
}

#[test]
fn bip32_vectors_give_the_published_keys() {
    for (seed, at, key, public) in BIP32 {
        let derived = keys::derive(&hex(seed), &path(at)).unwrap();
        assert_eq!(to_hex(&derived.secret().to_secret_bytes()), key, "key at {at}");
        assert_eq!(to_hex(&keys::public_key(&derived).serialize()), public, "public key at {at}");
    }
}

#[test]
fn the_extended_public_key_is_the_chain_code_and_the_public_key() {
    // The chain code is checked against `bip32`'s own extended key and the
    // public key against the published vectors; what this adds is the layout
    // the binding reads, and the refusals.
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    for at in ["m", "m/84'/0'/0'", "m/84'/0'/0'/0/7"] {
        let mut out = [0u8; 65];
        let code = unsafe {
            kc_secp256k1_extended_public_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), 65)
        };
        assert_eq!(code, KC_OK, "at {at}");
        let extended = ExtendedPrivateKey::<SecretKey>::derive_from_path(&seed[..], &path(at)).unwrap();
        assert_eq!(to_hex(&out[..32]), to_hex(&extended.attrs().chain_code), "chain code at {at}");
        assert_eq!(out[32..].to_vec(), public_key(handle, at, KC_PUBLIC_KEY_COMPRESSED).unwrap(), "public key at {at}");
    }
    for length in [64usize, 66] {
        let mut out = vec![0u8; length];
        let code = unsafe {
            kc_secp256k1_extended_public_key(handle, "m".as_ptr(), 1, out.as_mut_ptr(), length)
        };
        assert_eq!(code, KC_ERR_ARGUMENT, "into {length} bytes");
    }
    assert_eq!(kc_close(handle), KC_OK);
    let mut out = [0u8; 65];
    let code = unsafe { kc_secp256k1_extended_public_key(handle, "m".as_ptr(), 1, out.as_mut_ptr(), 65) };
    assert_eq!(code, KC_ERR_HANDLE);
}

#[test]
fn the_rfc_6979_vector_this_repository_pins() {
    // `test/evm_key_test.dart` pins it for the Dart signer: private key 1 over
    // the SHA-256 of "Satoshi Nakamoto", low `s`.
    let digest: [u8; 32] =
        hex("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e")
            .try_into()
            .unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    let key = DerivedKey::from_secret(SecretKey::from_secret_bytes(one).unwrap());
    let signature = keys::sign_digest(&key, &digest).unwrap();
    assert_eq!(
        to_hex(&signature[..32]),
        "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
    );
    assert_eq!(
        to_hex(&signature[32..64]),
        "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
    );
    assert_eq!(recovered(&signature, &digest), keys::public_key(&key));
}

#[test]
fn bip340_vectors_give_the_published_signatures() {
    for (index, (secret, public, aux, message, signature)) in BIP340.iter().enumerate() {
        let keypair = Keypair::from_secret_bytes(bytes32(secret)).unwrap();
        assert_eq!(
            to_hex(&keypair.x_only_public_key().0.to_byte_array()),
            *public,
            "public key of vector {index}"
        );
        let got =
            keys::schnorr_sign_with_aux(&keypair, &bytes32(message), &bytes32(aux)).unwrap();
        assert_eq!(to_hex(&got), *signature, "signature of vector {index}");
    }
}

#[test]
fn slip10_vectors_give_the_published_ed25519_keys() {
    // The core's own SLIP-10 (decision O13) against the specification's.
    for (seed, at, chain_code, key, public) in SLIP10_ED25519 {
        let node = keys::slip10_ed25519(&hex(seed), &path(at)).unwrap();
        assert_eq!(to_hex(&node[..32]), key, "key at {at}");
        assert_eq!(to_hex(&node[32..]), chain_code, "chain code at {at}");
        let derived = keys::derive_ed25519(&hex(seed), &path(at)).unwrap();
        assert_eq!(to_hex(&keys::ed25519_public_key(&derived)), public, "public key at {at}");
        assert_eq!(to_hex(&keys::ed25519_secret(&derived)[..]), key, "export at {at}");
    }
}

#[test]
fn rfc8032_vectors_give_the_published_signatures() {
    for (index, (secret, public, message, signature)) in RFC8032.iter().enumerate() {
        let key = Ed25519Key::from_secret(&bytes32(secret));
        assert_eq!(to_hex(&keys::ed25519_public_key(&key)), *public, "public key of TEST {index}");
        let got = keys::ed25519_sign(&key, &hex(message)).unwrap();
        assert_eq!(to_hex(&got), *signature, "signature of TEST {index}");
    }
}

#[test]
fn cip_0003_vectors_give_the_ledger_master_keys() {
    // The Ledger scheme as CIP-0003 publishes it: one vector hashes once, one
    // hashes again (the loop), one has a passphrase (BIP-39's, before this).
    for (phrase, passphrase, master) in CARDANO_LEDGER {
        let seed = keys::seed_from_phrase(phrase.as_bytes(), passphrase).unwrap();
        let node = keys::cardano_ledger_master(&seed[..]).unwrap();
        assert_eq!(to_hex(&node[..]), master, "{phrase:.20}… passphrase {passphrase:?}");
    }
}

#[test]
fn cip_0003_vectors_give_the_icarus_master_keys() {
    // The Icarus scheme as CIP-0003 publishes it, from the entropy the session
    // keeps: one vector with no passphrase — the wallet's case — and one with.
    for (phrase, passphrase, master) in CARDANO_ICARUS {
        let (_, entropy) = keys::phrase_secrets(phrase.as_bytes()).unwrap();
        let node = keys::cardano_icarus_master_with(entropy.as_bytes(), passphrase.as_bytes()).unwrap();
        assert_eq!(to_hex(&node[..]), master, "{phrase:.20}… passphrase {passphrase:?}");
        if passphrase.is_empty() {
            assert_eq!(keys::cardano_icarus_master(entropy.as_bytes()).unwrap()[..], node[..]);
            // And through a session: the master's public key, at `m`.
            let _abi = abi();
            let handle = open(phrase.as_bytes()).unwrap();
            assert_eq!(icarus_public_key(handle, "m").unwrap(), keys::cardano_public_key(&node));
            assert_eq!(kc_close(handle), KC_OK);
        }
    }
}

#[test]
fn ed25519_bip32_vectors_give_the_child_and_its_signature() {
    for (parent, index, child, message, signature) in CARDANO_BIP32 {
        let derived = keys::cardano_child(&node96(parent), bip32::ChildNumber(index)).unwrap();
        assert_eq!(to_hex(&derived[..64]), &child[..128], "extended key");
        assert_eq!(to_hex(&derived[64..]), &child[128..], "chain code");
        let signed = keys::cardano_sign(&derived, &hex(message)).unwrap();
        assert_eq!(to_hex(&signed), signature);
    }
}

#[test]
fn a_normal_cardano_child_is_its_parents_public_key_plus_eight_z() {
    // Khovratovich–Law's point, checked on the public side: a normal child's
    // public key is A + 8·trunc28(Z)·B and its chain code the right half of
    // the 0x03 HMAC, which needs nothing secret — so the private derivation
    // under test meets an independent computation, at the levels CIP-1852
    // leaves normal.
    use curve25519_dalek::{EdwardsPoint, Scalar as EdScalar};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use hmac::{Hmac, KeyInit, Mac};
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let account = keys::derive_cardano(&seed[..], &path("m/1852'/1815'/0'")).unwrap();
    for role in [0u32, 1, 2] {
        let parent = keys::cardano_child(&account, bip32::ChildNumber(role)).unwrap();
        let a = keys::cardano_public_key(&parent);
        for index in [0u32, 1, 7, 19, 1000] {
            let mac = |tag: u8| {
                let mut m = Hmac::<sha2::Sha512>::new_from_slice(&parent[64..]).unwrap();
                m.update(&[tag]);
                m.update(&a);
                m.update(&index.to_le_bytes());
                m.finalize().into_bytes()
            };
            let z = mac(0x02);
            let mut eight_z = [0u8; 32];
            let mut carry = 0u16;
            for i in 0..32 {
                let v = if i < 28 { u16::from(z[i]) << 3 } else { 0 } + carry;
                eight_z[i] = v as u8;
                carry = v >> 8;
            }
            let expected: EdwardsPoint = CompressedEdwardsY(a).decompress().unwrap()
                + EdwardsPoint::mul_base(&EdScalar::from_bytes_mod_order(eight_z));
            let child = keys::cardano_child(&parent, bip32::ChildNumber(index)).unwrap();
            assert_eq!(keys::cardano_public_key(&child), expected.compress().to_bytes(), "{role}/{index}");
            assert_eq!(child[64..], mac(0x03)[32..], "chain code {role}/{index}");
        }
    }
}

#[test]
fn starkware_vectors_give_the_published_stark_keys_and_grind() {
    // StarkWare's own key derivation, Apache-2.0: starkex-resources,
    // crypto/starkware/crypto/signature/test/key_derivation_test.js. A BIP-39
    // phrase's seed is the BIP-32 seed, a path is derived on secp256k1, and
    // the key is ground below the Stark curve's order — the same three steps
    // Argent's scheme takes from its own seed, held here to a source whose
    // licence lets a commercial wallet carry it (the owner, 6 November 2026:
    // Argent X's test file is under a non-commercial licence, and its vectors
    // were replaced). The paths are EIP-2645's for layer "starkex",
    // application "starkdeployement" and 0xa4864d977b944315389d1765ffa7e66F74ee8cd7,
    // as `getAccountPath` computes them; the first is EIP-2645's own example.
    let phrase = "range mountain blast problem vibrant void vivid doctor cluster enough melody \
                  salt layer language laptop boat major space monkey unit glimpse pause change vibrant";
    let seed = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
    for (index, private) in [
        (0, "06cf0a8bf113352eb863157a45c5e5567abb34f8d32cddafd2c22aa803f4892c"),
        (7, "0341751bdc42841da35ab74d13a1372c1f0250617e8a2ef96034d9f46e6847af"),
        (598, "041a4d591a868353d28b7947eb132aa4d00c4a022743689ffd20a3628d6ca28c"),
    ] {
        let at = path(&format!("m/2645'/579218131'/891216374'/1961790679'/2135936222'/{index}"));
        let mut tree = Zeroizing::new([0u8; 32]);
        tree.copy_from_slice(&keys::derive_from_any_seed(&seed[..], &at).unwrap().secret().to_secret_bytes());
        assert_eq!(to_hex(&keys::stark_grind(&tree).unwrap()[..]), private, "index {index}");
    }
    // The same file's grindKey vector.
    let ground = keys::stark_grind(&bytes32("86f3e7293141f20a8baff320e8ee4accb9d4a4bf2b4d295e8cee784db46e0519")).unwrap();
    assert_eq!(to_hex(&ground[..]), "05c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941");
    // And a Stark public key, from `starknet-crypto`'s own test
    // (`test_get_public_key_1`, MIT OR Apache-2.0): the byte order and padding
    // the core puts around the crate are what this checks.
    let key = bytes32("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc");
    assert_eq!(
        to_hex(&keys::starknet_public_key(&key)),
        "077a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43"
    );
}

#[test]
fn the_second_tree_is_bip32_for_every_seed_length_bip32_takes() {
    // `derive_from_any_seed` computes the master key itself; for the lengths
    // `bip32` takes it must be `bip32`'s master and children exactly.
    for (length, at) in [(16usize, "m/44'/9004'/0'/0/0"), (32, "m/44'/9004'/0'/0/3"), (64, "m/0/1'/2")] {
        let seed = sequence(length as u64, length);
        let mine = keys::derive_from_any_seed(&seed, &path(at)).unwrap();
        let theirs = ExtendedPrivateKey::<SecretKey>::derive_from_path(&seed, &path(at)).unwrap();
        assert_eq!(mine.secret().to_secret_bytes(), theirs.private_key().to_secret_bytes(), "{length} bytes");
    }
}

#[test]
fn a_starknet_key_comes_from_the_first_ethereum_key() {
    // The abandon phrase's first Ethereum key (the one every Ethereum tool
    // derives for it), then Argent's second step.
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let eth = bytes32("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727");
    for index in 0..3 {
        let at = path(&format!("m/44'/9004'/0'/0/{index}"));
        assert_eq!(
            keys::derive_starknet(&seed[..], &at).unwrap()[..],
            keys::starknet_from_secret(&eth, &at).unwrap()[..],
            "account {index}"
        );
    }
    // A secret with a leading zero byte seeds the tree with 31 bytes, so its
    // key is not the one all 32 bytes give.
    let mut zero_led = eth;
    zero_led[0] = 0;
    let at = path(STARKNET_0);
    let short = keys::starknet_from_secret(&zero_led, &at).unwrap();
    let mut all = Zeroizing::new([0u8; 32]);
    all.copy_from_slice(&keys::derive_from_any_seed(&zero_led, &at).unwrap().secret().to_secret_bytes());
    assert_ne!(short[..], keys::stark_grind(&all).unwrap()[..]);
}

fn recovered(signature: &[u8; 65], digest: &[u8; 32]) -> PublicKey {
    let id = RecoveryId::try_from(i32::from(signature[64])).unwrap();
    RecoverableSignature::from_compact(&signature[..64], id)
        .unwrap()
        .recover_ecdsa(Message::from_digest(*digest))
        .unwrap()
}

// --- What a handle answers -------------------------------------------------

#[test]
fn a_signature_recovers_to_the_key_reported_for_its_path_and_has_a_low_s() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    // No network's path: ICP's and then Kaspa's, here until 2f-19 and
    // 2f-20, sign only what the core read for a screen.
    for (i, at) in [DIGEST_0, "m/1'/2'/3'/4/6", "m/0/7/3", "m/2'/3'/4'/5/6"]
        .iter()
        .enumerate()
    {
        let reported = public_key(handle, at, KC_PUBLIC_KEY_COMPRESSED).unwrap();
        for n in 0..25 {
            let digest: [u8; 32] = sequence(1 + (i * 100 + n) as u64, 32).try_into().unwrap();
            let signature = sign(handle, at, &digest).unwrap();
            assert_eq!(recovered(&signature, &digest).serialize().to_vec(), reported, "{at} #{n}");
            let plain = Signature::from_compact(&signature[..64]).unwrap();
            let mut low = plain;
            low.normalize_s();
            assert_eq!(low, plain, "{at} #{n}: high s");
            // Deterministic: the same request is the same signature.
            assert_eq!(sign(handle, at, &digest).unwrap(), signature, "{at} #{n}");
        }
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_public_keys_and_the_export_are_one_key() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let compressed = public_key(handle, EVM_0, KC_PUBLIC_KEY_COMPRESSED).unwrap();
    let uncompressed = public_key(handle, EVM_0, KC_PUBLIC_KEY_UNCOMPRESSED).unwrap();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(
        PublicKey::from_slice(&compressed).unwrap(),
        PublicKey::from_slice(&uncompressed).unwrap()
    );
    let exported = export(handle, EVM_0).unwrap();
    let key = DerivedKey::from_secret(SecretKey::from_secret_bytes(exported).unwrap());
    assert_eq!(keys::public_key(&key).serialize().to_vec(), compressed);
    // And it is the key the seed gives at that path, not some other.
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    assert_eq!(keys::derive(&seed[..], &path(EVM_0)).unwrap().secret().to_secret_bytes(), exported);
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn two_phrases_are_two_wallets() {
    let _abi = abi();
    let a = open(ABANDON.as_bytes()).unwrap();
    let b = open(LEGAL.as_bytes()).unwrap();
    assert_ne!(export(a, EVM_0).unwrap(), export(b, EVM_0).unwrap());
    assert_eq!(kc_close(a), KC_OK);
    // Closing one leaves the other as it was.
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let expected = keys::derive(&seed[..], &path(EVM_0)).unwrap().secret().to_secret_bytes();
    assert_eq!(export(b, EVM_0).unwrap(), expected);
    assert_eq!(kc_close(b), KC_OK);
}

#[test]
fn a_bitcoin_signature_has_a_low_r_and_is_the_grind_written_out() {
    // The grind from its definition, not from `keys`: plain RFC 6979 first,
    // then the attempt number as 32 bytes of big-endian nonce data, until the
    // first byte of `r` is below 0x80.
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    // Outside the Bitcoin family, whose keys sign no bare digest since O37:
    // the grind itself is what `src/bitcoin.rs` signs every input with.
    let at = "m/84'/111111'/0'/0/0";
    let key = keys::derive(&seed[..], &path(at)).unwrap();
    let public = keys::public_key(&key);
    let half_order = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
    let mut ground = 0;
    for (i, digest) in sequence(84, 32 * 200).chunks(32).enumerate() {
        let digest: [u8; 32] = digest.try_into().unwrap();
        let got = sign_low_r(handle, at, &digest).unwrap();
        assert!(got[0] < 0x80, "digest {i}: r is high");
        assert!(to_hex(&got[32..]).as_str() <= half_order, "digest {i}: s is high");
        let message = Message::from_digest(digest);
        Signature::from_compact(&got).unwrap().verify(message, &public).unwrap();

        let mut expected = secp256k1::ecdsa::sign(message, key.secret());
        let mut attempt: u64 = 0;
        while expected.serialize_compact()[0] >= 0x80 {
            attempt += 1;
            let mut extra = [0u8; 32];
            extra[24..].copy_from_slice(&attempt.to_be_bytes());
            expected = secp256k1::ecdsa::sign_with_noncedata(message, key.secret(), &extra);
        }
        ground += usize::from(attempt > 0);
        assert_eq!(to_hex(&got), to_hex(&expected.serialize_compact()), "digest {i}");
    }
    // About half of all first signatures have a high `r`.
    assert!((60..140).contains(&ground), "{ground} of 200 needed grinding");
    assert_eq!(sign_low_r(handle, at, &[0u8; 32]), Err(KC_ERR_DIGEST));
    assert_eq!(sign_low_r(handle, at, &[0xffu8; 32]), Err(KC_ERR_DIGEST));
    assert_eq!(sign_low_r(handle, at, &[1u8; 31]), Err(KC_ERR_ARGUMENT));
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(sign_low_r(handle, at, &[1u8; 32]), Err(KC_ERR_HANDLE));
}

#[test]
fn a_schnorr_signature_verifies_against_its_key_and_its_tweaked_key() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let digest = [0x5au8; 32];
    let tweak = bytes32("6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30");
    for at in [DIGEST_0, "m/1'/2'/3'/4/6", "m"] {
        let plain = schnorr(handle, at, &digest, &[]).unwrap();
        schnorr::verify(&schnorr::Signature::from_byte_array(plain), &digest, &x_only(handle, at, None))
            .unwrap_or_else(|_| panic!("untweaked signature at {at}"));
        let tweaked = schnorr(handle, at, &digest, &tweak).unwrap();
        schnorr::verify(
            &schnorr::Signature::from_byte_array(tweaked),
            &digest,
            &x_only(handle, at, Some(&tweak)),
        )
        .unwrap_or_else(|_| panic!("tweaked signature at {at}"));
        // A tweaked signature does not verify against the untweaked key.
        assert!(
            schnorr::verify(&schnorr::Signature::from_byte_array(tweaked), &digest, &x_only(handle, at, None))
                .is_err()
        );
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_auxiliary_bytes_are_the_sha256_of_the_digest_and_the_signing_key() {
    // The derivation `blockchain_utils`' `signBip340Const` uses when it is
    // given no aux, written out from its definition rather than from
    // `keys::schnorr_sign`: SHA-256(digest || the key that signs, tweaked
    // before BIP-340's parity flip).
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let key = keys::derive(&seed[..], &path(DIGEST_0)).unwrap();
    let tweak = bytes32("0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710");
    for (digest, tweaked) in [([1u8; 32], false), ([0xffu8; 32], true), ([0u8; 32], true)] {
        let mut keypair = Keypair::from_secret_key(key.secret());
        if tweaked {
            keypair = keypair.add_xonly_tweak(&Scalar::from_be_bytes(tweak).unwrap()).unwrap();
        }
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(keypair.to_secret_bytes());
        let aux: [u8; 32] = hasher.finalize().into();
        let expected = keys::schnorr_sign_with_aux(&keypair, &digest, &aux).unwrap();
        let got = schnorr(handle, DIGEST_0, &digest, if tweaked { &tweak } else { &[] }).unwrap();
        assert_eq!(to_hex(&got), to_hex(&expected), "tweaked: {tweaked}");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn schnorr_refuses_bad_lengths_tweaks_and_handles() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let digest = [7u8; 32];
    for length in [1usize, 31, 33, 64] {
        assert_eq!(
            schnorr(handle, DIGEST_0, &digest, &vec![1u8; length]),
            Err(KC_ERR_ARGUMENT),
            "a tweak of {length} bytes"
        );
    }
    // Not below the order: no tagged hash a wallet makes, and not reduced here.
    assert_eq!(schnorr(handle, DIGEST_0, &digest, &[0xffu8; 32]), Err(KC_ERR_ARGUMENT));
    assert_eq!(schnorr(handle, DIGEST_0, &[7u8; 31], &[]), Err(KC_ERR_ARGUMENT));
    assert_eq!(schnorr(handle, "m/86h/0h", &digest, &[]), Err(KC_ERR_PATH));
    // A 32-byte tweak behind a null pointer is a null pointer, not "no tweak".
    let mut out = [0u8; 64];
    let code = unsafe {
        kc_secp256k1_schnorr_sign(
            handle,
            DIGEST_0.as_ptr(),
            DIGEST_0.len(),
            digest.as_ptr(),
            32,
            core::ptr::null(),
            32,
            out.as_mut_ptr(),
            64,
        )
    };
    assert_eq!(code, KC_ERR_ARGUMENT);
    for length in [63usize, 65] {
        let mut out = vec![0u8; length];
        let code = unsafe {
            kc_secp256k1_schnorr_sign(
                handle,
                DIGEST_0.as_ptr(),
                DIGEST_0.len(),
                digest.as_ptr(),
                32,
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
                length,
            )
        };
        assert_eq!(code, KC_ERR_ARGUMENT, "into {length} bytes");
        assert!(out.iter().all(|&b| b == 0), "a refusal wrote output");
    }
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(schnorr(handle, DIGEST_0, &digest, &[]), Err(KC_ERR_HANDLE));
}

// --- Handles ---------------------------------------------------------------

#[test]
fn a_closed_handle_signs_nothing() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(sign(handle, EVM_0, &[7u8; 32]), Err(KC_ERR_HANDLE));
    assert_eq!(public_key(handle, EVM_0, KC_PUBLIC_KEY_COMPRESSED), Err(KC_ERR_HANDLE));
    assert_eq!(export(handle, EVM_0), Err(KC_ERR_HANDLE));
    assert_eq!(kc_close(handle), KC_ERR_HANDLE, "closed twice");
}

#[test]
fn a_handle_is_never_issued_twice() {
    let _abi = abi();
    let first = open(ABANDON.as_bytes()).unwrap();
    assert_eq!(kc_close(first), KC_OK);
    let second = open(ABANDON.as_bytes()).unwrap();
    assert_ne!(first, second);
    // The old number does not reach the new session, same phrase or not.
    assert_eq!(export(first, EVM_0), Err(KC_ERR_HANDLE));
    assert!(export(second, EVM_0).is_ok());
    assert_eq!(kc_close(second), KC_OK);
}

#[test]
fn one_session_from_many_threads_gives_each_thread_the_same_answers() {
    // Two Dart isolates calling the core are two threads calling it: the
    // table's lock serialises them, and an answer must not depend on who else
    // is asking. Eight threads, every kind of key, against the answers one
    // thread gets alone.
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let expected = (
        sign(handle, DIGEST_0, &[3u8; 32]).unwrap(),
        ed_sign(handle, ED_0, b"isolate").unwrap(),
        cd_sign(handle, CARDANO_FREE, b"isolate").unwrap(),
        sk_sign(handle, STARKNET_FREE, &stark_hash(9)).unwrap(),
    );
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..12 {
                    assert_eq!(sign(handle, DIGEST_0, &[3u8; 32]).unwrap(), expected.0);
                    assert_eq!(ed_sign(handle, ED_0, b"isolate").unwrap(), expected.1);
                    assert_eq!(cd_sign(handle, CARDANO_FREE, b"isolate").unwrap(), expected.2);
                    assert_eq!(sk_sign(handle, STARKNET_FREE, &stark_hash(9)).unwrap(), expected.3);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a thread panicked");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn closing_while_other_threads_sign_leaves_them_a_refusal_or_a_true_answer() {
    // The lock is the whole guarantee: a close waits for the signature in
    // progress, and after it every caller is refused. No caller may see a
    // half-erased seed — a signature over it would not verify against the
    // key the open seed gives, which is what this checks of every answer.
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let public = PublicKey::from_slice(&public_key(handle, DIGEST_0, KC_PUBLIC_KEY_COMPRESSED).unwrap()).unwrap();
    let signers: Vec<_> = (0..6)
        .map(|n| {
            std::thread::spawn(move || {
                let mut refused = 0;
                for i in 0..400u32 {
                    let digest: [u8; 32] = sequence(u64::from(n * 1000 + i) + 1, 32).try_into().unwrap();
                    match sign(handle, DIGEST_0, &digest) {
                        Ok(signature) => {
                            let key = recovered(&signature, &digest);
                            assert_eq!(key, public, "a signature by a key not this wallet's");
                        }
                        Err(code) => {
                            assert_eq!(code, KC_ERR_HANDLE);
                            refused += 1;
                        }
                    }
                }
                refused
            })
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(kc_close(handle), KC_OK);
    let refused: u32 = signers.into_iter().map(|t| t.join().expect("a thread panicked")).sum();
    eprintln!("closing mid-flight: {refused} of 2400 signatures refused after the close");
    assert!(refused > 0, "the close landed after every signature, so this proved nothing");
    assert_eq!(sign(handle, DIGEST_0, &[3u8; 32]), Err(KC_ERR_HANDLE));
}

#[test]
fn a_close_waits_for_every_call_that_is_using_the_seed() {
    // The lock model (`docs/RUST_KEY_CORE_DESIGN.md#phase-5a`): a call holds
    // the table's lock for its whole derivation and signature, so a close
    // that arrives mid-call returns only after it. A model that copied the
    // seed out and let the lock go before deriving would sign correctly too —
    // the test above cannot tell the two apart — and would still be using
    // the seed after `kc_close` had said it was erased. Each of the
    // seventeen calls that reads a seed is held inside its derivation here
    // while another thread closes, and must not see the close return.
    let _abi = abi();
    let calls: [(&str, fn(u64) -> bool); 16] = [
        ("secp256k1 public key", |h| public_key(h, EVM_0, KC_PUBLIC_KEY_COMPRESSED).is_ok()),
        ("secp256k1 signature", |h| sign(h, DIGEST_0, &[3u8; 32]).is_ok()),
        ("secp256k1 export", |h| export(h, EVM_0).is_ok()),
        ("secp256k1 extended public key", |h| {
            let mut out = [0u8; 65];
            let code = unsafe {
                kc_secp256k1_extended_public_key(h, EVM_0.as_ptr(), EVM_0.len(), out.as_mut_ptr(), 65)
            };
            code == KC_OK
        }),
        ("low-R signature", |h| sign_low_r(h, DIGEST_0, &[3u8; 32]).is_ok()),
        ("Schnorr signature", |h| schnorr(h, DIGEST_0, &[3u8; 32], &[]).is_ok()),
        ("ed25519 public key", |h| ed_public_key(h, SOLANA_0).is_ok()),
        ("ed25519 signature", |h| ed_sign(h, ED_0, b"held").is_ok()),
        ("ed25519 export", |h| ed_export(h, SOLANA_0).is_ok()),
        ("Cardano public key", |h| cd_public_key(h, CARDANO_0).is_ok()),
        ("Cardano signature", |h| cd_sign(h, CARDANO_FREE, b"held").is_ok()),
        ("Cardano export", |h| cd_export(h, CARDANO_0).is_ok()),
        ("Starknet public key", |h| sk_public_key(h, STARKNET_0).is_ok()),
        ("Starknet signature", |h| sk_sign(h, STARKNET_FREE, &stark_hash(9)).is_ok()),
        ("Starknet export", |h| sk_export(h, STARKNET_0).is_ok()),
        ("personal message signature", |h| sign_personal(h, EVM_0, b"held").is_ok()),
    ];
    // And a one-key session's calls (O22), which read their key under the
    // same lock; and the typed data signatures, whose reading takes the key
    // under the lock too, so it is made when the session is opened.
    let phrase: fn() -> u64 = || open(LEGAL.as_bytes()).unwrap();
    let key_calls: [(&str, fn() -> u64, fn(u64) -> bool); 11] = [
        ("typed data signature", || {
            let h = open(LEGAL.as_bytes()).unwrap();
            read_typed_for(h, EVM_0, EIP712_HASHED[0].1).unwrap();
            h
        }, |h| sign_typed_unread(h, EVM_0, EIP712_HASHED[0].1).is_ok()),
        ("imported secp256k1 public key", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            public_key(h, "m", KC_PUBLIC_KEY_COMPRESSED).is_ok()
        }),
        ("imported secp256k1 signature", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            sign(h, "m", &[3u8; 32]).is_ok()
        }),
        ("imported low-R signature", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            sign_low_r(h, "m", &[3u8; 32]).is_ok()
        }),
        ("imported Schnorr signature", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            schnorr(h, "m", &[3u8; 32], &[]).is_ok()
        }),
        ("imported secp256k1 export", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            export(h, "m").is_ok()
        }),
        ("imported ed25519 public key", || open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap(), |h| {
            ed_public_key(h, "m").is_ok()
        }),
        ("imported ed25519 signature", || open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap(), |h| {
            ed_sign(h, "m", b"held").is_ok()
        }),
        ("imported ed25519 export", || open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap(), |h| {
            ed_export(h, "m").is_ok()
        }),
        ("imported typed data signature", || {
            let h = open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap();
            read_typed_for(h, "m", EIP712_HASHED[0].1).unwrap();
            h
        }, |h| sign_typed_unread(h, "m", EIP712_HASHED[0].1).is_ok()),
        ("imported personal message signature", || open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), |h| {
            sign_personal(h, "m", b"held").is_ok()
        }),
    ];
    let every = calls.iter().map(|&(name, call)| (name, phrase, call)).chain(key_calls);
    for (name, opener, call) in every {
        let handle = opener();
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::clone(&closed);
        let (inside, entered) = std::sync::mpsc::channel();
        let caller = std::thread::spawn(move || {
            let closed_while_inside = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let noted = std::sync::Arc::clone(&closed_while_inside);
            INSIDE_THE_LOCK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let _ = inside.send(());
                    // Long enough for a close that did not wait to have
                    // returned and been noted.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    noted.store(seen.load(Ordering::SeqCst), Ordering::SeqCst);
                }));
            });
            (call(handle), closed_while_inside.load(Ordering::SeqCst))
        });
        entered
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("{name}: never reached the seed under the table's lock"));
        assert_eq!(kc_close(handle), KC_OK, "{name}");
        closed.store(true, Ordering::SeqCst);
        let (answered, closed_while_inside) = caller.join().expect("the caller panicked");
        assert!(answered, "{name}: the call that held the lock was refused");
        assert!(!closed_while_inside, "{name}: kc_close returned while the call was using the seed");
    }
}

#[test]
fn zero_and_unknown_handles_are_refused() {
    let _abi = abi();
    for handle in [0, u64::MAX, NEXT_HANDLE.load(Ordering::Relaxed) + 1000] {
        assert_eq!(sign(handle, EVM_0, &[7u8; 32]), Err(KC_ERR_HANDLE), "{handle}");
        assert_eq!(kc_close(handle), KC_ERR_HANDLE, "{handle}");
    }
}

#[test]
fn close_all_closes_every_handle() {
    let _abi = abi();
    let before = sessions().len() as u64;
    let a = open(ABANDON.as_bytes()).unwrap();
    let b = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(kc_close_all(), before + 2);
    assert_eq!(export(a, EVM_0), Err(KC_ERR_HANDLE));
    assert_eq!(export(b, EVM_0), Err(KC_ERR_HANDLE));
    assert_eq!(kc_close_all(), 0);
}

// --- Refusals --------------------------------------------------------------

/// Text that is not a phrase in the form the wallet stores, each with why.
fn not_a_stored_phrase() -> Vec<(&'static str, Vec<u8>)> {
    let twelve_abandons = ["abandon"; 12].join(" ");
    let eleven = ABANDON.rsplit_once(' ').unwrap().0.to_string();
    let long = "abandon ".repeat(70);
    vec![
        ("bad checksum", twelve_abandons.into_bytes()),
        ("eleven words", eleven.into_bytes()),
        ("a word not in the list", ABANDON.replace("about", "aboot").into_bytes()),
        ("upper case", ABANDON.replace("about", "About").into_bytes()),
        ("two spaces", ABANDON.replacen(' ', "  ", 1).into_bytes()),
        ("a leading space", format!(" {ABANDON}").into_bytes()),
        ("a trailing space", format!("{ABANDON} ").into_bytes()),
        ("a tab", ABANDON.replacen(' ', "\t", 1).into_bytes()),
        ("a newline", format!("{ABANDON}\n").into_bytes()),
        ("not UTF-8", [ABANDON.as_bytes(), &[0xff]].concat()),
        ("not ASCII", ABANDON.replace("about", "abоut").into_bytes()), // Cyrillic о
        ("empty", Vec::new()),
        ("too long", long.into_bytes()),
    ]
}

#[test]
fn a_refused_phrase_leaves_no_handle() {
    let _abi = abi();
    let before = sessions().len();
    for (why, phrase) in not_a_stored_phrase() {
        assert_eq!(open(&phrase), Err(KC_ERR_PHRASE), "{why}");
    }
    assert_eq!(sessions().len(), before);
}

#[test]
fn paths_outside_the_wallet_form_are_refused() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let refused = [
        "", "m/", "M/44'", "44'/60'", "/m/0", "m//0", "m/44'/", "m/+44'", "m/44h", "m/44H",
        "m/044'", "m/-1", "m/0x1", "m/1 ", " m/1", "m/1''", "m/2147483648", "m/2147483648'",
        "m/4294967296", "m/99999999999",
    ];
    for at in refused {
        assert_eq!(sign(handle, at, &[7u8; 32]), Err(KC_ERR_PATH), "{at:?}");
        assert_eq!(export(handle, at), Err(KC_ERR_PATH), "{at:?}");
    }
    let mut not_utf8 = EVM_0.as_bytes().to_vec();
    not_utf8.push(0xff);
    assert_eq!(keys::parse_path(&not_utf8).err(), Some(Refusal::Path));
    let too_long = format!("m{}", "/2147483647'".repeat(22));
    assert!(too_long.len() > keys::MAX_PATH_BYTES);
    assert_eq!(export(handle, &too_long), Err(KC_ERR_PATH));

    for at in ["m", "m/0", "m/0'", "m/2147483647", "m/2147483647'", "m/10/0'/1"] {
        assert!(export(handle, at).is_ok(), "{at:?}");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn digests_the_dart_signer_refuses_are_refused_here() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let mut above = order.clone();
    above[31] += 1;
    for (why, digest) in [
        ("zero", vec![0u8; 32]),
        ("the order", order.clone()),
        ("the order plus one", above),
        ("all ones", vec![0xffu8; 32]),
    ] {
        assert_eq!(sign(handle, DIGEST_0, &digest), Err(KC_ERR_DIGEST), "{why}");
    }
    let mut below_order = order;
    below_order[31] -= 1;
    assert!(sign(handle, DIGEST_0, &below_order).is_ok(), "the order minus one");
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(sign(handle, DIGEST_0, &one).is_ok(), "one");
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn buffers_of_the_wrong_length_or_null_are_refused() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let at = EVM_0.as_bytes();
    let digest = [7u8; 32];
    let mut out = [0u8; 80];
    unsafe {
        assert_eq!(kc_open(ABANDON.as_ptr(), ABANDON.len(), core::ptr::null_mut()), KC_ERR_ARGUMENT);
        let mut h = 5u64;
        assert_eq!(kc_open(core::ptr::null(), 0, &mut h), KC_ERR_ARGUMENT);
        assert_eq!(h, 0);

        for (format, length) in [
            (KC_PUBLIC_KEY_COMPRESSED, 65),
            (KC_PUBLIC_KEY_UNCOMPRESSED, 33),
            (KC_PUBLIC_KEY_COMPRESSED, 32),
            (2, 33),
            (-1, 65),
        ] {
            let code = kc_secp256k1_public_key(
                handle, at.as_ptr(), at.len(), format, out.as_mut_ptr(), length,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "format {format}, {length} bytes");
        }
        let code = kc_secp256k1_public_key(
            handle, core::ptr::null(), 0, KC_PUBLIC_KEY_COMPRESSED, out.as_mut_ptr(), 33,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "null path");

        for (digest_len, out_len) in [(31, 65), (33, 65), (32, 64), (32, 66)] {
            let code = kc_secp256k1_sign_digest(
                handle, at.as_ptr(), at.len(), digest.as_ptr(), digest_len, out.as_mut_ptr(), out_len,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "digest {digest_len}, out {out_len}");
        }
        let code = kc_secp256k1_sign_digest(
            handle, at.as_ptr(), at.len(), digest.as_ptr(), 32, core::ptr::null_mut(), 65,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "null signature buffer");

        for length in [31, 33, 0] {
            let code = kc_secp256k1_export_private_key(
                handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "export into {length} bytes");
        }
    }
    assert_eq!(out, [0u8; 80], "a refusal wrote output");
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_abi_version_is_the_one_the_binding_expects() {
    // 38 since phase 7a: `kc_slip39_backup` and `kc_slip39_check`; 39 since
    // 7b: `kc_slip39_restore` and `kc_matches_session`. 41 since Zcash came
    // back on the core (15 November 2026): `kc_zcash_read_transaction`,
    // `kc_zcash_sign_transaction` and `KC_CURVE_SECP256K1_ZCASH`.
    assert_eq!(kc_abi_version(), 41);
}

// --- Starknet ----------------------------------------------------------------

#[test]
fn a_starknet_signature_verifies_against_the_key_reported_for_its_path() {
    use starknet_crypto::Felt;
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    for index in 0..3u64 {
        let at = format!("m/44'/9004'/0'/0/{index}");
        let public = sk_public_key(handle, &at).unwrap();
        let secret = keys::derive_starknet(&seed[..], &path(&at)).unwrap();
        assert_eq!(public, keys::starknet_public_key(&secret), "{at}");
        assert_eq!(sk_export(handle, &at).unwrap(), *secret, "{at}");
        // A key at the module's path signs only a hash read (2f-21): its
        // signature is the primitive's, verified against the key reported.
        for n in 0..6 {
            let hash = stark_hash(index * 100 + n);
            assert_eq!(sk_sign(handle, &at, &hash), Err(KC_ERR_UNSHOWN), "{at}, hash {n}");
            let signature = keys::starknet_sign(&secret, &hash).unwrap();
            let r = Felt::from_bytes_be(&signature[..32].try_into().unwrap());
            let s = Felt::from_bytes_be(&signature[32..].try_into().unwrap());
            assert!(
                starknet_crypto::verify(&Felt::from_bytes_be(&public), &Felt::from_bytes_be(&hash), &r, &s).unwrap(),
                "{at}, hash {n}"
            );
            assert_eq!(keys::starknet_sign(&secret, &hash).unwrap(), signature, "deterministic");
        }
        // And through the call, at a path no module writes.
        let free = format!("m/1'/2'/3'/4/{index}");
        let hash = stark_hash(index * 100 + 50);
        let signature = sk_sign(handle, &free, &hash).unwrap();
        let r = Felt::from_bytes_be(&signature[..32].try_into().unwrap());
        let s = Felt::from_bytes_be(&signature[32..].try_into().unwrap());
        assert!(
            starknet_crypto::verify(&Felt::from_bytes_be(&sk_public_key(handle, &free).unwrap()), &Felt::from_bytes_be(&hash), &r, &s).unwrap(),
            "{free}"
        );
        assert_eq!(sk_sign(handle, &free, &hash).unwrap(), signature, "deterministic");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn starknet_refuses_large_hashes_wrong_buffers_and_closed_handles() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let mut at_bound = [0u8; 32];
    at_bound[0] = 0x08;
    assert_eq!(sk_sign(handle, STARKNET_FREE, &at_bound), Err(KC_ERR_DIGEST), "2^251");
    assert_eq!(sk_sign(handle, STARKNET_FREE, &[0xffu8; 32]), Err(KC_ERR_DIGEST), "all ones");
    let mut below = [0xffu8; 32];
    below[0] = 0x07;
    assert!(sk_sign(handle, STARKNET_FREE, &below).is_ok(), "2^251 - 1");
    assert!(sk_sign(handle, STARKNET_FREE, &[0u8; 32]).is_ok(), "zero is a felt it signs");
    let mut out = [0u8; 80];
    let at = STARKNET_0.as_bytes();
    let hash = stark_hash(1);
    unsafe {
        for (hash_len, out_len) in [(31, 64), (33, 64), (32, 63), (32, 65)] {
            let code = kc_starknet_sign(handle, at.as_ptr(), at.len(), hash.as_ptr(), hash_len, out.as_mut_ptr(), out_len);
            assert_eq!(code, KC_ERR_ARGUMENT, "hash {hash_len}, out {out_len}");
        }
        for length in [0, 31, 33] {
            assert_eq!(kc_starknet_public_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length), KC_ERR_ARGUMENT);
            assert_eq!(kc_starknet_export_private_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length), KC_ERR_ARGUMENT);
        }
    }
    assert_eq!(out, [0u8; 80], "a refusal wrote output");
    assert_eq!(sk_public_key(handle, "m/44h/9004h"), Err(KC_ERR_PATH));
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(sk_public_key(handle, STARKNET_0), Err(KC_ERR_HANDLE));
    assert_eq!(sk_sign(handle, STARKNET_0, &hash), Err(KC_ERR_HANDLE));
    assert_eq!(sk_export(handle, STARKNET_0), Err(KC_ERR_HANDLE));
}

// --- Cardano -----------------------------------------------------------------

#[test]
fn a_cardano_signature_verifies_against_the_key_reported_for_its_path() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    for account in 0u32..2 {
        for (role, index) in [(0, 0), (0, 3), (1, 0), (2, 0)] {
            let at = format!("m/1852'/1815'/{account}'/{role}/{index}");
            let public = cd_public_key(handle, &at).unwrap();
            let node = keys::derive_cardano(&seed[..], &path(&at)).unwrap();
            assert_eq!(public, keys::cardano_public_key(&node), "{at}");
            let exported = cd_export(handle, &at).unwrap();
            assert_eq!(exported[..], node[..], "{at}");
            let verifying = VerifyingKey::from_bytes(&public).unwrap();
            // A key at the module's path signs only a body read (O58):
            // `a_cardano_key_signs_only_a_body_read_for_a_screen`. Bytes are
            // refused; the hash of a body of its own, read, is signed.
            for length in [0usize, 32, 300] {
                let message = sequence(u64::from(account) * 31 + length as u64 + 3, length);
                assert_eq!(cd_sign(handle, &at, &message), Err(KC_ERR_UNSHOWN), "{at}, {length} bytes");
            }
            let ttl = 1_000_000 + u64::from(account) * 100 + role * 10 + index;
            let body = cardano_body(&[([0x52; 32], ttl)], &[(&[0x61; 29], 2_000_000)], 170_000, ttl);
            let (_, hash) = crate::cardano::reading(&body).unwrap();
            read_cardano_as(handle, &body, &[&at]).unwrap();
            let signature = cd_sign(handle, &at, &hash).unwrap();
            verifying
                .verify_strict(&hash, &Ed25519Signature::from_bytes(&signature))
                .unwrap_or_else(|_| panic!("{at}"));
            read_cardano_as(handle, &body, &[&at]).unwrap();
            assert_eq!(cd_sign(handle, &at, &hash).unwrap(), signature, "deterministic");
            // And at a path no module writes, bytes as given.
            let message = sequence(u64::from(account) + 7, 300);
            let free = cd_sign(handle, CARDANO_FREE, &message).unwrap();
            VerifyingKey::from_bytes(&cd_public_key(handle, CARDANO_FREE).unwrap())
                .unwrap()
                .verify_strict(&message, &Ed25519Signature::from_bytes(&free))
                .unwrap();
        }
    }
    // Not SLIP-10's key at the same path, nor secp256k1's.
    assert_ne!(cd_export(handle, "m/1852'/1815'/0'").unwrap()[..32], ed_export(handle, "m/1852'/1815'/0'").unwrap());
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn cardano_refuses_wrong_buffers_unwritten_paths_and_closed_handles() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let at = CARDANO_0.as_bytes();
    let mut out = [0u8; 120];
    unsafe {
        for length in [0, 31, 33] {
            let code = kc_cardano_public_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length);
            assert_eq!(code, KC_ERR_ARGUMENT, "public key into {length} bytes");
        }
        for length in [0, 32, 95, 97] {
            let code = kc_cardano_export_private_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length);
            assert_eq!(code, KC_ERR_ARGUMENT, "export into {length} bytes");
        }
        let message = [5u8; 10];
        for length in [0, 63, 65] {
            let code = kc_cardano_sign(
                handle, at.as_ptr(), at.len(), message.as_ptr(), message.len(), out.as_mut_ptr(), length,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "signature into {length} bytes");
        }
        let code = kc_cardano_sign(handle, at.as_ptr(), at.len(), core::ptr::null(), 0, out.as_mut_ptr(), 64);
        assert_eq!(code, KC_ERR_ARGUMENT, "a null message");
    }
    assert_eq!(out, [0u8; 120], "a refusal wrote output");
    for bad in ["", "m/1852h/1815h/0h", "1852'/1815'/0'", "m/01852'", "m//0"] {
        assert_eq!(cd_public_key(handle, bad), Err(KC_ERR_PATH), "{bad:?}");
    }
    assert!(cd_public_key(handle, "m").is_ok(), "the master");
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(cd_public_key(handle, CARDANO_0), Err(KC_ERR_HANDLE));
    assert_eq!(cd_sign(handle, CARDANO_0, b"x"), Err(KC_ERR_HANDLE));
    assert_eq!(cd_export(handle, CARDANO_0), Err(KC_ERR_HANDLE));
}

// --- ed25519 -----------------------------------------------------------------

/// A path of each network the core signs ed25519 for, as its module writes
/// account [i]'s.
fn ed25519_paths(i: u32) -> Vec<String> {
    vec![
        format!("m/44'/501'/{i}'/0'"),      // Solana
        format!("m/44'/607'/{i}'"),         // TON
        format!("m/44'/397'/{i}'"),         // NEAR
        format!("m/44'/148'/{i}'"),         // Stellar
        format!("m/44'/283'/{i}'/0'/0'"),   // Algorand
        format!("m/44'/1729'/{i}'/0'"),     // Tezos
        format!("m/44'/508'/0'/0'/{i}'"),   // MultiversX
        format!("m/44'/637'/{i}'/0'/0'"),   // Aptos, Movement
        format!("m/44'/784'/{i}'/0'/0'"),   // Sui
        format!("m/44'/354'/{i}'/0'/0'"),   // Polkadot
    ]
}

#[test]
fn an_ed25519_signature_verifies_against_the_key_reported_for_its_path() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    for i in 0..3 {
        for at in ed25519_paths(i) {
            let public = ed_public_key(handle, &at).unwrap();
            let derived = keys::derive_ed25519(&seed[..], &path(&at)).unwrap();
            assert_eq!(public, keys::ed25519_public_key(&derived), "{at}");
            let exported = ed_export(handle, &at).unwrap();
            assert_eq!(SigningKey::from_bytes(&exported).verifying_key().to_bytes(), public, "{at}");
            let verifying = VerifyingKey::from_bytes(&public).unwrap();
            // Empty, short, a digest's length, a Solana message's limit and
            // longer: the message is signed as it is, whatever its length.
            // A Solana key signs only a message read for a screen (O58):
            // `a_solana_key_signs_only_a_message_read_for_a_screen`.
            // So does a Stellar key, the hash of a transaction read:
            // `a_stellar_key_signs_only_a_transaction_hash_read_for_a_screen`,
            // and a NEAR key: `a_near_key_signs_only_a_transaction_hash_read_for_a_screen`.
            // So does an Aptos or Movement key, a signing message read:
            // `an_aptos_key_signs_only_a_message_read_for_a_screen`.
            // And a Sui key, an intent message's digest read:
            // `a_sui_key_signs_only_a_digest_read_for_a_screen`.
            // And an Algorand key, a transaction read:
            // `an_algorand_key_signs_only_a_transaction_read_for_a_screen`.
            // And a Tezos key, a group's watermarked digest read:
            // `a_tezos_key_signs_only_a_digest_read_for_a_screen`.
            // And a MultiversX key, a signing JSON read:
            // `a_multiversx_key_signs_only_a_transaction_read_for_a_screen`.
            // And a Polkadot key, an Asset Hub signing payload read:
            // `a_polkadot_key_signs_only_a_payload_read_for_a_screen`.
            // And a TON key, a signing message's hash read:
            // `a_ton_key_signs_only_a_hash_read_for_a_screen`.
            if at.starts_with("m/44'/501'")
                || at.starts_with("m/44'/148'")
                || at.starts_with("m/44'/397'")
                || at.starts_with("m/44'/637'")
                || at.starts_with("m/44'/784'")
                || at.starts_with("m/44'/283'")
                || at.starts_with("m/44'/1729'")
                || at.starts_with("m/44'/508'")
                || at.starts_with("m/44'/354'")
                || at.starts_with("m/44'/607'")
            {
                assert_eq!(ed_sign(handle, &at, b"not a message"), Err(KC_ERR_UNSHOWN), "{at}");
                continue;
            }
            for length in [0usize, 1, 32, 64, 1232, 5000] {
                let message = sequence(u64::from(i) * 7919 + length as u64 + 1, length);
                let signature = ed_sign(handle, &at, &message).unwrap();
                verifying
                    .verify_strict(&message, &Ed25519Signature::from_bytes(&signature))
                    .unwrap_or_else(|_| panic!("{at}, {length} bytes"));
                assert_eq!(ed_sign(handle, &at, &message).unwrap(), signature, "deterministic");
                let mut other = message.clone();
                other.push(1);
                assert!(
                    verifying
                        .verify_strict(&other, &Ed25519Signature::from_bytes(&signature))
                        .is_err(),
                    "{at}: a signature that verifies for another message"
                );
            }
        }
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_two_curves_give_two_keys_at_one_path() {
    // One path, two derivations: SLIP-10's ed25519 key is not BIP-32's
    // secp256k1 key, so a call that reached the wrong one would be seen.
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    assert_ne!(ed_export(handle, SOLANA_0).unwrap(), export(handle, SOLANA_0).unwrap());
    let other = open(LEGAL.as_bytes()).unwrap();
    assert_ne!(ed_public_key(handle, SOLANA_0).unwrap(), ed_public_key(other, SOLANA_0).unwrap());
    assert_ne!(
        ed_public_key(handle, SOLANA_0).unwrap(),
        ed_public_key(handle, "m/44'/501'/1'/0'").unwrap()
    );
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(kc_close(other), KC_OK);
}

#[test]
fn ed25519_refuses_normal_levels_and_unwritten_forms() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let refused = [
        // A level that is not hardened, anywhere in the path.
        "m/44'/501'/0'/0", "m/0", "m/44'/501'/0/0'", "m/44/501'/0'/0'",
        // Forms the wallet does not write, as for secp256k1.
        "", "m/", "44'/501'", "m/44h/501h/0h/0h", "m/044'", "m//0'", "m/2147483648'",
    ];
    for at in refused {
        assert_eq!(ed_public_key(handle, at), Err(KC_ERR_PATH), "{at:?}");
        assert_eq!(ed_sign(handle, at, b"x"), Err(KC_ERR_PATH), "{at:?}");
        assert_eq!(ed_export(handle, at), Err(KC_ERR_PATH), "{at:?}");
    }
    for at in ["m", "m/0'", "m/2147483647'", SOLANA_0] {
        assert!(ed_export(handle, at).is_ok(), "{at:?}");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn ed25519_refuses_wrong_buffers_and_closed_handles() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let at = SOLANA_0.as_bytes();
    let message = [7u8; 40];
    let mut out = [0u8; 80];
    unsafe {
        for length in [0, 31, 33, 64] {
            let code = kc_ed25519_public_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length);
            assert_eq!(code, KC_ERR_ARGUMENT, "public key into {length} bytes");
            let code =
                kc_ed25519_export_private_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length);
            assert_eq!(code, KC_ERR_ARGUMENT, "export into {length} bytes");
        }
        for length in [0, 32, 63, 65] {
            let code = kc_ed25519_sign(
                handle, at.as_ptr(), at.len(), message.as_ptr(), message.len(), out.as_mut_ptr(), length,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "signature into {length} bytes");
        }
        let code = kc_ed25519_sign(
            handle, at.as_ptr(), at.len(), core::ptr::null(), 0, out.as_mut_ptr(), 64,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "a null message");
        let code = kc_ed25519_sign(
            handle, at.as_ptr(), at.len(), message.as_ptr(), message.len(), core::ptr::null_mut(), 64,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "a null signature buffer");
        let code = kc_ed25519_public_key(handle, core::ptr::null(), 0, out.as_mut_ptr(), 32);
        assert_eq!(code, KC_ERR_ARGUMENT, "a null path");
    }
    assert_eq!(out, [0u8; 80], "a refusal wrote output");
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(ed_public_key(handle, SOLANA_0), Err(KC_ERR_HANDLE));
    assert_eq!(ed_sign(handle, SOLANA_0, b"x"), Err(KC_ERR_HANDLE));
    assert_eq!(ed_export(handle, SOLANA_0), Err(KC_ERR_HANDLE));
    assert_eq!(ed_public_key(0, SOLANA_0), Err(KC_ERR_HANDLE));
}

// --- The stack -------------------------------------------------------------
//
// **What these read is memory no Rust value owns:** the stack below this frame,
// where the calls under test had theirs. That is outside what the language
// defines, and only done here, in tests, on targets whose stack grows down —
// the hosts these run on. It is the closest a test gets to what
// `tool/memory_residue` reads from a whole process.

/// How far below the test's frame the scans and the paint reach.
const SCAN_BYTES: usize = 256 * 1024;
/// The call under test runs at least this far below the test's frame…
const PAD_BYTES: usize = 8 * 1024;
/// …and the scan skips this much below its own frame, so it never reads its
/// own locals.
const GAP_BYTES: usize = 4 * 1024;

/// Runs [call] with its frames at least [`PAD_BYTES`] below the caller's.
#[inline(never)]
fn below<R>(call: impl FnOnce() -> R) -> R {
    let pad = [0u8; PAD_BYTES];
    core::hint::black_box(&pad);
    let result = call();
    core::hint::black_box(&pad);
    result
}

/// How far below this frame any 16-byte quarter of [secrets] — as written or
/// byte-reversed, the order libsecp256k1's scalars keep — first appears, or
/// `None`.
#[inline(never)]
fn found_below(secrets: &[Vec<u8>]) -> Option<usize> {
    let mut needles: Vec<Vec<u8>> = Vec::new();
    for secret in secrets {
        let reversed: Vec<u8> = secret.iter().rev().copied().collect();
        for form in [secret, &reversed] {
            needles.extend(form.chunks(16).map(<[u8]>::to_vec));
        }
    }
    let marker = 0u8;
    let top = core::hint::black_box(&marker as *const u8) as usize;
    for address in (top - SCAN_BYTES)..(top - GAP_BYTES - 16) {
        let first = unsafe { core::ptr::read_volatile(address as *const u8) };
        for needle in &needles {
            if first == needle[0]
                && (1..16).all(|i| unsafe {
                    core::ptr::read_volatile((address + i) as *const u8) == needle[i]
                })
            {
                return Some(top - address);
            }
        }
    }
    None
}

/// Every secret a derivation of [at] below [seed] touches: the seed, and the
/// key and chain code at each level from the master down.
fn secrets_along(seed: &[u8], at: &str) -> Vec<Vec<u8>> {
    let mut secrets = vec![seed.to_vec()];
    let mut prefix = String::from("m");
    let levels: Vec<&str> = at.split('/').skip(1).collect();
    for level in std::iter::once(None).chain(levels.iter().map(Some)) {
        if let Some(level) = level {
            prefix = format!("{prefix}/{level}");
        }
        let extended =
            ExtendedPrivateKey::<SecretKey>::derive_from_path(seed, &path(&prefix)).unwrap();
        secrets.push(extended.private_key().to_secret_bytes().to_vec());
        secrets.push(extended.attrs().chain_code.to_vec());
    }
    secrets
}

#[test]
fn the_scan_finds_a_key_the_library_leaves_on_the_stack() {
    // The control. Without the scrub, `bip32`'s frames keep the keys of a
    // derivation after it returns — the residue the scrub exists to remove,
    // and proof the scan below can see it.
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let secrets = secrets_along(&seed[..], EVM_0);
    scrub::stack();
    below(|| {
        let key = keys::derive(&seed[..], &path(EVM_0)).unwrap();
        core::hint::black_box(key.secret());
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed derivation: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scans below prove nothing");
    scrub::stack();
}

#[test]
fn open_leaves_no_seed_on_the_stack() {
    let _abi = abi();
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let secrets = vec![seed.to_vec()];
    scrub::stack();
    let handle = below(|| open(ABANDON.as_bytes()).unwrap());
    assert_eq!(found_below(&secrets), None);
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn sign_public_key_and_export_leave_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = secrets_along(&seed[..], DIGEST_0);
    scrub::stack();

    let signature = below(|| sign(handle, DIGEST_0, &[9u8; 32]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a signature");
    core::hint::black_box(signature);

    let signature = below(|| sign_low_r(handle, DIGEST_0, &[9u8; 32]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a low-R signature");
    core::hint::black_box(signature);

    // A tweaked Schnorr signature: the derivation's keys, and the tweaked key
    // and the auxiliary bytes made from it, must all be gone.
    let tweak = [0x42u8; 32];
    let key = keys::derive(&seed[..], &path(DIGEST_0)).unwrap();
    let tweaked = Keypair::from_secret_key(key.secret())
        .add_xonly_tweak(&Scalar::from_be_bytes(tweak).unwrap())
        .unwrap()
        .to_secret_bytes();
    drop(key);
    let mut schnorr_secrets = secrets.clone();
    schnorr_secrets.push(tweaked.to_vec());
    let mut hasher = Sha256::new();
    hasher.update([9u8; 32]);
    hasher.update(tweaked);
    schnorr_secrets.push(hasher.finalize().to_vec());
    scrub::stack();
    let signature = below(|| schnorr(handle, DIGEST_0, &[9u8; 32], &tweak).unwrap());
    assert_eq!(found_below(&schnorr_secrets), None, "after a Schnorr signature");
    core::hint::black_box(signature);

    let public = below(|| public_key(handle, DIGEST_0, KC_PUBLIC_KEY_UNCOMPRESSED).unwrap());
    assert_eq!(found_below(&secrets), None, "after a public key");
    core::hint::black_box(public);

    // The exported key goes straight into `exported`, in this frame, above the
    // scan: the caller asked for that copy. What must not be there is any
    // other — so no helper with a buffer of its own sits in between.
    let mut exported = [0u8; 32];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe {
        kc_secp256k1_export_private_key(handle, DIGEST_0.as_ptr(), DIGEST_0.len(), out, 32)
    });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an export");
    exported.fill(0);
    assert_eq!(kc_close(handle), KC_OK);
}

/// Every secret an ed25519 signature at [at] below [seed] touches: the seed;
/// SLIP-10's key and chain code at each level from the master down; and the
/// expanded key RFC 8032 makes of the last key — SHA-512 of it, the lower
/// half as hashed and as clamped, and the upper half (the nonce prefix).
///
/// The scan sees bytes. `curve25519-dalek` also holds the scalar as limbs and
/// as radix-16 digits while it multiplies, which no byte pattern here
/// matches; those lie in the same frames, under the same zeros.
fn ed25519_secrets_along(seed: &[u8], at: &str) -> Vec<Vec<u8>> {
    let mut secrets = vec![seed.to_vec()];
    let mut prefix = String::from("m");
    let levels: Vec<&str> = at.split('/').skip(1).collect();
    let mut last = Vec::new();
    for level in std::iter::once(None).chain(levels.iter().map(Some)) {
        if let Some(level) = level {
            prefix = format!("{prefix}/{level}");
        }
        let node = keys::slip10_ed25519(seed, &path(&prefix)).unwrap();
        secrets.push(node[..32].to_vec());
        secrets.push(node[32..].to_vec());
        last = node[..32].to_vec();
    }
    let expanded = Sha512::digest(&last);
    let mut clamped = expanded[..32].to_vec();
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    secrets.push(expanded[..32].to_vec());
    secrets.push(clamped);
    secrets.push(expanded[32..].to_vec());
    secrets
}

#[test]
fn the_scan_finds_an_ed25519_key_the_derivation_leaves_on_the_stack() {
    // The control for the test below: without the scrub, SLIP-10 and a
    // signature leave something of their secrets where the scan looks.
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let secrets = ed25519_secrets_along(&seed[..], ED_0);
    scrub::stack();
    below(|| {
        let key = keys::derive_ed25519(&seed[..], &path(ED_0)).unwrap();
        core::hint::black_box(keys::ed25519_sign(&key, &[9u8; 100]).unwrap());
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed ed25519 signature: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn ed25519_calls_leave_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = ed25519_secrets_along(&seed[..], ED_0);
    scrub::stack();

    let signature = below(|| ed_sign(handle, ED_0, &[9u8; 100]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a signature");
    core::hint::black_box(signature);

    let public = below(|| ed_public_key(handle, ED_0).unwrap());
    assert_eq!(found_below(&secrets), None, "after a public key");
    core::hint::black_box(public);

    // As for secp256k1's export: straight into this frame's buffer.
    let mut exported = [0u8; 32];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe {
        kc_ed25519_export_private_key(handle, ED_0.as_ptr(), ED_0.len(), out, 32)
    });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an export");
    exported.fill(0);
    assert_eq!(kc_close(handle), KC_OK);
}

/// Every secret a Cardano signature at [at] below [seed] touches: the seed,
/// and the extended key's two halves and the chain code at each level.
fn cardano_secrets_along(seed: &[u8], at: &str) -> Vec<Vec<u8>> {
    let mut secrets = vec![seed.to_vec()];
    let mut prefix = String::from("m");
    let levels: Vec<&str> = at.split('/').skip(1).collect();
    for level in std::iter::once(None).chain(levels.iter().map(Some)) {
        if let Some(level) = level {
            prefix = format!("{prefix}/{level}");
        }
        let node = keys::derive_cardano(seed, &path(&prefix)).unwrap();
        for part in [&node[..32], &node[32..64], &node[64..]] {
            secrets.push(part.to_vec());
        }
    }
    secrets
}

#[test]
fn the_scan_finds_a_cardano_key_the_derivation_leaves_on_the_stack() {
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let secrets = cardano_secrets_along(&seed[..], CARDANO_0);
    scrub::stack();
    below(|| {
        let node = keys::derive_cardano(&seed[..], &path(CARDANO_0)).unwrap();
        core::hint::black_box(keys::cardano_sign(&node, &[9u8; 100]).unwrap());
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed Cardano signature: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn cardano_calls_leave_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = cardano_secrets_along(&seed[..], CARDANO_0);
    scrub::stack();
    // A body of its own, read, so that the key at the module's path signs.
    let body = cardano_body(&[([0x51; 32], 0)], &[(&[0x61; 29], 5_000_000)], 170_000, 9_100_000);
    let (_, hash) = crate::cardano::reading(&body).unwrap();
    // The reading derives the signer's key too, to name its hash.
    let read = below(|| read_cardano_as(handle, &body, &[CARDANO_0]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a reading");
    core::hint::black_box(read);
    let signature = below(|| cd_sign(handle, CARDANO_0, &hash).unwrap());
    assert_eq!(found_below(&secrets), None, "after a signature");
    core::hint::black_box(signature);
    let public = below(|| cd_public_key(handle, CARDANO_0).unwrap());
    assert_eq!(found_below(&secrets), None, "after a public key");
    core::hint::black_box(public);
    let mut exported = [0u8; 96];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe {
        kc_cardano_export_private_key(handle, CARDANO_0.as_ptr(), CARDANO_0.len(), out, 96)
    });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an export");
    exported.fill(0);
    assert_eq!(kc_close(handle), KC_OK);
}

/// Every secret a Starknet signature at [at] below [seed] touches: the seed,
/// the Ethereum key that seeds Argent's tree and each node on its way, the
/// second tree's master and each level's key and chain code, and the ground
/// key.
fn starknet_secrets_along(seed: &[u8], at: &str) -> Vec<Vec<u8>> {
    let mut secrets = secrets_along(seed, keys::ARGENT_SECRET_PATH);
    let eth = keys::derive(seed, &path(keys::ARGENT_SECRET_PATH)).unwrap().secret().to_secret_bytes();
    let start = eth.iter().position(|b| *b != 0).unwrap_or(32);
    let second = &eth[start..];
    let master = {
        use hmac::{Hmac, KeyInit, Mac};
        let mut m = Hmac::<sha2::Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
        m.update(second);
        m.finalize().into_bytes().to_vec()
    };
    secrets.push(master[..32].to_vec());
    secrets.push(master[32..].to_vec());
    let mut prefix = String::from("m");
    for level in at.split('/').skip(1) {
        prefix = format!("{prefix}/{level}");
        secrets.push(keys::derive_from_any_seed(second, &path(&prefix)).unwrap().secret().to_secret_bytes().to_vec());
    }
    secrets.push(keys::derive_starknet(seed, &path(at)).unwrap().to_vec());
    secrets
}

#[test]
fn the_scan_finds_a_starknet_key_the_derivation_leaves_on_the_stack() {
    // The derivation alone: in an optimised build a signature after it runs
    // over the same stack and leaves nothing the scan can match — the Stark
    // key it works with is a field element in Montgomery form, not its bytes
    // — so derivation followed by a signature would make a control that
    // shows nothing, in a build where the derivation's residue is real.
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let secrets = starknet_secrets_along(&seed[..], STARKNET_0);
    scrub::stack();
    below(|| {
        core::hint::black_box(keys::derive_starknet(&seed[..], &path(STARKNET_0)).unwrap());
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed Starknet derivation: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn starknet_calls_leave_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = starknet_secrets_along(&seed[..], STARKNET_0);
    scrub::stack();
    // A transaction read first — the reading derives the key too — so that
    // the key at the module's path signs.
    let read = below(|| read_starknet(handle, STARKNET_0, STARKNET_INVOKE.0.as_bytes()).unwrap());
    assert_eq!(found_below(&secrets), None, "after a reading");
    core::hint::black_box(read);
    let signature = below(|| sk_sign(handle, STARKNET_0, &hex(&STARKNET_INVOKE.1[2..])).unwrap());
    assert_eq!(found_below(&secrets), None, "after a signature");
    core::hint::black_box(signature);
    let public = below(|| sk_public_key(handle, STARKNET_0).unwrap());
    assert_eq!(found_below(&secrets), None, "after a public key");
    core::hint::black_box(public);
    let mut exported = [0u8; 32];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe {
        kc_starknet_export_private_key(handle, STARKNET_0.as_ptr(), STARKNET_0.len(), out, 32)
    });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an export");
    exported.fill(0);
    assert_eq!(kc_close(handle), KC_OK);
}

/// Fills [`SCAN_BYTES`] below the caller with a pattern.
#[inline(never)]
fn paint() {
    let mut area = [0xa5u8; SCAN_BYTES];
    core::hint::black_box(&mut area);
}

/// How far below this frame the pattern [`paint`] left was first disturbed.
#[inline(never)]
fn deepest_write() -> usize {
    let marker = 0u8;
    let top = core::hint::black_box(&marker as *const u8) as usize;
    let low = top - SCAN_BYTES + GAP_BYTES;
    (low..top)
        .find(|&address| unsafe { core::ptr::read_volatile(address as *const u8) } != 0xa5)
        .map_or(0, |address| top - address)
}

#[test]
fn stack_use_is_well_inside_the_scrub() {
    // What each call's work uses, measured without the scrub (whose own zeros
    // would be what this found) and less the pad that keeps it below the
    // test's frame.
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let at = path(EVM_0);
    let measure = |what: &str, work: &dyn Fn()| {
        paint();
        below(work);
        let used = deepest_write().saturating_sub(PAD_BYTES);
        eprintln!("{what}: about {used} bytes of stack");
        assert!(used < scrub::STACK_SCRUB_BYTES / 2, "{what} used {used} bytes");
    };
    measure("open", &|| {
        core::hint::black_box(keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap());
    });
    measure("derive and sign", &|| {
        let key = keys::derive(&seed[..], &at).unwrap();
        core::hint::black_box(keys::sign_digest(&key, &[9u8; 32]).unwrap());
    });
    measure("derive and a tweaked Schnorr signature", &|| {
        let key = keys::derive(&seed[..], &at).unwrap();
        core::hint::black_box(keys::schnorr_sign(&key, &[9u8; 32], Some(&[0x42u8; 32])).unwrap());
    });
    measure("derive and public key", &|| {
        let key = keys::derive(&seed[..], &at).unwrap();
        core::hint::black_box(keys::public_key(&key).serialize_uncompressed());
    });
    let solana = path(SOLANA_0);
    measure("SLIP-10 and an ed25519 signature", &|| {
        let key = keys::derive_ed25519(&seed[..], &solana).unwrap();
        core::hint::black_box(keys::ed25519_sign(&key, &[9u8; 1232]).unwrap());
    });
    let cardano = path(CARDANO_0);
    measure("BIP32-Ed25519 and a Cardano signature", &|| {
        let node = keys::derive_cardano(&seed[..], &cardano).unwrap();
        core::hint::black_box(keys::cardano_sign(&node, &[9u8; 1232]).unwrap());
    });
    let starknet = path(STARKNET_0);
    measure("Argent's derivation and a Stark signature", &|| {
        let key = keys::derive_starknet(&seed[..], &starknet).unwrap();
        core::hint::black_box(keys::starknet_sign(&key, &stark_hash(5)).unwrap());
    });
    measure("a phrase's seed and entropy", &|| {
        core::hint::black_box(keys::phrase_secrets(LEGAL.as_bytes()).unwrap());
    });
    let transaction = EvmTx::sample(7, true);
    let (unsigned, expected) = (transaction.unsigned(), transaction.expected());
    measure("an EVM transaction read, hashed and signed", &|| {
        let read = evm::Expected::read(&expected).unwrap();
        let digest = evm::transaction_digest(&unsigned, &read).unwrap();
        let key = keys::derive(&seed[..], &at).unwrap();
        core::hint::black_box(keys::sign_digest(&key, &digest).unwrap());
    });
    let bitcoin_request = BtcTx::segwit_send().request();
    let legal = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    measure("a Bitcoin transaction read, hashed and signed", &|| {
        let request = bitcoin::Request::read(&bitcoin_request).unwrap();
        let key_at = |path: &[u8]| keys::derive(&legal[..], &keys::parse_path(path)?);
        core::hint::black_box(bitcoin::sign(&request, &key_at).unwrap());
    });
    let typed = EIP712_HASHED[3].1;
    measure("typed data read, hashed and signed", &|| {
        let digest = eip712::digest(typed.as_bytes()).unwrap();
        let key = keys::derive(&seed[..], &at).unwrap();
        core::hint::black_box(keys::sign_digest(&key, &digest).unwrap());
    });
    measure("the Icarus master and a Cardano key below it", &|| {
        let node = keys::derive_cardano_icarus(&[0x7f; 16], &cardano).unwrap();
        core::hint::black_box(keys::cardano_public_key(&node));
    });
    scrub::stack();
}

// --- A measurement -----------------------------------------------------------

#[test]
#[ignore = "a measurement, not a check: cargo test --release -- --ignored timing --nocapture"]
fn timing_of_open_and_of_a_signature() {
    // Each call as the binding makes it, scrub included: what decision O8's
    // `lowmemory` would cost is the difference in the second number.
    let _abi = abi();
    let start = std::time::Instant::now();
    for _ in 0..20 {
        let handle = open(ABANDON.as_bytes()).unwrap();
        assert_eq!(kc_close(handle), KC_OK);
    }
    let open_each = start.elapsed() / 20;
    let handle = open(ABANDON.as_bytes()).unwrap();
    let rounds = 200u32;
    let start = std::time::Instant::now();
    for n in 0..rounds {
        sign(handle, DIGEST_0, &sequence(u64::from(n) + 1, 32)).unwrap();
    }
    let sign_each = start.elapsed() / rounds;
    let tables = if cfg!(feature = "lowmemory") { "lowmemory" } else { "full tables" };
    eprintln!("timing ({tables}): open {open_each:?}; derive, sign and check {sign_each:?}");
    // Decisions O14 and O15: the `fiat` backend and no basepoint tables.
    let start = std::time::Instant::now();
    for n in 0..rounds {
        ed_sign(handle, ED_0, &sequence(u64::from(n) + 1, 200)).unwrap();
    }
    let ed25519_each = start.elapsed() / rounds;
    eprintln!("timing (fiat): SLIP-10, an ed25519 signature and its check {ed25519_each:?}");
    let start = std::time::Instant::now();
    for n in 0..rounds {
        cd_sign(handle, CARDANO_FREE, &sequence(u64::from(n) + 1, 200)).unwrap();
    }
    let cardano_each = start.elapsed() / rounds;
    eprintln!("timing (fiat): BIP32-Ed25519, a Cardano signature and its check {cardano_each:?}");
    let start = std::time::Instant::now();
    for n in 0..rounds {
        sk_sign(handle, STARKNET_FREE, &stark_hash(u64::from(n))).unwrap();
    }
    let starknet_each = start.elapsed() / rounds;
    eprintln!("timing: Argent's derivation, a Stark signature and its check {starknet_each:?}");
    assert_eq!(kc_close(handle), KC_OK);
}

// --- One-key sessions: imported keys (O22) ---------------------------------

#[test]
fn a_secp256k1_key_session_is_its_key_at_m() {
    // An imported key's session answers at `m` exactly as a phrase's session
    // answers at the path that key was derived on: the same public keys, and
    // the same signatures of every kind, all of them deterministic.
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    for at in [DIGEST_0, "m/1'/2'/3'/4/6"] {
        let secret = export(wallet, at).unwrap();
        let key = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
        for format in [KC_PUBLIC_KEY_COMPRESSED, KC_PUBLIC_KEY_UNCOMPRESSED] {
            assert_eq!(public_key(key, "m", format), public_key(wallet, at, format), "{at}");
        }
        let tweak = [0x42u8; 32];
        for n in 1..=8u64 {
            let digest: [u8; 32] = sequence(n, 32).try_into().unwrap();
            assert_eq!(sign(key, "m", &digest), sign(wallet, at, &digest), "{at} {n}");
            assert_eq!(sign_low_r(key, "m", &digest), sign_low_r(wallet, at, &digest), "{at} {n}");
            assert_eq!(schnorr(key, "m", &digest, &[]), schnorr(wallet, at, &digest, &[]), "{at} {n}");
            assert_eq!(
                schnorr(key, "m", &digest, &tweak),
                schnorr(wallet, at, &digest, &tweak),
                "{at} {n}, tweaked"
            );
        }
        assert_eq!(export(key, "m").unwrap(), secret);
        assert_eq!(kc_close(key), KC_OK);
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn an_ed25519_key_session_is_its_key_at_m() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let secret = ed_export(wallet, ED_0).unwrap();
    let key = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_public_key(key, "m"), ed_public_key(wallet, ED_0));
    for message in [&b""[..], b"imported", &[7u8; 300][..]] {
        assert_eq!(ed_sign(key, "m", message), ed_sign(wallet, ED_0, message));
    }
    assert_eq!(ed_export(key, "m").unwrap(), secret);
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_key_session_answers_its_own_curve_at_m_alone() {
    let _abi = abi();
    let secp = open_key(KC_CURVE_SECP256K1, &[1u8; 32]).unwrap();
    let ed = open_key(KC_CURVE_ED25519, &[1u8; 32]).unwrap();
    // Any other path would be a derivation that did not happen.
    assert_eq!(public_key(secp, EVM_0, KC_PUBLIC_KEY_COMPRESSED), Err(KC_ERR_PATH));
    assert_eq!(sign(secp, "m/0", &[3u8; 32]), Err(KC_ERR_PATH));
    assert_eq!(schnorr(secp, KASPA_0, &[3u8; 32], &[]), Err(KC_ERR_PATH));
    assert_eq!(export(secp, EVM_0), Err(KC_ERR_PATH));
    assert_eq!(ed_public_key(ed, SOLANA_0), Err(KC_ERR_PATH));
    assert_eq!(ed_export(ed, "m/0'"), Err(KC_ERR_PATH));
    // The other curve, a chain code, Cardano and Starknet are a phrase's.
    assert_eq!(ed_public_key(secp, "m"), Err(KC_ERR_KIND));
    assert_eq!(ed_sign(secp, "m", b"x"), Err(KC_ERR_KIND));
    assert_eq!(public_key(ed, "m", KC_PUBLIC_KEY_COMPRESSED), Err(KC_ERR_KIND));
    assert_eq!(sign(ed, "m", &[3u8; 32]), Err(KC_ERR_KIND));
    assert_eq!(export(ed, "m"), Err(KC_ERR_KIND));
    for key in [secp, ed] {
        assert_eq!(cd_public_key(key, CARDANO_0), Err(KC_ERR_KIND));
        assert_eq!(cd_sign(key, CARDANO_0, b"x"), Err(KC_ERR_KIND));
        assert_eq!(cd_export(key, CARDANO_0), Err(KC_ERR_KIND));
        assert_eq!(sk_public_key(key, STARKNET_0), Err(KC_ERR_KIND));
        assert_eq!(sk_sign(key, STARKNET_0, &stark_hash(9)), Err(KC_ERR_KIND));
        assert_eq!(sk_export(key, STARKNET_0), Err(KC_ERR_KIND));
        let mut out = [0u8; 65];
        let code = unsafe {
            kc_secp256k1_extended_public_key(key, "m".as_ptr(), 1, out.as_mut_ptr(), 65)
        };
        assert_eq!(code, KC_ERR_KIND);
        assert_eq!(kc_close(key), KC_OK);
    }
}

#[test]
fn kc_open_key_takes_32_bytes_that_are_a_key() {
    let _abi = abi();
    let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let mut top = order.clone();
    top[31] -= 1;
    assert_eq!(open_key(KC_CURVE_SECP256K1, &[0u8; 32]), Err(KC_ERR_KEY));
    assert_eq!(open_key(KC_CURVE_SECP256K1, &order), Err(KC_ERR_KEY));
    assert_eq!(open_key(KC_CURVE_SECP256K1, &[0xffu8; 32]), Err(KC_ERR_KEY));
    let highest = open_key(KC_CURVE_SECP256K1, &top).unwrap();
    assert_eq!(export(highest, "m").unwrap().to_vec(), top);
    // Every 32 bytes are an ed25519 seed, zeros included.
    let zeros = open_key(KC_CURVE_ED25519, &[0u8; 32]).unwrap();
    for len in [0, 31, 33, 64] {
        let bytes = vec![1u8; len];
        assert_eq!(open_key(KC_CURVE_SECP256K1, &bytes), Err(KC_ERR_ARGUMENT), "{len}");
        assert_eq!(open_key(KC_CURVE_ED25519, &bytes), Err(KC_ERR_ARGUMENT), "{len}");
    }
    // 4 is Solana's and 5 TRON's since O58, 6 the XRP Ledger's since O59,
    // 7 the Cosmos zones', 8 Stellar's, 9 Sui's, 10 Algorand's, 11 Tezos's,
    // 12 Filecoin's, 13 ICP's, 14 Kaspa's, 15 Zcash's (15 November 2026);
    // the next number is no curve.
    assert_eq!(open_key(16, &[1u8; 32]), Err(KC_ERR_ARGUMENT));
    assert_eq!(open_key(-1, &[1u8; 32]), Err(KC_ERR_ARGUMENT));
    let mut handle = 7u64;
    let code = unsafe { kc_open_key(KC_CURVE_SECP256K1, core::ptr::null(), 32, &mut handle) };
    assert_eq!((code, handle), (KC_ERR_ARGUMENT, 0));
    let code = unsafe {
        kc_open_key(KC_CURVE_SECP256K1, [1u8; 32].as_ptr(), 32, core::ptr::null_mut())
    };
    assert_eq!(code, KC_ERR_ARGUMENT);
    for key in [highest, zeros] {
        assert_eq!(kc_close(key), KC_OK);
    }
}

#[test]
fn a_closed_key_session_is_refused_and_close_all_counts_every_kind() {
    let _abi = abi();
    let key = open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap();
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(sign(key, "m", &[3u8; 32]), Err(KC_ERR_HANDLE));
    assert_eq!(export(key, "m"), Err(KC_ERR_HANDLE));
    assert_eq!(kc_close(key), KC_ERR_HANDLE);
    kc_close_all();
    let secp = open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap();
    let ed = open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(kc_close_all(), 3);
    for handle in [secp, ed, wallet] {
        assert_eq!(kc_close(handle), KC_ERR_HANDLE);
    }
}

#[test]
fn key_sessions_leave_no_key_on_the_stack() {
    let _abi = abi();
    let secret: [u8; 32] = sequence(77, 32).try_into().unwrap();
    let key = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    let tweak = [0x42u8; 32];
    let tweaked = Keypair::from_secret_key(&SecretKey::from_secret_bytes(secret).unwrap())
        .add_xonly_tweak(&Scalar::from_be_bytes(tweak).unwrap())
        .unwrap()
        .to_secret_bytes();
    let mut hasher = Sha256::new();
    hasher.update([9u8; 32]);
    hasher.update(tweaked);
    let secrets = vec![secret.to_vec(), tweaked.to_vec(), hasher.finalize().to_vec()];
    scrub::stack();

    let signature = below(|| sign(key, "m", &[9u8; 32]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a signature");
    core::hint::black_box(signature);
    let signature = below(|| sign_low_r(key, "m", &[9u8; 32]).unwrap());
    assert_eq!(found_below(&secrets), None, "after a low-R signature");
    core::hint::black_box(signature);
    let signature = below(|| schnorr(key, "m", &[9u8; 32], &tweak).unwrap());
    assert_eq!(found_below(&secrets), None, "after a Schnorr signature");
    core::hint::black_box(signature);
    let public = below(|| public_key(key, "m", KC_PUBLIC_KEY_UNCOMPRESSED).unwrap());
    assert_eq!(found_below(&secrets), None, "after a public key");
    core::hint::black_box(public);
    let mut exported = [0u8; 32];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe { kc_secp256k1_export_private_key(key, "m".as_ptr(), 1, out, 32) });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an export");
    exported.fill(0);
    assert_eq!(kc_close(key), KC_OK);

    let seed: [u8; 32] = sequence(78, 32).try_into().unwrap();
    let key = open_key(KC_CURVE_ED25519, &seed).unwrap();
    let expanded = Sha512::digest(seed);
    let mut clamped = expanded[..32].to_vec();
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let secrets = vec![
        seed.to_vec(),
        expanded[..32].to_vec(),
        clamped,
        expanded[32..].to_vec(),
    ];
    scrub::stack();
    let signature = below(|| ed_sign(key, "m", &[9u8; 100]).unwrap());
    assert_eq!(found_below(&secrets), None, "after an ed25519 signature");
    core::hint::black_box(signature);
    let public = below(|| ed_public_key(key, "m").unwrap());
    assert_eq!(found_below(&secrets), None, "after an ed25519 public key");
    core::hint::black_box(public);
    let mut exported = [0u8; 32];
    let out = exported.as_mut_ptr();
    let code = below(|| unsafe { kc_ed25519_export_private_key(key, "m".as_ptr(), 1, out, 32) });
    assert_eq!(code, KC_OK);
    assert_eq!(found_below(&secrets), None, "after an ed25519 export");
    exported.fill(0);
    assert_eq!(kc_close(key), KC_OK);
}

// --- The sealed phrase (phase 6a) -------------------------------------------

/// The key and the record [`ABANDON`] is sealed in by the wallet's own code:
/// pointycastle's AES-GCM, called as `CryptoUtils.encryptBytes` calls it, with
/// the key 01 02 … 20 and the nonce a0 a1 … ab fixed so the record is the same
/// on every run (generated 30 October 2026). The app's
/// `test/key_core_sealed_test.dart` seals thousands more at random, through
/// `CryptoUtils` itself, and opens them here.
const WALLET_KEY: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const WALLET_SEALED_ABANDON: &str = "a0a1a2a3a4a5a6a7a8a9aaabd8b35c0899da34241e6cc30595ea4ea436b5d1773c070ea44639b4933621b61550b3f8a68bbdde144c14a1f7c259200778d411aaa8f490f52986e29ea6596948cd20c28aca4422d1bbf2279a66b595ffacfd77251c993c56a890a94f933502bfe7efb90e57e9e5f4b30022347a";

/// Asserts that two sessions are one wallet: the same public key on every
/// curve and scheme the core answers.
fn same_wallet(a: u64, b: u64) {
    for at in [EVM_0, BTC_TAPROOT_0] {
        assert_eq!(
            public_key(a, at, KC_PUBLIC_KEY_COMPRESSED).unwrap(),
            public_key(b, at, KC_PUBLIC_KEY_COMPRESSED).unwrap(),
            "{at}"
        );
    }
    assert_eq!(ed_public_key(a, SOLANA_0).unwrap(), ed_public_key(b, SOLANA_0).unwrap());
    assert_eq!(cd_public_key(a, CARDANO_0).unwrap(), cd_public_key(b, CARDANO_0).unwrap());
    assert_eq!(sk_public_key(a, STARKNET_0).unwrap(), sk_public_key(b, STARKNET_0).unwrap());
}

#[test]
fn a_record_the_wallet_sealed_opens_to_its_phrases_wallet() {
    let _abi = abi();
    let sealed = open_sealed(&hex(WALLET_SEALED_ABANDON), &hex(WALLET_KEY)).unwrap();
    let phrase = open(ABANDON.as_bytes()).unwrap();
    same_wallet(sealed, phrase);
    // And the key `test/derivation_vectors_test.dart` pins, not only the same
    // answer twice.
    assert_eq!(
        to_hex(&export(sealed, EVM_0).unwrap()),
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
    );
    assert_eq!(kc_close(sealed), KC_OK);
    assert_eq!(kc_close(phrase), KC_OK);
}

#[test]
fn a_sealed_phrase_and_the_phrase_are_one_wallet_at_every_length() {
    let _abi = abi();
    for (i, (_, phrase, _, _)) in BIP39_TREZOR.iter().enumerate() {
        let key: [u8; 32] = sequence(i as u64 + 1, 32).try_into().unwrap();
        let nonce: [u8; 12] = sequence(i as u64 + 1000, 12).try_into().unwrap();
        let sealed = open_sealed(&seal(phrase.as_bytes(), &key, &nonce), &key).unwrap();
        let opened = open(phrase.as_bytes()).unwrap();
        same_wallet(sealed, opened);
        assert_eq!(kc_close(sealed), KC_OK);
        assert_eq!(kc_close(opened), KC_OK);
    }
}

#[test]
fn a_record_this_key_does_not_open_is_refused_as_a_seal() {
    let _abi = abi();
    let before = sessions().len();
    let key = hex(WALLET_KEY);
    let sealed = hex(WALLET_SEALED_ABANDON);
    // Every byte changed in turn — the nonce, the ciphertext and the tag.
    for i in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[i] ^= 0x01;
        assert_eq!(open_sealed(&changed, &key), Err(KC_ERR_SEAL), "byte {i} changed");
    }
    // Another key: one bit away, and nothing like it.
    let mut near = key.clone();
    near[31] ^= 0x80;
    assert_eq!(open_sealed(&sealed, &near), Err(KC_ERR_SEAL), "a key one bit away");
    assert_eq!(open_sealed(&sealed, &[0u8; 32]), Err(KC_ERR_SEAL), "a key of zeros");
    // Too short to hold a nonce and a tag, and a byte short or a byte long.
    for length in 0..28 {
        assert_eq!(open_sealed(&sealed[..length], &key), Err(KC_ERR_SEAL), "{length} bytes");
    }
    assert_eq!(open_sealed(&sealed[..sealed.len() - 1], &key), Err(KC_ERR_SEAL), "cut");
    let longer = [sealed.as_slice(), &[0]].concat();
    assert_eq!(open_sealed(&longer, &key), Err(KC_ERR_SEAL), "lengthened");
    assert_eq!(sessions().len(), before);
}

/// Records an older build may have sealed with other white space, each opened
/// as the Dart code opened it (O32 in the core, 14 November 2026).
fn white_space_variants() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("two spaces", ABANDON.replacen(' ', "  ", 1).into_bytes()),
        ("a leading space", format!(" {ABANDON}").into_bytes()),
        ("a trailing space", format!("{ABANDON} ").into_bytes()),
        ("a tab", ABANDON.replacen(' ', "\t", 1).into_bytes()),
        ("a newline", format!("{ABANDON}\n").into_bytes()),
        ("a carriage return and a newline", ABANDON.replacen(' ', "\r\n", 2).into_bytes()),
        ("a no-break space", ABANDON.replacen(' ', "\u{A0}", 1).into_bytes()),
        ("an ideographic space", ABANDON.replacen(' ', "\u{3000}", 1).into_bytes()),
        ("a byte-order mark first", format!("\u{FEFF}{ABANDON}").into_bytes()),
    ]
}

#[test]
fn a_record_with_other_white_space_opens_as_the_same_wallet() {
    // The Dart code split a record on `\s`, dropped the empty pieces and made
    // the seed of the words joined by one space: the same seed, the same
    // wallet. The core does the same, and only for a record.
    let _abi = abi();
    let key: [u8; 32] = hex(WALLET_KEY).try_into().unwrap();
    let canonical = open(ABANDON.as_bytes()).unwrap();
    for (i, (why, text)) in white_space_variants().into_iter().enumerate() {
        let nonce: [u8; 12] = sequence(i as u64 + 40, 12).try_into().unwrap();
        let opened = open_sealed(&seal(&text, &key, &nonce), &key)
            .unwrap_or_else(|e| panic!("{why}: {e}"));
        assert_eq!(sessions_match(opened, canonical), Ok(true), "{why}");
        assert_eq!(kc_close(opened), KC_OK);
        // A phrase handed in is still taken in the stored form only.
        assert_eq!(open(&text), Err(KC_ERR_PHRASE), "{why}, handed in");
    }
    assert_eq!(kc_close(canonical), KC_OK);
}

#[test]
fn a_record_that_opens_to_no_stored_phrase_is_refused_as_a_phrase() {
    // It opens — the key is the one — and what it holds is not a phrase the
    // Dart code could read either: capitals, another alphabet, a bad
    // checksum, the wrong length. White space alone is read (above).
    let _abi = abi();
    let before = sessions().len();
    let key: [u8; 32] = hex(WALLET_KEY).try_into().unwrap();
    let spaces: Vec<&str> = white_space_variants().iter().map(|(why, _)| *why).collect();
    for (i, (why, text)) in not_a_stored_phrase().into_iter().enumerate() {
        if spaces.contains(&why) {
            continue;
        }
        let nonce: [u8; 12] = sequence(i as u64 + 7, 12).try_into().unwrap();
        assert_eq!(open_sealed(&seal(&text, &key, &nonce), &key), Err(KC_ERR_PHRASE), "{why}");
    }
    assert_eq!(sessions().len(), before);
}

#[test]
fn kc_open_sealed_takes_a_32_byte_key_and_no_null_pointer() {
    let _abi = abi();
    let before = sessions().len();
    let key = hex(WALLET_KEY);
    let sealed = hex(WALLET_SEALED_ABANDON);
    let long = [key.as_slice(), &[0]].concat();
    for (why, k) in [("no key", &key[..0]), ("16 bytes", &key[..16]), ("31 bytes", &key[..31]), ("33 bytes", &long[..])] {
        assert_eq!(open_sealed(&sealed, k), Err(KC_ERR_ARGUMENT), "{why}");
    }
    unsafe {
        let mut handle = 5u64;
        let code = kc_open_sealed(sealed.as_ptr(), sealed.len(), core::ptr::null(), 32, &mut handle);
        assert_eq!((code, handle), (KC_ERR_ARGUMENT, 0), "a null key");
        handle = 5;
        let code = kc_open_sealed(core::ptr::null(), 0, key.as_ptr(), 32, &mut handle);
        assert_eq!((code, handle), (KC_ERR_ARGUMENT, 0), "a null record");
        let code = kc_open_sealed(sealed.as_ptr(), sealed.len(), key.as_ptr(), 32, core::ptr::null_mut());
        assert_eq!(code, KC_ERR_ARGUMENT, "nowhere to write the handle");
    }
    assert_eq!(sessions().len(), before);
}

/// AES-256's encryption of the zero block under [key]: GHASH's key, `H`.
fn ghash_key(key: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut block = GenericArray::default();
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

/// What an open of [`WALLET_SEALED_ABANDON`] handles: the vault key, GHASH's
/// key, the phrase and its seed.
fn seal_secrets() -> Vec<Vec<u8>> {
    let key = hex(WALLET_KEY);
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    vec![key.clone(), ghash_key(&key), ABANDON.as_bytes().to_vec(), seed.to_vec()]
}

#[test]
fn the_scan_finds_what_an_unscrubbed_open_of_a_seal_leaves_on_the_stack() {
    // The control for the test below: the same work without the scrub leaves
    // something of it here, so a scan that finds nothing after
    // `kc_open_sealed` is the scrub's doing and not a blind scan.
    //
    // **What it finds is the seed, and only the seed** (30 October 2026, debug
    // and release, each secret scanned alone): the vault key, GHASH's key and
    // the phrase were not found even without the scrub — `aes` keeps its round
    // keys fixsliced, not as the key, and the phrase is decrypted on the heap,
    // in a buffer written over when dropped. For those three the test below
    // shows absence with no control that could have seen them.
    let secrets = seal_secrets();
    let key: [u8; 32] = hex(WALLET_KEY).try_into().unwrap();
    let sealed = hex(WALLET_SEALED_ABANDON);
    scrub::stack();
    below(|| {
        let phrase = seal::open(&sealed, &key).unwrap();
        let seed = keys::seed_from_phrase(&phrase, "").unwrap();
        core::hint::black_box(&seed);
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed open of a seal: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn open_sealed_leaves_no_key_phrase_or_seed_on_the_stack() {
    let _abi = abi();
    let secrets = seal_secrets();
    let key = hex(WALLET_KEY);
    let sealed = hex(WALLET_SEALED_ABANDON);
    scrub::stack();
    let handle = below(|| open_sealed(&sealed, &key).unwrap());
    assert_eq!(found_below(&secrets), None);
    assert_eq!(kc_close(handle), KC_OK);
}

// --- The comparison and Icarus (phase 6c) -----------------------------------

/// BIP-39's published "ozone drill grab…" vector and its entropy: a phrase
/// whose entropy is no run of one byte, so a scan for it cannot be met by the
/// scrub's zeros or a fill pattern, as the all-zero and `7f` vectors' can.
fn ozone() -> (&'static str, Vec<u8>) {
    let (entropy, phrase, _, _) =
        BIP39_TREZOR.iter().find(|vector| vector.1.starts_with("ozone ")).unwrap();
    (phrase, hex(entropy))
}

/// The entropy [handle]'s session keeps, or `None` for a refusal.
fn held_entropy(handle: u64) -> Option<Vec<u8>> {
    with_phrase(handle, |phrase| Ok(phrase.entropy.as_bytes().to_vec())).ok()
}

#[test]
fn the_pbkdf2_here_gives_bip39s_published_seeds() {
    // BIP-39's seed is PBKDF2-HMAC-SHA512 of the phrase, salted "mnemonic"
    // and the passphrase, over 2,048 rounds: the 24 published seeds are 24
    // vectors of the function Icarus calls with other arguments.
    for (_, phrase, seed, _) in BIP39_TREZOR {
        let mut out = [0u8; 64];
        keys::pbkdf2_hmac_sha512(phrase.as_bytes(), b"mnemonicTREZOR", 2048, &mut out).unwrap();
        assert_eq!(to_hex(&out), seed, "{phrase:.20}…");
    }
}

#[test]
fn each_pbkdf2_block_is_numbered_from_one_big_endian() {
    // Icarus takes 96 bytes, two blocks, and the seeds above are one. Each
    // block's first `U` is the HMAC of the salt and the block's number, so
    // one round is that HMAC itself; and a block depends on its number alone,
    // so a longer output begins with a shorter one.
    use hmac::{Hmac, KeyInit, Mac};
    let first_u = |block: u32| {
        let mut mac = Hmac::<Sha512>::new_from_slice(b"password").unwrap();
        mac.update(b"salt");
        mac.update(&block.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let mut one_round = [0u8; 128];
    keys::pbkdf2_hmac_sha512(b"password", b"salt", 1, &mut one_round).unwrap();
    assert_eq!(one_round[..64], first_u(1)[..]);
    assert_eq!(one_round[64..], first_u(2)[..]);
    let mut short = [0u8; 64];
    let mut long = [0u8; 96];
    keys::pbkdf2_hmac_sha512(b"", &[0x9e; 16], 4096, &mut short).unwrap();
    keys::pbkdf2_hmac_sha512(b"", &[0x9e; 16], 4096, &mut long).unwrap();
    assert_eq!(long[..64], short[..]);
    assert_ne!(long[64..], short[..32], "the second block is a block of its own");
}

#[test]
fn a_session_keeps_the_entropy_its_phrase_is_written_from() {
    let _abi = abi();
    for (i, (entropy, phrase, _, _)) in BIP39_TREZOR.iter().enumerate() {
        let (seed, held) = keys::phrase_secrets(phrase.as_bytes()).unwrap();
        assert_eq!(to_hex(held.as_bytes()), *entropy, "{phrase:.20}…");
        assert_eq!(seed[..], keys::seed_from_phrase(phrase.as_bytes(), "").unwrap()[..]);
        let key: [u8; 32] = sequence(i as u64 + 50, 32).try_into().unwrap();
        let nonce: [u8; 12] = sequence(i as u64 + 5000, 12).try_into().unwrap();
        let opened = open(phrase.as_bytes()).unwrap();
        let sealed = open_sealed(&seal(phrase.as_bytes(), &key, &nonce), &key).unwrap();
        for handle in [opened, sealed] {
            assert_eq!(held_entropy(handle), Some(hex(entropy)), "{phrase:.20}…");
            assert_eq!(kc_close(handle), KC_OK);
        }
    }
}

#[test]
fn the_icarus_master_is_the_entropys_pbkdf2_with_kl_clamped() {
    // CIP-0003's Icarus: PBKDF2-HMAC-SHA512, the passphrase (none) as the
    // password and the entropy as the salt, 4,096 rounds, 96 bytes; then kL's
    // lowest three bits and highest three cleared and the second highest set.
    for (entropy, phrase, _, _) in BIP39_TREZOR {
        let entropy = hex(entropy);
        let master = keys::cardano_icarus_master(&entropy).unwrap();
        let mut raw = [0u8; 96];
        keys::pbkdf2_hmac_sha512(b"", &entropy, 4096, &mut raw).unwrap();
        assert_eq!(master[0], raw[0] & 0b1111_1000, "{phrase:.20}…");
        assert_eq!(master[31], (raw[31] & 0b0001_1111) | 0b0100_0000, "{phrase:.20}…");
        assert_eq!(master[1..31], raw[1..31]);
        assert_eq!(master[32..], raw[32..]);
        let seed = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
        assert_ne!(master[..], keys::cardano_ledger_master(&seed[..]).unwrap()[..]);
    }
}

#[test]
fn an_icarus_key_is_the_derivation_below_the_icarus_master_and_not_the_ledger_key() {
    let _abi = abi();
    for (entropy, phrase, _, _) in BIP39_TREZOR {
        let handle = open(phrase.as_bytes()).unwrap();
        for at in ["m", "m/1852'/1815'/0'", CARDANO_0, "m/1852'/1815'/0'/2/0", "m/1852'/1815'/3'/1/19"] {
            let node = keys::derive_cardano_icarus(&hex(entropy), &path(at)).unwrap();
            let icarus = icarus_public_key(handle, at).unwrap();
            assert_eq!(icarus, keys::cardano_public_key(&node), "{phrase:.20}… {at}");
            assert_ne!(icarus, cd_public_key(handle, at).unwrap(), "{phrase:.20}… {at}");
        }
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn icarus_refuses_wrong_buffers_paths_key_sessions_and_closed_handles() {
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    let at = CARDANO_0.as_bytes();
    let mut out = [0u8; 40];
    unsafe {
        for length in [0, 31, 33] {
            let code = kc_cardano_icarus_public_key(handle, at.as_ptr(), at.len(), out.as_mut_ptr(), length);
            assert_eq!(code, KC_ERR_ARGUMENT, "public key into {length} bytes");
        }
        let code = kc_cardano_icarus_public_key(handle, at.as_ptr(), at.len(), core::ptr::null_mut(), 32);
        assert_eq!(code, KC_ERR_ARGUMENT, "a null output");
        let code = kc_cardano_icarus_public_key(handle, core::ptr::null(), 0, out.as_mut_ptr(), 32);
        assert_eq!(code, KC_ERR_ARGUMENT, "a null path");
    }
    assert_eq!(out, [0u8; 40], "a refusal wrote output");
    for bad in ["", "m/1852h/1815h/0h", "1852'/1815'/0'", "m/01852'", "m//0"] {
        assert_eq!(icarus_public_key(handle, bad), Err(KC_ERR_PATH), "{bad:?}");
    }
    assert!(icarus_public_key(handle, "m").is_ok(), "the master");
    // An imported key has no phrase and so no entropy.
    for key in [open_key(KC_CURVE_SECP256K1, &[2u8; 32]).unwrap(), open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap()] {
        assert_eq!(icarus_public_key(key, "m"), Err(KC_ERR_KIND));
        assert_eq!(icarus_public_key(key, CARDANO_0), Err(KC_ERR_KIND));
        assert_eq!(kc_close(key), KC_OK);
    }
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(icarus_public_key(handle, CARDANO_0), Err(KC_ERR_HANDLE));
    assert_eq!(icarus_public_key(0, CARDANO_0), Err(KC_ERR_HANDLE));
}

#[test]
fn the_open_phrase_matches_and_no_other_does() {
    let _abi = abi();
    let count = BIP39_TREZOR.len();
    let phrase = |i: usize| BIP39_TREZOR[i % count].1.as_bytes();
    for i in 0..count {
        let key: [u8; 32] = sequence(i as u64 + 70, 32).try_into().unwrap();
        let nonce: [u8; 12] = sequence(i as u64 + 7000, 12).try_into().unwrap();
        let opened = open(phrase(i)).unwrap();
        let sealed = open_sealed(&seal(phrase(i), &key, &nonce), &key).unwrap();
        for handle in [opened, sealed] {
            assert_eq!(matches(handle, phrase(i)), Ok(true), "{i}");
            // The next phrase, and the one of the same length four along.
            assert_eq!(matches(handle, phrase(i + 1)), Ok(false), "{i} and {}", i + 1);
            assert_eq!(matches(handle, phrase(i + 4)), Ok(false), "{i} and {}", i + 4);
            assert_eq!(kc_close(handle), KC_OK);
        }
    }
    // Zero entropy at 12, 18 and 24 words: one prefix, three wallets.
    let zeros = [0, 4, 8].map(|i| BIP39_TREZOR[i].1.as_bytes());
    for (i, mine) in zeros.iter().enumerate() {
        let handle = open(mine).unwrap();
        for (j, theirs) in zeros.iter().enumerate() {
            assert_eq!(matches(handle, theirs), Ok(i == j), "{i} and {j}");
        }
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn a_candidate_not_in_the_stored_form_is_refused_as_a_phrase() {
    // Read as `kc_open` reads a phrase, and refused before the session is
    // looked at: a key session and a closed one give the same refusal.
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let key = open_key(KC_CURVE_ED25519, &[2u8; 32]).unwrap();
    let closed = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(kc_close(closed), KC_OK);
    for (why, text) in not_a_stored_phrase() {
        for handle in [wallet, key, closed] {
            assert_eq!(matches(handle, &text), Err(KC_ERR_PHRASE), "{why}");
        }
    }
    assert_eq!(matches(wallet, ABANDON.as_bytes()), Ok(true), "and the session is still open");
    for handle in [wallet, key] {
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn kc_matches_phrase_refuses_key_sessions_closed_handles_and_null_pointers() {
    let _abi = abi();
    for curve in [KC_CURVE_SECP256K1, KC_CURVE_ED25519] {
        let key = open_key(curve, &[2u8; 32]).unwrap();
        assert_eq!(matches(key, ABANDON.as_bytes()), Err(KC_ERR_KIND), "curve {curve}");
        assert_eq!(kc_close(key), KC_OK);
    }
    let wallet = open(ABANDON.as_bytes()).unwrap();
    unsafe {
        let mut out = 7u8;
        let code = kc_matches_phrase(wallet, core::ptr::null(), 0, &mut out);
        assert_eq!((code, out), (KC_ERR_ARGUMENT, 0), "a null candidate");
        let code = kc_matches_phrase(wallet, ABANDON.as_ptr(), ABANDON.len(), core::ptr::null_mut());
        assert_eq!(code, KC_ERR_ARGUMENT, "nowhere to write the answer");
    }
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(matches(wallet, ABANDON.as_bytes()), Err(KC_ERR_HANDLE));
    assert_eq!(matches(0, ABANDON.as_bytes()), Err(KC_ERR_HANDLE));
}

/// Every secret Icarus touches on the way to [at]: the entropy, the PBKDF2
/// output before the clamp, and each node's two halves and chain code.
fn icarus_secrets_along(entropy: &[u8], at: &str) -> Vec<Vec<u8>> {
    let mut raw = [0u8; 96];
    keys::pbkdf2_hmac_sha512(b"", entropy, 4096, &mut raw).unwrap();
    let mut secrets = vec![entropy.to_vec(), raw[..32].to_vec(), raw[32..64].to_vec()];
    let mut prefix = String::from("m");
    let levels: Vec<&str> = at.split('/').skip(1).collect();
    for level in std::iter::once(None).chain(levels.iter().map(Some)) {
        if let Some(level) = level {
            prefix = format!("{prefix}/{level}");
        }
        let node = keys::derive_cardano_icarus(entropy, &path(&prefix)).unwrap();
        for part in [&node[..32], &node[32..64], &node[64..]] {
            secrets.push(part.to_vec());
        }
    }
    secrets
}

#[test]
fn the_scan_finds_what_an_unscrubbed_icarus_derivation_leaves_on_the_stack() {
    let (_, entropy) = ozone();
    let secrets = icarus_secrets_along(&entropy, CARDANO_0);
    scrub::stack();
    below(|| {
        let node = keys::derive_cardano_icarus(&entropy, &path(CARDANO_0)).unwrap();
        core::hint::black_box(keys::cardano_public_key(&node));
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed Icarus derivation: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn the_icarus_key_leaves_no_entropy_or_node_on_the_stack() {
    let _abi = abi();
    let (phrase, entropy) = ozone();
    let handle = open(phrase.as_bytes()).unwrap();
    let secrets = icarus_secrets_along(&entropy, CARDANO_0);
    scrub::stack();
    let public = below(|| icarus_public_key(handle, CARDANO_0).unwrap());
    assert_eq!(found_below(&secrets), None);
    core::hint::black_box(public);
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_scan_finds_what_an_unscrubbed_open_leaves_of_the_entropy_or_the_seed() {
    // The control for the test below: the work `kc_open` now does — the seed
    // and the entropy — without the scrub.
    let (phrase, entropy) = ozone();
    let seed = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
    let secrets = vec![seed.to_vec(), entropy];
    scrub::stack();
    below(|| {
        core::hint::black_box(keys::phrase_secrets(phrase.as_bytes()).unwrap());
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed seed and entropy: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn open_and_open_sealed_leave_no_entropy_or_seed_on_the_stack() {
    let _abi = abi();
    let (phrase, entropy) = ozone();
    let seed = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
    let key = [0x5cu8; 32];
    let sealed = seal(phrase.as_bytes(), &key, &[0x3au8; 12]);
    let secrets = vec![seed.to_vec(), entropy, key.to_vec()];
    scrub::stack();
    let opened = below(|| open(phrase.as_bytes()).unwrap());
    assert_eq!(found_below(&secrets), None, "after kc_open");
    let from_seal = below(|| open_sealed(&sealed, &key).unwrap());
    assert_eq!(found_below(&secrets), None, "after kc_open_sealed");
    for handle in [opened, from_seal] {
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn the_scan_finds_what_an_unscrubbed_comparison_leaves_on_the_stack() {
    let (phrase, _) = ozone();
    let seed = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
    let secrets = vec![seed.to_vec()];
    scrub::stack();
    below(|| {
        let theirs = keys::seed_from_phrase(phrase.as_bytes(), "").unwrap();
        core::hint::black_box(bool::from(seed[..].ct_eq(&theirs[..])));
    });
    let depth = found_below(&secrets);
    eprintln!("unscrubbed comparison: residue found {depth:?} bytes down");
    assert!(depth.is_some(), "the control found nothing, so the scan below proves nothing");
    scrub::stack();
}

#[test]
fn a_comparison_leaves_neither_seed_on_the_stack() {
    let _abi = abi();
    let (phrase, _) = ozone();
    let other = LEGAL;
    let secrets = vec![
        keys::seed_from_phrase(phrase.as_bytes(), "").unwrap().to_vec(),
        keys::seed_from_phrase(other.as_bytes(), "").unwrap().to_vec(),
    ];
    let handle = open(phrase.as_bytes()).unwrap();
    scrub::stack();
    assert_eq!(below(|| matches(handle, phrase.as_bytes())), Ok(true));
    assert_eq!(found_below(&secrets), None, "after a match");
    assert_eq!(below(|| matches(handle, other.as_bytes())), Ok(false));
    assert_eq!(found_below(&secrets), None, "after another phrase");
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn the_icarus_keys_the_wallet_pins_for_the_canonical_phrase() {
    // `blockchain_utils`' `Cip1852.fromSeed(entropy, cardanoIcarus)`, the
    // derivation the app's other-paths question used in Dart (30 October
    // 2026): the master, and the payment and staking halves of account zero's
    // address. `tool/so_smoke.c` and the Dart oracle pin the payment key.
    let _abi = abi();
    let handle = open(ABANDON.as_bytes()).unwrap();
    for (at, pinned) in [
        ("m", "37fdfdbe9ac856469f8d83c66c57880246cd8bf7f852bf5b94336fe535c0efc8"),
        (CARDANO_0, "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a"),
        ("m/1852'/1815'/0'/2/0", "012f5dc3115b8a07981e6e50f5a671e2c6fbb26c3ffde1cd1dcaf40a7fe8f160"),
    ] {
        assert_eq!(to_hex(&icarus_public_key(handle, at).unwrap()), pinned, "{at}");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

// --- EVM transactions: sign what you see (2c) -------------------------------

/// RLP, written here rather than by the library under test, so a mistake the
/// decoder shares with its own encoder cannot pass.
fn rlp_length(offset: u8, len: usize) -> Vec<u8> {
    if len < 56 {
        return vec![offset + len as u8];
    }
    let be = minimal_be(len as u128);
    [vec![offset + 55 + be.len() as u8], be].concat()
}

fn rlp_string(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    [rlp_length(0x80, bytes.len()), bytes.to_vec()].concat()
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body = items.concat();
    [rlp_length(0xc0, body.len()), body].concat()
}

/// [n] big-endian with no leading zero; zero is empty.
fn minimal_be(n: u128) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(16);
    bytes[first..].to_vec()
}

fn word(n: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&n.to_be_bytes());
    out
}

/// An EVM transaction as the tests build it: its unsigned bytes in the form
/// web3dart writes, and the app's [`evm::Expected`] of it.
#[derive(Clone)]
struct EvmTx {
    eip1559: bool,
    chain: u128,
    nonce: u128,
    fee: u128,
    max_fee: u128,
    gas: u128,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
}

impl EvmTx {
    /// A transaction that looks random and is the same on every run.
    fn sample(seed: u64, eip1559: bool) -> Self {
        let bytes = sequence(seed, 64);
        let n = |i: usize, len: usize| bytes[i..i + len].iter().fold(0u128, |a, b| a << 8 | u128::from(*b));
        Self {
            eip1559,
            chain: [1, 137, 8453, 42161, 56][seed as usize % 5],
            nonce: n(0, 2),
            fee: n(2, 5),
            max_fee: if eip1559 { n(7, 6) } else { 0 },
            gas: 21_000 + n(13, 2),
            to: if seed % 7 == 0 { None } else { Some(bytes[15..35].try_into().unwrap()) },
            value: if seed % 3 == 0 { 0 } else { n(35, 9) },
            data: sequence(seed + 1000, (seed as usize * 37) % 300),
        }
    }

    fn unsigned(&self) -> Vec<u8> {
        let to = self.to.map(|a| rlp_string(&a)).unwrap_or_else(|| rlp_string(&[]));
        let num = |n: u128| rlp_string(&minimal_be(n));
        if self.eip1559 {
            let list = rlp_list(&[
                num(self.chain), num(self.nonce), num(self.fee), num(self.max_fee), num(self.gas),
                to, num(self.value), rlp_string(&self.data), rlp_list(&[]),
            ]);
            [vec![0x02], list].concat()
        } else {
            rlp_list(&[
                num(self.nonce), num(self.fee), num(self.gas), to, num(self.value),
                rlp_string(&self.data), num(self.chain), num(0), num(0),
            ])
        }
    }

    fn expected(&self) -> Vec<u8> {
        let mut out = vec![if self.eip1559 { 2 } else { 0 }];
        out.extend_from_slice(&word(self.chain));
        match self.to {
            Some(to) => {
                out.push(1);
                out.extend_from_slice(&to);
            }
            None => out.extend_from_slice(&[0u8; 21]),
        }
        for n in [self.value, self.gas, self.fee, self.max_fee] {
            out.extend_from_slice(&word(n));
        }
        out.extend_from_slice(&self.data);
        out
    }
}

/// [expected] read for a screen, then signed, as the app does since 2f-1b; a
/// reading a refusal left unused is taken back, so no test leaves one for
/// another.
fn sign_evm(handle: u64, path: &str, unsigned: &[u8], expected: &[u8]) -> Result<[u8; 65], i32> {
    let read = read_evm_for(handle, path, expected);
    let signed = sign_evm_unread(handle, path, unsigned, expected);
    if let (Ok(read), Err(_)) = (&read, &signed) {
        let left = evm::Shown::of(&evm::Expected::read(expected).unwrap(), signer_of(read, "from"));
        shown().retain(|entry| *entry != left);
    }
    signed
}

fn sign_evm_unread(handle: u64, path: &str, unsigned: &[u8], expected: &[u8]) -> Result<[u8; 65], i32> {
    let mut out = [0u8; 65];
    let code = unsafe {
        kc_secp256k1_sign_evm_transaction(
            handle,
            path.as_ptr(),
            path.len(),
            unsigned.as_ptr(),
            unsigned.len(),
            expected.as_ptr(),
            expected.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 65], "a refused transaction wrote its signature");
        Err(code)
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Keccak256::digest(bytes).into()
}

#[test]
fn eip_155s_example_is_signed_as_eip_155_publishes_it() {
    // EIP-155's own example: nonce 9, 20 gwei, 21,000 gas, one ether to
    // 0x3535…35 on chain 1, signed by the key 0x4646…46. Its signing data and
    // hash, and the r and s of its signed transaction, as the EIP gives them;
    // the Dart oracle holds web3dart to the same bytes.
    let _abi = abi();
    let tx = EvmTx {
        eip1559: false,
        chain: 1,
        nonce: 9,
        fee: 20_000_000_000,
        max_fee: 0,
        gas: 21_000,
        to: Some([0x35; 20]),
        value: 1_000_000_000_000_000_000,
        data: vec![],
    };
    let unsigned = tx.unsigned();
    assert_eq!(
        to_hex(&unsigned),
        "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
    );
    assert_eq!(
        to_hex(&keccak(&unsigned)),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );
    let key = open_key(KC_CURVE_SECP256K1, &[0x46; 32]).unwrap();
    let signature = sign_evm(key, "m", &unsigned, &tx.expected()).unwrap();
    assert_eq!(to_hex(&signature[..32]), "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276");
    assert_eq!(to_hex(&signature[32..64]), "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    assert_eq!(signature[64], 0, "v = 37 on chain 1");
    assert_eq!(kc_close(key), KC_OK);
}

#[test]
fn a_transaction_held_to_itself_is_signed_as_its_digest_would_be() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let legal = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let key = keys::derive(&legal[..], &path(EVM_0)).unwrap();
    for seed in 1..=60u64 {
        let tx = EvmTx::sample(seed, seed % 2 == 0);
        let unsigned = tx.unsigned();
        let signed = sign_evm(wallet, EVM_0, &unsigned, &tx.expected()).unwrap();
        assert_eq!(signed, keys::sign_digest(&key, &keccak(&unsigned)).unwrap(), "seed {seed}");
        let recovered = recovered(&signed, &keccak(&unsigned));
        assert_eq!(
            recovered.serialize(),
            public_key(wallet, EVM_0, KC_PUBLIC_KEY_COMPRESSED).unwrap()[..],
            "seed {seed}"
        );
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn every_field_the_review_covers_is_held_to_what_the_app_built() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    for eip1559 in [false, true] {
        let tx = EvmTx { data: vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3], ..EvmTx::sample(11, eip1559) };
        let unsigned = tx.unsigned();
        assert!(sign_evm(wallet, EVM_0, &unsigned, &tx.expected()).is_ok());
        let changed: Vec<(&str, EvmTx)> = vec![
            ("chain", EvmTx { chain: tx.chain + 1, ..tx.clone() }),
            ("recipient", EvmTx { to: Some([0x99; 20]), ..tx.clone() }),
            ("no recipient", EvmTx { to: None, ..tx.clone() }),
            ("value", EvmTx { value: tx.value + 1, ..tx.clone() }),
            ("gas limit", EvmTx { gas: tx.gas + 1, ..tx.clone() }),
            ("fee", EvmTx { fee: tx.fee + 1, ..tx.clone() }),
            ("call data", EvmTx { data: vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 4], ..tx.clone() }),
            ("call data cut", EvmTx { data: vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2], ..tx.clone() }),
            ("kind", EvmTx { eip1559: !eip1559, max_fee: if eip1559 { 0 } else { tx.fee }, ..tx.clone() }),
        ];
        let mut changed = changed;
        if eip1559 {
            changed.push(("maximum fee", EvmTx { max_fee: tx.max_fee + 1, ..tx.clone() }));
        }
        for (why, other) in changed {
            // The bytes changed under the app's transaction, and the app's
            // transaction changed under the bytes: both refused.
            assert_eq!(sign_evm(wallet, EVM_0, &other.unsigned(), &tx.expected()), Err(KC_ERR_TRANSACTION), "{why}, bytes");
            assert_eq!(sign_evm(wallet, EVM_0, &unsigned, &other.expected()), Err(KC_ERR_TRANSACTION), "{why}, expected");
        }
        // The nonce is the network's to fill, and is not held to anything.
        let renonced = EvmTx { nonce: tx.nonce + 1, ..tx.clone() };
        assert!(sign_evm(wallet, EVM_0, &renonced.unsigned(), &tx.expected()).is_ok());
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn only_the_forms_the_app_writes_are_read() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let legacy = EvmTx::sample(5, false);
    let typed = EvmTx::sample(6, true);
    let num = |n: u128| rlp_string(&minimal_be(n));
    let l = |items: Vec<Vec<u8>>| rlp_list(&items);
    let to = rlp_string(&[0x11; 20]);
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("empty", vec![], typed.expected()),
        ("EIP-2930", [vec![0x01], typed.unsigned()[1..].to_vec()].concat(), typed.expected()),
        ("type 3", [vec![0x03], typed.unsigned()[1..].to_vec()].concat(), typed.expected()),
        ("Celo", [vec![0x7b], typed.unsigned()[1..].to_vec()].concat(), typed.expected()),
        ("a byte after", [typed.unsigned(), vec![0]].concat(), typed.expected()),
        ("a legacy byte after", [legacy.unsigned(), vec![0x80]].concat(), legacy.expected()),
        ("cut short", typed.unsigned()[..typed.unsigned().len() - 1].to_vec(), typed.expected()),
        ("a string, not a list", [vec![0x02], rlp_string(&[1, 2, 3])].concat(), typed.expected()),
        ("an access list", [vec![0x02], l(vec![num(1), num(0), num(1), num(2), num(21000), to.clone(), num(0), rlp_string(&[]), l(vec![l(vec![to.clone(), l(vec![])])])])].concat(),
            EvmTx { eip1559: true, chain: 1, nonce: 0, fee: 1, max_fee: 2, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a field more", [vec![0x02], l(vec![num(1), num(0), num(1), num(2), num(21000), to.clone(), num(0), rlp_string(&[]), l(vec![]), num(0)])].concat(),
            EvmTx { eip1559: true, chain: 1, nonce: 0, fee: 1, max_fee: 2, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("chain zero", [vec![0x02], l(vec![num(0), num(0), num(1), num(2), num(21000), to.clone(), num(0), rlp_string(&[]), l(vec![])])].concat(),
            EvmTx { eip1559: true, chain: 0, nonce: 0, fee: 1, max_fee: 2, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("legacy without EIP-155", l(vec![num(0), num(1), num(21000), to.clone(), num(0), rlp_string(&[])]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("legacy, r not zero", l(vec![num(0), num(1), num(21000), to.clone(), num(0), rlp_string(&[]), num(1), num(1), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a leading zero", l(vec![num(0), rlp_string(&[0, 1]), num(21000), to.clone(), num(0), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("zero as 0x00", l(vec![vec![0x00], num(1), num(21000), to.clone(), num(0), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a nonce of nine bytes", l(vec![rlp_string(&[1; 9]), num(1), num(21000), to.clone(), num(0), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a value of 33 bytes", l(vec![num(0), num(1), num(21000), to.clone(), rlp_string(&[1; 33]), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a recipient of 19 bytes", l(vec![num(0), num(1), num(21000), rlp_string(&[0x11; 19]), num(0), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 1, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
        ("a single byte written long", l(vec![num(0), vec![0x81, 0x05], num(21000), to.clone(), num(0), rlp_string(&[]), num(1), num(0), num(0)]),
            EvmTx { eip1559: false, chain: 1, nonce: 0, fee: 5, max_fee: 0, gas: 21000, to: Some([0x11; 20]), value: 0, data: vec![] }.expected()),
    ];
    for (why, unsigned, expected) in cases {
        assert_eq!(sign_evm(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_TRANSACTION), "{why}");
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn the_app_s_transaction_in_another_layout_is_an_argument() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let tx = EvmTx::sample(3, true);
    let (unsigned, expected) = (tx.unsigned(), tx.expected());
    let with = |at: usize, value: u8| {
        let mut e = expected.clone();
        e[at] = value;
        e
    };
    for (why, other) in [
        ("short", expected[..evm::EXPECTED_FIXED_BYTES - 1].to_vec()),
        ("kind 1", with(0, 1)),
        ("presence byte 2", with(33, 2)),
        ("no recipient, an address", { let mut e = with(33, 0); e[40] = 1; e }),
    ] {
        assert_eq!(sign_evm(wallet, EVM_0, &unsigned, &other), Err(KC_ERR_ARGUMENT), "{why}");
    }
    let mut out = [0u8; 70];
    unsafe {
        for length in [0, 64, 66] {
            let code = kc_secp256k1_sign_evm_transaction(
                wallet, EVM_0.as_ptr(), EVM_0.len(), unsigned.as_ptr(), unsigned.len(),
                expected.as_ptr(), expected.len(), out.as_mut_ptr(), length,
            );
            assert_eq!(code, KC_ERR_ARGUMENT, "into {length} bytes");
        }
        let code = kc_secp256k1_sign_evm_transaction(
            wallet, EVM_0.as_ptr(), EVM_0.len(), core::ptr::null(), 0,
            expected.as_ptr(), expected.len(), out.as_mut_ptr(), 65,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "no transaction");
        let code = kc_secp256k1_sign_evm_transaction(
            wallet, EVM_0.as_ptr(), EVM_0.len(), unsigned.as_ptr(), unsigned.len(),
            core::ptr::null(), 0, out.as_mut_ptr(), 65,
        );
        assert_eq!(code, KC_ERR_ARGUMENT, "no expectation");
    }
    assert_eq!(out, [0u8; 70], "a refusal wrote output");
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(sign_evm(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_HANDLE));
}

#[test]
fn an_imported_key_signs_at_m_and_another_curve_is_refused() {
    let _abi = abi();
    let tx = EvmTx::sample(9, true);
    let secp = open_key(KC_CURVE_SECP256K1, &[7u8; 32]).unwrap();
    let signed = sign_evm(secp, "m", &tx.unsigned(), &tx.expected()).unwrap();
    assert_eq!(signed, sign(secp, "m", &keccak(&tx.unsigned())).unwrap());
    assert_eq!(sign_evm(secp, EVM_0, &tx.unsigned(), &tx.expected()), Err(KC_ERR_PATH));
    let ed = open_key(KC_CURVE_ED25519, &[7u8; 32]).unwrap();
    assert_eq!(sign_evm(ed, "m", &tx.unsigned(), &tx.expected()), Err(KC_ERR_KIND));
    for key in [secp, ed] {
        assert_eq!(kc_close(key), KC_OK);
    }
}

#[test]
fn an_evm_transaction_signature_leaves_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = secrets_along(&seed[..], EVM_0);
    let tx = EvmTx::sample(13, true);
    let (unsigned, expected) = (tx.unsigned(), tx.expected());
    scrub::stack();
    let signature = below(|| sign_evm(handle, EVM_0, &unsigned, &expected).unwrap());
    assert_eq!(found_below(&secrets), None);
    core::hint::black_box(signature);
    assert_eq!(kc_close(handle), KC_OK);
}


// ---------------------------------------------------------------------------
// Bitcoin-family transactions: sign what you see (2d)

const BTC_RECEIVE: &str = "m/84'/0'/0'/0/0";
const BTC_CHANGE: &str = "m/84'/0'/0'/1/0";

fn hash160_of(data: &[u8]) -> [u8; 20] {
    use ripemd::Digest as _;
    ripemd::Ripemd160::digest(Sha256::digest(data)).into()
}

fn sha256d_of(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn compact(n: usize) -> Vec<u8> {
    assert!(n < 0xfd, "the tests write short transactions");
    vec![n as u8]
}

fn public_at(path: &str) -> PublicKey {
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    keys::public_key(&keys::derive(&seed[..], &keys::parse_path(path.as_bytes()).unwrap()).unwrap())
}

/// The output script of [kind] (the core's numbering) for [key], written
/// here from the BIPs rather than by `src/bitcoin.rs`.
fn script_of(kind: u8, key: &PublicKey, _witness_script: &[u8]) -> Vec<u8> {
    match kind {
        0 => [&[0x76, 0xa9, 0x14][..], &hash160_of(&key.serialize()), &[0x88, 0xac]].concat(),
        1 => [&[0x76, 0xa9, 0x14][..], &hash160_of(&key.serialize_uncompressed()), &[0x88, 0xac]]
            .concat(),
        2 => {
            let redeem = [&[0x00, 0x14][..], &hash160_of(&key.serialize())].concat();
            [&[0xa9, 0x14][..], &hash160_of(&redeem), &[0x87]].concat()
        }
        3 => [&[0x00, 0x14][..], &hash160_of(&key.serialize())].concat(),
        4 => {
            let (internal, _) = key.x_only_public_key();
            let tweak = tagged(b"TapTweak", &internal.to_byte_array());
            let (output, _) = internal.add_tweak(&Scalar::from_be_bytes(tweak).unwrap()).unwrap();
            [&[0x51, 0x20][..], &output.to_byte_array()].concat()
        }
        _ => unreachable!(),
    }
}

fn tagged(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(message);
    hasher.finalize().into()
}


#[derive(Clone)]
struct BtcInput {
    txid: [u8; 32],
    vout: u32,
    sequence: u32,
    amount: u64,
    spent: Vec<u8>,
    kind: u8,
    path: String,
    witness_script: Vec<u8>,
    previous: Vec<u8>,
}

#[derive(Clone)]
struct BtcOutput {
    value: u64,
    script: Vec<u8>,
    change: Option<(u8, String, Vec<u8>)>,
}

/// A transaction and the request for it, written by the test from
/// `kc_bitcoin_sign_transaction`'s documented layout.
#[derive(Clone)]
struct BtcTx {
    flavour: u8,
    inputs: Vec<BtcInput>,
    outputs: Vec<BtcOutput>,
    fee: u64,
}

impl BtcTx {
    fn input(kind: u8, path: &str, amount: u64, n: u64) -> BtcInput {
        let key = public_at(path);
        let witness_script: Vec<u8> = Vec::new();
        let spent = script_of(kind, &key, &witness_script);
        BtcInput {
            txid: sequence(n, 32).try_into().unwrap(),
            vout: n as u32 % 3,
            sequence: 0xffff_fffd,
            amount,
            spent,
            kind,
            path: path.to_owned(),
            witness_script,
            previous: Vec::new(),
        }
    }

    /// A P2WPKH send: one input, a payment and change.
    fn segwit_send() -> Self {
        Self::send(vec![Self::input(3, BTC_RECEIVE, 100_000, 1)])
    }

    fn send(inputs: Vec<BtcInput>) -> Self {
        let spent: u64 = inputs.iter().map(|i| i.amount).sum();
        let change_key = public_at(BTC_CHANGE);
        let pay = BtcOutput {
            value: spent / 2,
            script: [&[0x00, 0x14][..], &sequence(99, 20)].concat(),
            change: None,
        };
        let change = BtcOutput {
            value: spent - spent / 2 - 1_000,
            script: script_of(3, &change_key, &[]),
            change: Some((3, BTC_CHANGE.to_owned(), Vec::new())),
        };
        Self { flavour: 0, inputs, outputs: vec![pay, change], fee: 1_000 }
    }

    fn unsigned(&self) -> Vec<u8> {
        let mut out = 2u32.to_le_bytes().to_vec();
        out.extend(compact(self.inputs.len()));
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_le_bytes());
            out.push(0);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        out.extend(compact(self.outputs.len()));
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            out.extend(compact(output.script.len()));
            out.extend_from_slice(&output.script);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn request(&self) -> Vec<u8> {
        self.request_for(&self.unsigned())
    }

    fn request_for(&self, unsigned: &[u8]) -> Vec<u8> {
        fn short(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = vec![self.flavour];
        out.extend_from_slice(&(unsigned.len() as u32).to_le_bytes());
        out.extend_from_slice(unsigned);
        for input in &self.inputs {
            out.extend_from_slice(&input.amount.to_le_bytes());
            short(&mut out, &input.spent);
            out.push(input.kind);
            short(&mut out, input.path.as_bytes());
            short(&mut out, &input.witness_script);
            out.extend_from_slice(&(input.previous.len() as u32).to_le_bytes());
            out.extend_from_slice(&input.previous);
        }
        out.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            short(&mut out, &output.script);
            match &output.change {
                None => {
                    out.push(0xff);
                    short(&mut out, &[]);
                    short(&mut out, &[]);
                }
                Some((kind, path, witness_script)) => {
                    out.push(*kind);
                    short(&mut out, path.as_bytes());
                    short(&mut out, witness_script);
                }
            }
        }
        out.extend_from_slice(&self.fee.to_le_bytes());
        out
    }

    /// Gives input [index] a previous transaction that pays its amount to
    /// its script at its index, and points the input at it.
    fn with_previous(mut self, index: usize) -> Self {
        let input = &self.inputs[index];
        let mut previous = 1u32.to_le_bytes().to_vec();
        previous.extend(compact(1));
        previous.extend_from_slice(&[0x77; 36]);
        previous.push(0);
        previous.extend_from_slice(&[0xff; 4]);
        previous.extend(compact(input.vout as usize + 1));
        for vout in 0..=input.vout {
            let (value, script) = if vout == input.vout {
                (input.amount, input.spent.clone())
            } else {
                (5_000, vec![0x51])
            };
            previous.extend_from_slice(&value.to_le_bytes());
            previous.extend(compact(script.len()));
            previous.extend_from_slice(&script);
        }
        previous.extend_from_slice(&0u32.to_le_bytes());
        let txid = sha256d_of(&previous);
        let input = &mut self.inputs[index];
        input.txid = txid;
        input.previous = previous;
        self
    }
}

/// [request] signed once a screen was shown it (2f-3): read first, as every
/// door does — a read the core refuses is the signature's refusal — and the
/// reading taken back when the signature is refused, so it is left to nobody.
fn sign_btc(handle: u64, request: &[u8], inputs: usize) -> Result<Vec<[u8; 96]>, i32> {
    read_btc(handle, request)?;
    let signed = sign_btc_unread(handle, request, inputs);
    if signed.is_err() {
        let id = bitcoin::request_id(request);
        shown_bitcoin().retain(|entry| *entry != id);
    }
    signed
}

/// [request] as `kc_bitcoin_read_transaction` reads it: the length first, then
/// the reading.
fn read_btc(handle: u64, request: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn sign_btc_unread(handle: u64, request: &[u8], inputs: usize) -> Result<Vec<[u8; 96]>, i32> {
    let mut out = vec![0u8; inputs * 96];
    let code = unsafe {
        kc_bitcoin_sign_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out.chunks(96).map(|c| c.try_into().unwrap()).collect())
    } else {
        assert!(out.iter().all(|b| *b == 0), "a refused transaction wrote a signature");
        Err(code)
    }
}

#[test]
fn bip_143s_own_examples_are_its_sighashes() {
    for (i, (tx, code, index, amount, hash_type, sighash)) in BIP143.iter().enumerate() {
        let bytes = hex(tx);
        let tx = bitcoin::Transaction::read(&bytes).unwrap();
        let got = bitcoin::segwit_v0_sighash(&tx, *index, &hex(code), *amount, *hash_type);
        assert_eq!(to_hex(&got), *sighash, "example {i}, hash type {hash_type:#x}");
    }
}

#[test]
fn bip_341s_key_path_spends_signature_messages_sighashes_and_signatures() {
    let bytes = hex(BIP341_TRANSACTION);
    let tx = bitcoin::Transaction::read(&bytes).unwrap();
    let scripts: Vec<Vec<u8>> = BIP341_SPENT.iter().map(|(_, s)| hex(s)).collect();
    let spent: Vec<(u64, &[u8])> =
        BIP341_SPENT.iter().zip(&scripts).map(|((a, _), s)| (*a, &s[..])).collect();
    let mut signed = 0;
    for (index, hash_type, internal, merkle_root, message, sighash, tweak, tweaked, witness) in
        BIP341_INPUTS
    {
        let why = format!("input {index}, hash type {hash_type:#x}");
        // The vectors' message starts with the epoch byte the sighash puts
        // before it.
        let got = bitcoin::taproot_signature_message(&tx, index, &spent, hash_type).unwrap();
        assert_eq!(format!("00{}", to_hex(&got)), message, "{why}");
        let digest = bitcoin::taproot_sighash(&tx, index, &spent, hash_type).unwrap();
        assert_eq!(to_hex(&digest), sighash, "{why}");
        if !merkle_root.is_empty() {
            continue; // a script tree's tweak: not BIP-86, which the wallet writes
        }
        let key = keys::secp256k1_key(&hex(internal).try_into().unwrap()).unwrap();
        let (output, got_tweak) = bitcoin::taproot_output_key(&keys::public_key(&key)).unwrap();
        assert_eq!(to_hex(&got_tweak), tweak, "{why}");
        let tweaked_key = SecretKey::from_secret_bytes(hex(tweaked).try_into().unwrap()).unwrap();
        assert_eq!(tweaked_key.x_only_public_key().0.to_byte_array(), output, "{why}");
        // The vectors sign with no auxiliary randomness; the signing call
        // the core uses, given the same, gives the same signature.
        let keypair = Keypair::from_secret_key(&tweaked_key);
        let signature = keys::schnorr_sign_with_aux(&keypair, &digest, &[0; 32]).unwrap();
        assert_eq!(to_hex(&signature), witness[..128], "{why}");
        signed += 1;
    }
    assert!(signed >= 1, "no BIP-86 spend was checked");
    for (internal, tweak, output, script) in BIP341_OUTPUTS {
        let key = PublicKey::from_slice(&[&[0x02][..], &hex(internal)].concat()).unwrap();
        let (got, got_tweak) = bitcoin::taproot_output_key(&key).unwrap();
        assert_eq!((to_hex(&got), to_hex(&got_tweak)), (output.to_owned(), tweak.to_owned()));
        assert_eq!(format!("5120{}", to_hex(&got)), script);
    }
}

#[test]
fn bitcoin_cores_legacy_sighashes() {
    for (i, (tx, script, index, hash_type, sighash)) in LEGACY_SIGHASH.iter().enumerate() {
        let bytes = hex(tx);
        let tx = bitcoin::Transaction::read(&bytes).unwrap();
        let got = bitcoin::legacy_sighash(&tx, *index, &hex(script), *hash_type);
        assert_eq!(to_hex(&got), *sighash, "case {i}, hash type {hash_type:#x}");
    }
}

#[test]
fn bitcoin_cash_nodes_sighashes_with_the_fork_flag_and_without() {
    let mut forked = 0;
    for (i, (tx, script, index, hash_type, regular, legacy)) in FORKID_SIGHASH.iter().enumerate() {
        let bytes = hex(tx);
        let tx = bitcoin::Transaction::read(&bytes).unwrap();
        let script = hex(script);
        assert_eq!(
            to_hex(&bitcoin::legacy_sighash(&tx, *index, &script, *hash_type)),
            *legacy,
            "case {i}, hash type {hash_type:#x}, without the fork flag"
        );
        if hash_type & 0x40 != 0 {
            // The file carries no amount; Bitcoin Cash Node's test signs
            // with none.
            let got = bitcoin::segwit_v0_sighash(&tx, *index, &script, 0, *hash_type);
            assert_eq!(to_hex(&got), *regular, "case {i}, hash type {hash_type:#x}");
            forked += 1;
        } else {
            assert_eq!(regular, legacy, "case {i}");
        }
    }
    assert!(forked >= 90, "{forked} cases with the fork flag");
}

/// The signature in [signed] verifies over its sighash with [key] — ECDSA,
/// low `r` and low `s`, or BIP-340 under BIP-86's output key.
fn assert_signed(signed: &[u8; 96], kind: u8, key: &PublicKey) {
    let (digest, signature) = (&signed[..32], &signed[32..]);
    if kind == 4 {
        let script = script_of(4, key, &[]);
        let output = XOnlyPublicKey::from_byte_array(script[2..].try_into().unwrap()).unwrap();
        schnorr::verify(&schnorr::Signature::from_byte_array(signature.try_into().unwrap()), digest, &output)
            .unwrap();
    } else {
        assert!(signature[0] < 0x80, "r is high");
        let message = Message::from_digest(digest.try_into().unwrap());
        Signature::from_compact(signature).unwrap().verify(message, key).unwrap();
    }
}

#[test]
fn a_segwit_send_is_signed_over_the_sighash_the_core_computed() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let tx = BtcTx::segwit_send();
    let signed = sign_btc(handle, &tx.request(), 1).unwrap();
    let unsigned = tx.unsigned();
    let read = bitcoin::Transaction::read(&unsigned).unwrap();
    let code = script_of(0, &public_at(BTC_RECEIVE), &[]);
    assert_eq!(signed[0][..32], bitcoin::segwit_v0_sighash(&read, 0, &code, 100_000, 1));
    assert_signed(&signed[0], 3, &public_at(BTC_RECEIVE));
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn every_kind_spends_its_keys_script() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let paths = [
        "m/44'/0'/0'/0/3",
        "m/44'/0'/0'/0/4",
        "m/49'/0'/0'/0/5",
        "m/84'/0'/0'/0/6",
        "m/86'/0'/0'/0/7",
    ];
    let inputs: Vec<BtcInput> = (0u8..5)
        .map(|kind| BtcTx::input(kind, paths[kind as usize], 40_000 + u64::from(kind), u64::from(kind) + 10))
        .collect();
    // The two legacy inputs carry the transactions they spend (O38).
    let tx = BtcTx::send(inputs).with_previous(0).with_previous(1);
    let signed = sign_btc(handle, &tx.request(), 5).unwrap();
    for (kind, signed) in signed.iter().enumerate() {
        assert_signed(signed, kind as u8, &public_at(paths[kind]));
    }
    // Each sighash is the one its kind takes.
    let unsigned = tx.unsigned();
    let read = bitcoin::Transaction::read(&unsigned).unwrap();
    assert_eq!(signed[0][..32], bitcoin::legacy_sighash(&read, 0, &tx.inputs[0].spent, 1));
    let spent: Vec<(u64, &[u8])> = tx.inputs.iter().map(|i| (i.amount, &i.spent[..])).collect();
    assert_eq!(signed[4][..32], bitcoin::taproot_sighash(&read, 4, &spent, 0).unwrap());
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn bitcoin_cash_signs_with_the_fork_flag_and_needs_no_previous_transaction() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let path = "m/44'/145'/0'/0/0";
    let mut tx = BtcTx::send(vec![BtcTx::input(0, path, 70_000, 3)]);
    tx.flavour = 1;
    let change = public_at(BTC_CHANGE);
    tx.outputs[1].script = script_of(0, &change, &[]);
    tx.outputs[1].change = Some((0, BTC_CHANGE.to_owned(), Vec::new()));
    let signed = sign_btc(handle, &tx.request(), 1).unwrap();
    let unsigned = tx.unsigned();
    let read = bitcoin::Transaction::read(&unsigned).unwrap();
    assert_eq!(
        signed[0][..32],
        bitcoin::segwit_v0_sighash(&read, 0, &tx.inputs[0].spent, 70_000, 0x41)
    );
    assert_signed(&signed[0], 0, &public_at(path));
    // The same transaction on the Bitcoin flavour is a legacy one, and has
    // no previous transaction.
    tx.flavour = 0;
    assert_eq!(sign_btc(handle, &tx.request(), 1), Err(KC_ERR_TRANSACTION));
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn what_the_app_did_not_build_is_refused() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let built = BtcTx::segwit_send();
    let refused = |tx: &BtcTx, request: Vec<u8>, why: &str| {
        assert_eq!(sign_btc(handle, &request, tx.inputs.len()), Err(KC_ERR_TRANSACTION), "{why}");
    };
    // The unsigned bytes differ from the outputs the app named.
    for (field, change) in [
        ("an amount", Box::new(|t: &mut BtcTx| t.outputs[0].value += 1) as Box<dyn Fn(&mut BtcTx)>),
        ("a recipient", Box::new(|t: &mut BtcTx| t.outputs[0].script[5] ^= 1)),
        ("an output more", Box::new(|t: &mut BtcTx| {
            let extra = t.outputs[0].clone();
            t.outputs.push(extra)
        })),
    ] {
        let mut other = built.clone();
        change(&mut other);
        refused(&built, built.request_for(&other.unsigned()), field);
    }
    let mut fee = built.clone();
    fee.fee += 1;
    refused(&fee, fee.request(), "a fee the outputs do not leave");
    let mut change = built.clone();
    change.outputs[1].change = Some((3, "m/84'/0'/0'/1/1".to_owned(), Vec::new()));
    refused(&change, change.request(), "change to another of the wallet's keys");
    let mut stranger = built.clone();
    stranger.outputs[1].script = [&[0x00, 0x14][..], &[0x42; 20]].concat();
    stranger.outputs[1].value = built.outputs[1].value;
    refused(&stranger, stranger.request(), "change to a script no key of ours has");
    let mut spent = built.clone();
    spent.inputs[0].path = "m/84'/0'/0'/0/1".to_owned();
    refused(&spent, spent.request(), "an input another key's script locks");
    let mut kind = built.clone();
    kind.inputs[0].kind = 2;
    refused(&kind, kind.request(), "an input of another kind");
    // The unsigned form, and nothing else.
    let mut with_script_sig = built.unsigned();
    with_script_sig[4 + 1 + 36] = 1;
    with_script_sig.insert(4 + 1 + 37, 0x51);
    refused(&built, built.request_for(&with_script_sig), "a script signature");
    let witnessed = [&built.unsigned()[..4], &[0x00, 0x01], &built.unsigned()[4..built.unsigned().len() - 4], &[0x00], &built.unsigned()[built.unsigned().len() - 4..]].concat();
    refused(&built, built.request_for(&witnessed), "a witness");
    // A legacy input: its previous transaction, and that transaction's.
    let legacy = BtcTx::send(vec![BtcTx::input(0, "m/44'/0'/0'/0/0", 50_000, 4)]);
    refused(&legacy, legacy.request(), "a legacy input with no previous transaction");
    let with = legacy.clone().with_previous(0);
    assert!(sign_btc(handle, &with.request(), 1).is_ok());
    let mut paid = with.clone();
    paid.inputs[0].amount -= 1;
    paid.fee -= 1;
    refused(&paid, paid.request(), "an amount the previous transaction does not pay");
    let mut other = with.clone();
    other.inputs[0].previous[10] ^= 1;
    refused(&other, other.request(), "a previous transaction of another id");
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn a_request_in_another_layout_is_an_argument() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let built = BtcTx::segwit_send();
    let request = built.request();
    let argument = |request: &[u8], why: &str| {
        assert_eq!(sign_btc(handle, request, 1), Err(KC_ERR_ARGUMENT), "{why}");
    };
    argument(&[&[2u8][..], &request[1..]].concat(), "an unknown flavour");
    argument(&[&request[..], &[0]].concat(), "a byte after the fee");
    argument(&request[..request.len() - 1], "a byte short");
    let mut kind = built.clone();
    kind.inputs[0].kind = 6;
    argument(&kind.request(), "an unknown kind");
    let mut cash = built.clone();
    cash.flavour = 1;
    argument(&cash.request(), "Bitcoin Cash with a segwit input");
    let mut witness = built.clone();
    witness.inputs[0].witness_script = vec![0x51];
    argument(&witness.request(), "a witness script for P2WPKH");
    let mut out = vec![0u8; 95];
    let code = unsafe {
        kc_bitcoin_sign_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len())
    };
    assert_eq!(code, KC_ERR_ARGUMENT, "an output not 96 bytes per input");
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(sign_btc(handle, &request, 1), Err(KC_ERR_HANDLE));
}

#[test]
fn an_imported_key_signs_a_bitcoin_input_at_m() {
    let _abi = abi();
    let secret = [0x46u8; 32];
    let handle = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    let key = keys::public_key(&keys::secp256k1_key(&secret).unwrap());
    let mut input = BtcTx::input(3, BTC_RECEIVE, 30_000, 6);
    input.path = "m".to_owned();
    input.spent = script_of(3, &key, &[]);
    let mut tx = BtcTx::send(vec![input]);
    tx.outputs[1].script = script_of(3, &key, &[]);
    tx.outputs[1].change = Some((3, "m".to_owned(), Vec::new()));
    let signed = sign_btc(handle, &tx.request(), 1).unwrap();
    assert_signed(&signed[0], 3, &key);
    let mut deeper = tx.clone();
    deeper.inputs[0].path = BTC_RECEIVE.to_owned();
    assert_eq!(sign_btc(handle, &deeper.request(), 1), Err(KC_ERR_PATH));
    let ed = open_key(KC_CURVE_ED25519, &[7; 32]).unwrap();
    assert_eq!(sign_btc(ed, &tx.request(), 1), Err(KC_ERR_KIND));
    for key in [handle, ed] {
        assert_eq!(kc_close(key), KC_OK);
    }
}

#[test]
fn a_bitcoin_transaction_signature_leaves_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let mut secrets = secrets_along(&seed[..], BTC_RECEIVE);
    secrets.extend(secrets_along(&seed[..], BTC_CHANGE));
    let request = BtcTx::segwit_send().request();
    scrub::stack();
    let signed = below(|| sign_btc(handle, &request, 1).unwrap());
    assert_eq!(found_below(&secrets), None);
    core::hint::black_box(signed);
    assert_eq!(kc_close(handle), KC_OK);
}

// ---------------------------------------------------------------------------
// The family's digest call closed (O37, 2d-5)

#[test]
fn a_bitcoin_family_key_signs_no_bare_digest() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let digest = [0x5au8; 32];
    for purpose in [44, 49, 84, 86] {
        for coin in [0, 2, 3, 145] {
            let at = format!("m/{purpose}'/{coin}'/0'/0/0");
            assert_eq!(sign(handle, &at, &digest), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
            assert_eq!(sign_low_r(handle, &at, &digest), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
            assert_eq!(schnorr(handle, &at, &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
            assert_eq!(
                schnorr(handle, &at, &digest, &[0x42; 32]),
                Err(KC_ERR_TRANSACTION_ONLY),
                "{at}, tweaked"
            );
            // Its public key, its export and its transactions are as before.
            assert!(public_key(handle, &at, KC_PUBLIC_KEY_COMPRESSED).is_ok(), "{at}");
            assert!(export(handle, &at).is_ok(), "{at}");
        }
    }
    // The neighbours sign: no network's path, another purpose over Bitcoin's
    // coin, a coin level not hardened, the root. (EVM's coin is refused too
    // since O43, `an_evm_key_signs_no_bare_digest`, and Kaspa's since 2f-20.)
    for at in [
        DIGEST_0,
        "m/1852'/0'/0'/0/0",
        "m/84'/0/0'/0/0",
        "m",
    ] {
        assert!(sign(handle, at, &digest).is_ok(), "{at}");
        assert!(sign_low_r(handle, at, &digest).is_ok(), "{at}");
        assert!(schnorr(handle, at, &digest, &[]).is_ok(), "{at}");
    }
    // And the family's keys sign what the core reads.
    let signed = sign_btc(handle, &BtcTx::segwit_send().request(), 1).unwrap();
    assert_signed(&signed[0], 3, &public_at(BTC_RECEIVE));
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn a_key_opened_as_bitcoins_signs_only_a_transaction_the_core_reads() {
    let _abi = abi();
    let secret = [0x46u8; 32];
    let handle = open_key(KC_CURVE_SECP256K1_BITCOIN, &secret).unwrap();
    let plain = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    for format in [KC_PUBLIC_KEY_COMPRESSED, KC_PUBLIC_KEY_UNCOMPRESSED] {
        assert_eq!(public_key(handle, "m", format), public_key(plain, "m", format));
    }
    assert_eq!(export(handle, "m"), export(plain, "m"));
    let digest = [0x33u8; 32];
    assert_eq!(sign(handle, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_low_r(handle, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(handle, "m", &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert!(sign(plain, "m", &digest).is_ok(), "a key opened as plain secp256k1 still signs");
    // Not an EVM key either.
    let tx = EvmTx::sample(5, true);
    assert_eq!(sign_evm(handle, "m", &tx.unsigned(), &tx.expected()), Err(KC_ERR_KIND));
    // A Bitcoin transaction it reads, it signs.
    let key = keys::public_key(&keys::secp256k1_key(&secret).unwrap());
    let mut input = BtcTx::input(3, BTC_RECEIVE, 30_000, 7);
    input.path = "m".to_owned();
    input.spent = script_of(3, &key, &[]);
    let mut btc = BtcTx::send(vec![input]);
    btc.outputs[1].script = script_of(3, &key, &[]);
    btc.outputs[1].change = Some((3, "m".to_owned(), Vec::new()));
    let signed = sign_btc(handle, &btc.request(), 1).unwrap();
    assert_signed(&signed[0], 3, &key);
    // A scalar that is no key is refused the same way.
    assert_eq!(open_key(KC_CURVE_SECP256K1_BITCOIN, &[0u8; 32]), Err(KC_ERR_KEY));
    for h in [handle, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

// ---------------------------------------------------------------------------
// EVM messages: sign what you see (2e)

type MessageEntry = unsafe extern "C" fn(u64, *const u8, usize, *const u8, usize, *mut u8, usize) -> i32;

fn sign_message_with(entry: MessageEntry, handle: u64, path: &str, data: &[u8]) -> Result<[u8; 65], i32> {
    let mut out = [0u8; 65];
    let code =
        unsafe { entry(handle, path.as_ptr(), path.len(), data.as_ptr(), data.len(), out.as_mut_ptr(), out.len()) };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 65], "a refused signature wrote its output");
        Err(code)
    }
}

/// [json] signed as typed data once a screen was shown it (2f-2, O54): read
/// first, as every door does, and the reading taken back when the signature
/// is refused, so it is left to nobody.
fn sign_typed(handle: u64, path: &str, json: &str) -> Result<[u8; 65], i32> {
    let read = read_typed_for(handle, path, json);
    let signed = sign_typed_unread(handle, path, json);
    if let (Ok(read), Err(_)) = (&read, &signed) {
        let entry = (typed_digest(json).unwrap(), signer_of(read, "signer"));
        shown_typed().retain(|kept| *kept != entry);
    }
    signed
}

fn sign_typed_unread(handle: u64, path: &str, json: &str) -> Result<[u8; 65], i32> {
    sign_message_with(kc_evm_sign_typed_data, handle, path, json.as_bytes())
}

/// [json] as `kc_evm_read_typed_data` reads it for the key at [at] below
/// [handle]: the length first, then the reading.
fn read_typed_for(handle: u64, at: &str, json: &str) -> Result<serde_json::Value, i32> {
    let data = json.as_bytes();
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_evm_read_typed_data(handle, at.as_ptr(), at.len(), data.as_ptr(), data.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        assert_eq!(needed, usize::MAX, "a refused reading wrote a length");
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_evm_read_typed_data(handle, at.as_ptr(), at.len(), data.as_ptr(), data.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [json] read for the legal phrase's first EVM account, from a session
/// opened for it alone: for the tests of what a reading says.
fn read_typed(json: &str) -> Result<serde_json::Value, i32> {
    let reader = open(LEGAL.as_bytes()).unwrap();
    let read = read_typed_for(reader, EVM_0, json);
    assert_eq!(kc_close(reader), KC_OK);
    read
}

fn sign_personal(handle: u64, path: &str, message: &[u8]) -> Result<[u8; 65], i32> {
    sign_message_with(kc_evm_sign_personal_message, handle, path, message)
}

fn typed_digest(json: &str) -> Result<[u8; 32], Refusal> {
    eip712::digest(json.as_bytes())
}

/// The EVM address of the key at [at], lower-case hex without `0x`.
fn evm_address(handle: u64, at: &str) -> String {
    let public = public_key(handle, at, KC_PUBLIC_KEY_UNCOMPRESSED).unwrap();
    to_hex(&keccak(&public[1..])[12..])
}

/// [evm_address]'s twenty bytes.
fn evm_from(handle: u64, at: &str) -> [u8; 20] {
    hex(&evm_address(handle, at)).try_into().unwrap()
}

/// A document of one struct `T` of [fields], valued [message], over an empty
/// domain.
fn one_struct(fields: serde_json::Value, message: serde_json::Value) -> String {
    serde_json::json!({
        "types": {"EIP712Domain": [], "T": fields},
        "primaryType": "T",
        "domain": {},
        "message": message,
    })
    .to_string()
}

/// [one_struct] with one field `v` of [kind], valued [value].
fn with_value(kind: &str, value: serde_json::Value) -> String {
    one_struct(serde_json::json!([{"name": "v", "type": kind}]), serde_json::json!({"v": value}))
}

/// What [with_value] of [kind] must hash to when `v` encodes as [word]:
/// written out from the EIP rather than read back from the core.
fn one_word_digest(kind: &str, word: &[u8; 32]) -> [u8; 32] {
    let domain = keccak(&keccak(b"EIP712Domain()"));
    let type_hash = keccak(format!("T({kind} v)").as_bytes());
    let message = keccak(&[&type_hash[..], word].concat());
    keccak(&[&[0x19u8, 0x01][..], &domain, &message].concat())
}

fn word_of(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

/// EIP-712's own example: Cow's mail to Bob.
fn spec_mail() -> String {
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    })
    .to_string()
}

#[test]
fn eip712_cases_of_another_implementation_and_the_spec_hash_alike() {
    for (name, document, digest) in EIP712_HASHED {
        assert_eq!(to_hex(&typed_digest(document).unwrap()), digest, "{name}");
    }
    assert_eq!(
        to_hex(&typed_digest(&spec_mail()).unwrap()),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
        "EIP-712's example"
    );
    assert_eq!(
        eip712::type_string(spec_mail().as_bytes(), "Mail").unwrap(),
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    );
}

#[test]
fn eip712_cases_the_app_refuses_are_refused_and_alloys_full_domain_with_its_salt_is_not() {
    for (name, document) in EIP712_REFUSED {
        assert_eq!(typed_digest(document), Err(Refusal::TypedData), "{name}");
    }
    // `test_full_domain` is refused for its absent `salt` alone.
    let full_domain = EIP712_REFUSED.iter().find(|(name, _)| *name == "test_full_domain").unwrap().1;
    let mut document: serde_json::Value = serde_json::from_str(full_domain).unwrap();
    document["domain"]["salt"] = serde_json::json!(format!("0x{}", "00".repeat(32)));
    assert!(typed_digest(&document.to_string()).is_ok());
}

#[test]
fn a_domain_only_document_signs_its_domain_alone_as_metamask_and_alloy_do() {
    // O46: with the domain's type as the primary type no message is hashed,
    // as MetaMask's eth-sig-util and alloy sign it — and the message is
    // empty, or it would be shown and not signed.
    let (document, alloys) = EIP712_DOMAIN_ONLY;
    assert_eq!(to_hex(&typed_digest(document).unwrap()), alloys, "alloy's digest");
    let domain = keccak(&keccak(b"EIP712Domain()"));
    assert_eq!(typed_digest(document), Ok(keccak(&[&[0x19u8, 0x01][..], &domain].concat())));
    // A declared domain, and its message empty though the type has fields.
    let declared = serde_json::json!({
        "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}]},
        "primaryType": "EIP712Domain",
        "domain": {"name": "Smartable", "chainId": 1},
        "message": {}
    });
    let mut word = [0u8; 32];
    word[31] = 1;
    let separator = keccak(
        &[&keccak(b"EIP712Domain(string name,uint256 chainId)")[..], &keccak(b"Smartable"), &word].concat(),
    );
    assert_eq!(typed_digest(&declared.to_string()), Ok(keccak(&[&[0x19u8, 0x01][..], &separator].concat())));
    // A message beside it, the domain's own fields or anything else, is refused.
    for message in [serde_json::json!({"name": "Smartable", "chainId": 1}), serde_json::json!({"x": 1})] {
        let mut beside = declared.clone();
        beside["message"] = message.clone();
        assert_eq!(typed_digest(&beside.to_string()), Err(Refusal::TypedData), "{message}");
    }
    let mut not_an_object = declared.clone();
    not_an_object["message"] = serde_json::json!([]);
    assert_eq!(typed_digest(&not_an_object.to_string()), Err(Refusal::TypedData));
}

#[test]
fn every_struct_a_type_reaches_is_in_its_type_string_in_the_apps_order() {
    // Behind a nested array (O45).
    let nested = serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Bar": [{"name": "items", "type": "Foo[2][]"}],
            "Foo": [{"name": "a", "type": "uint256"}]
        },
        "primaryType": "Bar",
        "domain": {},
        "message": {"items": [[{"a": 1}, {"a": 2}]]}
    })
    .to_string();
    assert_eq!(eip712::type_string(nested.as_bytes(), "Bar").unwrap(), "Bar(Foo[2][] items)Foo(uint256 a)");
    assert!(typed_digest(&nested).is_ok());
    // Sorted by UTF-16 code unit, as Dart sorts strings: U+1F600 is a
    // surrogate pair from U+D83D and sorts before U+FF21, which UTF-8's byte
    // order and code-point order put first.
    let ordered = serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Top": [
                {"name": "a", "type": "\u{FF21}"},
                {"name": "b", "type": "\u{1F600}"},
                {"name": "c", "type": "a"},
                {"name": "d", "type": "Z"}
            ],
            "\u{FF21}": [{"name": "x", "type": "uint8"}],
            "\u{1F600}": [{"name": "x", "type": "uint8"}],
            "a": [{"name": "x", "type": "uint8"}],
            "Z": [{"name": "x", "type": "uint8"}]
        },
        "primaryType": "Top",
        "domain": {},
        "message": {"a": {"x": 1}, "b": {"x": 2}, "c": {"x": 3}, "d": {"x": 4}}
    })
    .to_string();
    assert_eq!(
        eip712::type_string(ordered.as_bytes(), "Top").unwrap(),
        "Top(\u{FF21} a,\u{1F600} b,a c,Z d)Z(uint8 x)a(uint8 x)\u{1F600}(uint8 x)\u{FF21}(uint8 x)"
    );
}

#[test]
fn a_number_has_one_spelling_o44() {
    let seen = typed_digest(&with_value("uint256", serde_json::json!(137))).unwrap();
    let mut word = [0u8; 32];
    word[31] = 137;
    assert_eq!(seen, one_word_digest("uint256", &word));
    for text in ["137", "0137", "0x89", "0X89", "0x0089"] {
        assert_eq!(typed_digest(&with_value("uint256", serde_json::json!(text))), Ok(seen), "{text}");
    }
    for text in [
        "+0x89", " 137", "137 ", "+137", "--137", "0x-89", "0x+89", "0x 89", "0x", "-", "", "1_37", "1e2",
        "0x89\u{0}", "\u{0661}\u{0663}\u{0667}", "0b10001001", "137n",
    ] {
        assert_eq!(typed_digest(&with_value("uint256", serde_json::json!(text))), Err(Refusal::TypedData), "{text:?}");
    }
    for value in [
        serde_json::json!(137.0),
        serde_json::json!(1e2),
        serde_json::json!(true),
        serde_json::Value::Null,
        serde_json::json!([137]),
        serde_json::json!({"v": 137}),
    ] {
        assert_eq!(typed_digest(&with_value("uint256", value.clone())), Err(Refusal::TypedData), "{value}");
    }
}

#[test]
fn the_numbers_in_a_type_name_are_canonical_too_o44() {
    for (kind, value) in [
        ("uint8", serde_json::json!(1)),
        ("int16", serde_json::json!(1)),
        ("uint", serde_json::json!(1)),
        ("int", serde_json::json!(1)),
        ("bytes1", serde_json::json!("0x01")),
        ("bytes32", serde_json::json!(format!("0x{}", "11".repeat(32)))),
        ("uint8[3]", serde_json::json!([1, 2, 3])),
        ("uint8[1024]", serde_json::json!(vec![1; 1024])),
    ] {
        assert!(typed_digest(&with_value(kind, value)).is_ok(), "{kind}");
    }
    for kind in [
        "uint08", "int016", "bytes01", "uint8[03]", "uint8[+3]", "uint8[ 3]", "uint8[3 ]", "uint7", "uint0",
        "uint264", "int512", "bytes0", "bytes33", "uint8[0]", "uint8[1025]", "Uint8", "uint8]", "uint8[3]]",
        "uint8[[3]", "uintfoo", "",
    ] {
        assert_eq!(typed_digest(&with_value(kind, serde_json::json!([1, 2, 3]))), Err(Refusal::TypedData), "{kind}");
        assert_eq!(typed_digest(&with_value(kind, serde_json::json!(1))), Err(Refusal::TypedData), "{kind}");
    }
}

#[test]
fn a_number_is_held_to_its_types_range_and_signed_as_twos_complement() {
    let f = |n: usize| "ff".repeat(n);
    let z = |n: usize| "00".repeat(n);
    for (kind, value, word) in [
        ("uint8", serde_json::json!(255), format!("{}ff", z(31))),
        ("uint8", serde_json::json!("0"), z(32)),
        ("int8", serde_json::json!(-128), format!("{}80", f(31))),
        ("int8", serde_json::json!(127), format!("{}7f", z(31))),
        ("int8", serde_json::json!("-0"), z(32)),
        ("int8", serde_json::json!("-0x0"), z(32)),
        ("int256", serde_json::json!("-1"), f(32)),
        ("int256", serde_json::json!(format!("-0x8{}", "0".repeat(63))), format!("80{}", z(31))),
        ("int256", serde_json::json!(format!("0x7{}", "f".repeat(63))), format!("7f{}", f(31))),
        ("uint256", serde_json::json!(format!("0x{}", "f".repeat(64))), f(32)),
        ("uint256", serde_json::json!(format!("0x{}{}", "0".repeat(100), "f".repeat(64))), f(32)),
        ("int64", serde_json::json!(i64::MIN), format!("{}80{}", f(24), z(7))),
        ("uint64", serde_json::json!(i64::MAX), format!("{}7f{}", z(24), f(7))),
    ] {
        assert_eq!(
            typed_digest(&with_value(kind, value.clone())),
            Ok(one_word_digest(kind, &word_of(&word))),
            "{kind} {value}"
        );
    }
    for (kind, value) in [
        ("uint8", serde_json::json!(256)),
        ("uint8", serde_json::json!(-1)),
        ("uint8", serde_json::json!("-1")),
        ("int8", serde_json::json!(128)),
        ("int8", serde_json::json!(-129)),
        ("int256", serde_json::json!(format!("0x8{}", "0".repeat(63)))),
        ("int256", serde_json::json!(format!("-0x8{}1", "0".repeat(62)))),
        ("uint256", serde_json::json!(format!("0x1{}", "0".repeat(64)))),
        ("uint256", serde_json::json!("115792089237316195423570985008687907853269984665640564039457584007913129639936")),
        // Past 64 bits signed a JSON number is no longer an integer in the app's reading.
        ("uint64", serde_json::json!(u64::MAX)),
        ("uint256", serde_json::json!(9_223_372_036_854_775_808u64)),
    ] {
        assert_eq!(typed_digest(&with_value(kind, value.clone())), Err(Refusal::TypedData), "{kind} {value}");
    }
}

#[test]
fn every_other_value_is_read_as_the_app_reads_it() {
    let address = format!("0x{}", "aB".repeat(20));
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&[0xab; 20]);
    assert_eq!(typed_digest(&with_value("address", serde_json::json!(address))), Ok(one_word_digest("address", &word)));
    let mut truth = [0u8; 32];
    truth[31] = 1;
    assert_eq!(typed_digest(&with_value("bool", serde_json::json!(true))), Ok(one_word_digest("bool", &truth)));
    assert_eq!(typed_digest(&with_value("bool", serde_json::json!(false))), Ok(one_word_digest("bool", &[0u8; 32])));
    assert_eq!(typed_digest(&with_value("bytes", serde_json::json!("0x"))), Ok(one_word_digest("bytes", &keccak(b""))));
    assert_eq!(
        typed_digest(&with_value("bytes", serde_json::json!("0xC0ffee"))),
        Ok(one_word_digest("bytes", &keccak(&[0xc0, 0xff, 0xee])))
    );
    let mut four = [0u8; 32];
    four[..4].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(typed_digest(&with_value("bytes4", serde_json::json!("0x01020304"))), Ok(one_word_digest("bytes4", &four)));
    assert_eq!(
        typed_digest(&with_value("string", serde_json::json!("h\u{e9}llo \u{1F600}"))),
        Ok(one_word_digest("string", &keccak("h\u{e9}llo \u{1F600}".as_bytes())))
    );
    for (kind, value) in [
        ("address", serde_json::json!(format!("0X{}", "ab".repeat(20)))),
        ("address", serde_json::json!(format!("0x{}", "a".repeat(39)))),
        ("address", serde_json::json!(format!("0x{}", "a".repeat(41)))),
        ("address", serde_json::json!(format!("0x{}g", "a".repeat(39)))),
        ("address", serde_json::json!("ab".repeat(20))),
        ("address", serde_json::json!(1)),
        ("bool", serde_json::json!("true")),
        ("bool", serde_json::json!(1)),
        ("bytes", serde_json::json!("0x0")),
        ("bytes", serde_json::json!("0xzz")),
        ("bytes", serde_json::json!("ab")),
        ("bytes", serde_json::json!("0X01")),
        ("bytes", serde_json::json!([1, 2])),
        ("bytes4", serde_json::json!("0x010203")),
        ("bytes4", serde_json::json!("0x0102030405")),
        ("string", serde_json::json!(5)),
        ("string", serde_json::Value::Null),
        ("uint8[]", serde_json::json!({"0": 1})),
        ("uint8[2]", serde_json::json!([1])),
        ("uint8[2]", serde_json::json!([1, 2, 3])),
    ] {
        assert_eq!(typed_digest(&with_value(kind, value.clone())), Err(Refusal::TypedData), "{kind} {value}");
    }
    // A field the type declares is there; one it does not is not read.
    let fields = serde_json::json!([{"name": "v", "type": "uint8"}]);
    let plain = typed_digest(&one_struct(fields.clone(), serde_json::json!({"v": 1})));
    assert!(plain.is_ok());
    assert_eq!(typed_digest(&one_struct(fields.clone(), serde_json::json!({"v": 1, "w": "anything"}))), plain);
    assert_eq!(typed_digest(&one_struct(fields, serde_json::json!({}))), Err(Refusal::TypedData));
    // A struct may take a primitive's name, and is then a struct.
    let shadowed = serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "T": [{"name": "v", "type": "uint256"}],
            "uint256": [{"name": "x", "type": "bool"}]
        },
        "primaryType": "T",
        "domain": {},
        "message": {"v": {"x": true}}
    });
    assert!(typed_digest(&shadowed.to_string()).is_ok());
    assert_eq!(
        eip712::type_string(shadowed.to_string().as_bytes(), "T").unwrap(),
        "T(uint256 v)uint256(bool x)"
    );
    let mut as_number = shadowed.clone();
    as_number["message"]["v"] = serde_json::json!(5);
    assert_eq!(typed_digest(&as_number.to_string()), Err(Refusal::TypedData));
}

#[test]
fn a_document_short_of_the_shape_is_refused() {
    let good: serde_json::Value = serde_json::from_str(&spec_mail()).unwrap();
    assert!(typed_digest(&good.to_string()).is_ok());
    let broken: [(&str, fn(&mut serde_json::Value)); 16] = [
        ("no types", |d| d.as_object_mut().unwrap().remove("types").map(drop).unwrap()),
        ("types a list", |d| d["types"] = serde_json::json!([])),
        ("no primary type", |d| d.as_object_mut().unwrap().remove("primaryType").map(drop).unwrap()),
        ("an empty primary type", |d| d["primaryType"] = serde_json::json!("")),
        ("a primary type not declared", |d| d["primaryType"] = serde_json::json!("Letter")),
        ("a primary type a number", |d| d["primaryType"] = serde_json::json!(1)),
        ("no domain type", |d| d["types"].as_object_mut().unwrap().remove("EIP712Domain").map(drop).unwrap()),
        ("the domain type not a list", |d| d["types"]["EIP712Domain"] = serde_json::json!({})),
        ("no domain", |d| d.as_object_mut().unwrap().remove("domain").map(drop).unwrap()),
        ("a message that is text", |d| d["message"] = serde_json::json!("hello")),
        ("a field not an object", |d| d["types"]["Person"][0] = serde_json::json!("name")),
        ("a field with no name", |d| d["types"]["Person"][0]["name"] = serde_json::json!("")),
        ("a field's type a number", |d| d["types"]["Person"][0]["type"] = serde_json::json!(1)),
        ("a field named twice", |d| d["types"]["Person"][1]["name"] = serde_json::json!("name")),
        ("an unknown type no message reaches", |d| {
            d["types"]["Unused"] = serde_json::json!([{"name": "x", "type": "uint7"}])
        }),
        ("not an object", |d| *d = serde_json::json!([1, 2])),
    ];
    for (why, change) in broken {
        let mut document = good.clone();
        change(&mut document);
        assert_eq!(typed_digest(&document.to_string()), Err(Refusal::TypedData), "{why}");
    }
    for text in ["", "{", "null", "{\"types\":", "\u{feff}{}", "{} {}"] {
        assert_eq!(typed_digest(text), Err(Refusal::TypedData), "{text:?}");
    }
    assert_eq!(eip712::digest(&[0xff, 0xfe]), Err(Refusal::TypedData), "not UTF-8");
}

/// Structs `S0` to `S{last}`, each holding the next, the last a `uint8`.
fn struct_chain(last: usize) -> String {
    let mut types = serde_json::Map::new();
    types.insert("EIP712Domain".into(), serde_json::json!([]));
    for i in 0..last {
        types.insert(format!("S{i}"), serde_json::json!([{"name": "c", "type": format!("S{}", i + 1)}]));
    }
    types.insert(format!("S{last}"), serde_json::json!([{"name": "v", "type": "uint8"}]));
    let mut message = serde_json::json!({"v": 1});
    for _ in 0..last {
        message = serde_json::json!({"c": message});
    }
    serde_json::json!({"types": types, "primaryType": "S0", "domain": {}, "message": message}).to_string()
}

#[test]
fn the_limits_are_the_apps() {
    // Depth: the twelfth struct below the message, and no thirteenth.
    assert!(typed_digest(&struct_chain(12)).is_ok());
    assert_eq!(typed_digest(&struct_chain(13)), Err(Refusal::TypedData));
    // A hundred fields a struct.
    let fields = |n: usize| serde_json::Value::Array((0..n).map(|i| serde_json::json!({"name": format!("f{i}"), "type": "bool"})).collect());
    let values = |n: usize| serde_json::Value::Object((0..n).map(|i| (format!("f{i}"), serde_json::json!(true))).collect());
    assert!(typed_digest(&one_struct(fields(100), values(100))).is_ok());
    assert_eq!(typed_digest(&one_struct(fields(101), values(101))), Err(Refusal::TypedData));
    // 1,024 entries an array.
    assert!(typed_digest(&with_value("uint8[]", serde_json::json!(vec![1; 1024]))).is_ok());
    assert_eq!(typed_digest(&with_value("uint8[]", serde_json::json!(vec![1; 1025]))), Err(Refusal::TypedData));
    // 10,000 values in all: ten fields of 999 entries is ten thousand.
    let arrays = serde_json::Value::Array((0..10).map(|i| serde_json::json!({"name": format!("a{i}"), "type": "uint8[]"})).collect());
    let mut filled = serde_json::Value::Object((0..10).map(|i| (format!("a{i}"), serde_json::json!(vec![1; 999]))).collect());
    assert!(typed_digest(&one_struct(arrays.clone(), filled.clone())).is_ok());
    filled["a3"].as_array_mut().unwrap().push(serde_json::json!(1));
    assert_eq!(typed_digest(&one_struct(arrays, filled)), Err(Refusal::TypedData));
    // 128 KiB a string, in UTF-8 bytes, and a `bytes` value.
    assert!(typed_digest(&with_value("string", serde_json::json!("\u{e9}".repeat(65_536)))).is_ok());
    assert_eq!(typed_digest(&with_value("string", serde_json::json!("\u{e9}".repeat(65_536) + "x"))), Err(Refusal::TypedData));
    assert!(typed_digest(&with_value("bytes", serde_json::json!(format!("0x{}", "00".repeat(131_072))))).is_ok());
    assert_eq!(typed_digest(&with_value("bytes", serde_json::json!(format!("0x{}", "00".repeat(131_073))))), Err(Refusal::TypedData));
    // 512 KiB of JSON, counted before it is parsed: spaces count.
    let small = spec_mail();
    let at_cap = format!("{small}{}", " ".repeat(eip712::MAX_INPUT_BYTES - small.len()));
    assert_eq!(typed_digest(&at_cap), typed_digest(&small));
    assert_eq!(typed_digest(&format!("{at_cap} ")), Err(Refusal::TypedData));
}

#[test]
fn a_recursive_type_is_hashed_to_the_depth_limit() {
    // EIP-712 allows a type to reach itself; alloy refuses it as circular.
    // The data still ends, so the depth limit is what bounds it.
    let thread = |levels: usize| {
        let mut message = serde_json::json!({"text": "leaf", "replies": []});
        for i in 0..levels {
            message = serde_json::json!({"text": format!("level {i}"), "replies": [message]});
        }
        serde_json::json!({
            "types": {
                "EIP712Domain": [],
                "Mail": [{"name": "text", "type": "string"}, {"name": "replies", "type": "Mail[]"}]
            },
            "primaryType": "Mail",
            "domain": {},
            "message": message
        })
        .to_string()
    };
    assert_eq!(eip712::type_string(thread(0).as_bytes(), "Mail").unwrap(), "Mail(string text,Mail[] replies)");
    // An array and a struct are a level each: six replies deep is twelve.
    assert!(typed_digest(&thread(6)).is_ok());
    assert_eq!(typed_digest(&thread(7)), Err(Refusal::TypedData));
    let leaf = keccak(&[&keccak(b"Mail(string text,Mail[] replies)")[..], &keccak(b"leaf"), &keccak(b"")].concat());
    let domain = keccak(&keccak(b"EIP712Domain()"));
    assert_eq!(typed_digest(&thread(0)), Ok(keccak(&[&[0x19u8, 0x01][..], &domain, &leaf].concat())));
}

#[test]
fn json_the_app_would_take_and_the_core_cannot_read_is_refused_not_misread() {
    // A lone surrogate: Dart's `jsonEncode` writes one as an escape, and the
    // app would hash it as U+FFFD; serde_json refuses it.
    let lone = r#"{"types":{"EIP712Domain":[],"T":[{"name":"v","type":"string"}]},"primaryType":"T","domain":{},"message":{"v":"\ud800"}}"#;
    assert_eq!(typed_digest(lone), Err(Refusal::TypedData));
    let paired = lone.replace(r"\ud800", r"😀");
    assert_eq!(typed_digest(&paired), typed_digest(&with_value("string", serde_json::json!("\u{1F600}"))));
    // Nesting the message does not read: the app ignores it, serde_json
    // stops at 128 levels.
    let nested = |levels: usize| {
        format!(
            r#"{{"types":{{"EIP712Domain":[],"T":[{{"name":"v","type":"uint8"}}]}},"primaryType":"T","domain":{{}},"message":{{"v":1,"junk":{}1{}}}}}"#,
            "[".repeat(levels),
            "]".repeat(levels)
        )
    };
    let plain = typed_digest(&with_value("uint8", serde_json::json!(1)));
    assert_eq!(typed_digest(&nested(100)), plain);
    assert_eq!(typed_digest(&nested(200)), Err(Refusal::TypedData));
}

#[test]
fn thousands_of_chained_types_are_hashed_on_a_small_stack_not_overflowed() {
    // A chain of types through arrays the data leaves empty: the validator
    // never walks it, the type string does — with a list, so 11,000 types
    // need no deeper stack than one.
    let count = 11_000;
    let mut types = serde_json::Map::new();
    types.insert("EIP712Domain".into(), serde_json::json!([]));
    for i in 0..count {
        types.insert(format!("C{i}"), serde_json::json!([{"name": "n", "type": format!("C{}[]", i + 1)}]));
    }
    types.insert(format!("C{count}"), serde_json::json!([{"name": "v", "type": "uint8"}]));
    let document =
        serde_json::json!({"types": types, "primaryType": "C0", "domain": {}, "message": {"n": []}}).to_string();
    assert!(document.len() <= eip712::MAX_INPUT_BYTES, "{} bytes", document.len());
    let hashed = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || (typed_digest(&document), eip712::type_string(document.as_bytes(), "C0").map(|s| s.matches('(').count())))
        .unwrap()
        .join()
        .expect("the walk overflowed its stack");
    assert!(hashed.0.is_ok());
    assert_eq!(hashed.1, Ok(count + 1));
}

#[test]
fn the_entries_sign_the_digest_the_core_computed() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let key = keys::derive(&seed[..], &path(EVM_0)).unwrap();
    let public = public_key(wallet, EVM_0, KC_PUBLIC_KEY_COMPRESSED).unwrap();
    for (name, document, digest) in EIP712_HASHED {
        let digest: [u8; 32] = hex(digest).try_into().unwrap();
        let signed = sign_typed(wallet, EVM_0, document).unwrap();
        assert_eq!(signed, keys::sign_digest(&key, &digest).unwrap(), "{name}");
        assert_eq!(recovered(&signed, &digest).serialize().to_vec(), public, "{name}");
    }
    for message in [&b""[..], b"Hello World", &[0u8; 1000], &sequence(5, 70_000)] {
        let digest = keccak(&[b"\x19Ethereum Signed Message:\n".as_slice(), message.len().to_string().as_bytes(), message].concat());
        assert_eq!(evm::personal_message_digest(message), digest);
        assert_eq!(sign_personal(wallet, EVM_0, message).unwrap(), keys::sign_digest(&key, &digest).unwrap());
    }
    // alloy-primitives' digest of "Hello World".
    let (hello, hashed) = EIP191_HASH;
    assert_eq!(to_hex(&evm::personal_message_digest(hello.as_bytes())), hashed);
    // web3.js's signature of "Some data", made with its documented key.
    let (secret, address, message, signature) = EIP191_SIGNED;
    let web3 = open_key(KC_CURVE_SECP256K1, &hex(secret)).unwrap();
    assert_eq!(evm_address(web3, "m"), address.to_lowercase(), "the key is the address's");
    let signed = sign_personal(web3, "m", message.as_bytes()).unwrap();
    let published = hex(signature);
    assert_eq!(signed[..64], published[..64]);
    assert_eq!(signed[64] + 27, published[64]);
    // Cow's key in EIP-712's example signs Cow's mail.
    let cow = open_key(KC_CURVE_SECP256K1, &keccak(b"cow")).unwrap();
    assert_eq!(evm_address(cow, "m"), "cd2a3d9f938e13cd947ec05abc7fe734df8dd826");
    let spec = word_of("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
    let mailed = sign_typed(cow, "m", &spec_mail()).unwrap();
    assert_eq!(recovered(&mailed, &spec).serialize().to_vec(), public_key(cow, "m", KC_PUBLIC_KEY_COMPRESSED).unwrap());
    for h in [wallet, web3, cow] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn the_message_entries_refuse_what_they_do_not_sign() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let document = spec_mail();
    // A key of the Bitcoin family signs no message (O37).
    for at in [BTC_RECEIVE, BTC_TAPROOT_0, "m/44'/2'/0'/0/0", "m/44'/3'/0'/0/0", "m/44'/145'/0'/0/0", "m/49'/0'/0'/0/0"] {
        assert_eq!(sign_typed(wallet, at, &document), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_personal(wallet, at, b"hello"), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
    }
    let bitcoin = open_key(KC_CURVE_SECP256K1_BITCOIN, &[0x46u8; 32]).unwrap();
    assert_eq!(sign_typed(bitcoin, "m", &document), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(bitcoin, "m", b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    let ed = open_key(KC_CURVE_ED25519, &[7u8; 32]).unwrap();
    assert_eq!(sign_typed(ed, "m", &document), Err(KC_ERR_KIND));
    assert_eq!(sign_personal(ed, "m", b"hello"), Err(KC_ERR_KIND));
    let secp = open_key(KC_CURVE_SECP256K1, &[7u8; 32]).unwrap();
    assert_eq!(sign_typed(secp, EVM_0, &document), Err(KC_ERR_PATH));
    assert_eq!(sign_personal(secp, EVM_0, b"hello"), Err(KC_ERR_PATH));
    assert_eq!(sign_typed(wallet, "m/44'/60'/0'/0/x", &document), Err(KC_ERR_PATH));
    // Typed data that does not read is refused before any key is asked.
    assert_eq!(sign_typed(wallet, EVM_0, "{}"), Err(KC_ERR_TYPED_DATA));
    assert_eq!(sign_typed(0, EVM_0, "{}"), Err(KC_ERR_TYPED_DATA));
    // Buffers.
    for entry in [kc_evm_sign_typed_data as MessageEntry, kc_evm_sign_personal_message] {
        let mut out = [0u8; 66];
        let data = document.as_bytes();
        let code = unsafe { entry(wallet, EVM_0.as_ptr(), EVM_0.len(), data.as_ptr(), data.len(), out.as_mut_ptr(), 64) };
        assert_eq!(code, KC_ERR_ARGUMENT);
        let code = unsafe { entry(wallet, EVM_0.as_ptr(), EVM_0.len(), data.as_ptr(), data.len(), out.as_mut_ptr(), 66) };
        assert_eq!(code, KC_ERR_ARGUMENT);
        let code = unsafe { entry(wallet, EVM_0.as_ptr(), EVM_0.len(), core::ptr::null(), 0, out.as_mut_ptr(), 65) };
        assert_eq!(code, KC_ERR_ARGUMENT);
        let code = unsafe { entry(wallet, EVM_0.as_ptr(), EVM_0.len(), data.as_ptr(), data.len(), core::ptr::null_mut(), 65) };
        assert_eq!(code, KC_ERR_ARGUMENT);
        assert_eq!(out, [0u8; 66]);
    }
    for h in [bitcoin, ed, secp] {
        assert_eq!(kc_close(h), KC_OK);
    }
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(sign_typed(wallet, EVM_0, &document), Err(KC_ERR_HANDLE));
    assert_eq!(sign_personal(wallet, EVM_0, b"hello"), Err(KC_ERR_HANDLE));
}

#[test]
fn a_message_signature_leaves_no_key_on_the_stack() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let seed = keys::seed_from_phrase(LEGAL.as_bytes(), "").unwrap();
    let secrets = secrets_along(&seed[..], EVM_0);
    let document = EIP712_HASHED[3].1;
    scrub::stack();
    let typed = below(|| sign_typed(handle, EVM_0, document).unwrap());
    assert_eq!(found_below(&secrets), None, "typed data");
    scrub::stack();
    let personal = below(|| sign_personal(handle, EVM_0, b"Some data").unwrap());
    assert_eq!(found_below(&secrets), None, "a personal message");
    core::hint::black_box((typed, personal));
    assert_eq!(kc_close(handle), KC_OK);
}

// ---------------------------------------------------------------------------
// EVM's digest call closed (2e-3, O43)

#[test]
fn an_evm_key_signs_no_bare_digest() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let digest = [0x5au8; 32];
    let tweak = [0x42u8; 32];
    // The wallet's EVM accounts, Ledger Live's layout and the account level.
    for at in [EVM_0, "m/44'/60'/0'/0/7", "m/44'/60'/3'/0/0", "m/44'/60'/0'"] {
        assert_eq!(sign(handle, at, &digest), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_low_r(handle, at, &digest), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(schnorr(handle, at, &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(schnorr(handle, at, &digest, &tweak), Err(KC_ERR_TRANSACTION_ONLY), "{at}, tweaked");
        // Its public key and its export are as before.
        assert!(public_key(handle, at, KC_PUBLIC_KEY_COMPRESSED).is_ok(), "{at}");
        assert!(export(handle, at).is_ok(), "{at}");
    }
    // What it reads, it signs.
    let tx = EvmTx::sample(11, true);
    assert!(sign_evm(handle, EVM_0, &tx.unsigned(), &tx.expected()).is_ok());
    assert!(sign_personal(handle, EVM_0, b"hello").is_ok());
    assert!(sign_typed(handle, EVM_0, &spec_mail()).is_ok());
    // Starknet's key, which Argent derives from the first EVM key, inside.
    assert!(sk_sign(handle, STARKNET_FREE, &stark_hash(3)).is_ok());
    // The neighbours sign: another coin, another purpose over coin 60, a coin
    // level not hardened, TRON's, the root.
    for at in ["m/44'/61'/0'/0/0", "m/49'/60'/0'/0/0", "m/44'/60/0'/0/0", DIGEST_0, "m"] {
        assert!(sign(handle, at, &digest).is_ok(), "{at}");
        assert!(sign_low_r(handle, at, &digest).is_ok(), "{at}");
        assert!(schnorr(handle, at, &digest, &[]).is_ok(), "{at}");
    }
    assert_eq!(kc_close(handle), KC_OK);
}

#[test]
fn a_key_opened_as_evms_signs_only_what_the_core_reads() {
    let _abi = abi();
    let secret = [0x46u8; 32];
    let handle = open_key(KC_CURVE_SECP256K1_EVM, &secret).unwrap();
    let plain = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    for format in [KC_PUBLIC_KEY_COMPRESSED, KC_PUBLIC_KEY_UNCOMPRESSED] {
        assert_eq!(public_key(handle, "m", format), public_key(plain, "m", format));
    }
    assert_eq!(export(handle, "m"), export(plain, "m"));
    let digest = [0x33u8; 32];
    assert_eq!(sign(handle, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_low_r(handle, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(handle, "m", &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert!(sign(plain, "m", &digest).is_ok(), "a key opened as plain secp256k1 still signs");
    // A transaction, a message and typed data, as the plain key signs them.
    let tx = EvmTx::sample(5, true);
    assert_eq!(
        sign_evm(handle, "m", &tx.unsigned(), &tx.expected()),
        sign_evm(plain, "m", &tx.unsigned(), &tx.expected())
    );
    assert_eq!(sign_personal(handle, "m", b"hello"), sign_personal(plain, "m", b"hello"));
    assert_eq!(sign_typed(handle, "m", &spec_mail()), sign_typed(plain, "m", &spec_mail()));
    assert!(sign_typed(handle, "m", &spec_mail()).is_ok());
    // Not a Bitcoin key: a transaction its key would spend is refused.
    let key = keys::public_key(&keys::secp256k1_key(&secret).unwrap());
    let mut input = BtcTx::input(3, BTC_RECEIVE, 30_000, 7);
    input.path = "m".to_owned();
    input.spent = script_of(3, &key, &[]);
    let mut btc = BtcTx::send(vec![input]);
    btc.outputs[1].script = script_of(3, &key, &[]);
    btc.outputs[1].change = Some((3, "m".to_owned(), Vec::new()));
    assert_eq!(sign_btc(handle, &btc.request(), 1).map(|_| ()), Err(KC_ERR_KIND));
    assert!(sign_btc(plain, &btc.request(), 1).is_ok(), "the plain key signs it");
    // A scalar that is no key is refused the same way.
    assert_eq!(open_key(KC_CURVE_SECP256K1_EVM, &[0u8; 32]), Err(KC_ERR_KEY));
    for h in [handle, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

// ---------------------------------------------------------------------------
// The screen shows what the core read: an EVM transaction (2f-1)

/// [expected] as `kc_evm_read_transaction` reads it for the key at [at]
/// below [handle], through the protocol the binding uses: the length first,
/// then the reading.
fn read_evm_for(handle: u64, at: &str, expected: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_evm_read_transaction(handle, at.as_ptr(), at.len(), expected.as_ptr(), expected.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_evm_read_transaction(handle, at.as_ptr(), at.len(), expected.as_ptr(), expected.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [expected] read for the legal phrase's first EVM account, from a session
/// opened for it alone: for the tests of what a reading says.
fn read_evm(expected: &[u8]) -> Result<serde_json::Value, i32> {
    let reader = open(LEGAL.as_bytes()).unwrap();
    let read = read_evm_for(reader, EVM_0, expected);
    assert_eq!(kc_close(reader), KC_OK);
    read
}

/// The twenty bytes of a reading's `from`, or of a typed reading's `signer`.
fn signer_of(read: &serde_json::Value, field: &str) -> [u8; 20] {
    let text = read[field].as_str().unwrap();
    hex(text.strip_prefix("0x").unwrap()).try_into().unwrap()
}

/// The call node of a transaction carrying [data].
fn read_call(data: &[u8]) -> serde_json::Value {
    let tx = EvmTx { data: data.to_vec(), ..EvmTx::sample(3, true) };
    read_evm(&tx.expected()).unwrap()["call"].clone()
}

fn abi_word(n: u128) -> Vec<u8> {
    let mut w = vec![0u8; 16];
    w.extend_from_slice(&n.to_be_bytes());
    w
}

fn abi_address(byte: u8) -> Vec<u8> {
    let mut w = vec![0u8; 12];
    w.extend_from_slice(&[byte; 20]);
    w
}

/// `multicall(bytes[])` carrying [calls].
fn multicall(calls: &[Vec<u8>]) -> Vec<u8> {
    let mut out = hex("ac9650d8");
    out.extend(abi_word(32));
    out.extend(abi_word(calls.len() as u128));
    let mut at = calls.len() * 32;
    let mut bodies = Vec::new();
    for call in calls {
        out.extend(abi_word(at as u128));
        let mut body = abi_word(call.len() as u128);
        body.extend(call);
        body.resize(body.len() + (32 - call.len() % 32) % 32, 0);
        at += body.len();
        bodies.extend(body);
    }
    out.extend(bodies);
    out
}

#[test]
fn an_evm_transaction_is_read_with_its_facts() {
    // A reading is kept for a signature (2f-1b): held, so the readings this
    // leaves never push out one a signing test beside it is about to use.
    let _abi = abi();
    for seed in 1..=40u64 {
        let tx = EvmTx::sample(seed, seed % 2 == 0);
        let reading = read_evm(&tx.expected()).unwrap();
        let word = |n: u128| format!("0x{}", to_hex(&abi_word(n)));
        assert_eq!(reading["kind"], if tx.eip1559 { 2 } else { 0 }, "{seed}");
        assert_eq!(reading["chainId"], word(tx.chain), "{seed}");
        let to: serde_json::Value = tx.to.map(|to| format!("0x{}", to_hex(&to))).into();
        assert_eq!(reading["to"], to, "{seed}");
        assert_eq!(reading["value"], word(tx.value), "{seed}");
        assert_eq!(reading["gasLimit"], word(tx.gas), "{seed}");
        assert_eq!(reading["fee"], word(tx.fee), "{seed}");
        assert_eq!(reading["maxFee"], word(tx.max_fee), "{seed}");
        assert_eq!(reading["data"], format!("0x{}", to_hex(&tx.data)), "{seed}");
    }
}

#[test]
fn the_reading_of_a_call_is_the_apps() {
    // A reading is kept for a signature (2f-1b): held, so the readings this
    // leaves never push out one a signing test beside it is about to use.
    let _abi = abi();
    let approve = |amount: u128, high: bool| {
        let mut data = hex("095ea7b3");
        data.extend(abi_address(0x11));
        let mut word = abi_word(amount);
        if high {
            word[0] = 1;
        }
        data.extend(word);
        data
    };
    assert_eq!(read_call(&[])["reading"], "none");
    assert_eq!(read_call(&[0x09, 0x5e, 0xa7])["reading"], "malformed");
    let unlimited = read_call(&approve(1, true));
    assert_eq!(unlimited["reading"], "decoded");
    assert_eq!(unlimited["selector"], "0x095ea7b3");
    assert_eq!(unlimited["call"]["kind"], "approve");
    assert_eq!(unlimited["call"]["spender"], format!("0x{}", "11".repeat(20)));
    assert_eq!(unlimited["call"]["unlimited"], true);
    assert_eq!(unlimited["call"]["grants"], true);
    let below = read_call(&approve(u128::MAX, false));
    assert_eq!(below["call"]["unlimited"], false, "2^128 − 1 is a figure");
    let revoke = read_call(&approve(0, false));
    assert_eq!(revoke["call"]["kind"], "revoke");
    assert_eq!(revoke["call"]["grants"], false);
    // An address with anything in its top twelve bytes is no address.
    let mut dirty = hex("095ea7b3");
    let mut word = abi_address(0x11);
    word[11] = 1;
    dirty.extend(word);
    dirty.extend(abi_word(1));
    assert_eq!(read_call(&dirty)["reading"], "malformed");
    // A strict bool.
    for (flag, reading, kind) in [(1u128, "decoded", "approveAll"), (0, "decoded", "revokeAll"), (2, "malformed", "")] {
        let mut data = hex("a22cb465");
        data.extend(abi_address(0x22));
        data.extend(abi_word(flag));
        let node = read_call(&data);
        assert_eq!(node["reading"], reading, "{flag}");
        if !kind.is_empty() {
            assert_eq!(node["call"]["kind"], kind, "{flag}");
        }
    }
    // transferFrom names whose tokens move.
    let mut from = hex("23b872dd");
    from.extend(abi_address(0x33));
    from.extend(abi_address(0x44));
    from.extend(abi_word(5));
    let moved = read_call(&from);
    assert_eq!(moved["call"]["from"], format!("0x{}", "33".repeat(20)));
    assert_eq!(moved["call"]["recipient"], format!("0x{}", "44".repeat(20)));
    // An unknown selector, and Universal Router's execute, are unknown.
    assert_eq!(read_call(&hex("deadbeef"))["reading"], "unknown");
    assert_eq!(read_call(&[hex("3593564c"), abi_word(32), abi_word(0)].concat())["reading"], "unknown");
    // A batch: its calls, its grant, the depth it stops at.
    let transfer = [hex("a9059cbb"), abi_address(0x55), abi_word(9)].concat();
    let one = read_call(&multicall(&[approve(1, true), transfer.clone()]));
    assert_eq!(one["call"]["kind"], "batch");
    assert_eq!(one["call"]["grants"], true);
    assert_eq!(one["call"]["children"][0]["call"]["kind"], "approve");
    assert_eq!(one["call"]["children"][1]["selector"], "0xa9059cbb");
    let deep = read_call(&multicall(&[multicall(&[multicall(&[multicall(&[transfer.clone()])])])]));
    let mut node = &deep;
    for _ in 0..3 {
        node = &node["call"]["children"][0];
    }
    assert_eq!(node["reading"], "tooDeep");
    assert_eq!(deep["reading"], "decoded", "too deep does not climb");
    // A malformed call climbs out of its batch.
    let truncated = read_call(&multicall(&[hex("095ea7b3")]));
    assert_eq!(truncated["reading"], "malformed");
    assert_eq!(truncated["call"]["kind"], "batch");
    // Thirty-two calls are read; a count of thirty-three is not.
    let calls: Vec<Vec<u8>> = (0..32).map(|_| transfer.clone()).collect();
    assert_eq!(read_call(&multicall(&calls))["reading"], "decoded");
    let mut claimed = hex("ac9650d8");
    claimed.extend(abi_word(32));
    claimed.extend(abi_word(33));
    assert_eq!(read_call(&claimed)["reading"], "malformed");
    // Thirty-three real calls are not read either.
    let calls: Vec<Vec<u8>> = (0..33).map(|_| transfer.clone()).collect();
    assert_eq!(read_call(&multicall(&calls))["reading"], "malformed");
    // An offset aimed between words, at a count that would read: refused for
    // its alignment alone. Aligned, the same bytes are an empty batch.
    let mut misaligned = hex("ac9650d8");
    misaligned.extend(abi_word(33));
    misaligned.push(0);
    misaligned.extend(abi_word(0));
    assert_eq!(read_call(&misaligned)["reading"], "malformed");
    let mut aligned = hex("ac9650d8");
    aligned.extend(abi_word(32));
    aligned.extend(abi_word(0));
    assert_eq!(read_call(&aligned)["reading"], "decoded");
    // tryAggregate's leading flag is a strict bool too.
    for (flag, reading) in [(1u128, "decoded"), (0, "decoded"), (3, "malformed")] {
        let mut data = hex("bce38bd7");
        data.extend(abi_word(flag));
        data.extend(abi_word(64));
        data.extend(abi_word(0));
        assert_eq!(read_call(&data)["reading"], reading, "flag {flag}");
    }
}

#[test]
fn a_reading_is_written_only_into_a_buffer_that_holds_it() {
    // A reading is kept for a signature (2f-1b): held, so the readings this
    // leaves never push out one a signing test beside it is about to use.
    let _abi = abi();
    let tx = EvmTx::sample(5, true);
    let expected = tx.expected();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = |out: *mut u8, cap: usize, len: *mut usize| unsafe {
        kc_evm_read_transaction(wallet, EVM_0.as_ptr(), EVM_0.len(), expected.as_ptr(), expected.len(), out, cap, len)
    };
    let mut needed = 0usize;
    let code = read(core::ptr::null_mut(), 0, &mut needed);
    assert_eq!(code, KC_ERR_BUFFER);
    assert!(needed > 0);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = read(short.as_mut_ptr(), short.len(), &mut written);
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(read_evm(&expected[..10]), Err(KC_ERR_ARGUMENT));
    let mut other = expected.clone();
    other[0] = 1;
    assert_eq!(read_evm(&other), Err(KC_ERR_ARGUMENT));
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- Signed only as shown (2f-1b, O53) ---------------------------------------

/// A transaction on a network no other test uses, so the readings it leaves
/// are its own.
fn unshared(n: u128, eip1559: bool) -> EvmTx {
    EvmTx { chain: 9_100_000 + n, ..EvmTx::sample(n as u64 + 300, eip1559) }
}

#[test]
fn an_evm_transaction_is_signed_once_per_reading_a_screen_was_given() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    for eip1559 in [false, true] {
        let tx = unshared(u128::from(eip1559), eip1559);
        let (unsigned, expected) = (tx.unsigned(), tx.expected());
        assert_eq!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_UNSHOWN), "never read");
        // Asking the length gives no reading.
        let mut needed = 0usize;
        unsafe {
            kc_evm_read_transaction(
                wallet,
                EVM_0.as_ptr(),
                EVM_0.len(),
                expected.as_ptr(),
                expected.len(),
                core::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        assert_eq!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_UNSHOWN), "only its length asked");
        read_evm_for(wallet, EVM_0, &expected).unwrap();
        // Read twice, the same facts: still one signature.
        read_evm_for(wallet, EVM_0, &expected).unwrap();
        assert!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected).is_ok());
        assert_eq!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_UNSHOWN), "a second signature");
        read_evm_for(wallet, EVM_0, &expected).unwrap();
        assert!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected).is_ok(), "read again, signed again");
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn the_fee_may_move_within_its_cap_and_nothing_else_may() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let wallet_from = evm_from(wallet, EVM_0);
    for eip1559 in [false, true] {
        let shown = unshared(10 + u128::from(eip1559), eip1559);
        let signs = |tx: &EvmTx| {
            read_evm_for(wallet, EVM_0, &shown.expected()).unwrap();
            let signed = sign_evm_unread(wallet, EVM_0, &tx.unsigned(), &tx.expected());
            // Taken back when refused, so the next case starts clean.
            let left = evm::Shown::of(&evm::Expected::read(&shown.expected()).unwrap(), wallet_from);
            shown_readings_without(&left);
            signed.is_ok()
        };
        let price = |tx: &mut EvmTx, p: u128| if eip1559 { tx.max_fee = p } else { tx.fee = p };
        let base = if eip1559 { shown.max_fee } else { shown.fee };
        // Within the cap: a lower price, or a lower limit at a higher price.
        let mut cheaper = shown.clone();
        price(&mut cheaper, base - 1);
        assert!(signs(&cheaper), "a lower price, EIP-1559 {eip1559}");
        let mut traded = EvmTx { gas: shown.gas / 2, ..shown.clone() };
        price(&mut traded, base * 2);
        assert!(signs(&traded), "half the limit at twice the price, EIP-1559 {eip1559}");
        // Past it, by one.
        let mut dearer = shown.clone();
        price(&mut dearer, base + 1);
        assert!(!signs(&dearer), "a higher price, EIP-1559 {eip1559}");
        assert!(!signs(&EvmTx { gas: shown.gas + 1, ..shown.clone() }), "a higher limit, EIP-1559 {eip1559}");
        // The facts, not at all.
        for (why, other) in [
            ("another value", EvmTx { value: shown.value + 1, ..shown.clone() }),
            ("another recipient", EvmTx { to: Some([0x77; 20]), ..shown.clone() }),
            ("a creation", EvmTx { to: None, ..shown.clone() }),
            ("other call data", EvmTx { data: [shown.data.clone(), vec![0]].concat(), ..shown.clone() }),
            ("another network", EvmTx { chain: shown.chain + 1, ..shown.clone() }),
            ("the other kind", EvmTx { eip1559: !eip1559, max_fee: shown.fee, ..shown.clone() }),
        ] {
            assert!(!signs(&other), "{why}, EIP-1559 {eip1559}");
        }
        // A nonce is no fact the screen shows: it may be anything.
        assert!(signs(&EvmTx { nonce: shown.nonce + 9, ..shown.clone() }), "another nonce");
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

/// Takes [left] out of the readings kept, if it is there.
fn shown_readings_without(left: &evm::Shown) {
    shown().retain(|entry| entry != left);
}

#[test]
fn a_refused_signature_keeps_its_reading_and_old_readings_go_first() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let tx = unshared(20, true);
    read_evm_for(wallet, EVM_0, &tx.expected()).unwrap();
    // A path the wallet does not write, and a key of the Bitcoin family:
    // refused, the reading kept for the signature that is made.
    assert_eq!(sign_evm_unread(wallet, "m/44'/60'/x", &tx.unsigned(), &tx.expected()), Err(KC_ERR_PATH));
    let bitcoin = open_key(KC_CURVE_SECP256K1_BITCOIN, &[0x46; 32]).unwrap();
    assert_eq!(sign_evm_unread(bitcoin, "m", &tx.unsigned(), &tx.expected()), Err(KC_ERR_KIND));
    assert!(sign_evm_unread(wallet, EVM_0, &tx.unsigned(), &tx.expected()).is_ok());
    // The sixty-fifth reading pushes out the first.
    let txs: Vec<EvmTx> = (0..=MAX_SHOWN as u128).map(|n| unshared(1000 + n, false)).collect();
    for tx in &txs {
        read_evm_for(wallet, EVM_0, &tx.expected()).unwrap();
    }
    assert_eq!(sign_evm_unread(wallet, EVM_0, &txs[0].unsigned(), &txs[0].expected()), Err(KC_ERR_UNSHOWN));
    assert!(sign_evm_unread(wallet, EVM_0, &txs[1].unsigned(), &txs[1].expected()).is_ok());
    for tx in &txs[2..] {
        shown_readings_without(&evm::Shown::of(&evm::Expected::read(&tx.expected()).unwrap(), evm_from(wallet, EVM_0)));
    }
    for h in [wallet, bitcoin] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn an_evm_reading_signs_by_the_key_it_was_read_for_alone() {
    // A transaction's facts name no signer: a reading for one account let
    // any other key sign the same facts, until the reading was held to the
    // key it was read for (the owner's request of 5 November 2026).
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    let imported = open_key(KC_CURVE_SECP256K1_EVM, &[0x47; 32]).unwrap();
    let tx = unshared(30, true);
    let (unsigned, expected) = (tx.unsigned(), tx.expected());
    let read = read_evm_for(wallet, EVM_0, &expected).unwrap();
    assert_eq!(read["from"], format!("0x{}", evm_address(wallet, EVM_0)));
    for (why, handle, at) in [
        ("the next account", wallet, "m/44'/60'/0'/0/1"),
        ("another phrase's first", other, EVM_0),
        ("an imported key", imported, "m"),
    ] {
        assert_eq!(sign_evm_unread(handle, at, &unsigned, &expected), Err(KC_ERR_UNSHOWN), "{why}");
    }
    assert!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected).is_ok(), "its own key, the reading kept");
    // Read for another key, signed by that key alone.
    read_evm_for(other, EVM_0, &expected).unwrap();
    assert_eq!(sign_evm_unread(wallet, EVM_0, &unsigned, &expected), Err(KC_ERR_UNSHOWN), "another's reading");
    assert!(sign_evm_unread(other, EVM_0, &unsigned, &expected).is_ok());
    let read = read_evm_for(imported, "m", &expected).unwrap();
    assert_eq!(read["from"], format!("0x{}", evm_address(imported, "m")));
    assert!(sign_evm_unread(imported, "m", &unsigned, &expected).is_ok());
    // A key the signature refuses is refused its reading the same way.
    let bitcoin = open_key(KC_CURVE_SECP256K1_BITCOIN, &[0x46; 32]).unwrap();
    assert_eq!(read_evm_for(bitcoin, "m", &expected), Err(KC_ERR_KIND));
    assert_eq!(read_evm_for(imported, EVM_0, &expected), Err(KC_ERR_PATH));
    assert_eq!(read_evm_for(wallet, "m/44'/60'/x", &expected), Err(KC_ERR_PATH));
    for h in [wallet, other, imported, bitcoin] {
        assert_eq!(kc_close(h), KC_OK);
    }
    assert_eq!(read_evm_for(wallet, EVM_0, &expected), Err(KC_ERR_HANDLE));
}

#[test]
fn the_fee_cap_is_the_whole_product() {
    // A reading is kept for a signature (2f-1b): held, so the readings this
    // leaves never push out one a signing test beside it is about to use.
    let _abi = abi();
    // The largest gas limit times the largest price, which no 256-bit word
    // holds, and the reading's cap of an ordinary transaction.
    let mut expected = EvmTx::sample(7, true).expected();
    expected[86..118].fill(0xff);
    expected[150..182].fill(0xff);
    let cap = evm::fee_cap(&evm::Expected::read(&expected).unwrap());
    // (2^256 − 1)² = 2^512 − 2^257 + 1.
    let mut square = [0xffu8; 64];
    square[31] = 0xfe;
    square[32..63].fill(0);
    square[63] = 1;
    assert_eq!(cap, square);
    let tx = EvmTx::sample(8, true);
    let reading = read_evm(&tx.expected()).unwrap();
    let mut product = [0u8; 64];
    product[48..].copy_from_slice(&(tx.gas * tx.max_fee).to_be_bytes());
    assert_eq!(reading["feeCap"], format!("0x{}", to_hex(&product)));
}

// --- Typed data read for a screen (2f-2, O54–O56) -----------------------------

/// A document on a network no other test signs on, so the readings it leaves
/// are its own.
fn unshared_typed(n: u64) -> String {
    serde_json::json!({
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}],
            "Note": [{"name": "text", "type": "string"}]
        },
        "primaryType": "Note",
        "domain": {"name": "unshared", "chainId": 9_200_000 + n},
        "message": {"text": format!("note {n}")}
    })
    .to_string()
}

#[test]
fn a_typed_document_is_signed_once_per_reading_a_screen_was_given() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let document = unshared_typed(1);
    assert_eq!(sign_typed_unread(wallet, EVM_0, &document), Err(KC_ERR_UNSHOWN), "never read");
    let data = document.as_bytes();
    let mut needed = 0usize;
    unsafe {
        kc_evm_read_typed_data(wallet, EVM_0.as_ptr(), EVM_0.len(), data.as_ptr(), data.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(sign_typed_unread(wallet, EVM_0, &document), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_typed_for(wallet, EVM_0, &document).unwrap();
    read_typed_for(wallet, EVM_0, &document).unwrap();
    // Another document read beside it signs nothing of this one's.
    let other = unshared_typed(2);
    read_typed_for(wallet, EVM_0, &other).unwrap();
    assert!(sign_typed_unread(wallet, EVM_0, &document).is_ok(), "read, signed");
    assert_eq!(sign_typed_unread(wallet, EVM_0, &document), Err(KC_ERR_UNSHOWN), "read twice, signed once");
    read_typed_for(wallet, EVM_0, &document).unwrap();
    assert!(sign_typed_unread(wallet, EVM_0, &document).is_ok(), "read again, signed again");
    assert!(sign_typed_unread(wallet, EVM_0, &other).is_ok());
    // Its signature is 2e's, over the same digest, by the key at the path.
    read_typed_for(wallet, EVM_0, &document).unwrap();
    let signed = sign_typed_unread(wallet, EVM_0, &document).unwrap();
    let digest = typed_digest(&document).unwrap();
    assert_eq!(
        recovered(&signed, &digest).serialize().to_vec(),
        public_key(wallet, EVM_0, KC_PUBLIC_KEY_COMPRESSED).unwrap()
    );
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_refused_typed_signature_keeps_its_reading() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let document = unshared_typed(3);
    read_typed_for(wallet, EVM_0, &document).unwrap();
    assert_eq!(sign_typed_unread(wallet, "m/44'/60'/x", &document), Err(KC_ERR_PATH));
    let bitcoin = open_key(KC_CURVE_SECP256K1_BITCOIN, &[0x46; 32]).unwrap();
    assert_eq!(sign_typed_unread(bitcoin, "m", &document), Err(KC_ERR_TRANSACTION_ONLY));
    assert!(sign_typed_unread(wallet, EVM_0, &document).is_ok());
    // The sixty-fifth reading pushes out the first.
    let documents: Vec<String> = (0..=MAX_SHOWN as u64).map(|n| unshared_typed(100 + n)).collect();
    for document in &documents {
        read_typed_for(wallet, EVM_0, document).unwrap();
    }
    assert_eq!(sign_typed_unread(wallet, EVM_0, &documents[0]), Err(KC_ERR_UNSHOWN));
    assert!(sign_typed_unread(wallet, EVM_0, &documents[1]).is_ok());
    for document in &documents[2..] {
        let entry = (typed_digest(document).unwrap(), evm_from(wallet, EVM_0));
        shown_typed().retain(|kept| *kept != entry);
    }
    for h in [wallet, bitcoin] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_typed_reading_signs_by_the_key_it_was_read_for_alone() {
    // A document names no signer either: held to the key it was read for,
    // as a transaction's reading is (the owner's request of 5 November 2026).
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    let imported = open_key(KC_CURVE_SECP256K1_EVM, &[0x47; 32]).unwrap();
    let document = unshared_typed(500);
    let read = read_typed_for(wallet, EVM_0, &document).unwrap();
    assert_eq!(read["signer"], format!("0x{}", evm_address(wallet, EVM_0)));
    for (why, handle, at) in [
        ("the next account", wallet, "m/44'/60'/0'/0/1"),
        ("another phrase's first", other, EVM_0),
        ("an imported key", imported, "m"),
    ] {
        assert_eq!(sign_typed_unread(handle, at, &document), Err(KC_ERR_UNSHOWN), "{why}");
    }
    assert!(sign_typed_unread(wallet, EVM_0, &document).is_ok(), "its own key, the reading kept");
    read_typed_for(other, EVM_0, &document).unwrap();
    assert_eq!(sign_typed_unread(wallet, EVM_0, &document), Err(KC_ERR_UNSHOWN), "another's reading");
    assert!(sign_typed_unread(other, EVM_0, &document).is_ok());
    let read = read_typed_for(imported, "m", &document).unwrap();
    assert_eq!(read["signer"], format!("0x{}", evm_address(imported, "m")));
    assert!(sign_typed_unread(imported, "m", &document).is_ok());
    // A key the signature refuses is refused its reading the same way.
    let bitcoin = open_key(KC_CURVE_SECP256K1_BITCOIN, &[0x46; 32]).unwrap();
    assert_eq!(read_typed_for(bitcoin, "m", &document), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(read_typed_for(wallet, "m/84'/0'/0'/0/0", &document), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(read_typed_for(imported, EVM_0, &document), Err(KC_ERR_PATH));
    for h in [wallet, other, imported, bitcoin] {
        assert_eq!(kc_close(h), KC_OK);
    }
    assert_eq!(read_typed_for(wallet, EVM_0, &document), Err(KC_ERR_HANDLE));
}

#[test]
fn a_typed_reading_is_what_is_signed_and_names_what_is_not() {
    // A reading is kept for a signature: held, as the other readings are.
    let _abi = abi();
    let mut mail: serde_json::Value = serde_json::from_str(&spec_mail()).unwrap();
    mail["domain"]["salt2"] = serde_json::json!("not declared");
    mail["message"]["from"]["extra"] = serde_json::json!(1);
    mail["message"]["note"] = serde_json::json!("n");
    let document = mail.to_string();
    let reading = read_typed(&document).unwrap();
    assert_eq!(reading["primaryType"], "Mail");
    assert_eq!(reading["domainOnly"], false);
    assert_eq!(reading["digest"], format!("0x{}", to_hex(&typed_digest(&document).unwrap())));
    assert_eq!(
        reading["domain"],
        serde_json::json!([
            {"name": "name", "type": "string", "value": "Ether Mail"},
            {"name": "version", "type": "string", "value": "1"},
            {"name": "chainId", "type": "uint256", "value": "1"},
            {"name": "verifyingContract", "type": "address", "value": "0xcccccccccccccccccccccccccccccccccccccccc"}
        ])
    );
    let person = |name: &str, wallet: &str| {
        serde_json::json!([
            {"name": "name", "type": "string", "value": name},
            {"name": "wallet", "type": "address", "value": wallet}
        ])
    };
    assert_eq!(
        reading["message"],
        serde_json::json!([
            {"name": "from", "type": "Person", "value": person("Cow", "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826")},
            {"name": "to", "type": "Person", "value": person("Bob", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
            {"name": "contents", "type": "string", "value": "Hello, Bob!"}
        ])
    );
    assert_eq!(reading["unsigned"], serde_json::json!(["domain.salt2", "message.from.extra", "message.note"]));
    assert_eq!(reading["unsignedCount"], 3);
    assert_eq!(reading["permit"], serde_json::Value::Null);
    // Every primitive as it is hashed, structs in arrays, and a value beside
    // one of them that is not signed.
    let values = serde_json::json!({
        "types": {
            "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
            "S": [{"name": "x", "type": "address"}],
            "T": [
                {"name": "a", "type": "int256"}, {"name": "b", "type": "uint8"}, {"name": "c", "type": "bytes"},
                {"name": "d", "type": "bytes4"}, {"name": "e", "type": "bool"}, {"name": "f", "type": "uint256[]"},
                {"name": "g", "type": "S[2]"}, {"name": "h", "type": "uint256"}
            ]
        },
        "primaryType": "T",
        "domain": {"chainId": "0x2105"},
        "message": {
            "a": "-0x10", "b": 7, "c": "0xABcd", "d": "0xDEADBEEF", "e": false, "f": ["0x1", 2, "3"],
            "g": [{"x": "0x000000000000000000000000000000000000dEaD"}, {"x": "0x00000000000000000000000000000000000000Aa", "y": 1}],
            "h": format!("0x{}", "f".repeat(64))
        }
    })
    .to_string();
    let reading = read_typed(&values).unwrap();
    let value = |name: &str| {
        reading["message"].as_array().unwrap().iter().find(|f| f["name"] == name).unwrap()["value"].clone()
    };
    assert_eq!(reading["domain"][0]["value"], "8453");
    assert_eq!(value("a"), "-16");
    assert_eq!(value("b"), "7");
    assert_eq!(value("c"), "0xabcd");
    assert_eq!(value("d"), "0xdeadbeef");
    assert_eq!(value("e"), false);
    assert_eq!(value("f"), serde_json::json!(["1", "2", "3"]));
    assert_eq!(
        value("g"),
        serde_json::json!([
            [{"name": "x", "type": "address", "value": "0x000000000000000000000000000000000000dead"}],
            [{"name": "x", "type": "address", "value": "0x00000000000000000000000000000000000000aa"}]
        ])
    );
    assert_eq!(value("h"), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    assert_eq!(reading["unsigned"], serde_json::json!(["message.g[1].y"]));
    // Many not signed: twenty named, sorted, and all of them counted.
    let mut crowded: serde_json::Value = serde_json::from_str(&spec_mail()).unwrap();
    for i in 0..25 {
        crowded["message"][format!("x{i:02}")] = serde_json::json!(i);
    }
    let reading = read_typed(&crowded.to_string()).unwrap();
    assert_eq!(reading["unsignedCount"], 25);
    let named: Vec<String> = (0..20).map(|i| format!("message.x{i:02}")).collect();
    assert_eq!(reading["unsigned"], serde_json::json!(named));
    // The domain alone (O46): no message.
    let domain_only = serde_json::json!({
        "types": {"EIP712Domain": [{"name": "name", "type": "string"}]},
        "primaryType": "EIP712Domain",
        "domain": {"name": "Only"},
        "message": {}
    })
    .to_string();
    let reading = read_typed(&domain_only).unwrap();
    assert_eq!(reading["domainOnly"], true);
    assert_eq!(reading["message"], serde_json::json!([]));
    assert_eq!(reading["digest"], format!("0x{}", to_hex(&typed_digest(&domain_only).unwrap())));
    // What the signature refuses, the reading refuses, and writes nothing.
    for refused in ["{}", "[", "{\"types\":1}"] {
        assert_eq!(read_typed(refused), Err(KC_ERR_TYPED_DATA), "{refused}");
    }
    for (name, document) in EIP712_REFUSED {
        assert_eq!(read_typed(document), Err(KC_ERR_TYPED_DATA), "{name}");
    }
}

#[test]
fn a_typed_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let document = spec_mail();
    let data = document.as_bytes();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = |data: *const u8, len: usize, out: *mut u8, cap: usize, written: *mut usize| unsafe {
        kc_evm_read_typed_data(wallet, EVM_0.as_ptr(), EVM_0.len(), data, len, out, cap, written)
    };
    let mut needed = 0usize;
    assert_eq!(read(data.as_ptr(), data.len(), core::ptr::null_mut(), 0, &mut needed), KC_ERR_BUFFER);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = read(data.as_ptr(), data.len(), short.as_mut_ptr(), short.len(), &mut written);
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(data.as_ptr(), data.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(read(core::ptr::null(), 0, short.as_mut_ptr(), short.len(), &mut written), KC_ERR_ARGUMENT);
    assert_eq!(kc_close(wallet), KC_OK);
}

const PERMIT_TOKEN: &str = "0x1F9840a85d5aF5bf1D1762F925BDADdC4201F984";
const PERMIT_SPENDER: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const PERMIT_OWNER: &str = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";

/// `"address owner,uint256 value"` as a type's list of fields.
fn typed_fields(spec: &str) -> serde_json::Value {
    spec.split(',')
        .map(|field| {
            let (kind, name) = field.split_once(' ').unwrap();
            serde_json::json!({"name": name, "type": kind})
        })
        .collect()
}

fn permit_document(primary: &str, structs: &[(&str, &str)], message: serde_json::Value) -> serde_json::Value {
    let mut types = serde_json::Map::new();
    types.insert(
        "EIP712Domain".into(),
        typed_fields("string name,string version,uint256 chainId,address verifyingContract"),
    );
    for (name, spec) in structs {
        types.insert((*name).into(), typed_fields(spec));
    }
    serde_json::json!({
        "types": types,
        "primaryType": primary,
        "domain": {"name": "Token", "version": "1", "chainId": 1, "verifyingContract": PERMIT_TOKEN},
        "message": message
    })
}

const EIP2612: &str = "address owner,address spender,uint256 value,uint256 nonce,uint256 deadline";
const DAI: &str = "address holder,address spender,uint256 nonce,uint256 expiry,bool allowed";
const DETAILS: &str = "address token,uint160 amount,uint48 expiration,uint48 nonce";
const TOKEN_PERMISSIONS: &str = "address token,uint256 amount";

fn standard_permits() -> Vec<(&'static str, serde_json::Value)> {
    let details = |amount: &str, expiration: u64| {
        serde_json::json!({"token": PERMIT_TOKEN, "amount": amount, "expiration": expiration, "nonce": 0})
    };
    let permitted = |amount: &str| serde_json::json!({"token": PERMIT_TOKEN, "amount": amount});
    vec![
        ("erc2612", permit_document("Permit", &[("Permit", EIP2612)], serde_json::json!({
            "owner": PERMIT_OWNER, "spender": PERMIT_SPENDER, "value": "1000", "nonce": 0, "deadline": 1893456000u64
        }))),
        ("daiPermit", permit_document("Permit", &[("Permit", DAI)], serde_json::json!({
            "holder": PERMIT_OWNER, "spender": PERMIT_SPENDER, "nonce": 0, "expiry": 0, "allowed": true
        }))),
        ("permit2Single", permit_document(
            "PermitSingle",
            &[("PermitSingle", "PermitDetails details,address spender,uint256 sigDeadline"), ("PermitDetails", DETAILS)],
            serde_json::json!({
                "details": details("0xffffffffffffffffffffffffffffffffffffffff", 1900000000),
                "spender": PERMIT_SPENDER, "sigDeadline": 1800000000u64
            }),
        )),
        ("permit2Batch", permit_document(
            "PermitBatch",
            &[("PermitBatch", "PermitDetails[] details,address spender,uint256 sigDeadline"), ("PermitDetails", DETAILS)],
            serde_json::json!({
                "details": [details("5", 1700000000), details("6", 1900000000)],
                "spender": PERMIT_SPENDER, "sigDeadline": 1800000000u64
            }),
        )),
        ("permit2Transfer", permit_document(
            "PermitTransferFrom",
            &[
                ("PermitTransferFrom", "TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline"),
                ("TokenPermissions", TOKEN_PERMISSIONS),
            ],
            serde_json::json!({"permitted": permitted("7"), "spender": PERMIT_SPENDER, "nonce": 3, "deadline": 1800000000u64}),
        )),
        ("permit2BatchTransfer", permit_document(
            "PermitBatchTransferFrom",
            &[
                ("PermitBatchTransferFrom", "TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline"),
                ("TokenPermissions", TOKEN_PERMISSIONS),
            ],
            serde_json::json!({
                "permitted": [permitted("8"), permitted("340282366920938463463374607431768211456")],
                "spender": PERMIT_SPENDER, "nonce": 3, "deadline": 1800000000u64
            }),
        )),
    ]
}

#[test]
fn the_six_standard_permits_are_read_and_nothing_shaped_otherwise() {
    let _abi = abi();
    let token = PERMIT_TOKEN.to_lowercase();
    let spender = PERMIT_SPENDER.to_lowercase();
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let item = |amount: &str, unlimited: bool, expiration: Option<&str>| {
        serde_json::json!({"token": token, "amount": amount, "unlimited": unlimited, "expiration": expiration})
    };
    let expected = [
        (vec![item("1000", false, None)], serde_json::json!("1893456000")),
        (vec![item(max, true, None)], serde_json::json!(max)),
        (vec![item("1461501637330902918203684832716283019655932542975", true, Some("1900000000"))], serde_json::json!("1900000000")),
        (vec![item("5", false, Some("1700000000")), item("6", false, Some("1900000000"))], serde_json::Value::Null),
        (vec![item("7", false, None)], serde_json::json!("1800000000")),
        (vec![item("8", false, None), item("340282366920938463463374607431768211456", true, None)], serde_json::json!("1800000000")),
    ];
    for ((kind, document), (items, deadline)) in standard_permits().into_iter().zip(expected) {
        let permit = read_typed(&document.to_string()).unwrap()["permit"].clone();
        assert_eq!(
            permit,
            serde_json::json!({"kind": kind, "spender": spender, "items": items, "deadline": deadline}),
            "{kind}"
        );
    }
    // One below 2^128 is not unlimited.
    let mut below = standard_permits()[0].1.clone();
    below["message"]["value"] = serde_json::json!("340282366920938463463374607431768211455");
    assert_eq!(read_typed(&below.to_string()).unwrap()["permit"]["items"][0]["unlimited"], false);
    // DAI's expiry, when there is one, is its deadline.
    let mut dated = standard_permits()[1].1.clone();
    dated["message"]["expiry"] = serde_json::json!(1900000000u64);
    assert_eq!(read_typed(&dated.to_string()).unwrap()["permit"]["deadline"], "1900000000");
    // Shaped otherwise, or granting nothing: no permit, whatever it is called.
    let changed: Vec<(&str, fn(&mut serde_json::Value))> = vec![
        ("EIP-2612's fields in another order", |d| {
            d["types"]["Permit"] = typed_fields("address owner,address spender,uint256 nonce,uint256 value,uint256 deadline")
        }),
        ("a spender declared as text", |d| {
            d["types"]["Permit"] = typed_fields("address owner,string spender,uint256 value,uint256 nonce,uint256 deadline");
            d["message"]["spender"] = serde_json::json!("anyone");
        }),
        ("a page's own Permit", |d| {
            d["types"]["Permit"] = typed_fields("address spender,uint256 value");
            d["message"] = serde_json::json!({"spender": PERMIT_SPENDER, "value": "1"});
        }),
        ("no verifying contract declared", |d| {
            d["types"]["EIP712Domain"] = typed_fields("string name,string version,uint256 chainId");
        }),
        ("the verifying contract declared as text", |d| {
            d["types"]["EIP712Domain"] = typed_fields("string name,string version,uint256 chainId,string verifyingContract");
        }),
    ];
    for (why, change) in changed {
        let mut document = standard_permits()[0].1.clone();
        change(&mut document);
        assert_eq!(read_typed(&document.to_string()).unwrap()["permit"], serde_json::Value::Null, "{why}");
    }
    let mut revoked = standard_permits()[1].1.clone();
    revoked["message"]["allowed"] = serde_json::json!(false);
    assert_eq!(read_typed(&revoked.to_string()).unwrap()["permit"], serde_json::Value::Null, "DAI's allowed: false");
    for (at, field) in [(3, "details"), (5, "permitted")] {
        let mut empty = standard_permits()[at].1.clone();
        empty["message"][field] = serde_json::json!([]);
        assert_eq!(read_typed(&empty.to_string()).unwrap()["permit"], serde_json::Value::Null, "an empty {field}");
    }
    // Permit2's witness transfer is not one of the six.
    let mut witness = standard_permits()[4].1.clone();
    let mut types = witness["types"].as_object().unwrap().clone();
    let fields = types.remove("PermitTransferFrom").unwrap();
    let mut fields = fields.as_array().unwrap().clone();
    fields.push(serde_json::json!({"name": "witness", "type": "string"}));
    types.insert("PermitWitnessTransferFrom".into(), serde_json::Value::Array(fields));
    witness["types"] = serde_json::Value::Object(types);
    witness["primaryType"] = serde_json::json!("PermitWitnessTransferFrom");
    witness["message"]["witness"] = serde_json::json!("w");
    assert_eq!(read_typed(&witness.to_string()).unwrap()["permit"], serde_json::Value::Null, "a witness transfer");
}

// --- A Bitcoin-family send read for a screen (2f-3) ---------------------------

#[test]
fn a_bitcoin_send_is_read_for_its_screen_with_change_the_core_found() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let tx = BtcTx::segwit_send();
    let reading = read_btc(handle, &tx.request()).unwrap();
    let txid: String = bitcoin::Transaction::read(&tx.unsigned()).unwrap().txid().iter().rev().map(|b| format!("{b:02x}")).collect();
    assert_eq!(reading["flavour"], "bitcoin");
    assert_eq!(reading["txid"], txid);
    let outpoint: String = tx.inputs[0].txid.iter().rev().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        reading["inputs"],
        serde_json::json!([{"txid": outpoint, "vout": tx.inputs[0].vout, "amount": "100000", "kind": "p2wpkh"}])
    );
    assert_eq!(
        reading["outputs"],
        serde_json::json!([
            {"value": "50000", "script": format!("0x{}", to_hex(&tx.outputs[0].script)), "change": false},
            {"value": "49000", "script": format!("0x{}", to_hex(&tx.outputs[1].script)), "change": true}
        ])
    );
    assert_eq!((reading["spent"].clone(), reading["fee"].clone()), (serde_json::json!("100000"), serde_json::json!("1000")));
    // Change that is not the key's at its path is no reading at all.
    let mut stranger = tx.clone();
    stranger.outputs[1].change = Some((3, "m/84'/0'/0'/1/1".to_owned(), Vec::new()));
    assert_eq!(read_btc(handle, &stranger.request()), Err(KC_ERR_TRANSACTION));
    // An input that is not its key's, nor.
    let mut foreign = tx.clone();
    foreign.inputs[0].path = "m/84'/0'/0'/0/1".to_owned();
    assert_eq!(read_btc(handle, &foreign.request()), Err(KC_ERR_TRANSACTION));
    // The outputs in the transaction's order, whatever order the app named them in.
    let mut swapped = tx.clone();
    swapped.outputs.swap(0, 1);
    let mut named = tx.clone();
    named.outputs = swapped.outputs.clone();
    let reading = read_btc(handle, &named.request_for(&tx.unsigned())).unwrap();
    assert_eq!(reading["outputs"][0]["change"], false);
    assert_eq!(reading["outputs"][1]["change"], true);
    for id in [tx.request(), named.request_for(&tx.unsigned())].map(|r| bitcoin::request_id(&r)) {
        shown_bitcoin().retain(|entry| *entry != id);
    }
    assert_eq!(kc_close(handle), KC_OK);
    assert_eq!(read_btc(handle, &tx.request()), Err(KC_ERR_HANDLE));
}

#[test]
fn a_bitcoin_send_is_signed_once_per_reading_a_screen_was_given() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    // A send of its own: no other test's reading stands for it.
    let mut tx = BtcTx::send(vec![BtcTx::input(3, BTC_RECEIVE, 123_456, 77)]);
    tx.fee = 2_000;
    tx.outputs[1].value -= 1_000;
    let request = tx.request();
    assert_eq!(sign_btc_unread(handle, &request, 1), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(sign_btc_unread(handle, &request, 1), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_btc(handle, &request).unwrap();
    read_btc(handle, &request).unwrap();
    // Another request, a byte apart, is not this one's reading.
    let mut other = tx.clone();
    other.fee += 1;
    other.outputs[1].value -= 1;
    assert_eq!(sign_btc_unread(handle, &other.request(), 1), Err(KC_ERR_UNSHOWN));
    assert!(sign_btc_unread(handle, &request, 1).is_ok());
    assert_eq!(sign_btc_unread(handle, &request, 1), Err(KC_ERR_UNSHOWN), "read twice, signed once");
    // A refused signature gives its reading back.
    read_btc(handle, &request).unwrap();
    let evm = open_key(KC_CURVE_SECP256K1_EVM, &[0x46; 32]).unwrap();
    assert_eq!(sign_btc_unread(evm, &request, 1), Err(KC_ERR_KIND));
    assert!(sign_btc_unread(handle, &request, 1).is_ok(), "kept after a refusal");
    for h in [handle, evm] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_bitcoin_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let handle = open(LEGAL.as_bytes()).unwrap();
    let request = BtcTx::segwit_send().request();
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe {
        kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), short.as_mut_ptr(), short.len(), &mut written)
    };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_bitcoin_read_transaction(handle, request.as_ptr(), request.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
    assert_eq!(read_btc(handle, &request[..request.len() - 1]), Err(KC_ERR_ARGUMENT));
    assert_eq!(kc_close(handle), KC_OK);
}

// --- A Solana message read for a screen (O52, O58) ----------------------------

/// [message] as `kc_solana_read_message` reads it: the length first, then the
/// reading.
fn read_solana(message: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_solana_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_solana_read_message(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn compact_u16(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = n;
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn b58(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for c in text.bytes() {
        let mut carry = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".iter().position(|a| *a == c).unwrap() as u32;
        for byte in out.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
    }
    out
}

/// A legacy message: [header], [keys], a blockhash of [n], and [instructions]
/// as (program index, account indexes, data).
fn solana_message(header: [u8; 3], keys: &[[u8; 32]], n: u8, instructions: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = header.to_vec();
    out.extend(compact_u16(keys.len()));
    for key in keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&[n; 32]);
    out.extend(compact_u16(instructions.len()));
    for (program, accounts, data) in instructions {
        out.push(*program);
        out.extend(compact_u16(accounts.len()));
        out.extend_from_slice(accounts);
        out.extend(compact_u16(data.len()));
        out.extend_from_slice(data);
    }
    out
}

fn sol_transfer(payer: [u8; 32], to: [u8; 32], lamports: u64, n: u8) -> Vec<u8> {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    solana_message([1, 0, 1], &[payer, to, [0; 32]], n, &[(2, vec![0, 1], data)])
}

#[test]
fn a_solana_transfer_is_read_with_its_facts() {
    let _abi = abi();
    let payer = [0x11; 32];
    let to = [0x22; 32];
    let message = sol_transfer(payer, to, 1_500_000, 7);
    let reading = read_solana(&message).unwrap();
    assert_eq!(reading["versioned"], false);
    assert_eq!(reading["header"], serde_json::json!([1, 0, 1]));
    assert_eq!(reading["feePayer"], solana::base58(&payer));
    assert_eq!(reading["blockhash"], solana::base58(&[7; 32]));
    assert_eq!(reading["accounts"][2], "11111111111111111111111111111111");
    let instruction = &reading["instructions"][0];
    assert_eq!(instruction["program"], "11111111111111111111111111111111");
    assert_eq!(
        instruction["decoded"],
        serde_json::json!({"kind": "systemTransfer", "from": solana::base58(&payer), "to": solana::base58(&to), "lamports": "1500000"})
    );
    // The compute budget, a memo, a token transfer checked and the account it
    // pays into, created idempotently — held to its owner and mint.
    let token = b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    let ata_program = b58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    let budget = b58("ComputeBudget111111111111111111111111111111");
    let memo = b58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
    let owner = [0x33; 32];
    let mint = [0x44; 32];
    let source = [0x55; 32];
    let ata = derived_ata(&owner, &token, &mint);
    let keys = [payer, ata, source, owner, mint, [0; 32], token, ata_program, budget, memo];
    let mut checked = vec![12];
    checked.extend_from_slice(&2_500_000u64.to_le_bytes());
    checked.push(6);
    let mut price = vec![3];
    price.extend_from_slice(&7_000u64.to_le_bytes());
    let message = solana_message(
        [1, 0, 6],
        &keys,
        9,
        &[
            (8, vec![], [vec![2], 200_000u32.to_le_bytes().to_vec()].concat()),
            (8, vec![], price),
            (7, vec![0, 1, 3, 4, 5, 6], vec![1]),
            (6, vec![2, 4, 1, 0], checked),
            (9, vec![0], b"for lunch".to_vec()),
        ],
    );
    let reading = read_solana(&message).unwrap();
    let decoded: Vec<serde_json::Value> =
        reading["instructions"].as_array().unwrap().iter().map(|i| i["decoded"].clone()).collect();
    assert_eq!(decoded[0], serde_json::json!({"kind": "computeUnitLimit", "units": 200000}));
    assert_eq!(decoded[1], serde_json::json!({"kind": "computeUnitPrice", "microLamports": "7000"}));
    assert_eq!(decoded[2]["kind"], "createTokenAccount");
    assert_eq!(decoded[2]["idempotent"], true);
    assert_eq!(decoded[2]["owner"], solana::base58(&owner));
    assert_eq!(decoded[2]["derived"], true);
    assert_eq!(decoded[3]["kind"], "tokenTransferChecked");
    assert_eq!(decoded[3]["destination"], solana::base58(&ata));
    assert_eq!((decoded[3]["amount"].clone(), decoded[3]["decimals"].clone()), (serde_json::json!("2500000"), serde_json::json!(6)));
    assert_eq!(decoded[4], serde_json::json!({"kind": "memo", "text": "for lunch"}));
    // An account that is not the owner's for the mint is said to be so.
    let mut stranger = keys;
    stranger[1] = [0x66; 32];
    let message = solana_message([1, 0, 6], &stranger, 9, &[(7, vec![0, 1, 3, 4, 5, 6], vec![1])]);
    assert_eq!(read_solana(&message).unwrap()["instructions"][0]["decoded"]["derived"], false);
    // A program no send of this wallet's uses is its bytes, not a description.
    let message = solana_message([1, 0, 1], &[payer, to, [0x77; 32]], 1, &[(2, vec![0, 1], vec![9, 9])]);
    let instruction = &read_solana(&message).unwrap()["instructions"][0];
    assert_eq!((instruction["decoded"].clone(), instruction["data"].clone()), (serde_json::Value::Null, serde_json::json!("0x0909")));
}

/// The associated token account, derived here from the rule rather than by
/// `src/solana.rs`: the first bump from 255 whose hash is off the curve.
fn derived_ata(owner: &[u8; 32], program: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    let ata_program = b58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    for bump in (0..=255u8).rev() {
        let hash: [u8; 32] = Sha256::digest(
            [&owner[..], &program[..], &mint[..], &[bump], &ata_program[..], b"ProgramDerivedAddress"].concat(),
        )
        .into();
        if curve25519_dalek::edwards::CompressedEdwardsY(hash).decompress().is_none() {
            return hash;
        }
    }
    unreachable!("no bump off the curve")
}

#[test]
fn a_version_0_message_is_read_with_its_tables_and_what_does_not_read_is_refused() {
    let _abi = abi();
    let payer = [0x11; 32];
    let mut v0 = vec![0x80];
    let legacy = sol_transfer(payer, [0x22; 32], 5, 3);
    v0.extend_from_slice(&legacy);
    // One table: two writable picks, one read-only.
    v0.extend(compact_u16(1));
    v0.extend_from_slice(&[0x99; 32]);
    v0.extend([2, 4, 5, 1, 7]);
    let reading = read_solana(&v0).unwrap();
    assert_eq!(reading["versioned"], true);
    assert_eq!(reading["lookups"], serde_json::json!([{"table": solana::base58(&[0x99; 32]), "writable": [4, 5], "readonly": [7]}]));
    for (why, message) in [
        ("version 1", [&[0x81u8][..], &legacy].concat()),
        ("a byte after the last field", [&legacy[..], &[0]].concat()),
        ("a byte short", legacy[..legacy.len() - 1].to_vec()),
        ("no account", solana_message([1, 0, 0], &[], 0, &[])),
        ("more signers than accounts", solana_message([2, 0, 0], &[payer], 0, &[])),
        ("a program outside the accounts", solana_message([1, 0, 0], &[payer], 0, &[(1, vec![], vec![])])),
        ("an account outside the message", solana_message([1, 0, 1], &[payer, [0; 32]], 0, &[(1, vec![5], vec![])])),
        // A count spelled with a zero byte after its first, and one past
        // sixteen bits: lengths the runtime refuses.
        ("a length not in its shortest form", {
            let mut m = vec![1, 0, 0, 0x81, 0x00];
            m.extend_from_slice(&payer);
            m.extend_from_slice(&[0; 32]);
            m.push(0);
            m
        }),
        ("a length past sixteen bits", {
            let mut m = vec![1, 0, 0, 0xff, 0xff, 0x04];
            m.extend_from_slice(&payer);
            m
        }),
    ] {
        assert_eq!(read_solana(&message), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_solana_key_signs_only_a_message_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let payer = ed_public_key(wallet, SOLANA_0).unwrap();
    // A message of its own, so no other test's reading stands for it.
    let message = sol_transfer(payer, [0x23; 32], 4_242, 42);
    assert_eq!(ed_sign(wallet, SOLANA_0, &message), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_solana_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, SOLANA_0, &message), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_solana(&message).unwrap();
    read_solana(&message).unwrap();
    let signature = ed_sign(wallet, SOLANA_0, &message).unwrap();
    VerifyingKey::from_bytes(&payer)
        .unwrap()
        .verify_strict(&message, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, SOLANA_0, &message), Err(KC_ERR_UNSHOWN), "read twice, signed once");
    // Every Solana layout the wallet writes, and none of the other networks.
    for at in ["m/44'/501'/0'", "m/44'/501'/3'/0'", "m/44'/501'"] {
        assert_eq!(ed_sign(wallet, at, &message), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert!(ed_sign(wallet, ED_0, b"a Stellar signature").is_ok());
    // A refused signature gives its reading back.
    read_solana(&message).unwrap();
    assert_eq!(ed_sign(wallet, "m/44'/501'/0'/0", &message), Err(KC_ERR_PATH));
    assert!(ed_sign(wallet, SOLANA_0, &message).is_ok(), "kept after a refusal");
    // An imported Solana key, opened as one, is held the same way; a plain
    // ed25519 key is not.
    let secret = ed_export(wallet, SOLANA_0).unwrap();
    let solana_key = open_key(KC_CURVE_ED25519_SOLANA, &secret).unwrap();
    let plain = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_public_key(solana_key, "m").unwrap(), payer);
    assert_eq!(ed_sign(solana_key, "m", &message), Err(KC_ERR_UNSHOWN));
    read_solana(&message).unwrap();
    assert_eq!(ed_sign(solana_key, "m", &message).unwrap(), signature);
    assert_eq!(ed_sign(plain, "m", &message).unwrap(), signature);
    assert_eq!(ed_export(solana_key, "m").unwrap(), secret);
    for h in [wallet, solana_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_solana_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let message = sol_transfer([0x11; 32], [0x24; 32], 1, 1);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_solana_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_solana_read_message(message.as_ptr(), message.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_solana_read_message(message.as_ptr(), message.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
    // Base58 as Solana spells its addresses: leading zeros as ones.
    assert_eq!(solana::base58(&[0; 32]), "11111111111111111111111111111111");
    assert_eq!(solana::base58(&b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
}


// --- A TRON transaction read for a screen (O58) -------------------------------

/// [raw] as `kc_tron_read_transaction` reads it: the length first, then the
/// reading.
fn read_tron(raw: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn pb_varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn pb_int(number: u64, value: u64) -> Vec<u8> {
    [pb_varint(number << 3), pb_varint(value)].concat()
}

fn pb_bytes(number: u64, bytes: &[u8]) -> Vec<u8> {
    [pb_varint(number << 3 | 2), pb_varint(bytes.len() as u64), bytes.to_vec()].concat()
}

/// A TRON address: `0x41` and twenty bytes of [n].
fn tron_address(n: u8) -> Vec<u8> {
    [vec![0x41], vec![n; 20]].concat()
}

const TRANSFER: &str = "type.googleapis.com/protocol.TransferContract";
const TRIGGER: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// `raw_data` as a node writes it: the reference block, the expiry, [extra],
/// one contract of [kind] at [url] with [value], and the timestamp.
fn tron_raw(kind: u64, url: &str, value: &[u8], extra: &[u8]) -> Vec<u8> {
    let any = [pb_bytes(1, url.as_bytes()), pb_bytes(2, value)].concat();
    let contract = [pb_int(1, kind), pb_bytes(2, &any)].concat();
    [
        pb_bytes(1, &[0xab, 0xcd]),
        pb_bytes(4, &[0x11; 8]),
        pb_int(8, 1_700_000_060_000),
        extra.to_vec(),
        pb_bytes(11, &contract),
        pb_int(14, 1_700_000_000_000),
    ]
    .concat()
}

fn trx_transfer(from: &[u8], to: &[u8], amount: u64) -> Vec<u8> {
    let value = [pb_bytes(1, from), pb_bytes(2, to), pb_int(3, amount)].concat();
    tron_raw(1, TRANSFER, &value, &[])
}

/// `transfer(address,uint256)` to [to] — its word as TRON's encoder writes it,
/// `0x41` in front — of the 32-byte [amount].
fn trc20_call(to: &[u8], amount: [u8; 32]) -> Vec<u8> {
    [vec![0xa9, 0x05, 0x9c, 0xbb], vec![0; 11], to.to_vec(), amount.to_vec()].concat()
}

fn trigger(from: &[u8], contract: &[u8], data: &[u8], extra: &[u8]) -> Vec<u8> {
    [pb_bytes(1, from), pb_bytes(2, contract), extra.to_vec(), pb_bytes(4, data)].concat()
}

#[test]
fn a_tron_transfer_is_read_with_its_facts() {
    let _abi = abi();
    // TRON's own example of an address: its hex form and base58check.
    let example = hex("418840e6c55b9ada326d211d818c34a994aeced808");
    let raw = trx_transfer(&example, &tron_address(0x22), 1_500_000);
    let reading = read_tron(&raw).unwrap();
    assert_eq!(reading["txid"], to_hex(&Sha256::digest(&raw)));
    assert_eq!(reading["refBlockBytes"], "0xabcd");
    assert_eq!(reading["refBlockNum"], serde_json::Value::Null);
    assert_eq!(reading["refBlockHash"], "0x1111111111111111");
    assert_eq!(reading["expiration"], "1700000060000");
    assert_eq!(reading["timestamp"], "1700000000000");
    assert_eq!(reading["feeLimit"], serde_json::Value::Null);
    assert_eq!(reading["data"], serde_json::Value::Null);
    assert_eq!(reading["memo"], serde_json::Value::Null);
    let contract = &reading["contract"];
    assert_eq!(contract["type"], "1");
    assert_eq!(contract["typeUrl"], TRANSFER);
    assert_eq!(contract["decoded"]["kind"], "trxTransfer");
    assert_eq!(contract["decoded"]["from"], "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL");
    assert_eq!(contract["decoded"]["amount"], "1500000");

    // A TRC-20 transfer with a memo and a fee limit, as a THORChain deposit.
    let mut amount = [0u8; 32];
    amount[0] = 0x80;
    let call = trc20_call(&tron_address(0x33), amount);
    let memo = "=:ETH.ETH:0x1111111111111111111111111111111111111111";
    let raw = tron_raw(
        31,
        TRIGGER,
        &trigger(&example, &tron_address(0x44), &call, &[]),
        &[pb_bytes(10, memo.as_bytes()), pb_int(18, 30_000_000)].concat(),
    );
    let reading = read_tron(&raw).unwrap();
    assert_eq!(reading["memo"], memo);
    assert_eq!(reading["feeLimit"], "30000000");
    let decoded = &reading["contract"]["decoded"];
    assert_eq!(decoded["kind"], "contractCall");
    assert_eq!(decoded["from"], "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL");
    assert_eq!(decoded["callValue"], "0");
    assert_eq!(decoded["call"]["kind"], "trc20Transfer");
    assert_eq!(
        decoded["call"]["amount"],
        "57896044618658097711785492504343953926634992332820282019728792003956564819968",
        "2^255, the amount's whole word"
    );
    // A recipient's word behind a zero byte reads as the same recipient.
    let mut zeroed = call.clone();
    zeroed[15] = 0;
    let raw = tron_raw(31, TRIGGER, &trigger(&example, &tron_address(0x44), &zeroed, &[]), &[]);
    assert_eq!(read_tron(&raw).unwrap()["contract"]["decoded"]["call"], decoded["call"]);

    // What is read and not described: a contract of another kind, a URL
    // not its type's, a field the contract does not name or names twice, an
    // owner that is no address, a call that is not `transfer`, a word with
    // more than an address in it, a memo that is not text.
    let value = [pb_bytes(1, &example), pb_bytes(2, &tron_address(2)), pb_int(3, 5)].concat();
    let not_decoded = [
        ("a freeze", tron_raw(54, "type.googleapis.com/protocol.FreezeBalanceV2Contract", &value, &[])),
        ("a transfer's type at a call's URL", tron_raw(1, TRIGGER, &value, &[])),
        ("a field of its own", tron_raw(1, TRANSFER, &[value.clone(), pb_int(9, 1)].concat(), &[])),
        ("an amount twice", tron_raw(1, TRANSFER, &[value.clone(), pb_int(3, 6)].concat(), &[])),
        (
            "an owner of twenty bytes",
            tron_raw(1, TRANSFER, &[pb_bytes(1, &[0x41; 20]), pb_bytes(2, &tron_address(2))].concat(), &[]),
        ),
        ("an owner as a number", tron_raw(1, TRANSFER, &[pb_int(1, 7), pb_bytes(2, &tron_address(2))].concat(), &[])),
    ];
    for (why, raw) in not_decoded {
        let reading = read_tron(&raw).unwrap();
        assert_eq!(reading["contract"]["decoded"], serde_json::Value::Null, "{why}");
    }
    let mut approve = call.clone();
    approve[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    let mut wide = call.clone();
    wide[4] = 1;
    for (why, data) in [("approve", approve), ("a wide word", wide), ("short", call[..67].to_vec())] {
        let raw = tron_raw(31, TRIGGER, &trigger(&example, &tron_address(0x44), &data, &[]), &[]);
        let reading = read_tron(&raw).unwrap();
        assert_eq!(reading["contract"]["decoded"]["call"], serde_json::Value::Null, "{why}");
        assert_eq!(reading["contract"]["decoded"]["data"], solana_hex(&data), "{why}");
    }
    let raw = tron_raw(1, TRANSFER, &value, &pb_bytes(10, &[0xff, 0xfe]));
    let reading = read_tron(&raw).unwrap();
    assert_eq!((reading["data"].clone(), reading["memo"].clone()), (serde_json::json!("0xfffe"), serde_json::Value::Null));
}

fn solana_hex(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

#[test]
fn what_no_tron_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let raw = trx_transfer(&tron_address(1), &tron_address(2), 9);
    let any = [pb_bytes(1, TRANSFER.as_bytes()), pb_bytes(2, &[])].concat();
    let contract = [pb_int(1, 1), pb_bytes(2, &any)].concat();
    let refused = [
        ("nothing", Vec::new()),
        ("no contract", pb_int(8, 5)),
        ("two contracts", [raw.clone(), pb_bytes(11, &contract)].concat()),
        ("an authority", [raw.clone(), pb_bytes(9, &[1])].concat()),
        ("scripts", [raw.clone(), pb_bytes(12, &[1])].concat()),
        ("the expiry twice", [raw.clone(), pb_int(8, 1)].concat()),
        ("a field it does not name", [raw.clone(), pb_int(15, 1)].concat()),
        ("a permission", [pb_bytes(11, &[contract.clone(), pb_int(5, 2)].concat())].concat()),
        ("a contract with no type", pb_bytes(11, &pb_bytes(2, &any))),
        ("a parameter with no value", pb_bytes(11, &[pb_int(1, 1), pb_bytes(2, &pb_bytes(1, b"x"))].concat())),
        ("bytes where a number goes", [raw.clone(), pb_bytes(8, &[1])].concat()),
        ("a number where bytes go", [pb_int(1, 1), raw.clone()].concat()),
        ("a varint longer than it needs", [raw.clone(), vec![0x70, 0x80, 0x00]].concat()),
        ("a tag longer than it needs", [raw.clone(), vec![0xf0, 0x80, 0x00, 0x01]].concat()),
        ("a varint past 64 bits", [raw.clone(), vec![0x70], vec![0xff; 9], vec![0x02]].concat()),
        ("a varint cut short", [raw.clone(), vec![0x70, 0x80]].concat()),
        ("a fixed 64-bit field", [raw.clone(), vec![0x71], vec![0; 8]].concat()),
        ("a fixed 32-bit field", [raw.clone(), vec![0x75], vec![0; 4]].concat()),
        ("field zero", [raw.clone(), vec![0x00, 0x01]].concat()),
        ("a length past the end", [raw.clone(), vec![0x52, 0x05, 0x01]].concat()),
    ];
    for (why, raw) in refused {
        assert_eq!(read_tron(&raw), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_tron_key_signs_only_a_transaction_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let from = public_key(wallet, TRON_0, KC_PUBLIC_KEY_COMPRESSED).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let raw = trx_transfer(&tron_address(0x51), &tron_address(0x52), 4_242);
    let digest: [u8; 32] = Sha256::digest(&raw).into();
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_tron(&raw).unwrap();
    read_tron(&raw).unwrap();
    let signature = sign(wallet, TRON_0, &digest).unwrap();
    assert_eq!(recovered(&signature, &digest).serialize().to_vec(), from);
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN), "read twice, signed once");
    // Every TRON path, and no other kind of signature by a TRON key.
    read_tron(&raw).unwrap();
    for at in ["m/44'/195'/0'/0/1", "m/44'/195'/3'", "m/44'/195'"] {
        assert_eq!(sign(wallet, at, &[7u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(sign_low_r(wallet, TRON_0, &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(wallet, TRON_0, &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(wallet, TRON_0, b"a TRON key"), Err(KC_ERR_TRANSACTION_ONLY));
    assert!(sign(wallet, DIGEST_0, &[7u8; 32]).is_ok(), "a key at no network's path signs digests");
    assert_eq!(sign(wallet, TRON_0, &digest).unwrap(), signature, "the reading kept is still there");

    // An imported TRON key, opened as one, is held the same way — and a
    // refused signature gives its reading back; a plain secp256k1 key is not.
    let secret = export(wallet, TRON_0).unwrap();
    let tron_key = open_key(KC_CURVE_SECP256K1_TRON, &secret).unwrap();
    let plain = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    assert_eq!(public_key(tron_key, "m", KC_PUBLIC_KEY_COMPRESSED).unwrap(), from);
    assert_eq!(sign(tron_key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_tron(&raw).unwrap();
    assert_eq!(sign(tron_key, "m/0", &digest), Err(KC_ERR_PATH));
    assert_eq!(sign(tron_key, "m", &digest).unwrap(), signature, "kept after a refusal");
    assert_eq!(sign(plain, "m", &digest).unwrap(), signature);
    assert_eq!(sign_low_r(tron_key, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(tron_key, "m", b"a TRON key"), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(tron_key, "m").unwrap(), secret);
    assert_eq!(open_key(KC_CURVE_SECP256K1_TRON, &[0u8; 32]), Err(KC_ERR_KEY));
    for h in [wallet, tron_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_tron_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let raw = trx_transfer(&tron_address(1), &tron_address(0x53), 1);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_tron_read_transaction(raw.as_ptr(), raw.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
    // Only its length asked: nothing kept.
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let digest: [u8; 32] = Sha256::digest(&raw).into();
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN));
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- An XRP Ledger payment read for a screen, its expiry aside (O59) ----------

/// [blob] as `kc_xrpl_read_transaction` reads it: the length first, then the
/// reading.
fn read_xrpl(blob: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn xrpl_sign(handle: u64, path: &str, blob: &[u8]) -> Result<[u8; 64], i32> {
    let mut out = [0u8; 64];
    let code = unsafe {
        kc_xrpl_sign_transaction(handle, path.as_ptr(), path.len(), blob.as_ptr(), blob.len(), out.as_mut_ptr(), out.len())
    };
    if code == KC_OK {
        Ok(out)
    } else {
        assert_eq!(out, [0u8; 64], "a refused signature wrote its output");
        Err(code)
    }
}

/// A payment's signing serialisation, as `xrpl_dart` writes the module's.
struct Pay<'a> {
    sequence: u32,
    tag: Option<u32>,
    last: Option<u32>,
    amount: u64,
    fee: u64,
    key: &'a [u8],
    account: [u8; 20],
    destination: [u8; 20],
    memo: Option<&'a [u8]>,
}

impl Pay<'_> {
    fn blob(&self) -> Vec<u8> {
        let mut out = vec![0x12, 0x00, 0x00, 0x24];
        out.extend(self.sequence.to_be_bytes());
        if let Some(tag) = self.tag {
            out.push(0x2e);
            out.extend(tag.to_be_bytes());
        }
        if let Some(last) = self.last {
            out.extend([0x20, 0x1b]);
            out.extend(last.to_be_bytes());
        }
        out.push(0x61);
        out.extend((self.amount | 1 << 62).to_be_bytes());
        out.push(0x68);
        out.extend((self.fee | 1 << 62).to_be_bytes());
        out.extend([0x73, self.key.len() as u8]);
        out.extend(self.key);
        out.extend([0x81, 20]);
        out.extend(self.account);
        out.extend([0x83, 20]);
        out.extend(self.destination);
        if let Some(memo) = self.memo {
            out.extend([0xf9, 0xea, 0x7d, memo.len() as u8]);
            out.extend(memo);
            out.extend([0xe1, 0xf1]);
        }
        out
    }
}

/// `xrpl_dart`'s signing serialisation of the module's payment, with a memo
/// and a tag and without, from the key 0707…07 (the module's own library is
/// the vector).
const XRPL_PLAIN: &str = "1200002400000005201b000000686140000000000f424068400000000000000c732102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f8114a3c6b1ee4a49d9f2af3b3802974744fba924164a8314b5f762798a53d543a014caf8b297cff8f2f937e8";
const XRPL_TAGGED: &str = "12000024000000052e0000002a201b000000686140000000000f424068400000000000000c732102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f8114a3c6b1ee4a49d9f2af3b3802974744fba924164a8314b5f762798a53d543a014caf8b297cff8f2f937e8f9ea7d026869e1f1";

#[test]
fn an_xrpl_payment_is_read_with_its_facts() {
    let _abi = abi();
    let reading = read_xrpl(&hex(XRPL_PLAIN)).unwrap();
    assert_eq!(
        reading,
        serde_json::json!({
            "transactionType": "Payment",
            "flags": null,
            "sequence": 5,
            "destinationTag": null,
            "lastLedgerSequence": 104,
            "amount": "1000000",
            "fee": "12",
            "signingPubKey": "0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
            "account": "rEvywqqNLE5Qy2NWd6EbWE3MZ2FKPZS3Jf",
            "destination": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "memos": [],
        })
    );
    let tagged = read_xrpl(&hex(XRPL_TAGGED)).unwrap();
    assert_eq!(tagged["destinationTag"], 42);
    assert_eq!(
        tagged["memos"],
        serde_json::json!([{"type": null, "data": "0x6869", "format": null, "text": "hi"}])
    );
    // The serialisation written here is xrpl_dart's, byte for byte.
    let pay = Pay {
        sequence: 5,
        tag: Some(42),
        last: Some(104),
        amount: 1_000_000,
        fee: 12,
        key: &hex("02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"),
        account: hex("a3c6b1ee4a49d9f2af3b3802974744fba924164a").try_into().unwrap(),
        destination: hex("b5f762798a53d543a014caf8b297cff8f2f937e8").try_into().unwrap(),
        memo: Some(b"hi"),
    };
    assert_eq!(pay.blob(), hex(XRPL_TAGGED));
    // A memo that is not text, and every memo field.
    let mut blob = Pay { memo: None, ..pay }.blob();
    blob.extend([0xf9, 0xea, 0x7c, 1, 0xaa, 0x7d, 2, 0xff, 0xfe, 0x7e, 0, 0xe1, 0xea, 0xe1, 0xf1]);
    assert_eq!(
        read_xrpl(&blob).unwrap()["memos"],
        serde_json::json!([
            {"type": "0xaa", "data": "0xfffe", "format": "0x", "text": null},
            {"type": null, "data": null, "format": null, "text": null},
        ])
    );
    // Flags are read, and one with no expiry is read without one.
    let mut flagged = hex(XRPL_PLAIN);
    flagged.splice(3..3, [0x22, 0x80, 0, 0, 0]);
    assert_eq!(read_xrpl(&flagged).unwrap()["flags"], 0x8000_0000u32);
    let open = Pay { last: None, tag: None, memo: None, ..pay }.blob();
    assert_eq!(read_xrpl(&open).unwrap()["lastLedgerSequence"], serde_json::Value::Null);
}

#[test]
fn what_no_payment_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let plain = hex(XRPL_PLAIN);
    let with = |at: usize, bytes: &[u8]| {
        let mut out = plain.clone();
        out.splice(at..at, bytes.iter().copied());
        out
    };
    let changed = |at: usize, byte: u8| {
        let mut out = plain.clone();
        out[at] = byte;
        out
    };
    let amount_at = plain.windows(1).position(|w| w[0] == 0x61).unwrap();
    let refused = [
        ("nothing", Vec::new()),
        ("another transaction type", changed(2, 20)),
        ("an issued currency's amount", changed(amount_at + 1, 0xd4)),
        ("a negative amount", changed(amount_at + 1, 0x00)),
        ("a SendMax", [plain.clone(), vec![0x69], (1u64 << 62 | 5).to_be_bytes().to_vec()].concat()),
        ("a signature", with(plain.len() - 44, &[0x74, 1, 0xaa])),
        ("a source tag", with(3, &[0x23, 0, 0, 0, 1])),
        ("a field out of order", [plain[3..8].to_vec(), plain[..3].to_vec(), plain[8..].to_vec()].concat()),
        ("a field twice", with(8, &[0x24, 0, 0, 0, 6])),
        ("a code longer than it needs", [vec![0x20, 0x04], plain[4..].to_vec()].concat()),
        ("an account of nineteen bytes", {
            let at = plain.len() - 44;
            [plain[..at].to_vec(), vec![0x81, 19], plain[at + 2..at + 21].to_vec(), plain[at + 22..].to_vec()].concat()
        }),
        ("no fee", {
            let at = amount_at + 9;
            [plain[..at].to_vec(), plain[at + 9..].to_vec()].concat()
        }),
        ("a byte after the last field", [plain.clone(), vec![0x00]].concat()),
        ("cut short", plain[..plain.len() - 1].to_vec()),
        ("a memo field it does not name", [plain.clone(), vec![0xf9, 0xea, 0x71, 0, 0xe1, 0xf1]].concat()),
        ("an array of something else", [plain.clone(), vec![0xf9, 0xe2, 0xe1, 0xf1]].concat()),
        ("an unclosed memo", [plain.clone(), vec![0xf9, 0xea, 0x7d, 0]].concat()),
    ];
    for (why, blob) in refused {
        assert_eq!(read_xrpl(&blob), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn an_xrpl_key_signs_only_a_payment_read_for_a_screen_its_expiry_aside() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = public_key(wallet, XRP_0, KC_PUBLIC_KEY_COMPRESSED).unwrap();
    // A payment of its own, so no other test's reading stands for it.
    let reviewed = Pay {
        sequence: 77,
        tag: Some(9),
        last: Some(1_000),
        amount: 4_242,
        fee: 12,
        key: &key,
        account: [0x61; 20],
        destination: [0x62; 20],
        memo: None,
    };
    let signed = Pay { last: Some(1_204), ..reviewed };
    assert_eq!(xrpl_sign(wallet, XRP_0, &signed.blob()), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    let blob = reviewed.blob();
    unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(xrpl_sign(wallet, XRP_0, &signed.blob()), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_xrpl(&reviewed.blob()).unwrap();
    // Every other field held: another amount, recipient, tag, fee or sequence
    // is not the payment read.
    for (why, other) in [
        ("amount", Pay { amount: 4_243, ..signed }),
        ("recipient", Pay { destination: [0x63; 20], ..signed }),
        ("tag", Pay { tag: None, ..signed }),
        ("fee", Pay { fee: 13, ..signed }),
        ("sequence", Pay { sequence: 78, ..signed }),
        ("memo", Pay { memo: Some(b"x"), ..signed }),
    ] {
        assert_eq!(xrpl_sign(wallet, XRP_0, &other.blob()), Err(KC_ERR_UNSHOWN), "{why}");
    }
    assert_eq!(xrpl_sign(wallet, XRP_0, &Pay { last: None, ..signed }.blob()), Err(KC_ERR_TRANSACTION), "no expiry");
    assert_eq!(xrpl_sign(wallet, DIGEST_0, &signed.blob()), Err(KC_ERR_KIND), "not an XRP key");
    // The expiry set at the signature, the signature over the core's own
    // digest of what it signs.
    let signature = xrpl_sign(wallet, XRP_0, &signed.blob()).unwrap();
    let digest: [u8; 32] = Sha512::digest([b"STX\0".as_slice(), &signed.blob()].concat())[..32].try_into().unwrap();
    Signature::from_compact(&signature)
        .unwrap()
        .verify(Message::from_digest(digest), &PublicKey::from_slice(&key).unwrap())
        .expect("the signature verifies over SHA-512's half of STX and the blob");
    assert_eq!(xrpl_sign(wallet, XRP_0, &signed.blob()), Err(KC_ERR_UNSHOWN), "signed once");
    // No digest of any kind by an XRP key, and no EVM message.
    assert_eq!(sign(wallet, XRP_0, &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_low_r(wallet, XRP_0, &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(wallet, XRP_0, &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(wallet, XRP_0, b"an XRP key"), Err(KC_ERR_TRANSACTION_ONLY));

    // An imported XRP key, opened as one, is held the same way, and a refused
    // signature gives its reading back; a plain secp256k1 key signs no payment.
    let secret = export(wallet, XRP_0).unwrap();
    let xrp_key = open_key(KC_CURVE_SECP256K1_XRP, &secret).unwrap();
    let plain = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    assert_eq!(public_key(xrp_key, "m", KC_PUBLIC_KEY_COMPRESSED).unwrap(), key);
    assert_eq!(xrpl_sign(xrp_key, "m", &signed.blob()), Err(KC_ERR_UNSHOWN));
    read_xrpl(&reviewed.blob()).unwrap();
    assert_eq!(xrpl_sign(xrp_key, "m/0", &signed.blob()), Err(KC_ERR_PATH));
    assert_eq!(xrpl_sign(xrp_key, "m", &signed.blob()).unwrap(), signature, "kept after a refusal");
    read_xrpl(&reviewed.blob()).unwrap();
    assert_eq!(xrpl_sign(plain, "m", &signed.blob()), Err(KC_ERR_KIND));
    assert_eq!(sign(xrp_key, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(xrp_key, "m").unwrap(), secret);
    assert!(xrpl_sign(wallet, XRP_0, &signed.blob()).is_ok(), "the reading still kept");
    for h in [wallet, xrp_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn an_xrpl_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let blob = hex(XRPL_PLAIN);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_xrpl_read_transaction(blob.as_ptr(), blob.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- A Cosmos SignDoc read for a screen (O58) ----------------------------------

/// [sign_doc] as `kc_cosmos_read_sign_doc` reads it: the length first, then
/// the reading.
fn read_cosmos(sign_doc: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_cosmos_read_sign_doc(sign_doc.as_ptr(), sign_doc.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_cosmos_read_sign_doc(sign_doc.as_ptr(), sign_doc.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn coin_bytes(denom: &str, amount: &str) -> Vec<u8> {
    [pb_bytes(1, denom.as_bytes()), pb_bytes(2, amount.as_bytes())].concat()
}

/// A `SignDoc` as the app's `CosmosTx` writes a transfer's: [amount] of
/// `uatom` from [from] to [to], [memo], one signer of [key] at [sequence], a
/// fee, the Hub's chain id and [account].
fn sign_doc(from: &str, to: &str, amount: &str, memo: &str, key: &[u8], sequence: u64, account: u64, extra_body: &[u8]) -> Vec<u8> {
    let send = [pb_bytes(1, from.as_bytes()), pb_bytes(2, to.as_bytes()), pb_bytes(3, &coin_bytes("uatom", amount))].concat();
    let any = [pb_bytes(1, b"/cosmos.bank.v1beta1.MsgSend"), pb_bytes(2, &send)].concat();
    let body = [pb_bytes(1, &any), if memo.is_empty() { vec![] } else { pb_bytes(2, memo.as_bytes()) }, extra_body.to_vec()].concat();
    let public = [pb_bytes(1, b"/cosmos.crypto.secp256k1.PubKey"), pb_bytes(2, &pb_bytes(1, key))].concat();
    let mode = pb_bytes(1, &pb_int(1, 1));
    let signer = [pb_bytes(1, &public), pb_bytes(2, &mode), if sequence == 0 { vec![] } else { pb_int(3, sequence) }].concat();
    let fee = [pb_bytes(1, &coin_bytes("uatom", "5000")), pb_int(2, 200_000)].concat();
    let auth = [pb_bytes(1, &signer), pb_bytes(2, &fee)].concat();
    [pb_bytes(1, &body), pb_bytes(2, &auth), pb_bytes(3, b"cosmoshub-4"), if account == 0 { vec![] } else { pb_int(4, account) }].concat()
}

#[test]
fn a_cosmos_sign_doc_is_read_with_its_facts() {
    let _abi = abi();
    let key = [0x02; 33];
    let doc = sign_doc("cosmos1from", "cosmos1to", "1500000", "deposit 42", &key, 7, 12345, &[]);
    let reading = read_cosmos(&doc).unwrap();
    assert_eq!(
        reading,
        serde_json::json!({
            "chainId": "cosmoshub-4",
            "accountNumber": "12345",
            "messages": [{
                "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
                "value": format!("0x{}", to_hex(&[pb_bytes(1, b"cosmos1from"), pb_bytes(2, b"cosmos1to"), pb_bytes(3, &coin_bytes("uatom", "1500000"))].concat())),
                "decoded": {"kind": "send", "from": "cosmos1from", "to": "cosmos1to", "amount": [{"denom": "uatom", "amount": "1500000"}]},
            }],
            "memo": "deposit 42",
            "timeoutHeight": null,
            "signers": [{"publicKeyType": "/cosmos.crypto.secp256k1.PubKey", "publicKey": format!("0x{}", to_hex(&key)), "signMode": "1", "sequence": "7"}],
            "fee": {"amount": [{"denom": "uatom", "amount": "5000"}], "gasLimit": "200000", "payer": null, "granter": null},
        })
    );
    // A genesis account's number and a first sequence are zero, and are not
    // written; a timeout height is read.
    let first = read_cosmos(&sign_doc("cosmos1from", "cosmos1to", "1", "", &key, 0, 0, &pb_int(3, 99))).unwrap();
    assert_eq!(first["accountNumber"], "0");
    assert_eq!(first["signers"][0]["sequence"], "0");
    assert_eq!(first["memo"], "");
    assert_eq!(first["timeoutHeight"], "99");
    // Another message is read and not decoded; a MsgSend with a field of its
    // own is not decoded either.
    let vote = [pb_bytes(1, b"/cosmos.gov.v1.MsgVote"), pb_bytes(2, &[0x08, 0x01])].concat();
    let doc = [pb_bytes(1, &pb_bytes(1, &vote)), pb_bytes(3, b"cosmoshub-4")].concat();
    let reading = read_cosmos(&doc).unwrap();
    assert_eq!(reading["messages"][0]["decoded"], serde_json::Value::Null);
    assert_eq!(reading["signers"], serde_json::json!([]));
    assert_eq!(reading["fee"], serde_json::Value::Null);
    let odd = [pb_bytes(1, b"cosmos1from"), pb_bytes(2, b"cosmos1to"), pb_int(9, 1)].concat();
    let any = [pb_bytes(1, b"/cosmos.bank.v1beta1.MsgSend"), pb_bytes(2, &odd)].concat();
    let doc = pb_bytes(1, &pb_bytes(1, &any));
    assert_eq!(read_cosmos(&doc).unwrap()["messages"][0]["decoded"], serde_json::Value::Null);
}

#[test]
fn what_no_cosmos_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let key = [0x02; 33];
    let doc = sign_doc("cosmos1from", "cosmos1to", "1", "", &key, 1, 1, &[]);
    let body_with = |extra: &[u8]| sign_doc("cosmos1from", "cosmos1to", "1", "", &key, 1, 1, extra);
    let auth_with = |extra: &[u8]| {
        let fee = [pb_bytes(1, &coin_bytes("uatom", "5000")), pb_int(2, 200_000)].concat();
        [pb_bytes(1, &pb_bytes(1, b"")), pb_bytes(2, &[pb_bytes(2, &fee), extra.to_vec()].concat())].concat()
    };
    let several_keys = pb_bytes(1, &pb_bytes(2, &pb_bytes(2, &pb_bytes(1, &[0x08, 0x01]))));
    let refused = [
        ("an extension option", body_with(&pb_bytes(1023, &[0x0a, 0x00]))),
        ("a non-critical extension option", body_with(&pb_bytes(2047, &[0x0a, 0x00]))),
        ("an unordered body", body_with(&pb_int(4, 1))),
        ("a timeout by time", body_with(&pb_bytes(5, &[0x08, 0x01]))),
        ("the memo twice", body_with(&[pb_bytes(2, b"a"), pb_bytes(2, b"b")].concat())),
        ("a memo that is not text", body_with(&pb_bytes(2, &[0xff]))),
        ("a tip", auth_with(&pb_bytes(3, &[0x0a, 0x00]))),
        ("a signer of several keys", [pb_bytes(2, &several_keys)].concat()),
        ("a field the sign doc does not name", [doc.clone(), pb_int(5, 1)].concat()),
        ("the chain twice", [doc.clone(), pb_bytes(3, b"osmosis-1")].concat()),
        ("a number where bytes go", [pb_int(1, 1), doc.clone()].concat()),
        ("a varint longer than it needs", [doc.clone(), vec![0x20, 0x81, 0x00]].concat()),
        ("cut short", doc[..doc.len() - 1].to_vec()),
    ];
    for (why, doc) in refused {
        assert_eq!(read_cosmos(&doc), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_cosmos_key_signs_only_a_sign_doc_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = public_key(wallet, COSMOS_0, KC_PUBLIC_KEY_COMPRESSED).unwrap();
    // A document of its own, so no other test's reading stands for it.
    let doc = sign_doc("cosmos1own", "cosmos1other", "4242", "", &key, 3, 9, &[]);
    let digest: [u8; 32] = Sha256::digest(&doc).into();
    assert_eq!(sign(wallet, COSMOS_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_cosmos_read_sign_doc(doc.as_ptr(), doc.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(sign(wallet, COSMOS_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_cosmos(&doc).unwrap();
    let signature = sign(wallet, COSMOS_0, &digest).unwrap();
    assert_eq!(recovered(&signature, &digest).serialize().to_vec(), key);
    assert_eq!(sign(wallet, COSMOS_0, &digest), Err(KC_ERR_UNSHOWN), "signed once");
    // Every zone's path — Kava's 459 among them — and no other kind of
    // signature by such a key; a TRON reading is not a Cosmos one.
    read_cosmos(&doc).unwrap();
    for at in ["m/44'/118'/0'/0/3", "m/44'/459'/0'/0/0", "m/44'/118'"] {
        assert_eq!(sign(wallet, at, &[7u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(sign_low_r(wallet, COSMOS_0, &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(wallet, COSMOS_0, &digest, &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(wallet, COSMOS_0, b"a Cosmos key"), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN), "a Cosmos reading signs no TRON digest");
    assert_eq!(sign(wallet, COSMOS_0, &digest).unwrap(), signature, "the reading kept is still there");

    // An imported Cosmos key, opened as one, is held the same way, and a
    // refused signature gives its reading back; a plain one is not held.
    let secret = export(wallet, COSMOS_0).unwrap();
    let cosmos_key = open_key(KC_CURVE_SECP256K1_COSMOS, &secret).unwrap();
    let plain = open_key(KC_CURVE_SECP256K1, &secret).unwrap();
    assert_eq!(public_key(cosmos_key, "m", KC_PUBLIC_KEY_COMPRESSED).unwrap(), key);
    assert_eq!(sign(cosmos_key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_cosmos(&doc).unwrap();
    assert_eq!(sign(cosmos_key, "m/0", &digest), Err(KC_ERR_PATH));
    assert_eq!(sign(cosmos_key, "m", &digest).unwrap(), signature, "kept after a refusal");
    assert_eq!(sign(plain, "m", &digest).unwrap(), signature);
    assert_eq!(sign_low_r(cosmos_key, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(cosmos_key, "m").unwrap(), secret);
    for h in [wallet, cosmos_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_cosmos_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let doc = sign_doc("cosmos1a", "cosmos1b", "1", "", &[0x02; 33], 1, 1, &[]);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_cosmos_read_sign_doc(doc.as_ptr(), doc.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_cosmos_read_sign_doc(doc.as_ptr(), doc.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_cosmos_read_sign_doc(doc.as_ptr(), doc.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- A Stellar transaction read for a screen (O58) -----------------------------

/// [payload] as `kc_stellar_read_transaction` reads it: the length first,
/// then the reading.
fn read_stellar(payload: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn xdr_u32(n: u32) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

fn xdr_i64(n: i64) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

/// A `MuxedAccount` of [key], with no id.
fn xdr_account(key: [u8; 32]) -> Vec<u8> {
    [xdr_u32(0), key.to_vec()].concat()
}

/// The public network's `TransactionSignaturePayload` of a transaction from
/// [source] at [sequence] with [memo] and [operations], a time window to
/// [max_time].
fn stellar_payload(source: [u8; 32], sequence: i64, memo: &[u8], operations: &[Vec<u8>], max_time: u64) -> Vec<u8> {
    let network: [u8; 32] = Sha256::digest(b"Public Global Stellar Network ; September 2015").into();
    [
        network.to_vec(),
        xdr_u32(2),
        xdr_account(source),
        xdr_u32(100),
        xdr_i64(sequence),
        xdr_u32(1),
        0u64.to_be_bytes().to_vec(),
        max_time.to_be_bytes().to_vec(),
        memo.to_vec(),
        xdr_u32(operations.len() as u32),
        operations.concat(),
        xdr_u32(0),
    ]
    .concat()
}

fn stellar_payment(to: [u8; 32], amount: i64) -> Vec<u8> {
    [xdr_u32(0), xdr_u32(1), xdr_account(to), xdr_u32(0), xdr_i64(amount)].concat()
}

fn memo_text(text: &[u8]) -> Vec<u8> {
    let pad = (4 - text.len() % 4) % 4;
    [xdr_u32(1), xdr_u32(text.len() as u32), text.to_vec(), vec![0; pad]].concat()
}

/// USDC's issuer on the public network.
const USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

#[test]
fn a_stellar_transaction_is_read_with_its_facts() {
    let _abi = abi();
    let key = [0x44; 32];
    let source = [0x11; 32];
    let issuer = [0x33; 32];
    let usdc = [xdr_u32(1), b"USDC".to_vec(), xdr_account(issuer)].concat();
    let operations = vec![
        stellar_payment([0x22; 32], 15_000_000),
        [xdr_u32(0), xdr_u32(0), xdr_account(key), xdr_i64(20_000_000)].concat(),
        [xdr_u32(0), xdr_u32(6), usdc.clone(), xdr_i64(i64::MAX)].concat(),
        [
            xdr_u32(1), xdr_account(source),
            xdr_u32(13), xdr_u32(0), xdr_i64(5), xdr_account(source), usdc.clone(), xdr_i64(4),
            xdr_u32(1), [xdr_u32(2), b"LONGERCODE".to_vec(), vec![0, 0], xdr_account(issuer)].concat(),
        ]
        .concat(),
    ];
    let payload = stellar_payload(source, 77, &memo_text(b"deposit 42"), &operations, 1_700_000_300);
    let reading = read_stellar(&payload).unwrap();
    assert_eq!(reading["publicNetwork"], true);
    assert_eq!(reading["fee"], "100");
    assert_eq!(reading["sequence"], "77");
    assert_eq!(reading["timeBounds"], serde_json::json!({"minTime": "0", "maxTime": "1700000300"}));
    assert_eq!(reading["memo"], serde_json::json!({"type": "text", "bytes": format!("0x{}", to_hex(b"deposit 42")), "text": "deposit 42"}));
    let ops = &reading["operations"];
    assert_eq!(ops[0]["type"], "payment");
    assert_eq!(ops[0]["asset"], "native");
    assert_eq!(ops[0]["amount"], "15000000");
    assert_eq!(ops[1]["type"], "createAccount");
    assert!(ops[1]["destination"].as_str().unwrap().starts_with('G'));
    assert_eq!(ops[2]["type"], "changeTrust");
    assert_eq!(ops[2]["limit"], i64::MAX.to_string());
    assert_eq!(ops[3]["type"], "pathPaymentStrictSend");
    assert_eq!(ops[3]["path"].as_array().unwrap().len(), 1);
    assert!(ops[3]["path"][0].as_str().unwrap().starts_with("LONGERCODE:G"));
    assert_eq!(ops[3]["source"], reading["source"]);
    // A muxed source reads as its M… address; the other memo kinds.
    let mut muxed = stellar_payload(source, 1, &xdr_u32(0), &[stellar_payment([0x22; 32], 1)], 1);
    muxed.splice(36..40, [0, 0, 1, 0].iter().copied().chain(7u64.to_be_bytes()));
    assert!(read_stellar(&muxed).unwrap()["source"].as_str().unwrap().starts_with('M'));
    for (memo, kind) in [
        ([xdr_u32(2), 9u64.to_be_bytes().to_vec()].concat(), "id"),
        ([xdr_u32(3), vec![7; 32]].concat(), "hash"),
        ([xdr_u32(4), vec![7; 32]].concat(), "return"),
    ] {
        let payload = stellar_payload(source, 1, &memo, &[stellar_payment([0x22; 32], 1)], 1);
        assert_eq!(read_stellar(&payload).unwrap()["memo"]["type"], kind);
    }
    // USDC's issuer spelled as Stellar spells it: its key, read back from the
    // address, written out again with its checksum.
    let usdc_issuer = [xdr_u32(1), b"USDC".to_vec(), xdr_u32(0), stellar_issuer_key().to_vec()].concat();
    let payload = stellar_payload(source, 1, &xdr_u32(0), &[[xdr_u32(0), xdr_u32(6), usdc_issuer, xdr_i64(1)].concat()], 1);
    assert_eq!(read_stellar(&payload).unwrap()["operations"][0]["asset"], format!("USDC:{USDC_ISSUER}"));
}

/// [USDC_ISSUER]'s key, decoded from its strkey.
fn stellar_issuer_key() -> [u8; 32] {
    let mut bits = 0u32;
    let mut buffer = 0u64;
    let mut out = Vec::new();
    for c in USDC_ISSUER.bytes() {
        let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".iter().position(|a| *a == c).unwrap() as u64;
        buffer = buffer << 5 | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out[1..33].try_into().unwrap()
}

#[test]
fn what_no_stellar_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let source = [0x11; 32];
    let pay = stellar_payment([0x22; 32], 1);
    let good = stellar_payload(source, 1, &xdr_u32(0), &[pay.clone()], 1);
    let with_memo = |memo: Vec<u8>| stellar_payload(source, 1, &memo, &[pay.clone()], 1);
    let with_op = |op: Vec<u8>| stellar_payload(source, 1, &xdr_u32(0), &[op], 1);
    let mut fee_bump = good.clone();
    fee_bump[35] = 5;
    let mut v2 = good.clone();
    v2[36 + 36 + 4 + 8 + 3] = 2;
    let refused = [
        ("a fee bump", fee_bump),
        ("preconditions beyond a window", v2),
        ("no operation", stellar_payload(source, 1, &xdr_u32(0), &[], 1)),
        ("an operation the module does not write", with_op([xdr_u32(0), xdr_u32(10)].concat())),
        ("a pool share", with_op([xdr_u32(0), xdr_u32(6), xdr_u32(3)].concat())),
        ("a negative amount", with_op(stellar_payment([0x22; 32], -1))),
        ("an asset code with a zero inside", with_op([xdr_u32(0), xdr_u32(6), xdr_u32(1), b"U\0SD".to_vec(), xdr_account([3; 32]), xdr_i64(1)].concat())),
        ("a short code in the long variant", with_op([xdr_u32(0), xdr_u32(6), xdr_u32(2), b"USDC\0\0\0\0\0\0\0\0".to_vec(), xdr_account([3; 32]), xdr_i64(1)].concat())),
        ("a memo of 29 bytes", with_memo(memo_text(&[b'a'; 29]))),
        ("a memo whose padding is not zero", with_memo([xdr_u32(1), xdr_u32(1), b"a".to_vec(), vec![0, 0, 1]].concat())),
        ("a Soroban extension", { let mut p = good.clone(); let n = p.len(); p[n - 1] = 1; p }),
        ("a byte after the last field", [good.clone(), vec![0]].concat()),
        ("cut short", good[..good.len() - 1].to_vec()),
    ];
    for (why, payload) in refused {
        assert_eq!(read_stellar(&payload), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_stellar_key_signs_only_a_transaction_hash_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, STELLAR_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let payload = stellar_payload(key, 4242, &xdr_u32(0), &[stellar_payment([0x23; 32], 7)], 42);
    let hash: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(ed_sign(wallet, STELLAR_0, &hash), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, STELLAR_0, &hash), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_stellar(&payload).unwrap();
    assert_eq!(ed_sign(wallet, STELLAR_0, &payload), Err(KC_ERR_UNSHOWN), "the payload itself is not its hash");
    let signature = ed_sign(wallet, STELLAR_0, &hash).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, STELLAR_0, &hash), Err(KC_ERR_UNSHOWN), "signed once");
    // Every Stellar account, and a Stellar reading is not a Solana one.
    read_stellar(&payload).unwrap();
    for at in ["m/44'/148'/3'", "m/44'/148'"] {
        assert_eq!(ed_sign(wallet, at, &[9u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, SOLANA_0, &hash), Err(KC_ERR_UNSHOWN));
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(ed_sign(wallet, STELLAR_0, &hash).unwrap(), signature, "the reading kept is still there");

    // An imported Stellar key, opened as one, is held the same way, and a
    // refused signature gives its reading back; a plain ed25519 key is not.
    let secret = ed_export(wallet, STELLAR_0).unwrap();
    let stellar_key = open_key(KC_CURVE_ED25519_STELLAR, &secret).unwrap();
    let plain = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_public_key(stellar_key, "m").unwrap(), key);
    assert_eq!(ed_sign(stellar_key, "m", &hash), Err(KC_ERR_UNSHOWN));
    read_stellar(&payload).unwrap();
    assert_eq!(ed_sign(stellar_key, "m/0'", &hash), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(stellar_key, "m", &hash).unwrap(), signature, "kept after a refusal");
    assert_eq!(ed_sign(plain, "m", &hash).unwrap(), signature);
    assert_eq!(ed_export(stellar_key, "m").unwrap(), secret);
    for h in [wallet, stellar_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_stellar_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let payload = stellar_payload([0x11; 32], 1, &xdr_u32(0), &[stellar_payment([0x24; 32], 1)], 1);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_stellar_read_transaction(payload.as_ptr(), payload.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- NEAR (O58) ---------------------------------------------------------------

const NEAR_0: &str = "m/44'/397'/0'";

fn read_near(transaction: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_near_read_transaction(transaction.as_ptr(), transaction.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_near_read_transaction(transaction.as_ptr(), transaction.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// A Borsh string.
fn borsh_string(text: &str) -> Vec<u8> {
    [(text.len() as u32).to_le_bytes().to_vec(), text.as_bytes().to_vec()].concat()
}

/// A NEAR transaction from [signer], its key [key], at [nonce] to
/// [receiver], of [actions], each already written.
fn near_transaction(signer: &str, key: [u8; 32], nonce: u64, receiver: &str, actions: &[Vec<u8>]) -> Vec<u8> {
    [
        borsh_string(signer),
        vec![0],
        key.to_vec(),
        nonce.to_le_bytes().to_vec(),
        borsh_string(receiver),
        vec![9u8; 32],
        (actions.len() as u32).to_le_bytes().to_vec(),
        actions.concat(),
    ]
    .concat()
}

fn near_transfer(deposit: u128) -> Vec<u8> {
    [vec![3], deposit.to_le_bytes().to_vec()].concat()
}

#[test]
fn a_near_transaction_is_read_with_its_facts() {
    let _abi = abi();
    let key = [0x11u8; 32];
    let signer = to_hex(&key);
    // 2^128 - 1 yoctoNEAR: a deposit past 64 bits, as a string.
    let bytes = near_transaction(&signer, key, 7, "alice.near", &[near_transfer(u128::MAX), near_transfer(1)]);
    let reading = read_near(&bytes).unwrap();
    assert_eq!(reading["signerId"], signer);
    assert_eq!(reading["publicKey"], format!("ed25519:{}", solana::base58(&key)));
    assert_eq!(reading["nonce"], "7");
    assert_eq!(reading["receiverId"], "alice.near");
    assert_eq!(reading["blockHash"], solana::base58(&[9u8; 32]));
    assert_eq!(
        reading["actions"],
        serde_json::json!([
            {"type": "transfer", "deposit": u128::MAX.to_string()},
            {"type": "transfer", "deposit": "1"},
        ])
    );
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(reading["hash"], solana::base58(&hash));
    // Every spelling of an account id NEAR takes.
    for id in ["ab", "a-b_c.d", "0x1234567890abcdef1234567890abcdef12345678", "sub.alice.near", &"a".repeat(64)] {
        let bytes = near_transaction(&signer, key, 1, id, &[near_transfer(1)]);
        assert_eq!(read_near(&bytes).unwrap()["receiverId"], id, "{id}");
    }
}

#[test]
fn what_no_near_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let key = [0x22u8; 32];
    let signer = to_hex(&key);
    let plain = near_transaction(&signer, key, 1, "bob.near", &[near_transfer(5)]);
    let mut secp = plain.clone();
    secp[4 + 64] = 1;
    let mut stake = plain.clone();
    let action_at = plain.len() - 17;
    stake[action_at] = 4;
    let function_call = near_transaction(&signer, key, 1, "bob.near", &[[vec![2], vec![0; 40]].concat()]);
    for (why, bytes) in [
        ("an empty transaction", vec![]),
        ("a byte after the last action", [plain.clone(), vec![0]].concat()),
        ("the last byte missing", plain[..plain.len() - 1].to_vec()),
        ("a secp256k1 key", secp),
        ("a stake", stake),
        ("a function call", function_call),
        ("no action", near_transaction(&signer, key, 1, "bob.near", &[])),
        ("101 actions", near_transaction(&signer, key, 1, "bob.near", &vec![near_transfer(1); 101])),
        ("an id of one letter", near_transaction(&signer, key, 1, "b", &[near_transfer(1)])),
        ("an id of 65", near_transaction(&signer, key, 1, &"b".repeat(65), &[near_transfer(1)])),
        ("capitals", near_transaction(&signer, key, 1, "Bob.near", &[near_transfer(1)])),
        ("two separators", near_transaction(&signer, key, 1, "bob--x.near", &[near_transfer(1)])),
        ("a trailing dot", near_transaction(&signer, key, 1, "bob.near.", &[near_transfer(1)])),
        ("a leading separator", near_transaction(&signer, key, 1, "_bob.near", &[near_transfer(1)])),
        ("an empty part", near_transaction(&signer, key, 1, "bob..near", &[near_transfer(1)])),
        ("a space", near_transaction(&signer, key, 1, "bob near", &[near_transfer(1)])),
        ("not UTF-8", [borsh_string("ab")[..4].to_vec(), vec![0xff, 0xfe], plain[4 + 64..].to_vec()].concat()),
        ("a length past the end", [vec![0xff, 0xff, 0xff, 0xff], plain[4..].to_vec()].concat()),
    ] {
        assert_eq!(read_near(&bytes), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_near_key_signs_only_a_transaction_hash_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, NEAR_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let bytes = near_transaction(&to_hex(&key), key, 4242, "carol.near", &[near_transfer(7)]);
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(ed_sign(wallet, NEAR_0, &hash), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_near_read_transaction(bytes.as_ptr(), bytes.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, NEAR_0, &hash), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_near(&bytes).unwrap();
    assert_eq!(ed_sign(wallet, NEAR_0, &bytes), Err(KC_ERR_UNSHOWN), "the transaction itself is not its hash");
    // A NEAR reading is not a Stellar one, nor the other way round.
    assert_eq!(ed_sign(wallet, STELLAR_0, &hash), Err(KC_ERR_UNSHOWN));
    let signature = ed_sign(wallet, NEAR_0, &hash).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, NEAR_0, &hash), Err(KC_ERR_UNSHOWN), "signed once");
    // Every NEAR account, the Ledger branch the wallet looks under among them.
    read_near(&bytes).unwrap();
    for at in ["m/44'/397'/3'", "m/44'/397'/0'/0'/1'", "m/44'/397'"] {
        assert_eq!(ed_sign(wallet, at, &[9u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    // A refused signature gives its reading back.
    assert_eq!(ed_sign(wallet, "m/44'/397'/0'/0", &hash), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(wallet, NEAR_0, &hash).unwrap(), signature, "the reading kept is still there");
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_near_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let bytes = near_transaction("dave.near", [0x33; 32], 1, "erin.near", &[near_transfer(1)]);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_near_read_transaction(bytes.as_ptr(), bytes.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_near_read_transaction(bytes.as_ptr(), bytes.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_near_read_transaction(bytes.as_ptr(), bytes.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- Aptos and Movement (O58) -------------------------------------------------

const APTOS_0: &str = "m/44'/637'/0'/0'/0'";

fn read_aptos(message: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// The signing message of `0x1::aptos_account::transfer` from [sender] at
/// [sequence] of [amount] to [recipient], on [chain].
fn aptos_message(sender: [u8; 32], sequence: u64, recipient: [u8; 32], amount: u64, chain: u8) -> Vec<u8> {
    use sha3::Digest as _;
    let domain: [u8; 32] = sha3::Sha3_256::digest(b"APTOS::RawTransaction").into();
    let mut framework = [0u8; 32];
    framework[31] = 1;
    [
        domain.to_vec(),
        sender.to_vec(),
        sequence.to_le_bytes().to_vec(),
        vec![2],
        framework.to_vec(),
        vec![13],
        b"aptos_account".to_vec(),
        vec![8],
        b"transfer".to_vec(),
        vec![0, 2, 32],
        recipient.to_vec(),
        vec![8],
        amount.to_le_bytes().to_vec(),
        2000u64.to_le_bytes().to_vec(),
        100u64.to_le_bytes().to_vec(),
        1_700_000_060u64.to_le_bytes().to_vec(),
        vec![chain],
    ]
    .concat()
}

#[test]
fn an_aptos_transaction_is_read_with_its_facts() {
    let _abi = abi();
    let message = aptos_message([0x11; 32], 7, [0x22; 32], u64::MAX, 1);
    let reading = read_aptos(&message).unwrap();
    assert_eq!(reading["sender"], format!("0x{}", "11".repeat(32)));
    assert_eq!(reading["sequenceNumber"], "7");
    assert_eq!(reading["function"], "0x1::aptos_account::transfer");
    assert_eq!(reading["recipient"], format!("0x{}", "22".repeat(32)));
    assert_eq!(reading["amount"], u64::MAX.to_string());
    assert_eq!(reading["maxGasAmount"], "2000");
    assert_eq!(reading["gasUnitPrice"], "100");
    assert_eq!(reading["expirationTimestampSecs"], "1700000060");
    assert_eq!(reading["chainId"], 1);
    // Movement's message is Aptos's, its chain 126.
    assert_eq!(read_aptos(&aptos_message([0x11; 32], 7, [0x22; 32], 5, 126)).unwrap()["chainId"], 126);
}

#[test]
fn what_no_aptos_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let plain = aptos_message([0x11; 32], 7, [0x22; 32], 5, 1);
    let mut domain = plain.clone();
    domain[0] ^= 1;
    let mut script = plain.clone();
    script[72] = 0;
    let mut other_module = plain.clone();
    other_module[73 + 31] = 3;
    let mut coin = plain.clone();
    coin[106..119].copy_from_slice(b"aptos_coinxxx");
    let mut function = plain.clone();
    function[120..128].copy_from_slice(b"transfeR");
    let mut type_args = plain.clone();
    type_args[128] = 1;
    let mut three_args = plain.clone();
    three_args[129] = 3;
    let mut short_address = plain.clone();
    short_address[130] = 31;
    let long_uleb = [plain[..72].to_vec(), vec![0x82, 0x00], plain[73..].to_vec()].concat();
    for (why, message) in [
        ("an empty message", vec![]),
        ("another domain", domain),
        ("a script", script),
        ("a module not the framework's", other_module),
        ("another module", coin),
        ("another function", function),
        ("a type argument", type_args),
        ("three arguments", three_args),
        ("an address argument of 31 bytes", short_address),
        ("a ULEB128 longer than it needs", long_uleb),
        ("a byte after the chain id", [plain.clone(), vec![0]].concat()),
        ("the chain id missing", plain[..plain.len() - 1].to_vec()),
    ] {
        assert_eq!(read_aptos(&message), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn an_aptos_key_signs_only_a_message_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, APTOS_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let message = aptos_message([0x44; 32], 4242, [0x23; 32], 7, 1);
    assert_eq!(ed_sign(wallet, APTOS_0, &message), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, APTOS_0, &message), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_aptos(&message).unwrap();
    let digest: [u8; 32] = Sha256::digest(&message).into();
    assert_eq!(ed_sign(wallet, APTOS_0, &digest), Err(KC_ERR_UNSHOWN), "its hash is not it");
    // An Aptos reading signs nothing by a Solana key.
    assert_eq!(ed_sign(wallet, SOLANA_0, &message), Err(KC_ERR_UNSHOWN));
    let signature = ed_sign(wallet, APTOS_0, &message).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&message, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, APTOS_0, &message), Err(KC_ERR_UNSHOWN), "signed once");
    // Every account, Movement's message among them.
    let movement = aptos_message([0x44; 32], 4242, [0x23; 32], 7, 126);
    read_aptos(&movement).unwrap();
    for at in ["m/44'/637'/3'/0'/0'", "m/44'/637'"] {
        assert_eq!(ed_sign(wallet, at, b"not a message"), Err(KC_ERR_UNSHOWN), "{at}");
    }
    // A refused signature gives its reading back.
    assert_eq!(ed_sign(wallet, "m/44'/637'/0'/0'/0", &movement), Err(KC_ERR_PATH));
    assert!(ed_sign(wallet, APTOS_0, &movement).is_ok(), "the reading kept is still there");
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn an_aptos_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let message = aptos_message([0x55; 32], 1, [0x66; 32], 1, 1);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_aptos_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- Sui (O58, O60) ------------------------------------------------------------

const SUI_0: &str = "m/44'/784'/0'/0'/0'";

fn read_sui(message: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

fn blake2b256(parts: &[&[u8]]) -> [u8; 32] {
    use blake2::Digest as _;
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The intent message of the transfer the Sui module writes — [amount] split
/// off the gas coin and handed to [recipient] — from [sender], paid by
/// [coins] gas coins.
fn sui_message(sender: [u8; 32], recipient: [u8; 32], amount: u64, coins: u8) -> Vec<u8> {
    let mut gas = vec![coins];
    for c in 0..coins {
        gas.extend_from_slice(&[0x33 + c; 32]);
        gas.extend_from_slice(&5u64.to_le_bytes());
        gas.push(32);
        gas.extend_from_slice(&[0x44; 32]);
    }
    [
        vec![0, 0, 0, 0, 0, 2, 0, 8],
        amount.to_le_bytes().to_vec(),
        vec![0, 32],
        recipient.to_vec(),
        vec![2, 2, 0, 1, 1, 0, 0, 1, 1, 3, 0, 0, 0, 0, 1, 1, 0],
        sender.to_vec(),
        gas,
        sender.to_vec(),
        750u64.to_le_bytes().to_vec(),
        5_000_000u64.to_le_bytes().to_vec(),
        vec![0],
    ]
    .concat()
}

#[test]
fn a_sui_transaction_is_read_with_its_facts() {
    let _abi = abi();
    // The bytes `on_chain` writes for this transfer, as the module builds it.
    let message = sui_message([0x11; 32], [0x22; 32], 1000, 1);
    assert_eq!(
        to_hex(&message),
        "0000000000020008e80300000000000000202222222222222222222222222222\
         2222222222222222222222222222222222220202000101000001010300000000\
         0101001111111111111111111111111111111111111111111111111111111111\
         1111110133333333333333333333333333333333333333333333333333333333\
         3333333305000000000000002044444444444444444444444444444444444444\
         4444444444444444444444444411111111111111111111111111111111111111\
         11111111111111111111111111ee02000000000000404b4c000000000000"
    );
    let reading = read_sui(&message).unwrap();
    assert_eq!(reading["sender"], format!("0x{}", "11".repeat(32)));
    assert_eq!(reading["recipient"], format!("0x{}", "22".repeat(32)));
    assert_eq!(reading["amount"], "1000");
    assert_eq!(reading["gasOwner"], reading["sender"]);
    assert_eq!(reading["gasPrice"], "750");
    assert_eq!(reading["gasBudget"], "5000000");
    assert_eq!(reading["gasPayment"][0]["objectId"], format!("0x{}", "33".repeat(32)));
    assert_eq!(reading["gasPayment"][0]["version"], "5");
    assert_eq!(reading["gasPayment"][0]["digest"], solana::base58(&[0x44; 32]));
    assert_eq!(
        reading["transactionDigest"],
        solana::base58(&blake2b256(&[b"TransactionData::", &message[3..]]))
    );
    assert_eq!(read_sui(&sui_message([1; 32], [2; 32], u64::MAX, 3)).unwrap()["gasPayment"].as_array().unwrap().len(), 3);
}

#[test]
fn what_no_sui_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let plain = sui_message([0x11; 32], [0x22; 32], 5, 1);
    let at = |i: usize, b: u8| {
        let mut m = plain.clone();
        m[i] = b;
        m
    };
    for (why, message) in [
        ("an empty message", vec![]),
        ("a personal message's intent", at(0, 3)),
        ("another version", at(1, 1)),
        ("TransactionData V2", at(3, 1)),
        ("a system transaction", at(4, 1)),
        ("three inputs", at(5, 3)),
        ("an object input", at(6, 1)),
        ("an amount of 16 bytes", at(7, 16)),
        ("a MoveCall", at(51, 0)),
        ("another coin split", at(52, 1)),
        ("two amounts", at(53, 2)),
        ("another input split", at(55, 1)),
        ("a MergeCoins", at(57, 3)),
        ("a Result, not a nested one", at(59, 2)),
        ("the second result", at(62, 1)),
        ("paid to input 0", at(65, 0)),
        ("no gas coin", at(99, 0)),
        ("a digest of 31 bytes", at(140, 31)),
        ("an expiry", at(plain.len() - 1, 1)),
        ("a byte after", [plain.clone(), vec![0]].concat()),
        ("a ULEB128 longer than it needs", [plain[..5].to_vec(), vec![0x82, 0x00], plain[6..].to_vec()].concat()),
    ] {
        assert_eq!(read_sui(&message), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_sui_key_signs_only_a_digest_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, SUI_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let message = sui_message(key, [0x23; 32], 4242, 1);
    let digest = blake2b256(&[&message]);
    assert_eq!(ed_sign(wallet, SUI_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, SUI_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_sui(&message).unwrap();
    assert_eq!(ed_sign(wallet, SUI_0, &message), Err(KC_ERR_UNSHOWN), "the message itself is not its digest");
    assert_eq!(ed_sign(wallet, STELLAR_0, &digest), Err(KC_ERR_UNSHOWN), "a Sui reading is not a Stellar one");
    let signature = ed_sign(wallet, SUI_0, &digest).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&digest, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, SUI_0, &digest), Err(KC_ERR_UNSHOWN), "signed once");
    read_sui(&message).unwrap();
    for at in ["m/44'/784'/3'/0'/0'", "m/44'/784'"] {
        assert_eq!(ed_sign(wallet, at, &[9u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, SUI_0, &digest).unwrap(), signature, "the reading kept is still there");

    // An imported Sui key, opened as one, is held the same way, and a refused
    // signature gives its reading back; a plain ed25519 key is not.
    let secret = ed_export(wallet, SUI_0).unwrap();
    let sui_key = open_key(KC_CURVE_ED25519_SUI, &secret).unwrap();
    let plain = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_public_key(sui_key, "m").unwrap(), key);
    assert_eq!(ed_sign(sui_key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_sui(&message).unwrap();
    assert_eq!(ed_sign(sui_key, "m/0'", &digest), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(sui_key, "m", &digest).unwrap(), signature, "kept after a refusal");
    assert_eq!(ed_sign(plain, "m", &digest).unwrap(), signature);
    assert_eq!(ed_export(sui_key, "m").unwrap(), secret);
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    for h in [wallet, sui_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_sui_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let message = sui_message([0x55; 32], [0x66; 32], 1, 1);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_sui_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- Algorand (O58) -------------------------------------------------------------

const ALGORAND_0: &str = "m/44'/283'/0'/0'/0'";

fn read_algorand(message: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// Canonical msgpack, as the Algorand module's writer writes it.
fn mp_uint(v: u64) -> Vec<u8> {
    match v {
        0..=0x7f => vec![v as u8],
        0x80..=0xff => vec![0xcc, v as u8],
        0x100..=0xffff => [vec![0xcd], (v as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![0xce], (v as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![0xcf], v.to_be_bytes().to_vec()].concat(),
    }
}

fn mp_text(t: &str) -> Vec<u8> {
    assert!(t.len() < 32);
    [vec![0xa0 | t.len() as u8], t.as_bytes().to_vec()].concat()
}

fn mp_bytes(b: &[u8]) -> Vec<u8> {
    assert!(b.len() <= 0xff);
    [vec![0xc4, b.len() as u8], b.to_vec()].concat()
}

/// A map of [entries], already in their canonical order.
fn mp_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() < 16);
    let mut out = vec![0x80 | entries.len() as u8];
    for (key, value) in entries {
        out.extend(mp_text(key));
        out.extend_from_slice(value);
    }
    out
}

const ALGORAND_MAINNET: [u8; 32] = [
    0xc0, 0x61, 0xc4, 0xd8, 0xfc, 0x1d, 0xbd, 0xde, 0xd2, 0xd7, 0x60, 0x4b, 0xe4, 0x56, 0x8e, 0x3f,
    0x6d, 0x04, 0x19, 0x87, 0xac, 0x37, 0xbd, 0xe4, 0xb6, 0x20, 0xb5, 0xab, 0x39, 0x24, 0x8a, 0xdf,
];

/// `TX` and a payment of [amount] from [sender] to [receiver], with [extra]
/// fields in their places.
fn algorand_payment(sender: [u8; 32], receiver: [u8; 32], amount: u64, note: &[u8]) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = vec![
        ("amt", mp_uint(amount)),
        ("fee", mp_uint(1000)),
        ("fv", mp_uint(50_000_000)),
        ("gen", mp_text("mainnet-v1.0")),
        ("gh", mp_bytes(&ALGORAND_MAINNET)),
        ("lv", mp_uint(50_001_000)),
    ];
    if !note.is_empty() {
        entries.push(("note", mp_bytes(note)));
    }
    entries.extend([("rcv", mp_bytes(&receiver)), ("snd", mp_bytes(&sender)), ("type", mp_text("pay"))]);
    [b"TX".to_vec(), mp_map(&entries)].concat()
}

#[test]
fn an_algorand_transaction_is_read_with_its_facts() {
    let _abi = abi();
    let message = algorand_payment([0x11; 32], [0x22; 32], 5_000_000, b"deposit 42");
    let reading = read_algorand(&message).unwrap();
    assert_eq!(reading["mainnet"], true);
    let fields = &reading["transaction"]["map"];
    assert_eq!(fields["amt"], serde_json::json!({"uint": "5000000"}));
    assert_eq!(fields["type"], serde_json::json!({"text": "pay"}));
    assert_eq!(fields["snd"], serde_json::json!({"bytes": format!("0x{}", "11".repeat(32))}));
    assert_eq!(fields["note"], serde_json::json!({"bytes": format!("0x{}", to_hex(b"deposit 42"))}));
    // The id Algorand names it by: base32 of SHA-512/256 of the message.
    let id: [u8; 32] = <sha2::Sha512_256 as sha2::Digest>::digest(&message).into();
    let expected: String = {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bits: Vec<u8> = id.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)).collect();
        bits.chunks(5)
            .map(|c| {
                let v = c.iter().fold(0u8, |v, b| v << 1 | b) << (5 - c.len());
                ALPHABET[v as usize] as char
            })
            .collect()
    };
    assert_eq!(reading["id"], expected);
    // Another network's genesis is read, and said.
    let mut testnet = message.clone();
    let at = testnet.windows(32).position(|w| w == ALGORAND_MAINNET).unwrap();
    testnet[at] ^= 1;
    assert_eq!(read_algorand(&testnet).unwrap()["mainnet"], false);
    // A venue's application call, with an array, a nested map and a nil in
    // an array, read field for field.
    let call = [
        b"TX".to_vec(),
        mp_map(&[
            ("apaa", [vec![0x92], mp_bytes(b"swap"), vec![0xc0]].concat()),
            ("apbx", [vec![0x91], mp_map(&[("i", mp_uint(1)), ("n", mp_bytes(b"box"))])].concat()),
            ("apid", mp_uint(1_002_541_853)),
            ("fee", mp_uint(2000)),
            ("snd", mp_bytes(&[0x11; 32])),
            ("type", mp_text("appl")),
        ]),
    ]
    .concat();
    let read = read_algorand(&call).unwrap();
    assert_eq!(read["transaction"]["map"]["apaa"], serde_json::json!({"array": [{"bytes": format!("0x{}", to_hex(b"swap"))}, null]}));
    assert_eq!(read["transaction"]["map"]["apbx"]["array"][0]["map"]["i"], serde_json::json!({"uint": "1"}));
    assert_eq!(read["mainnet"], false, "no genesis named");
}

#[test]
fn what_no_algorand_transaction_of_this_wallet_carries_is_refused() {
    let _abi = abi();
    let plain = algorand_payment([0x11; 32], [0x22; 32], 5, b"");
    let body = &plain[2..];
    let with = |field: (&str, Vec<u8>)| {
        // The payment's fields with [field] in its canonical place.
        let mut entries: Vec<(String, Vec<u8>)> = vec![
            ("amt".into(), mp_uint(5)),
            ("fee".into(), mp_uint(1000)),
            ("snd".into(), mp_bytes(&[0x11; 32])),
            ("type".into(), mp_text("pay")),
        ];
        entries.push((field.0.into(), field.1));
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let borrowed: Vec<(&str, Vec<u8>)> = entries.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        [b"TX".to_vec(), mp_map(&borrowed)].concat()
    };
    let mut unsorted = plain.clone();
    // "amt" and "fee" swapped: the same entries out of order.
    let amt = [mp_text("amt"), mp_uint(5)].concat();
    let fee = [mp_text("fee"), mp_uint(1000)].concat();
    unsorted.splice(3..3 + amt.len() + fee.len(), [fee.clone(), amt.clone()].concat());
    let long_int = [b"TX".to_vec(), mp_map(&[("amt", vec![0xcc, 5]), ("snd", mp_bytes(&[1; 32])), ("type", mp_text("pay"))])].concat();
    let long_bytes = [b"TX".to_vec(), mp_map(&[("snd", [vec![0xc5, 0, 32], vec![1; 32]].concat()), ("type", mp_text("pay"))])].concat();
    let long_text = [b"TX".to_vec(), mp_map(&[("snd", mp_bytes(&[1; 32])), ("type", [vec![0xd9, 3], b"pay".to_vec()].concat())])].concat();
    let mut deep = vec![0x91; 20];
    deep.push(0x00);
    for (why, message) in [
        ("an empty message", vec![]),
        ("no TX prefix", body.to_vec()),
        ("another prefix", [b"MX".to_vec(), body.to_vec()].concat()),
        ("keys out of order", unsorted),
        ("a key twice", with(("amt", mp_uint(6)))),
        ("a zero", with(("fv", mp_uint(0)))),
        ("an empty note", with(("note", mp_bytes(b"")))),
        ("an empty string", with(("gen", mp_text("")))),
        ("a nil value", with(("lx", vec![0xc0]))),
        ("a boolean", with(("nonpart", vec![0xc3]))),
        ("a float", with(("x", [vec![0xcb], vec![0; 8]].concat()))),
        ("a negative integer", with(("x", vec![0xff]))),
        ("an integer longer than it needs", long_int),
        ("a byte string longer than it needs", long_bytes),
        ("a string longer than it needs", long_text),
        ("nested past the limit", with(("apaa", deep))),
        ("a rekey", with(("rekey", mp_bytes(&[9; 32])))),
        ("a close", with(("close", mp_bytes(&[9; 32])))),
        ("an asset close", with(("aclose", mp_bytes(&[9; 32])))),
        ("no sender", [b"TX".to_vec(), mp_map(&[("type", mp_text("pay"))])].concat()),
        ("a sender of 31 bytes", [b"TX".to_vec(), mp_map(&[("snd", mp_bytes(&[1; 31])), ("type", mp_text("pay"))])].concat()),
        ("no type", [b"TX".to_vec(), mp_map(&[("snd", mp_bytes(&[1; 32]))])].concat()),
        ("a byte after", [plain.clone(), vec![0]].concat()),
        ("not a map", [b"TX".to_vec(), vec![0x90]].concat()),
    ] {
        assert_eq!(read_algorand(&message), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn an_algorand_key_signs_only_a_transaction_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, ALGORAND_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let message = algorand_payment(key, [0x23; 32], 4242, b"");
    assert_eq!(ed_sign(wallet, ALGORAND_0, &message), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, ALGORAND_0, &message), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_algorand(&message).unwrap();
    assert_eq!(ed_sign(wallet, APTOS_0, &message), Err(KC_ERR_UNSHOWN), "an Algorand reading is not an Aptos one");
    let signature = ed_sign(wallet, ALGORAND_0, &message).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&message, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, ALGORAND_0, &message), Err(KC_ERR_UNSHOWN), "signed once");
    read_algorand(&message).unwrap();
    for at in ["m/44'/283'/3'/0'/0'", "m/44'/283'"] {
        assert_eq!(ed_sign(wallet, at, b"not a transaction"), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, ALGORAND_0, &message).unwrap(), signature, "the reading kept is still there");

    // An imported Algorand key, opened as one, is held the same way, and a
    // refused signature gives its reading back; a plain ed25519 key is not.
    let secret = ed_export(wallet, ALGORAND_0).unwrap();
    let algorand_key = open_key(KC_CURVE_ED25519_ALGORAND, &secret).unwrap();
    let plain = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_public_key(algorand_key, "m").unwrap(), key);
    assert_eq!(ed_sign(algorand_key, "m", &message), Err(KC_ERR_UNSHOWN));
    read_algorand(&message).unwrap();
    assert_eq!(ed_sign(algorand_key, "m/0'", &message), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(algorand_key, "m", &message).unwrap(), signature, "kept after a refusal");
    assert_eq!(ed_sign(plain, "m", &message).unwrap(), signature);
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    for h in [wallet, algorand_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn an_algorand_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let message = algorand_payment([0x55; 32], [0x66; 32], 1, b"");
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_algorand_read_transaction(message.as_ptr(), message.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- Tezos (O58, O60) ------------------------------------------------------------

const TEZOS_0: &str = "m/44'/1729'/0'/0'";

fn read_tezos(forged: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// What the module's forger writes, printed by it: a reveal and a transfer of
/// one tez from `tz1X3Yj3…`, at branch `BLEM7g…`.
const TEZOS_SEND: &str = "44444444444444444444444444444444444444444444444444444444444444446b007d1c05728fa017919cba7ccf7ff007eacfee7d55900308e80700001111111111111111111111111111111111111111111111111111111111111111006c007d1c05728fa017919cba7ccf7ff007eacfee7d55e80709dc0b8102c0843d0000222222222222222222222222222222222222222200";

/// The same forger's FA1.2 `transfer` of 1,234,567 to `tz1NkWZ…` at
/// `KT1DFVM…`.
const TEZOS_TOKEN: &str = "44444444444444444444444444444444444444444444444444444444444444446c007d1c05728fa017919cba7ccf7ff007eacfee7d55d00f09a09c01640001333333333333333333333333333333333333333300ffff087472616e736665720000005b07070100000024747a315833596a337458387835636772797a636852737974656371476d31684c6831506407070100000024747a314e6b575a4753545463394355626e354b37457279377a736951596f33624e7237620087da9601";

#[test]
fn a_tezos_group_is_read_with_its_facts() {
    let _abi = abi();
    let send = read_tezos(&hex(TEZOS_SEND)).unwrap();
    assert_eq!(send["branch"], "BLEM7gReMtRLxxYR8E4tVbA8ERuZvsqba2hX93SwqQPtKn5uvZt");
    let ops = send["operations"].as_array().unwrap();
    assert_eq!(ops[0]["kind"], "reveal");
    assert_eq!(ops[0]["source"], "tz1X3Yj3tX8x5cgryzchRsytecqGm1hLh1Pd");
    assert_eq!((ops[0]["fee"].as_str(), ops[0]["counter"].as_str()), (Some("400"), Some("8")));
    assert!(ops[0]["publicKey"].as_str().unwrap().starts_with("edpk"));
    assert_eq!(ops[1]["kind"], "transaction");
    assert_eq!(ops[1]["amount"], "1000000");
    assert_eq!(ops[1]["destination"], "tz1NkWZGSTTc9CUbn5K7Ery7zsiQYo3bNr7b");
    assert_eq!((ops[1]["gasLimit"].as_str(), ops[1]["storageLimit"].as_str()), (Some("1500"), Some("257")));
    assert_eq!(ops[1]["entrypoint"], serde_json::Value::Null);
    let token = read_tezos(&hex(TEZOS_TOKEN)).unwrap();
    let call = &token["operations"][0];
    assert_eq!(call["destination"], "KT1DFVMzCwF9vbGnWT2ANNd9KYxiu96V34D9");
    assert_eq!(call["entrypoint"], "transfer");
    assert_eq!(
        call["parameters"],
        serde_json::json!({"prim": "Pair", "args": [
            {"string": "tz1X3Yj3tX8x5cgryzchRsytecqGm1hLh1Pd"},
            {"prim": "Pair", "args": [
                {"string": "tz1NkWZGSTTc9CUbn5K7Ery7zsiQYo3bNr7b"},
                {"int": "1234567"},
            ]},
        ]})
    );
    // A negative integer, a long one, bytes, Unit, a named entrypoint and a
    // pair of three, as the forger writes them.
    let branch = hex(&TEZOS_TOKEN[..64]);
    let call = |params: &[u8], entrypoint: &[u8]| -> Vec<u8> {
        // The call's operation up to its parameters' flag.
        let head = hex(&TEZOS_TOKEN[64..64 + 2 * 52]);
        [branch.clone(), head, entrypoint.to_vec(), (params.len() as u32).to_be_bytes().to_vec(), params.to_vec()].concat()
    };
    let pair3 = vec![0x09, 0x07, 0, 0, 0, 10, 0x00, 0x41, 0x03, 0x0b, 0x0a, 0, 0, 0, 1, 0xab, 0, 0, 0, 0];
    let read = read_tezos(&call(&pair3, &[0xff, 0x02])).unwrap();
    assert_eq!(read["operations"][0]["entrypoint"], "do");
    assert_eq!(
        read["operations"][0]["parameters"],
        serde_json::json!({"prim": "Pair", "args": [{"int": "-1"}, {"prim": "Unit"}, {"bytes": "ab"}]})
    );
    // 2^70 - 1: past 64 bits, as the forger's BigInt writes it.
    let big = vec![0x00, 0x80 | 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    assert_eq!(read_tezos(&call(&big, &[0xff, 0x00])).unwrap()["operations"][0]["parameters"]["int"], "1180591620717411303423");
}

#[test]
fn what_the_tezos_forger_never_writes_is_refused() {
    let _abi = abi();
    let send = hex(TEZOS_SEND);
    let token = hex(TEZOS_TOKEN);
    let at = |bytes: &[u8], i: usize, b: u8| {
        let mut m = bytes.to_vec();
        m[i] = b;
        m
    };
    let params_at = 32 + 1 + 21 + 2 + 1 + 3 + 1 + 1 + 22 + 1 + 1 + 9 + 4;
    let with_params = |params: &[u8]| {
        [token[..params_at - 4].to_vec(), (params.len() as u32).to_be_bytes().to_vec(), params.to_vec()].concat()
    };
    for (why, forged) in [
        ("an empty group", vec![]),
        ("a branch and nothing", send[..32].to_vec()),
        ("an origination", at(&send, 32, 0x6d)),
        ("a delegation", at(&send, 32, 0x6e)),
        ("a source of another curve's tag", at(&send, 33, 0x03)),
        ("a secp256k1 key revealed", at(&send, 32 + 1 + 21 + 2 + 1 + 2 + 1, 0x01)),
        ("a reveal with a proof", at(&send, 32 + 1 + 21 + 2 + 1 + 2 + 1 + 33, 0xff)),
        ("a zarith longer than it needs", [send[..32 + 22].to_vec(), vec![0x90, 0x83, 0x00], send[32 + 22 + 2..].to_vec()].concat()),
        ("a byte after", [send.clone(), vec![0]].concat()),
        ("an originated destination without its padding", at(&token, 32 + 1 + 21 + 2 + 1 + 3 + 1 + 1 + 1 + 20, 1)),
        // `default` by name rather than by its code: the bytes after the
        // parameters' flag are the entrypoint, ten of them for `transfer`.
        ("a named entrypoint written out", [token[..params_at - 4 - 10].to_vec(), vec![0xff, 7], b"default".to_vec(), token[params_at - 4..].to_vec()].concat()),
        ("an annotation", with_params(&[0x04, 0x0b, 0, 0, 0, 0])),
        ("a sequence", with_params(&[0x02, 0, 0, 0, 0])),
        ("a primitive the forger does not write", with_params(&[0x03, 0x0c])),
        ("a general form of two arguments", with_params(&[0x09, 0x07, 0, 0, 0, 4, 0x03, 0x0b, 0x03, 0x0b, 0, 0, 0, 0])),
        ("minus zero", with_params(&[0x00, 0x40])),
        ("an argument shorter than its length", [token[..params_at - 4].to_vec(), vec![0, 0, 0, 9], vec![0x03, 0x0b]].concat()),
        ("a string not UTF-8", with_params(&[0x01, 0, 0, 0, 1, 0xff])),
    ] {
        assert_eq!(read_tezos(&forged), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_tezos_key_signs_only_a_digest_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, TEZOS_0).unwrap();
    // A group of its own — another branch — so no other test's reading
    // stands for it.
    let mut forged = hex(TEZOS_SEND);
    forged[0] = 0x45;
    let digest = blake2b256(&[&[0x03], &forged]);
    assert_eq!(ed_sign(wallet, TEZOS_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, TEZOS_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_tezos(&forged).unwrap();
    assert_eq!(ed_sign(wallet, TEZOS_0, &blake2b256(&[&forged])), Err(KC_ERR_UNSHOWN), "no watermark is not it");
    assert_eq!(ed_sign(wallet, SUI_0, &digest), Err(KC_ERR_UNSHOWN), "a Tezos reading is not a Sui one");
    let signature = ed_sign(wallet, TEZOS_0, &digest).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&digest, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, TEZOS_0, &digest), Err(KC_ERR_UNSHOWN), "signed once");
    read_tezos(&forged).unwrap();
    for at in ["m/44'/1729'/3'/0'", "m/44'/1729'"] {
        assert_eq!(ed_sign(wallet, at, &[9u8; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, TEZOS_0, &digest).unwrap(), signature, "the reading kept is still there");
    let secret = ed_export(wallet, TEZOS_0).unwrap();
    let tezos_key = open_key(KC_CURVE_ED25519_TEZOS, &secret).unwrap();
    let plain = open_key(KC_CURVE_ED25519, &secret).unwrap();
    assert_eq!(ed_sign(tezos_key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_tezos(&forged).unwrap();
    assert_eq!(ed_sign(tezos_key, "m/0'", &digest), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(tezos_key, "m", &digest).unwrap(), signature, "kept after a refusal");
    assert_eq!(ed_sign(plain, "m", &digest).unwrap(), signature);
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    for h in [wallet, tezos_key, plain] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_tezos_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let forged = hex(TEZOS_TOKEN);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_tezos_read_operation(forged.as_ptr(), forged.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- MultiversX (O58) -------------------------------------------------------------

const MULTIVERSX_0: &str = "m/44'/508'/0'/0'/0'";

fn read_multiversx(payload: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

const ERD_A: &str = "erd1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspavcaj";
const ERD_B: &str = "erd1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qjfjdy7";

/// What the module's `MultiversxTransaction` writes, printed by it: one EGLD
/// from `ERD_A` to `ERD_B`, and an ESDT transfer of 1,000,000 USDC-c76f1f.
const MULTIVERSX_EGLD: &str = r#"{"nonce":7,"value":"1000000000000000000","receiver":"erd1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qjfjdy7","sender":"erd1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspavcaj","gasPrice":1000000000,"gasLimit":50000,"chainID":"1","version":1}"#;
const MULTIVERSX_ESDT: &str = r#"{"nonce":8,"value":"0","receiver":"erd1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qjfjdy7","sender":"erd1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspavcaj","gasPrice":1000000000,"gasLimit":500000,"data":"RVNEVFRyYW5zZmVyQDU1NTM0NDQzMmQ2MzM3MzY2NjMxNjZAMGY0MjQw","chainID":"1","version":1}"#;

#[test]
fn a_multiversx_transaction_is_read_with_its_facts() {
    let _abi = abi();
    let egld = read_multiversx(MULTIVERSX_EGLD.as_bytes()).unwrap();
    assert_eq!(egld["nonce"], "7");
    assert_eq!(egld["value"], "1000000000000000000");
    assert_eq!((egld["sender"].as_str(), egld["receiver"].as_str()), (Some(ERD_A), Some(ERD_B)));
    assert_eq!((egld["gasPrice"].as_str(), egld["gasLimit"].as_str()), (Some("1000000000"), Some("50000")));
    assert_eq!(egld["data"], serde_json::Value::Null);
    assert_eq!(egld["mainnet"], true);
    let esdt = read_multiversx(MULTIVERSX_ESDT.as_bytes()).unwrap();
    assert_eq!(esdt["dataText"], "ESDTTransfer@555344432d633736663166@0f4240");
    let devnet = MULTIVERSX_EGLD.replace(r#""chainID":"1""#, r#""chainID":"D""#);
    assert_eq!(read_multiversx(devnet.as_bytes()).unwrap()["mainnet"], false);
}

#[test]
fn what_the_multiversx_module_never_writes_is_refused() {
    let _abi = abi();
    let egld = MULTIVERSX_EGLD;
    let esdt = MULTIVERSX_ESDT;
    for (why, payload) in [
        ("an empty payload", String::new()),
        ("whitespace", egld.replace(r#","value""#, r#", "value""#)),
        ("keys in another order", egld.replace(r#""nonce":7,"value":"1000000000000000000""#, r#""value":"1000000000000000000","nonce":7"#)),
        ("an option", egld.replace(r#""version":1}"#, r#""version":1,"options":1}"#)),
        ("a version 2", egld.replace(r#""version":1}"#, r#""version":2}"#)),
        ("a guardian", egld.replace(r#","chainID""#, r#","guardian":"erd1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspavcaj","chainID""#)),
        ("a leading zero", egld.replace(r#""nonce":7"#, r#""nonce":07"#)),
        ("a value as a number", egld.replace(r#""value":"1000000000000000000""#, r#""value":1000000000000000000"#)),
        ("an escape", egld.replace(r#""chainID":"1""#, r#""chainID":"\u0031""#)),
        ("a checksum wrong", egld.replace("qjfjdy7", "qjfjdy8")),
        ("an address of another prefix", egld.replace(ERD_B, "erd2yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qjfjdy7")),
        ("an address in capitals", egld.replace(ERD_B, &ERD_B.to_uppercase())),
        ("data not padded", esdt.replace("MGY0MjQw\"", "MGY0MjQ\"")),
        ("data in the URL alphabet", esdt.replace("RVNEVFRy", "RVNEVF-y")),
        ("empty data", egld.replace(r#","chainID""#, r#","data":"","chainID""#)),
        ("a byte after", format!("{egld} ")),
        ("a gas limit past 63 bits", egld.replace(r#""gasLimit":50000"#, r#""gasLimit":9223372036854775808"#)),
    ] {
        assert_eq!(read_multiversx(payload.as_bytes()), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_multiversx_key_signs_only_a_transaction_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, MULTIVERSX_0).unwrap();
    // A transaction of its own, so no other test's reading stands for it.
    let payload = MULTIVERSX_EGLD.replace(r#""nonce":7"#, r#""nonce":4242"#);
    let payload = payload.as_bytes();
    assert_eq!(ed_sign(wallet, MULTIVERSX_0, payload), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(ed_sign(wallet, MULTIVERSX_0, payload), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_multiversx(payload).unwrap();
    assert_eq!(ed_sign(wallet, ALGORAND_0, payload), Err(KC_ERR_UNSHOWN), "a MultiversX reading is not an Algorand one");
    let signature = ed_sign(wallet, MULTIVERSX_0, payload).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(payload, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, MULTIVERSX_0, payload), Err(KC_ERR_UNSHOWN), "signed once");
    read_multiversx(payload).unwrap();
    for at in ["m/44'/508'/0'/0'/3'", "m/44'/508'"] {
        assert_eq!(ed_sign(wallet, at, b"not a transaction"), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, "m/44'/508'/0'/0'/0", payload), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(wallet, MULTIVERSX_0, payload).unwrap(), signature, "the reading kept is still there");
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_multiversx_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let payload = MULTIVERSX_ESDT.as_bytes();
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_multiversx_read_transaction(payload.as_ptr(), payload.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}


// --- Polkadot (O58) ---------------------------------------------------------------

const POLKADOT_0: &str = "m/44'/354'/0'/0'/0'";

/// [payload] as `kc_polkadot_read_transaction` reads it for the key at [at] below [handle]: the
/// length first, then the reading.
fn read_polkadot_for(handle: u64, at: &str, payload: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_polkadot_read_transaction(handle, at.as_ptr(), at.len(), payload.as_ptr(), payload.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_polkadot_read_transaction(handle, at.as_ptr(), at.len(), payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [payload] read for the legal phrase's key at [`POLKADOT_0`], from a session
/// opened for it alone: for the tests of what a reading says.
fn read_polkadot(payload: &[u8]) -> Result<serde_json::Value, i32> {
    let reader = open(LEGAL.as_bytes()).unwrap();
    let read = read_polkadot_for(reader, POLKADOT_0, payload);
    assert_eq!(kc_close(reader), KC_OK);
    read
}

/// What the module's `assetHubPayload` writes, printed by it from Asset Hub's
/// metadata at spec 2005000: one DOT to `0x22…22`, nonce 3, born at block
/// 21,391,665 with a period of 64; and 12,345 Planck at nonce 70,000, born at
/// block 21,391,700.
const POLKADOT_ONE_DOT: &str = "0a030022222222222222222222222222222222222222222222222222222222222222220700e40b540215030c00000008981e000f00000068d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f222222222222222222222222222222222222222222222222222222222222222200";
const POLKADOT_SMALL: &str = "0a03002222222222222222222222222222222222222222222222222222222222222222e5c04501c245040000000008981e000f00000068d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f222222222222222222222222222222222222222222222222222222222222222200";

fn polkadot_bytes(hex_text: &str) -> Vec<u8> {
    hex(hex_text)
}

/// [POLKADOT_ONE_DOT] with [from] replaced by [to], once.
fn polkadot_with(from: &str, to: &str) -> Vec<u8> {
    assert_eq!(POLKADOT_ONE_DOT.matches(from).count(), 1, "{from}");
    polkadot_bytes(&POLKADOT_ONE_DOT.replacen(from, to, 1))
}

#[test]
fn a_polkadot_transfer_is_read_with_its_facts() {
    let _abi = abi();
    let one = read_polkadot(&polkadot_bytes(POLKADOT_ONE_DOT)).unwrap();
    assert_eq!(one["call"], "Balances.transfer_keep_alive");
    assert_eq!(one["dest"], format!("0x{}", "22".repeat(32)));
    assert_eq!(one["amount"], "10000000000");
    assert_eq!((one["era"]["period"].as_str(), one["era"]["phase"].as_str()), (Some("64"), Some("49")));
    assert_eq!((one["nonce"].as_str(), one["tip"].as_str()), (Some("3"), Some("0")));
    assert_eq!((one["specVersion"].as_str(), one["transactionVersion"].as_str()), (Some("2005000"), Some("15")));
    assert_eq!(one["genesisHash"], "0x68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f");
    assert_eq!(one["blockHash"], format!("0x{}", "22".repeat(32)));
    assert_eq!(one["assetHub"], true);
    let small = read_polkadot(&polkadot_bytes(POLKADOT_SMALL)).unwrap();
    assert_eq!((small["amount"].as_str(), small["nonce"].as_str()), (Some("12345"), Some("70000")));
    assert_eq!(small["era"]["phase"], "20");
    // The relay chain's genesis is read, and said not to be Asset Hub's.
    let relay = polkadot_with(
        "68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f",
        "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
    );
    assert_eq!(read_polkadot(&relay).unwrap()["assetHub"], false);
    // A tip, and an amount of sixteen bytes, the most a u128 takes.
    let tipped = polkadot_with("0c00000008981e", "0c0700e40b5402000008981e");
    assert_eq!(read_polkadot(&tipped).unwrap()["tip"], "10000000000");
    let most = polkadot_with("0700e40b5402", &format!("33{}", "ff".repeat(16)));
    assert_eq!(read_polkadot(&most).unwrap()["amount"], u128::MAX.to_string());
}

#[test]
fn what_the_polkadot_module_never_writes_is_refused() {
    let _abi = abi();
    let whole = polkadot_bytes(POLKADOT_ONE_DOT);
    let mut after = whole.clone();
    after.push(0);
    for (why, payload) in [
        ("an empty payload", Vec::new()),
        ("transfer_allow_death", polkadot_with("0a0300", "0a0000")),
        ("another pallet", polkadot_with("0a0300", "0b0300")),
        ("an address by index", polkadot_with("0a030022", "0a030122")),
        ("an immortal era", polkadot_with("0215030c", "02000c")),
        ("a period of two", polkadot_with("0215030c", "0210030c")),
        ("a phase outside its period", polkadot_with("0215030c", "0205040c")),
        ("an amount in a longer form", polkadot_with("0700e40b5402", "0b00e40b540200")),
        ("an amount past sixteen bytes", polkadot_with("0700e40b5402", &format!("37{}01", "00".repeat(16)))),
        ("a small amount in two bytes", polkadot_with("0700e40b5402", "0100")),
        ("a nonce past four bytes", polkadot_with("15030c", "1503070000000001")),
        ("an asset paying the fee", polkadot_with("0c00000008", "0c00010008")),
        ("the metadata hash's mode on", polkadot_with("0c00000008", "0c00000108")),
        ("a metadata hash", polkadot_with(&format!("{}00", "22".repeat(32)), &format!("{}01{}", "22".repeat(32), "33".repeat(32)))),
        ("cut short", whole[..whole.len() - 1].to_vec()),
        ("a byte after", after),
    ] {
        assert_eq!(read_polkadot(&payload), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_polkadot_key_signs_only_a_payload_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, POLKADOT_0).unwrap();
    // A payload of its own, so no other test's reading stands for it.
    let payload = polkadot_with("15030c00", "1503c245040000");
    let payload = &payload[..];
    assert_eq!(ed_sign(wallet, POLKADOT_0, payload), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe {
        kc_polkadot_read_transaction(
            wallet,
            POLKADOT_0.as_ptr(),
            POLKADOT_0.len(),
            payload.as_ptr(),
            payload.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    assert_eq!(ed_sign(wallet, POLKADOT_0, payload), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_polkadot_for(wallet, POLKADOT_0, payload).unwrap();
    assert_eq!(ed_sign(wallet, MULTIVERSX_0, payload), Err(KC_ERR_UNSHOWN), "a Polkadot reading is not a MultiversX one");
    let signature = ed_sign(wallet, POLKADOT_0, payload).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(payload, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, POLKADOT_0, payload), Err(KC_ERR_UNSHOWN), "signed once");
    read_polkadot_for(wallet, POLKADOT_0, payload).unwrap();
    for at in ["m/44'/354'/3'/0'/0'", "m/44'/354'"] {
        assert_eq!(ed_sign(wallet, at, b"not a payload"), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, "m/44'/354'/0'/0'/0", payload), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(wallet, POLKADOT_0, payload).unwrap(), signature, "the reading kept is still there");
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_polkadot_reading_signs_by_the_key_it_was_read_for_alone() {
    // A signing payload names no signer: held to the key it was read for
    // (the owner's request of 5 November 2026).
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    // A payload of its own, so no other test's reading stands for it.
    let payload = polkadot_with("15030c00", "1503c245080000");
    let read = read_polkadot_for(wallet, POLKADOT_0, &payload).unwrap();
    assert_eq!(read["signer"], format!("0x{}", to_hex(&ed_public_key(wallet, POLKADOT_0).unwrap())));
    for (why, handle, at) in [("the next account", wallet, "m/44'/354'/1'/0'/0'"), ("another phrase's first", other, POLKADOT_0)] {
        assert_eq!(ed_sign(handle, at, &payload), Err(KC_ERR_UNSHOWN), "{why}");
    }
    assert!(ed_sign(wallet, POLKADOT_0, &payload).is_ok(), "its own key, the reading kept");
    read_polkadot_for(other, POLKADOT_0, &payload).unwrap();
    assert_eq!(ed_sign(wallet, POLKADOT_0, &payload), Err(KC_ERR_UNSHOWN), "another's reading");
    assert!(ed_sign(other, POLKADOT_0, &payload).is_ok());
    // Only a phrase's Polkadot key is read for.
    let imported = open_key(KC_CURVE_ED25519, &[0x47; 32]).unwrap();
    assert_eq!(read_polkadot_for(imported, POLKADOT_0, &payload), Err(KC_ERR_KIND));
    assert_eq!(read_polkadot_for(imported, "m", &payload), Err(KC_ERR_PATH));
    assert_eq!(read_polkadot_for(wallet, MULTIVERSX_0, &payload), Err(KC_ERR_PATH));
    // A level not hardened is refused before the session is asked.
    let (refused, holds) = lock_entries(|| read_polkadot_for(wallet, "m/44'/354'/0'/0'/0", &payload));
    assert_eq!((refused, holds), (Err(KC_ERR_PATH), 0));
    for h in [wallet, other, imported] {
        assert_eq!(kc_close(h), KC_OK);
    }
    assert_eq!(read_polkadot_for(wallet, POLKADOT_0, &payload), Err(KC_ERR_HANDLE));
}

#[test]
fn a_polkadot_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let payload = polkadot_bytes(POLKADOT_SMALL);
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = |out: *mut u8, cap: usize, written: *mut usize| unsafe {
        kc_polkadot_read_transaction(wallet, POLKADOT_0.as_ptr(), POLKADOT_0.len(), payload.as_ptr(), payload.len(), out, cap, written)
    };
    let mut needed = 0usize;
    assert_eq!(read(core::ptr::null_mut(), 0, &mut needed), KC_ERR_BUFFER);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = read(short.as_mut_ptr(), short.len(), &mut written);
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- TON (O58) ---------------------------------------------------------------------

const TON_0: &str = "m/44'/607'/0'";

/// [boc] as `kc_ton_read_transfer` reads it for the key at [at] below [handle]: the
/// length first, then the reading.
fn read_ton_for(handle: u64, at: &str, boc: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_ton_read_transfer(handle, at.as_ptr(), at.len(), boc.as_ptr(), boc.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_ton_read_transfer(handle, at.as_ptr(), at.len(), boc.as_ptr(), boc.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [boc] read for the legal phrase's key at [`TON_0`], from a session
/// opened for it alone: for the tests of what a reading says.
fn read_ton(boc: &[u8]) -> Result<serde_json::Value, i32> {
    let reader = open(LEGAL.as_bytes()).unwrap();
    let read = read_ton_for(reader, TON_0, boc);
    assert_eq!(kc_close(reader), KC_OK);
    read
}

/// What `ton_dart`'s `TonSerializationUtils.serializeMessage` writes for a
/// v4R2 wallet of the public key `11…11`, printed by it with `toBoc()` and
/// `hash()`, at `valid_until` 1,793,802,566: one TON to `TON_TO`, at seqno 5;
/// the same with the comment "deposit 12345", bounceable, at 6; with a
/// 400-byte comment at 7; a jetton transfer of 1,000,000 units to `TON_TO`
/// through `TON_JW` with the memo "memo 9" at 8; a STON.fi swap of 5 TON with
/// a fee of 0.0375 TON to `TON_TREASURY` at 9; and a first message, at 0.
const TON_PLAIN: (&str, &str) = ("b5ee9c7241010201004700011c29a9a3176aeb414600000005000101006842002776490dcea6ab506ca33b00b6a4e1359cd8ebc80d3f0a9f33019f8a3504437a21dcd650000000000000000000000000000097d2bead", "c0fddaf2a0857fb719695514998ed359fd5420847cf225fa03ff4ffc244e0940");
const TON_COMMENT: (&str, &str) = ("b5ee9c7241010201005800011c29a9a3176aeb414600000006000101008a62002776490dcea6ab506ca33b00b6a4e1359cd8ebc80d3f0a9f33019f8a3504437a21dcd6500000000000000000000000000000000000006465706f736974203132333435d1f938ee", "b27d1a6fa5493a649b4cab4222627062b09fcaa6528d8da73d6fafb706c6dd78");
const TON_LONG: (&str, &str) = ("b5ee9c72410206010001e700011c29a9a3176aeb414600000007000101016842002776490dcea6ab506ca33b00b6a4e1359cd8ebc80d3f0a9f33019f8a3504437a21dcd65000000000000000000000000000010201fe000000007878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878780301fe787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878780401fe7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787805002e7878787878787878787878787878787878787878787878c61178b5", "1dddc61bd5b4988c57368dc5a7e256232c87e6293b1431ce08d2691596e56d45");
const TON_JETTON: (&str, &str) = ("b5ee9c724101040100ab00011c29a9a3176aeb4146000000080001010168620008a85a8c5931356a8c4cfcc443fc4125b8032a2b22afbff1409f80934cd2030fa017d78400000000000000000000000000010201a80f8a7ea5000000000000000030f42408009dd924373a9aad41b28cec02da9384d67363af2034fc2a7ccc067e28d4110de90020303ab90297a70f8bfae2089014dc1ab72730ac746837480f3f6feb7be9aa818203030014000000006d656d6f2039f21f454b", "5710b745f29241e59aa15cdae1b9ab7ef003796ca012fbe37e156394a9ed9c63");
const TON_SWAP: (&str, &str) = ("b5ee9c724102040100010600021e29a9a3176aeb414600000009000101010301d9620008a85a8c5931356a8c4cfcc443fc4125b8032a2b22afbff1409f80934cd2030fa809a8669200000000000000000000000000000f8a7ea500000000000000005012a05f200800ef3b9902a271b2a01c8938a523cfe24e71847aaeb6a620001ed44a77ac0e709c102c1b8103020095259385618009dd924373a9aad41b28cec02da9384d67363af2034fc2a7ccc067e28d4110de86d9be5d0020303ab90297a70f8bfae2089014dc1ab72730ac746837480f3f6feb7be9aa81900068420041efeaa97ecffa5e9e6258725f058f0e8ec5ec6e6ad2e45be4f9d0f06a5b64512011e1a3000000000000000000000000000056ef3597", "4c90e519dc04b7669c3cfee778969dae32682925fe2fdc5118c79713c2def04e");
const TON_FIRST: (&str, &str) = ("b5ee9c7241010201004500011c29a9a317ffffffff00000000000101006442002776490dcea6ab506ca33b00b6a4e1359cd8ebc80d3f0a9f33019f8a3504437a101f4000000000000000000000000000a9dbdd40", "f8eb2802a42375d08fe7b91d8050a07f34637e7ebea2c9d9c3eda054381cde2e");

const TON_OWNER: &str = "0:80c0eae40a5e9c3e2feb88224053706adc9cc2b1d1a0dd203cfdbfadefa6aa06";
const TON_TO: &str = "0:4eec921b9d4d56a0d94676016d49c26b39b1d7901a7e153e66033f146a0886f4";
const TON_JW: &str = "0:1150b518b2626ad51899f98887f8824b70065456455f7fe2813f012699a4061f";
const TON_ROUTER: &str = "0:779dcc815138d9500e449c5291e7f12738c23d575b5310000f6a253bd607384e";

/// A cell for the tests to write: its bits and its references.
#[derive(Clone, Default)]
struct TonCell {
    bits: Vec<bool>,
    refs: Vec<TonCell>,
}

impl TonCell {
    fn uint(mut self, v: u128, n: usize) -> Self {
        for i in (0..n).rev() {
            self.bits.push(v >> i & 1 == 1);
        }
        self
    }

    fn bit(self, b: bool) -> Self {
        self.uint(u128::from(b), 1)
    }

    fn bytes(mut self, bytes: &[u8]) -> Self {
        for b in bytes {
            self = self.uint(u128::from(*b), 8);
        }
        self
    }

    /// `Coins` in its shortest form, or in [length] bytes.
    fn coins_in(self, v: u128, length: usize) -> Self {
        self.uint(length as u128, 4).uint(v, 8 * length)
    }

    fn coins(self, v: u128) -> Self {
        let length = (128 - v.leading_zeros() as usize).div_ceil(8);
        self.coins_in(v, length)
    }

    fn address(self, raw: &str) -> Self {
        let (workchain, account) = raw.split_once(':').unwrap();
        self.uint(0b10, 2).bit(false).uint(u128::from(workchain.parse::<i8>().unwrap() as u8), 8).bytes(&hex(account))
    }

    fn reference(mut self, cell: TonCell) -> Self {
        self.refs.push(cell);
        self
    }
}

/// [cell]'s descriptors and data, as a bag holds them, its [refs]
/// references counted but not written.
fn ton_cell_bytes(cell: &TonCell, refs: usize) -> Vec<u8> {
    let bits = cell.bits.len();
    let mut out = vec![refs as u8, (bits / 8 + bits.div_ceil(8)) as u8];
    let mut data = vec![0u8; bits.div_ceil(8)];
    for (i, b) in cell.bits.iter().enumerate() {
        if *b {
            data[i / 8] |= 0x80 >> (i % 8);
        }
    }
    if bits % 8 != 0 {
        data[bits / 8] |= 0x80 >> (bits % 8);
    }
    out.extend(data);
    out
}

/// [root] as a bag of cells, as `ton_dart` writes a small one: one-byte
/// references, the shortest offsets, cells in pre-order, a CRC32C.
fn ton_boc(root: &TonCell) -> Vec<u8> {
    fn walk<'a>(cell: &'a TonCell, out: &mut Vec<&'a TonCell>) {
        out.push(cell);
        for child in &cell.refs {
            walk(child, out);
        }
    }
    let mut cells = Vec::new();
    walk(root, &mut cells);
    let mut index = Vec::new();
    let mut next = 0usize;
    fn number(cell: &TonCell, next: &mut usize, index: &mut Vec<usize>) {
        index.push(*next);
        *next += 1;
        for child in &cell.refs {
            number(child, next, index);
        }
    }
    number(root, &mut next, &mut index);
    // Each cell's references by their pre-order numbers.
    fn children(cell: &TonCell, at: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut next = at + 1;
        for child in &cell.refs {
            out.push(next);
            fn size(c: &TonCell) -> usize {
                1 + c.refs.iter().map(size).sum::<usize>()
            }
            next += size(child);
        }
        out
    }
    let mut body = Vec::new();
    for (at, cell) in cells.iter().enumerate() {
        let bits = cell.bits.len();
        body.push(cell.refs.len() as u8);
        body.push((bits / 8 + bits.div_ceil(8)) as u8);
        let mut data = vec![0u8; bits.div_ceil(8)];
        for (i, b) in cell.bits.iter().enumerate() {
            if *b {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        if bits % 8 != 0 {
            data[bits / 8] |= 0x80 >> (bits % 8);
        }
        body.extend_from_slice(&data);
        for child in children(cell, at) {
            body.push(child as u8);
        }
    }
    let offset = if body.len() < 256 { 1 } else { 2 };
    let mut boc = vec![0xb5, 0xee, 0x9c, 0x72, 0x41, offset as u8, cells.len() as u8, 1, 0];
    boc.extend_from_slice(&body.len().to_be_bytes()[8 - offset..]);
    boc.push(0);
    boc.extend_from_slice(&body);
    let sum = crate::ton::crc32c(&boc);
    boc.extend_from_slice(&sum.to_le_bytes());
    boc
}

/// The cell `TonHelper.internal` writes: [value] to [to], [bounce], [body]
/// inline.
fn ton_message(to: &str, value: u128, bounce: bool, body: TonCell) -> TonCell {
    let mut cell = TonCell::default()
        .bit(false)
        .bit(true)
        .bit(bounce)
        .bit(false)
        .uint(0, 2)
        .address(to)
        .coins(value)
        .bit(false)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
        .bit(false)
        .bit(false);
    cell.bits.extend(body.bits);
    cell.refs.extend(body.refs);
    cell
}

/// A v4R2 signing message at seqno [seqno] carrying [messages], mode 1.
fn ton_signing(seqno: u128, messages: Vec<TonCell>) -> TonCell {
    let mut root = TonCell::default().uint(698983191, 32).uint(1793802566, 32).uint(seqno, 32).uint(0, 8);
    for m in messages {
        root = root.uint(1, 8).reference(m);
    }
    root
}

fn ton_comment(text: &str) -> TonCell {
    TonCell::default().uint(0, 32).bytes(text.as_bytes())
}

#[test]
fn a_ton_transfer_is_read_with_its_facts_and_its_hash() {
    let _abi = abi();
    for (what, (boc, hash)) in [
        ("plain", TON_PLAIN),
        ("comment", TON_COMMENT),
        ("long", TON_LONG),
        ("jetton", TON_JETTON),
        ("swap", TON_SWAP),
        ("first", TON_FIRST),
    ] {
        let read = read_ton(&hex(boc)).unwrap_or_else(|code| panic!("{what}: {code}"));
        assert_eq!(read["hash"], format!("0x{hash}"), "{what}: the hash ton_dart takes");
        assert_eq!((read["wallet"].as_str(), read["subwalletId"].as_str()), (Some("v4R2"), Some("698983191")), "{what}");
    }
    let plain = read_ton(&hex(TON_PLAIN.0)).unwrap();
    assert_eq!((plain["validUntil"].as_str(), plain["seqno"].as_str()), (Some("1793802566"), Some("5")));
    let payment = &plain["messages"][0];
    assert_eq!((payment["mode"].as_str(), payment["bounce"].as_bool()), (Some("1"), Some(false)));
    assert_eq!((payment["destination"].as_str(), payment["value"].as_str()), (Some(TON_TO), Some("1000000000")));
    assert_eq!(payment["body"]["kind"], "none");
    let comment = read_ton(&hex(TON_COMMENT.0)).unwrap();
    assert_eq!(comment["messages"][0]["bounce"], true);
    assert_eq!(comment["messages"][0]["body"], serde_json::json!({"kind": "comment", "text": "deposit 12345"}));
    let long = read_ton(&hex(TON_LONG.0)).unwrap();
    assert_eq!(long["messages"][0]["body"]["text"], "x".repeat(400));
    let jetton = read_ton(&hex(TON_JETTON.0)).unwrap();
    let transfer = &jetton["messages"][0];
    assert_eq!((transfer["destination"].as_str(), transfer["value"].as_str()), (Some(TON_JW), Some("50000000")));
    assert_eq!(
        transfer["body"],
        serde_json::json!({
            "kind": "jettonTransfer", "queryId": "0", "amount": "1000000", "destination": TON_TO,
            "responseDestination": TON_OWNER, "forwardTonAmount": "1",
            "forwardPayload": {"kind": "comment", "text": "memo 9"},
        })
    );
    let swap = read_ton(&hex(TON_SWAP.0)).unwrap();
    assert_eq!(swap["messages"].as_array().unwrap().len(), 2);
    assert_eq!(
        swap["messages"][0]["body"],
        serde_json::json!({
            "kind": "jettonTransfer", "queryId": "0", "amount": "5000000000", "destination": TON_ROUTER,
            "responseDestination": null, "forwardTonAmount": "185000000",
            "forwardPayload": {"kind": "stonfiSwap", "askJettonWallet": TON_TO, "minAsk": "7135022", "receiver": TON_OWNER, "referral": null},
        })
    );
    assert_eq!((swap["messages"][1]["value"].as_str(), swap["messages"][1]["bounce"].as_bool()), (Some("37500000"), Some(false)));
    assert_eq!(swap["messages"][1]["body"]["kind"], "none");
    let first = read_ton(&hex(TON_FIRST.0)).unwrap();
    assert_eq!((first["validUntil"].as_str(), first["seqno"].as_str()), (Some("4294967295"), Some("0")));
    // The tests' own writer writes what ton_dart writes.
    let plain_built = ton_signing(5, vec![ton_message(TON_TO, 1_000_000_000, false, TonCell::default())]);
    assert_eq!(to_hex(&ton_boc(&plain_built)), TON_PLAIN.0);
    let comment_built = ton_signing(6, vec![ton_message(TON_TO, 1_000_000_000, true, ton_comment("deposit 12345"))]);
    assert_eq!(to_hex(&ton_boc(&comment_built)), TON_COMMENT.0);
    // A referral, a masterchain address, a body in a cell of its own.
    let swap_body = TonCell::default()
        .uint(0x2593_8561, 32)
        .address(TON_TO)
        .coins(1)
        .address(TON_OWNER)
        .bit(true)
        .address("-1:3333333333333333333333333333333333333333333333333333333333333333");
    let transfer_body = TonCell::default()
        .uint(0x0f8a_7ea5, 32)
        .uint(7, 64)
        .coins(5)
        .address(TON_ROUTER)
        .uint(0, 2)
        .bit(false)
        .coins(9)
        .bit(true)
        .reference(swap_body);
    let mut referred = ton_message(TON_JW, 10, true, TonCell::default());
    *referred.bits.last_mut().unwrap() = true;
    let referred = referred.reference(transfer_body);
    let read = read_ton(&ton_boc(&ton_signing(3, vec![referred]))).unwrap();
    assert_eq!(read["messages"][0]["body"]["queryId"], "7");
    assert_eq!(
        read["messages"][0]["body"]["forwardPayload"]["referral"],
        "-1:3333333333333333333333333333333333333333333333333333333333333333"
    );
}

#[test]
fn what_the_ton_module_never_writes_is_refused() {
    let _abi = abi();
    let pay = |body: TonCell| ton_signing(5, vec![ton_message(TON_TO, 1000, false, body)]);
    let with = |edit: &dyn Fn(&mut TonCell)| {
        let mut m = ton_message(TON_TO, 1000, false, TonCell::default());
        edit(&mut m);
        ton_boc(&ton_signing(5, vec![m]))
    };
    let jetton = |tail: &dyn Fn(TonCell) -> TonCell| {
        let body = TonCell::default().uint(0x0f8a_7ea5, 32).uint(0, 64).coins(5).address(TON_TO).uint(0, 2);
        ton_boc(&pay(tail(body)))
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("another wallet's opcode", ton_boc(&TonCell::default().uint(698983191, 32).uint(1, 32).uint(5, 32).uint(1, 8).uint(1, 8).reference(ton_message(TON_TO, 1, false, TonCell::default())))),
        ("no message", ton_boc(&ton_signing(5, vec![]))),
        ("five messages", ton_boc(&ton_signing(5, vec![ton_message(TON_TO, 1, false, TonCell::default()); 5]))),
        ("a mode missing", {
            let mut root = ton_signing(5, vec![ton_message(TON_TO, 1, false, TonCell::default())]);
            root.bits.truncate(root.bits.len() - 8);
            ton_boc(&root)
        }),
        ("an external message", with(&|m| m.bits[0] = true)),
        ("instant hypercube routing", with(&|m| m.bits[1] = false)),
        ("bounced", with(&|m| m.bits[3] = true)),
        ("a state init", with(&|m| { let n = m.bits.len(); m.bits[n - 2] = true })),
        ("a body in a cell that is not there", with(&|m| { let n = m.bits.len(); m.bits[n - 1] = true })),
        ("an extra currency", with(&|m| m.bits[6 + 267 + 4 + 16] = true)),
        ("from an address", ton_boc(&ton_signing(5, vec![TonCell::default().bit(false).bit(true).bit(false).bit(false).address(TON_OWNER).address(TON_TO).coins(1000).bit(false).coins(0).coins(0).uint(0, 64).uint(0, 32).bit(false).bit(false)]))),
        ("to no address", ton_boc(&ton_signing(5, vec![TonCell::default().bit(false).bit(true).bit(false).bit(false).uint(0, 2).uint(0, 2).coins(1000).bit(false).coins(0).coins(0).uint(0, 64).uint(0, 32).bit(false).bit(false)]))),
        // The destination's anycast flag set, and nothing else changed.
        ("an anycast", with(&|m| m.bits[6 + 2] = true)),
        ("a value with a leading zero", ton_boc(&ton_signing(5, vec![TonCell::default().bit(false).bit(true).bit(false).bit(false).uint(0, 2).address(TON_TO).coins_in(1000, 3).bit(false).coins(0).coins(0).uint(0, 64).uint(0, 32).bit(false).bit(false)]))),
        ("a forward fee", ton_boc(&ton_signing(5, vec![TonCell::default().bit(false).bit(true).bit(false).bit(false).uint(0, 2).address(TON_TO).coins(1000).bit(false).coins(0).coins(1).uint(0, 64).uint(0, 32).bit(false).bit(false)]))),
        ("a logical time", ton_boc(&ton_signing(5, vec![TonCell::default().bit(false).bit(true).bit(false).bit(false).uint(0, 2).address(TON_TO).coins(1000).bit(false).coins(0).coins(0).uint(1, 64).uint(0, 32).bit(false).bit(false)]))),
        ("a body of another kind", ton_boc(&pay(TonCell::default().uint(0x1234_5678, 32)))),
        ("an empty comment", ton_boc(&pay(TonCell::default().uint(0, 32)))),
        ("a comment not in whole bytes", ton_boc(&pay(TonCell::default().uint(0, 32).uint(0, 7)))),
        ("a comment through an empty cell", ton_boc(&pay(ton_comment("ab").reference(TonCell::default())))),
        ("a comment through two cells at once", ton_boc(&pay(ton_comment("ab").reference(TonCell::default().bytes(b"c")).reference(TonCell::default().bytes(b"d"))))),
        ("a comment that is not UTF-8", ton_boc(&pay(TonCell::default().uint(0, 32).bytes(&[0xff])))),
        ("a custom payload", jetton(&|b| b.bit(true).reference(TonCell::default()).coins(1).bit(false))),
        ("a jetton transfer with a bit after", jetton(&|b| b.bit(false).coins(1).bit(false).bit(true))),
        ("a forward payload inline", jetton(&|b| b.bit(false).coins(1).bit(false).uint(0, 32))),
        ("a forward payload of another kind", jetton(&|b| b.bit(false).coins(1).bit(true).reference(TonCell::default().uint(1, 32)))),
        ("a swap with a bit after", jetton(&|b| b.bit(false).coins(1).bit(true).reference(TonCell::default().uint(0x2593_8561, 32).address(TON_TO).coins(1).address(TON_OWNER).bit(false).bit(true)))),
        ("a jetton transfer to no address", ton_boc(&pay(TonCell::default().uint(0x0f8a_7ea5, 32).uint(0, 64).coins(5).uint(0, 2).uint(0, 2).bit(false).coins(1).bit(false)))),
    ];
    // The bag itself: each edited, then its CRC32C written again, so that the
    // checksum is not what refuses it.
    let good = hex(TON_PLAIN.0);
    let mut wrong_sum = good.clone();
    *wrong_sum.last_mut().unwrap() ^= 1;
    cases.push(("a CRC32C wrong", wrong_sum));
    let mut after = good.clone();
    after.push(0);
    cases.push(("a byte after", after));
    cases.push(("cut short", good[..good.len() - 1].to_vec()));
    let mut edited = |what: &'static str, edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = good[..good.len() - 4].to_vec();
        edit(&mut bytes);
        let sum = crate::ton::crc32c(&bytes);
        bytes.extend_from_slice(&sum.to_le_bytes());
        cases.push((what, bytes));
    };
    edited("another magic", &|b| b[0] = 0xb6);
    edited("two roots", &|b| b[7] = 2);
    edited("an absent cell", &|b| b[8] = 1);
    edited("cache bits", &|b| b[4] |= 0x20);
    edited("references of no bytes", &|b| b[4] &= 0xf8);
    edited("a size it does not have", &|b| b[9] += 1);
    edited("another root", &|b| b[10] = 1);
    edited("an exotic cell", &|b| b[11] |= 0x08);
    edited("a level", &|b| b[11] |= 0x20);
    edited("stored hashes", &|b| b[11] |= 0x10);
    edited("a reference to itself", &|b| b[11 + 2 + 14] = 0);
    edited("a reference past the end", &|b| b[11 + 2 + 14] = 2);
    for (why, boc) in &cases {
        assert_eq!(read_ton(boc), Err(KC_ERR_TRANSACTION), "{why}");
    }
    // A cell no one refers to.
    let mut extra = hex(TON_PLAIN.0);
    extra.truncate(extra.len() - 4);
    extra[6] = 3;
    extra[9] += 2;
    extra.extend_from_slice(&[0, 0]);
    let sum = crate::ton::crc32c(&extra);
    extra.extend_from_slice(&sum.to_le_bytes());
    assert_eq!(read_ton(&extra), Err(KC_ERR_TRANSACTION), "a cell not reached");
    // Without a CRC32C, the same reading.
    let mut bare = hex(TON_PLAIN.0);
    bare.truncate(bare.len() - 4);
    bare[4] &= !0x40;
    assert_eq!(read_ton(&bare).unwrap(), read_ton(&hex(TON_PLAIN.0)).unwrap());
    // A reference backwards: the message, last, refers to its empty body,
    // put before it — a bag that reads, but not in the order one is written.
    let message = {
        let mut m = ton_message(TON_TO, 1000, false, TonCell::default());
        *m.bits.last_mut().unwrap() = true;
        m
    };
    let root = ton_signing(5, vec![]).uint(1, 8);
    let mut cells = ton_cell_bytes(&root, 1);
    cells.push(2);
    cells.extend(ton_cell_bytes(&TonCell::default(), 0));
    cells.extend(ton_cell_bytes(&message, 1));
    cells.push(1);
    let mut backwards = vec![0xb5, 0xee, 0x9c, 0x72, 0x41, 1, 3, 1, 0, cells.len() as u8, 0];
    backwards.extend(cells);
    let sum = crate::ton::crc32c(&backwards);
    backwards.extend_from_slice(&sum.to_le_bytes());
    assert_eq!(read_ton(&backwards), Err(KC_ERR_TRANSACTION), "a reference backwards");
    // A completion tag that marks no bit: the root's last byte made 0x80
    // and its length odd.
    let mut tagless = good[..good.len() - 4].to_vec();
    tagless[12] = 0x1d;
    tagless.insert(11 + 2 + 14, 0x80);
    tagless[9] += 1;
    let sum = crate::ton::crc32c(&tagless);
    tagless.extend_from_slice(&sum.to_le_bytes());
    assert_eq!(read_ton(&tagless), Err(KC_ERR_TRANSACTION), "a completion tag of no bit");
}

#[test]
fn a_ton_key_signs_only_a_hash_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = ed_public_key(wallet, TON_0).unwrap();
    // A message of its own, so no other test's reading stands for it.
    let boc = ton_boc(&ton_signing(4242, vec![ton_message(TON_TO, 4242, false, TonCell::default())]));
    // Its hash taken without keeping a reading.
    let (_, hash) = crate::ton::reading(&boc, &key).unwrap();
    assert_eq!(ed_sign(wallet, TON_0, &hash), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe {
        kc_ton_read_transfer(wallet, TON_0.as_ptr(), TON_0.len(), boc.as_ptr(), boc.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(ed_sign(wallet, TON_0, &hash), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_ton_for(wallet, TON_0, &boc).unwrap();
    assert_eq!(ed_sign(wallet, POLKADOT_0, &hash), Err(KC_ERR_UNSHOWN), "a TON reading is not a Polkadot one");
    assert_eq!(ed_sign(wallet, TON_0, &boc), Err(KC_ERR_UNSHOWN), "the bag is not what is signed, its hash is");
    let signature = ed_sign(wallet, TON_0, &hash).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &Ed25519Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(ed_sign(wallet, TON_0, &hash), Err(KC_ERR_UNSHOWN), "signed once");
    read_ton_for(wallet, TON_0, &boc).unwrap();
    for at in ["m/44'/607'/3'", "m/44'/607'"] {
        assert_eq!(ed_sign(wallet, at, &[7; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(ed_sign(wallet, "m/44'/607'/0", &hash), Err(KC_ERR_PATH));
    assert_eq!(ed_sign(wallet, TON_0, &hash).unwrap(), signature, "the reading kept is still there");
    assert!(ed_sign(wallet, ED_0, b"bytes at no network's path").is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_ton_reading_signs_by_the_key_it_was_read_for_alone() {
    // A v4R2 signing message names no wallet: held to the key it was read
    // for (the owner's request of 5 November 2026).
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    let key = ed_public_key(wallet, TON_0).unwrap();
    // A message of its own, so no other test's reading stands for it.
    let boc = ton_boc(&ton_signing(4343, vec![ton_message(TON_TO, 4343, false, TonCell::default())]));
    let (_, hash) = crate::ton::reading(&boc, &key).unwrap();
    let read = read_ton_for(wallet, TON_0, &boc).unwrap();
    assert_eq!(read["publicKey"], format!("0x{}", to_hex(&key)));
    for (why, handle, at) in [("the next account", wallet, "m/44'/607'/1'"), ("another phrase's first", other, TON_0)] {
        assert_eq!(ed_sign(handle, at, &hash), Err(KC_ERR_UNSHOWN), "{why}");
    }
    assert!(ed_sign(wallet, TON_0, &hash).is_ok(), "its own key, the reading kept");
    read_ton_for(other, TON_0, &boc).unwrap();
    assert_eq!(ed_sign(wallet, TON_0, &hash), Err(KC_ERR_UNSHOWN), "another's reading");
    assert!(ed_sign(other, TON_0, &hash).is_ok());
    // Only a phrase's TON key is read for.
    let imported = open_key(KC_CURVE_ED25519, &[0x47; 32]).unwrap();
    assert_eq!(read_ton_for(imported, TON_0, &boc), Err(KC_ERR_KIND));
    assert_eq!(read_ton_for(imported, "m", &boc), Err(KC_ERR_PATH));
    assert_eq!(read_ton_for(wallet, POLKADOT_0, &boc), Err(KC_ERR_PATH));
    // A level not hardened is refused before the session is asked.
    let (refused, holds) = lock_entries(|| read_ton_for(wallet, "m/44'/607'/0", &boc));
    assert_eq!((refused, holds), (Err(KC_ERR_PATH), 0));
    for h in [wallet, other, imported] {
        assert_eq!(kc_close(h), KC_OK);
    }
    assert_eq!(read_ton_for(wallet, TON_0, &boc), Err(KC_ERR_HANDLE));
}

#[test]
fn a_ton_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let boc = hex(TON_SWAP.0);
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = |out: *mut u8, cap: usize, written: *mut usize| unsafe {
        kc_ton_read_transfer(wallet, TON_0.as_ptr(), TON_0.len(), boc.as_ptr(), boc.len(), out, cap, written)
    };
    let mut needed = 0usize;
    assert_eq!(read(core::ptr::null_mut(), 0, &mut needed), KC_ERR_BUFFER);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = read(short.as_mut_ptr(), short.len(), &mut written);
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- Cardano (O58) -----------------------------------------------------------------

/// [paths] in `kc_cardano_read_transaction`'s layout for its signers.
fn cardano_signers(paths: &[&str]) -> Vec<u8> {
    let mut out = (paths.len() as u16).to_le_bytes().to_vec();
    for path in paths {
        out.extend((path.len() as u16).to_le_bytes());
        out.extend(path.as_bytes());
    }
    out
}

/// [body] read below [handle]'s phrase, to be signed by the keys at [paths].
fn read_cardano_as(handle: u64, body: &[u8], paths: &[&str]) -> Result<serde_json::Value, i32> {
    let signers = cardano_signers(paths);
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_cardano_read_transaction(
            handle,
            body.as_ptr(),
            body.len(),
            signers.as_ptr(),
            signers.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_cardano_read_transaction(
            handle,
            body.as_ptr(),
            body.len(),
            signers.as_ptr(),
            signers.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [body] read by a phrase of its own, its one signer the module's first
/// key: for the tests that hold a body's facts, which no key changes.
fn read_cardano(body: &[u8]) -> Result<serde_json::Value, i32> {
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = read_cardano_as(wallet, body, &[CARDANO_0]);
    assert_eq!(kc_close(wallet), KC_OK);
    read
}

/// The payment key hash of [handle]'s Cardano key at [at], hex: BLAKE2b-224
/// of its public key, by the `blake2` crate itself.
fn cardano_key_hash(handle: u64, at: &str) -> String {
    use blake2::Digest as _;
    to_hex(&blake2::Blake2b::<blake2::digest::consts::U28>::digest(cd_public_key(handle, at).unwrap()))
}

/// A CBOR head in its shortest form.
fn cbor(major: u8, value: u64) -> Vec<u8> {
    let m = major << 5;
    match value {
        0..=23 => vec![m | value as u8],
        24..=0xff => vec![m | 24, value as u8],
        0x100..=0xffff => [vec![m | 25], (value as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (value as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], value.to_be_bytes().to_vec()].concat(),
    }
}

fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    [cbor(2, bytes.len() as u64), bytes.to_vec()].concat()
}

/// A body as `on_chain` writes one: the inputs as a set, each output a map
/// of its address and its lovelace, the fee, the time to live.
fn cardano_body(inputs: &[([u8; 32], u64)], outputs: &[(&[u8], u64)], fee: u64, ttl: u64) -> Vec<u8> {
    let mut b = cbor(5, 4);
    b.extend(cbor(0, 0));
    b.extend(cbor(6, 258));
    b.extend(cbor(4, inputs.len() as u64));
    for (id, index) in inputs {
        b.extend(cbor(4, 2));
        b.extend(cbor_bytes(id));
        b.extend(cbor(0, *index));
    }
    b.extend(cbor(0, 1));
    b.extend(cbor(4, outputs.len() as u64));
    for (address, lovelace) in outputs {
        b.extend(cbor(5, 2));
        b.extend(cbor(0, 0));
        b.extend(cbor_bytes(address));
        b.extend(cbor(0, 1));
        b.extend(cbor(0, *lovelace));
    }
    b.extend(cbor(0, 2));
    b.extend(cbor(0, fee));
    b.extend(cbor(0, 3));
    b.extend(cbor(0, ttl));
    b
}

/// What the module's `on_chain` wrote, cut from the transaction it
/// submitted: two ADA from the BIP-39 test phrase's first account to its
/// second, spending one output of ten ADA, the change back; and the whole
/// transaction, whose one witness signs the body's BLAKE2b-256.
const CARDANO_BODY: (&str, &str) = (
    "a400d90102818258200000000000000000000000000000000000000000000000000000000332212781000182a200583901724038f8b030597ed190929f13fea3d557138b48c74cafd30d4b6c42876c29f8c45c3fa7d3af0ea45fb2564ace831f70e7d3d5b8c251739a011a001e8480a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a00776e4b021a0002a3b5031a05f5fd20",
    "81893c529c9b11c1915be6c821def1385941a2b138615e7efc070cfe4db29fdb",
);
const CARDANO_WITNESS: (&str, &str) = (
    "cd2b047d1a803eee059769cffb3dfd0a4b9327e55bc78aa962d9bd4f720db0b2",
    "a627488390978665108c6e4aac7e375bea51da54369d61176fb0331971ae4c981c2152d36551df7ad578f374f3c8858d19f6a2064b185ecb72aad597a33fd90a",
);

#[test]
fn a_cardano_body_is_read_with_its_facts_and_its_hash() {
    let _abi = abi();
    let body = hex(CARDANO_BODY.0);
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let read = read_cardano_as(wallet, &body, &[CARDANO_0, "m/1852'/1815'/0'/1/0"]).unwrap();
    assert_eq!(read["hash"], format!("0x{}", CARDANO_BODY.1));
    // The signers' payment key hashes, in the order named.
    assert_eq!(
        read["witnesses"],
        serde_json::json!([cardano_key_hash(wallet, CARDANO_0), cardano_key_hash(wallet, "m/1852'/1815'/0'/1/0")])
    );
    assert_eq!(kc_close(wallet), KC_OK);
    // The hash read is what the module's witness signed.
    VerifyingKey::from_bytes(&hex(CARDANO_WITNESS.0).try_into().unwrap())
        .unwrap()
        .verify_strict(&hex(CARDANO_BODY.1), &Ed25519Signature::from_bytes(&hex(CARDANO_WITNESS.1).try_into().unwrap()))
        .unwrap();
    assert_eq!(
        read["inputs"],
        serde_json::json!([{"txId": "0000000000000000000000000000000000000000000000000000000332212781", "index": "0"}])
    );
    assert_eq!(read["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(read["outputs"][0]["address"].as_str().unwrap().len(), 114);
    assert_eq!((read["outputs"][0]["lovelace"].as_str(), read["outputs"][1]["lovelace"].as_str()), (Some("2000000"), Some("7827019")));
    assert_eq!((read["fee"].as_str(), read["ttl"].as_str()), (Some("172981"), Some("100007200")));
    // The tests' own writer writes what on_chain writes.
    let recipient = hex("01724038f8b030597ed190929f13fea3d557138b48c74cafd30d4b6c42876c29f8c45c3fa7d3af0ea45fb2564ace831f70e7d3d5b8c251739a");
    let change = hex("0114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c");
    let id: [u8; 32] = hex("0000000000000000000000000000000000000000000000000000000332212781").try_into().unwrap();
    assert_eq!(
        to_hex(&cardano_body(&[(id, 0)], &[(&recipient, 2_000_000), (&change, 7_827_019)], 172_981, 100_007_200)),
        CARDANO_BODY.0
    );
    // Many inputs, a big amount, an eight-byte number.
    let many: Vec<([u8; 32], u64)> = (0..30).map(|i| ([i as u8; 32], i)).collect();
    let read = read_cardano(&cardano_body(&many, &[(&recipient, u64::MAX)], 0, 0)).unwrap();
    assert_eq!(read["inputs"].as_array().unwrap().len(), 30);
    assert_eq!(read["outputs"][0]["lovelace"], u64::MAX.to_string());
}

#[test]
fn what_the_cardano_module_never_writes_is_refused() {
    let _abi = abi();
    let address: &[u8] = &[0x61; 29];
    let good = cardano_body(&[([1; 32], 0)], &[(address, 1_000_000)], 170_000, 1_000);
    assert!(read_cardano(&good).is_ok());
    let tail = |b: &mut Vec<u8>| {
        // The fee and the time to live, as `good` ends.
        b.extend(cbor(0, 2));
        b.extend(cbor(0, 170_000));
        b.extend(cbor(0, 3));
        b.extend(cbor(0, 1_000));
    };
    let inputs = |b: &mut Vec<u8>| {
        b.extend(cbor(0, 0));
        b.extend(cbor(6, 258));
        b.extend(cbor(4, 1));
        b.extend(cbor(4, 2));
        b.extend(cbor_bytes(&[1; 32]));
        b.extend(cbor(0, 0));
    };
    let outputs = |b: &mut Vec<u8>| {
        b.extend(cbor(0, 1));
        b.extend(cbor(4, 1));
        b.extend(cbor(5, 2));
        b.extend(cbor(0, 0));
        b.extend(cbor_bytes(address));
        b.extend(cbor(0, 1));
        b.extend(cbor(0, 1_000_000));
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![];
    // Another key: a certificate (4) after the time to live.
    let mut b = cbor(5, 5);
    inputs(&mut b);
    outputs(&mut b);
    tail(&mut b);
    b.extend(cbor(0, 4));
    b.extend(cbor(4, 0));
    cases.push(("a certificate", b));
    // No time to live.
    let mut b = cbor(5, 3);
    inputs(&mut b);
    outputs(&mut b);
    b.extend(cbor(0, 2));
    b.extend(cbor(0, 170_000));
    cases.push(("no time to live", b));
    // The inputs as a bare array.
    let mut b = cbor(5, 4);
    b.extend(cbor(0, 0));
    b.extend(cbor(4, 1));
    b.extend(cbor(4, 2));
    b.extend(cbor_bytes(&[1; 32]));
    b.extend(cbor(0, 0));
    outputs(&mut b);
    tail(&mut b);
    cases.push(("inputs not a set", b));
    cases.push(("no input", cardano_body(&[], &[(address, 1)], 1, 1)));
    cases.push(("an input twice", cardano_body(&[([1; 32], 0), ([1; 32], 0)], &[(address, 1)], 1, 1)));
    // An input id of 31 bytes.
    let mut b = cbor(5, 4);
    b.extend(cbor(0, 0));
    b.extend(cbor(6, 258));
    b.extend(cbor(4, 1));
    b.extend(cbor(4, 2));
    b.extend(cbor_bytes(&[1; 31]));
    b.extend(cbor(0, 0));
    outputs(&mut b);
    tail(&mut b);
    cases.push(("an id of 31 bytes", b));
    // An output in the old array form.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    b.extend(cbor(0, 1));
    b.extend(cbor(4, 1));
    b.extend(cbor(4, 2));
    b.extend(cbor_bytes(address));
    b.extend(cbor(0, 1_000_000));
    tail(&mut b);
    cases.push(("an output as an array", b));
    // A native asset beside the lovelace.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    b.extend(cbor(0, 1));
    b.extend(cbor(4, 1));
    b.extend(cbor(5, 2));
    b.extend(cbor(0, 0));
    b.extend(cbor_bytes(address));
    b.extend(cbor(0, 1));
    b.extend(cbor(4, 2));
    b.extend(cbor(0, 1_000_000));
    b.extend(cbor(5, 0));
    tail(&mut b);
    cases.push(("a native asset", b));
    // A datum.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    b.extend(cbor(0, 1));
    b.extend(cbor(4, 1));
    b.extend(cbor(5, 3));
    b.extend(cbor(0, 0));
    b.extend(cbor_bytes(address));
    b.extend(cbor(0, 1));
    b.extend(cbor(0, 1_000_000));
    b.extend(cbor(0, 2));
    b.extend(cbor(4, 2));
    b.extend(cbor(0, 0));
    b.extend(cbor_bytes(&[2; 32]));
    tail(&mut b);
    cases.push(("a datum", b));
    // The fee written longer than it needs: 0x1a for a number that fits 0x19.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    outputs(&mut b);
    b.extend(cbor(0, 2));
    b.extend([0x1a, 0, 0, 0x01, 0x00]);
    b.extend(cbor(0, 3));
    b.extend(cbor(0, 1_000));
    cases.push(("a fee not in its shortest form", b));
    // An indefinite array of outputs.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    b.extend(cbor(0, 1));
    b.push(0x9f);
    b.extend(cbor(5, 2));
    b.extend(cbor(0, 0));
    b.extend(cbor_bytes(address));
    b.extend(cbor(0, 1));
    b.extend(cbor(0, 1_000_000));
    b.push(0xff);
    tail(&mut b);
    cases.push(("an indefinite array", b));
    // The time to live before the fee.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    outputs(&mut b);
    b.extend(cbor(0, 3));
    b.extend(cbor(0, 1_000));
    b.extend(cbor(0, 2));
    b.extend(cbor(0, 170_000));
    cases.push(("keys out of order", b));
    cases.push(("an empty address", cardano_body(&[([1; 32], 0)], &[(&[], 1)], 1, 1)));
    // A body claiming five entries and holding four.
    let mut five = good.clone();
    five[0] = 0xa5;
    cases.push(("a map claiming an entry it does not hold", five));
    // The inputs under another tag than the set's.
    let mut b = cbor(5, 4);
    b.extend(cbor(0, 0));
    b.extend(cbor(6, 259));
    b.extend(cbor(4, 1));
    b.extend(cbor(4, 2));
    b.extend(cbor_bytes(&[1; 32]));
    b.extend(cbor(0, 0));
    outputs(&mut b);
    tail(&mut b);
    cases.push(("inputs under another tag", b));
    // An output claiming three entries and holding two.
    let mut b = cbor(5, 4);
    inputs(&mut b);
    b.extend(cbor(0, 1));
    b.extend(cbor(4, 1));
    b.extend(cbor(5, 3));
    b.extend(cbor(0, 0));
    b.extend(cbor_bytes(address));
    b.extend(cbor(0, 1));
    b.extend(cbor(0, 1_000_000));
    tail(&mut b);
    cases.push(("an output claiming an entry it does not hold", b));
    let mut after = good.clone();
    after.push(0);
    cases.push(("a byte after", after));
    cases.push(("cut short", good[..good.len() - 1].to_vec()));
    cases.push(("a whole transaction, not its body", [vec![0x84], good.clone(), vec![0xa0, 0xf5, 0xf6]].concat()));
    for (why, body) in &cases {
        assert_eq!(read_cardano(body), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_cardano_key_signs_only_a_body_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    // A body of its own, spending from two addresses, so no other test's
    // reading stands for it: a witness for each of two keys.
    let body = cardano_body(&[([0x53; 32], 0), ([0x54; 32], 1)], &[(&[0x61; 29], 3_000_000)], 175_000, 4242);
    let (_, hash) = crate::cardano::reading(&body).unwrap();
    let role_0 = "m/1852'/1815'/0'/0/0";
    let role_1 = "m/1852'/1815'/0'/1/0";
    assert_eq!(cd_sign(wallet, role_0, &hash), Err(KC_ERR_UNSHOWN), "never read");
    let signers = cardano_signers(&[role_0, role_1]);
    let mut needed = 0usize;
    unsafe {
        kc_cardano_read_transaction(
            wallet,
            body.as_ptr(),
            body.len(),
            signers.as_ptr(),
            signers.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    assert_eq!(cd_sign(wallet, role_0, &hash), Err(KC_ERR_UNSHOWN), "only its length asked");
    // **One reading, a signature for each key it names, each once.**
    let read = read_cardano_as(wallet, &body, &[role_0, role_1]).unwrap();
    assert_eq!(read["witnesses"], serde_json::json!([cardano_key_hash(wallet, role_0), cardano_key_hash(wallet, role_1)]));
    assert_eq!(cd_sign(wallet, role_0, &body), Err(KC_ERR_UNSHOWN), "the body is not what is signed, its hash is");
    assert_eq!(ed_sign(wallet, TON_0, &hash), Err(KC_ERR_UNSHOWN), "a Cardano reading is not a TON one");
    let first = cd_sign(wallet, role_0, &hash).unwrap();
    VerifyingKey::from_bytes(&cd_public_key(wallet, role_0).unwrap())
        .unwrap()
        .verify_strict(&hash, &Ed25519Signature::from_bytes(&first))
        .unwrap();
    assert_eq!(cd_sign(wallet, role_0, &hash), Err(KC_ERR_UNSHOWN), "a key once");
    let second = cd_sign(wallet, role_1, &hash).unwrap();
    VerifyingKey::from_bytes(&cd_public_key(wallet, role_1).unwrap())
        .unwrap()
        .verify_strict(&hash, &Ed25519Signature::from_bytes(&second))
        .unwrap();
    assert_eq!(cd_sign(wallet, role_1, &hash), Err(KC_ERR_UNSHOWN), "both used");
    // A key the reading did not name signs nothing of it.
    read_cardano_as(wallet, &body, &[role_0]).unwrap();
    assert_eq!(cd_sign(wallet, role_1, &hash), Err(KC_ERR_UNSHOWN), "a key not named");
    assert_eq!(cd_sign(wallet, role_0, &hash).unwrap(), first);
    // **A key named twice is refused at the reading, and nothing is kept**
    // (the owner's decision of 5 November 2026). A path is spelt one way
    // only, as the wallet writes it, so one key has one name.
    assert_eq!(read_cardano_as(wallet, &body, &[role_0, role_1, role_0]), Err(KC_ERR_TRANSACTION), "a key twice");
    assert_eq!(read_cardano_as(wallet, &body, &[role_0, "m/1852h/1815h/0h/0/0"]), Err(KC_ERR_PATH), "another spelling");
    assert_eq!(cd_sign(wallet, role_0, &hash), Err(KC_ERR_UNSHOWN), "nothing kept by a refused reading");
    assert_eq!(cd_sign(wallet, role_1, &hash), Err(KC_ERR_UNSHOWN), "nothing kept by a refused reading");
    // No signer, a layout that does not read, a key that is not Cardano's.
    for (why, signers, code) in [
        ("none", 0u16.to_le_bytes().to_vec(), KC_ERR_ARGUMENT),
        ("a byte after", [cardano_signers(&[role_0]), vec![0]].concat(), KC_ERR_ARGUMENT),
        ("cut short", cardano_signers(&[role_0])[..5].to_vec(), KC_ERR_ARGUMENT),
        ("an EVM key", cardano_signers(&[EVM_0]), KC_ERR_PATH),
        ("not a path", cardano_signers(&["m/1852'/x"]), KC_ERR_PATH),
    ] {
        let mut needed = 0usize;
        let got = unsafe {
            kc_cardano_read_transaction(
                wallet,
                body.as_ptr(),
                body.len(),
                signers.as_ptr(),
                signers.len(),
                core::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        assert_eq!(got, code, "{why}");
    }
    // Two readings asked together keep two signatures of a key, not one.
    read_cardano_as(wallet, &body, &[role_1]).unwrap();
    read_cardano_as(wallet, &body, &[role_1]).unwrap();
    assert_eq!(cd_sign(wallet, role_1, &hash).unwrap(), second);
    assert_eq!(cd_sign(wallet, role_1, &hash).unwrap(), second);
    assert_eq!(cd_sign(wallet, role_1, &hash), Err(KC_ERR_UNSHOWN), "two readings, two signatures");
    for at in ["m/1852'/1815'/3'/0/0", "m/1852'/1815'", "m/1852'/1815'/0'/2/0"] {
        assert_eq!(cd_sign(wallet, at, &[7; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert!(cd_sign(wallet, CARDANO_FREE, b"bytes at no module's path").is_ok());
    // A reading asks the session for its keys: a closed one, or a key's, reads
    // nothing.
    let key = open_key(KC_CURVE_ED25519, &[1u8; 32]).unwrap();
    assert_eq!(read_cardano_as(key, &body, &[role_0]), Err(KC_ERR_KIND));
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(read_cardano_as(wallet, &body, &[role_0]), Err(KC_ERR_HANDLE));
}

#[test]
fn a_cardano_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let body = hex(CARDANO_BODY.0);
    let signers = cardano_signers(&[CARDANO_0]);
    let read = |out: *mut u8, cap: usize, length: *mut usize| unsafe {
        kc_cardano_read_transaction(wallet, body.as_ptr(), body.len(), signers.as_ptr(), signers.len(), out, cap, length)
    };
    let mut needed = 0usize;
    assert_eq!(read(core::ptr::null_mut(), 0, &mut needed), KC_ERR_BUFFER);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    assert_eq!((read(short.as_mut_ptr(), short.len(), &mut written), written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- Filecoin (O58) ----------------------------------------------------------------

const FILECOIN_0: &str = "m/44'/461'/0'/0/0";

fn read_filecoin(message: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// What the module's `FilecoinMessage` writes, printed by it with its CID
/// and signing digest: one FIL from `f1abjx…` to `f1ys5q…` at nonce 7, a gas
/// limit of 1,500,000, a cap of 150,000 and a premium of 100,000 attoFIL;
/// and one attoFIL at nonce 0, a premium of zero.
const FILECOIN_ONE: (&str, &str, &str) = (
    "8a005501c4bb08204821c4c5ee4fffb9860438995bb83811550100537285faff2ef1c04fa030ab28a1e6dcc4ba600749000de0b6b3a76400001a0016e36044000249f044000186a00040",
    "0171a0e40220ed1cfdfa2ba28ae7e24616d29f937834b61bd776639704c369039b9655a7121a",
    "aab1ba023508810afe86150ef62ceed68bdba7bca5b96f1021434811f8fea359",
);
const FILECOIN_SMALL: (&str, &str, &str) = (
    "8a005501c4bb08204821c4c5ee4fffb9860438995bb83811550100537285faff2ef1c04fa030ab28a1e6dcc4ba60004200011a000927c0420064400040",
    "0171a0e4022018185f416723270697e99109db7b2710113c21d1d6d0cd30861636e150dacd29",
    "3e68ccb5a71f794e64b34da806f4da68a6bdbae723672d29f3bf5757e7a79454",
);
const FIL_TO: &str = "f1ys5qqiciehcml3sp764ymbbytfn3qoar5fo3iwy";
const FIL_FROM: &str = "f1abjxfbp274xpdqcpuaykwkfb43omjotacm2p3za";

/// A message as the module writes one, every field given.
#[allow(clippy::too_many_arguments)]
fn filecoin_message(
    version: u64,
    to: &[u8],
    from: &[u8],
    nonce: u64,
    value: &[u8],
    gas_limit: Vec<u8>,
    fee_cap: &[u8],
    premium: &[u8],
    method: u64,
    params: &[u8],
) -> Vec<u8> {
    let mut b = cbor(4, 10);
    b.extend(cbor(0, version));
    b.extend(cbor_bytes(to));
    b.extend(cbor_bytes(from));
    b.extend(cbor(0, nonce));
    b.extend(cbor_bytes(value));
    b.extend(gas_limit);
    b.extend(cbor_bytes(fee_cap));
    b.extend(cbor_bytes(premium));
    b.extend(cbor(0, method));
    b.extend(cbor_bytes(params));
    b
}

#[test]
fn a_filecoin_message_is_read_with_its_facts_and_its_digest() {
    let _abi = abi();
    let one = read_filecoin(&hex(FILECOIN_ONE.0)).unwrap();
    assert_eq!((one["to"].as_str(), one["from"].as_str()), (Some(FIL_TO), Some(FIL_FROM)));
    assert_eq!((one["nonce"].as_str(), one["value"].as_str()), (Some("7"), Some("1000000000000000000")));
    assert_eq!(
        (one["gasLimit"].as_str(), one["gasFeeCap"].as_str(), one["gasPremium"].as_str()),
        (Some("1500000"), Some("150000"), Some("100000"))
    );
    assert_eq!(one["cid"], "bafy2bzacedwrz7p2forivz7ciylnfh4tpa2lmg6xozrzobgdnebzxfsvu4jbu");
    assert_eq!(one["hash"], format!("0x{}", FILECOIN_ONE.2));
    let small = read_filecoin(&hex(FILECOIN_SMALL.0)).unwrap();
    assert_eq!((small["value"].as_str(), small["gasPremium"].as_str()), (Some("1"), Some("0")));
    assert_eq!(small["cid"], "bafy2bzaceambqx2bm4rsobux5giqtw33e4ibcpbb2hlnbtjqqyldnykq3lgss");
    assert_eq!(small["hash"], format!("0x{}", FILECOIN_SMALL.2));
    // The tests' own writer writes what the module writes.
    let to = hex("01c4bb08204821c4c5ee4fffb9860438995bb83811");
    let from = hex("0100537285faff2ef1c04fa030ab28a1e6dcc4ba60");
    let built = filecoin_message(0, &to, &from, 0, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[], 0, &[]);
    assert_eq!(to_hex(&built), FILECOIN_SMALL.0);
    // The most a u128 holds, and the largest gas limit.
    let most = filecoin_message(0, &to, &from, u64::MAX, &[[0u8].as_slice(), &[0xff; 16]].concat(), cbor(0, i64::MAX as u64), &[0, 1], &[0, 1], 0, &[]);
    let read = read_filecoin(&most).unwrap();
    assert_eq!(read["value"], u128::MAX.to_string());
    assert_eq!(read["nonce"], u64::MAX.to_string());
}

#[test]
fn what_the_filecoin_module_never_writes_is_refused() {
    let _abi = abi();
    let to = hex("01c4bb08204821c4c5ee4fffb9860438995bb83811");
    let from = hex("0100537285faff2ef1c04fa030ab28a1e6dcc4ba60");
    let good = filecoin_message(0, &to, &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[]);
    assert!(read_filecoin(&good).is_ok());
    let mut f3 = vec![3u8];
    f3.extend([0x11; 48]);
    let mut after = good.clone();
    after.push(0);
    let mut eleven = good.clone();
    eleven[0] = 0x8b;
    for (why, message) in [
        ("an empty message", Vec::new()),
        ("version 1", filecoin_message(1, &to, &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("a method call", filecoin_message(0, &to, &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 2, &[])),
        ("parameters", filecoin_message(0, &to, &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[0x80])),
        ("to an f3 address", filecoin_message(0, &f3, &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("to an f0 address", filecoin_message(0, &[0, 0x81, 0x08], &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("from an f2 address", filecoin_message(0, &to, &[[2u8].as_slice(), &[0x22; 20]].concat(), 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("an address cut short", filecoin_message(0, &to[..20], &from, 3, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("a negative value", filecoin_message(0, &to, &from, 3, &[1, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("a value with a leading zero", filecoin_message(0, &to, &from, 3, &[0, 0, 1], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("zero as a sign alone", filecoin_message(0, &to, &from, 3, &[0], cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("a value past 128 bits", filecoin_message(0, &to, &from, 3, &[[0u8].as_slice(), &[1; 17]].concat(), cbor(0, 600_000), &[0, 0x64], &[0, 1], 0, &[])),
        ("a gas limit not in its shortest form", filecoin_message(0, &to, &from, 3, &[0, 1], vec![0x1a, 0, 0, 0, 0x10], &[0, 0x64], &[0, 1], 0, &[])),
        ("a gas limit past 63 bits", filecoin_message(0, &to, &from, 3, &[0, 1], cbor(0, 1 << 63), &[0, 0x64], &[0, 1], 0, &[])),
        ("a negative gas limit", filecoin_message(0, &to, &from, 3, &[0, 1], cbor(1, 5), &[0, 0x64], &[0, 1], 0, &[])),
        ("eleven elements", eleven),
        ("a byte after", after),
        ("cut short", good[..good.len() - 1].to_vec()),
    ] {
        assert_eq!(read_filecoin(&message), Err(KC_ERR_TRANSACTION), "{why}");
    }
}

#[test]
fn a_filecoin_key_signs_only_the_digest_of_a_message_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let to = hex("01c4bb08204821c4c5ee4fffb9860438995bb83811");
    let from = hex("0100537285faff2ef1c04fa030ab28a1e6dcc4ba60");
    // A message of its own, so no other test's reading stands for it.
    let message = filecoin_message(0, &to, &from, 4242, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[], 0, &[]);
    let (_, digest) = crate::filecoin::reading(&message).unwrap();
    assert_eq!(sign(wallet, FILECOIN_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(sign(wallet, FILECOIN_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_filecoin(&message).unwrap();
    assert_eq!(sign(wallet, TRON_0, &digest), Err(KC_ERR_UNSHOWN), "a Filecoin reading is not a TRON one");
    let signature = sign(wallet, FILECOIN_0, &digest).unwrap();
    let public = PublicKey::from_slice(&public_key(wallet, FILECOIN_0, KC_PUBLIC_KEY_COMPRESSED).unwrap()).unwrap();
    let recovered = RecoverableSignature::from_compact(&signature[..64], RecoveryId::try_from(i32::from(signature[64])).unwrap())
        .unwrap()
        .recover(Message::from_digest(digest))
        .unwrap();
    assert_eq!(recovered, public, "recoverable, as Filecoin needs");
    assert_eq!(sign(wallet, FILECOIN_0, &digest), Err(KC_ERR_UNSHOWN), "signed once");
    for at in ["m/44'/461'/3'/0/0", "m/44'/461'"] {
        assert_eq!(sign(wallet, at, &[7; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    // No other kind of signature by a Filecoin key.
    assert_eq!(sign_low_r(wallet, FILECOIN_0, &[3u8; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(wallet, FILECOIN_0, &[3u8; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(wallet, FILECOIN_0, b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    // An imported Filecoin key, opened as one, the same; a refused signature
    // gives its reading back.
    let secret = export(wallet, FILECOIN_0).unwrap();
    let key = open_key(KC_CURVE_SECP256K1_FILECOIN, &secret).unwrap();
    assert_eq!(public_key(key, "m", KC_PUBLIC_KEY_COMPRESSED).unwrap(), public.serialize().to_vec());
    assert_eq!(sign(key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_filecoin(&message).unwrap();
    assert_eq!(sign(key, "m/0", &digest), Err(KC_ERR_PATH));
    assert_eq!(sign(key, "m", &digest).unwrap(), signature, "kept after a refusal, as the phrase's key signs");
    assert_eq!(sign(key, "m", &digest), Err(KC_ERR_UNSHOWN), "signed once");
    assert_eq!(sign_low_r(key, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(key, "m", b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(key, "m").unwrap(), secret);
    assert_eq!(open_key(KC_CURVE_SECP256K1_FILECOIN, &[0u8; 32]), Err(KC_ERR_KEY));
    // A key opened as plain secp256k1 is not gated.
    let plain = open_key(KC_CURVE_SECP256K1, &[0x42; 32]).unwrap();
    assert!(sign(plain, "m", &[9; 32]).is_ok());
    for handle in [key, plain, wallet] {
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn a_filecoin_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let message = hex(FILECOIN_ONE.0);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_filecoin_read_message(message.as_ptr(), message.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- One hold of the lock -----------------------------------------------------

/// How many times [call] enters the table's lock on this thread.
fn lock_entries<T>(call: impl FnOnce() -> T) -> (T, u32) {
    LOCK_ENTRIES.with(|n| n.set(0));
    let out = call();
    (out, LOCK_ENTRIES.with(|n| n.get()))
}

#[test]
fn each_signature_holds_the_sessions_lock_once() {
    // **A gate decided in one hold and a signature made in another** let a
    // close come between them, refusing a call that had already reached the
    // key — found on 4 November 2026 by
    // `a_close_waits_for_every_call_that_is_using_the_seed`, which caught the
    // race now and then; this counts the holds, every time.
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let to = hex("01c4bb08204821c4c5ee4fffb9860438995bb83811");
    let from = hex("0100537285faff2ef1c04fa030ab28a1e6dcc4ba60");
    let filecoin = filecoin_message(0, &to, &from, 8181, &[0, 1], cbor(0, 600_000), &[0, 0x64], &[], 0, &[]);
    let (_, filecoin_digest) = crate::filecoin::reading(&filecoin).unwrap();
    let body = cardano_body(&[([0x58; 32], 0)], &[(&[0x61; 29], 1_000_000)], 170_000, 8181);
    let (_, body_hash) = crate::cardano::reading(&body).unwrap();
    let ton = ton_boc(&ton_signing(8181, vec![ton_message(TON_TO, 8181, false, TonCell::default())]));
    let (_, ton_hash) = crate::ton::reading(&ton, &[0; 32]).unwrap();
    for (name, signed, call) in [
        ("an ed25519 signature at no network's path", true, Box::new(|| ed_sign(wallet, ED_0, b"once").is_ok()) as Box<dyn Fn() -> bool>),
        ("a TON key's, unshown", false, Box::new(|| ed_sign(wallet, TON_0, &ton_hash).is_ok())),
        ("a digest at no network's path", true, Box::new(|| sign(wallet, DIGEST_0, &[3u8; 32]).is_ok())),
        ("a Filecoin key's, unshown", false, Box::new(|| sign(wallet, FILECOIN_0, &filecoin_digest).is_ok())),
        ("a Filecoin key's, read", true, Box::new(|| {
            read_filecoin(&filecoin).unwrap();
            sign(wallet, FILECOIN_0, &filecoin_digest).is_ok()
        })),
        ("a Bitcoin key's digest, refused", false, Box::new(|| sign(wallet, "m/84'/0'/0'/0/0", &[3u8; 32]).is_ok())),
        ("a Cardano signature at no module's path", true, Box::new(|| cd_sign(wallet, CARDANO_FREE, b"once").is_ok())),
        ("a Cardano key's, unshown", false, Box::new(|| cd_sign(wallet, CARDANO_0, &body_hash).is_ok())),
    ] {
        let (made, holds) = lock_entries(call);
        assert_eq!(made, signed, "{name}");
        assert_eq!(holds, 1, "{name}: held the lock {holds} times");
    }
    // A TON key's, read: its reading holds the lock itself, once, to take
    // the key it is for, so it is counted apart.
    let mut out = vec![0u8; 4096];
    let mut written = 0usize;
    let (code, holds) = lock_entries(|| unsafe {
        kc_ton_read_transfer(wallet, TON_0.as_ptr(), TON_0.len(), ton.as_ptr(), ton.len(), out.as_mut_ptr(), out.len(), &mut written)
    });
    assert_eq!((code, holds), (KC_OK, 1), "a TON reading");
    let (made, holds) = lock_entries(|| ed_sign(wallet, TON_0, &ton_hash).is_ok());
    assert_eq!((made, holds), (true, 1), "a TON key's, read");
    // A Cardano key's, read: its reading holds the lock itself now, once, to
    // name its signers, so it is counted apart.
    let signers = cardano_signers(&[CARDANO_0]);
    let mut out = vec![0u8; 4096];
    let mut written = 0usize;
    let (code, holds) = lock_entries(|| unsafe {
        kc_cardano_read_transaction(
            wallet,
            body.as_ptr(),
            body.len(),
            signers.as_ptr(),
            signers.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    });
    assert_eq!((code, holds), (KC_OK, 1), "a Cardano reading");
    let (made, holds) = lock_entries(|| cd_sign(wallet, CARDANO_0, &body_hash).is_ok());
    assert_eq!((made, holds), (true, 1), "a Cardano key's, read");
    // A Kaspa send, unshown and read: its reading holds the lock itself, so
    // it is read before the signature is counted. A send of its own, so no
    // other test's reading stands for it.
    let send = kaspa_request(
        KASPA_0,
        0,
        &[kaspa_in(0x88, 8, 8181)],
        &[(1_000, 0, kaspa_script(&[0x22; 32]))],
        0,
        [0; 20],
        0,
        7181,
    );
    let other = open(ABANDON.as_bytes()).unwrap();
    let (made, holds) = lock_entries(|| kaspa_sign(other, &send).is_ok());
    assert_eq!((made, holds), (false, 1), "a Kaspa send, unshown");
    read_kaspa(other, &send).unwrap();
    let (made, holds) = lock_entries(|| kaspa_sign(other, &send).is_ok());
    assert_eq!((made, holds), (true, 1), "a Kaspa send, read");
    // A Starknet key's, unshown and read.
    let starknet = starknet_edited(STARKNET_INVOKE.0, |o| { o.insert("nonce".into(), "0x51".into()); });
    let (_, holds) = lock_entries(|| read_starknet(wallet, STARKNET_0, &starknet).unwrap());
    assert_eq!(holds, 2, "a Starknet reading: its length, then itself");
    let hash: [u8; 32] = {
        let read = read_starknet(wallet, STARKNET_0, &starknet).unwrap();
        hex(&read["hash"].as_str().unwrap()[2..]).try_into().unwrap()
    };
    let (made, holds) = lock_entries(|| sk_sign(wallet, STARKNET_0, &hash).is_ok());
    assert_eq!((made, holds), (true, 1), "a Starknet key's, read");
    let (made, holds) = lock_entries(|| sk_sign(wallet, STARKNET_0, &hash).is_ok());
    assert_eq!((made, holds), (false, 1), "a Starknet key's, unshown");
    assert_eq!(kc_close(other), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- ICP (O58) --------------------------------------------------------------------

const ICP_0: &str = "m/44'/223'/0'/0/0";

fn read_icp(content: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe { kc_icp_read_call(content.as_ptr(), content.len(), core::ptr::null_mut(), 0, &mut needed) };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe { kc_icp_read_call(content.as_ptr(), content.len(), out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// What the module's `IcRequest.contentCbor` writes, printed by it with its
/// request id and signing digest: one ICP to the account `80459651 22…22`,
/// memo 1,700,000,000,000, created at 1.7e18 ns, expiring four minutes on;
/// and one e8 to `805f668d 33…33`, the largest memo, at 1.8e18 ns.
const ICP_ONE: (&str, &str, &str) = ("a66c726571756573745f747970656463616c6c6b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d65687472616e736665726361726758824449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca80d01010520804596512222222222222222222222222222222222222222222222222222222210270000000000000068e5cf8b010000000100002a36fe9c971700e1f505000000006673656e646572581df1faf000dcb4a48342b3babf4c1685e5c5984f979a8a2e0ddc124912026e696e67726573735f6578706972791b17979d3617476000", "50deafe62c63f261c600203c91cc96d0331adbb91cfaa058e9bcf04b5a1bad5a", "d37e71ef3ad17acb3eab159726d4af97784e29299d32ff6da969de366b150016");
const ICP_SMALL: (&str, &str, &str) = ("a66c726571756573745f747970656463616c6c6b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d65687472616e736665726361726758824449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca80d01010520805f668d333333333333333333333333333333333333333333333333333333331027000000000000ffffffffffffffff00010000b49376e2fa1801000000000000006673656e646572581df1faf000dcb4a48342b3babf4c1685e5c5984f979a8a2e0ddc124912026e696e67726573735f6578706972791b18fae2ae74d16000", "3b7193caeab56808a1218ae92d1c8d8b7379c7f05df75989816a587e0b00dbf3", "5bfdea928a179d6e4fc50aad91d2e45edc0d744d1a657803b552846770b1f51c");
const ICP_SENDER: &str = "f1faf000dcb4a48342b3babf4c1685e5c5984f979a8a2e0ddc12491202";
/// `DIDL` and `TransferArgs`' type table, as the module writes them.
const ICP_TYPES: &str = "4449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca80d010105";

/// A `transfer` argument: the type table, then the values in field-hash
/// order — to, fee, memo, from_subaccount, created_at_time, amount.
fn icp_arg(to: &[u8], fee: u64, memo: u64, subaccount: Option<&[u8]>, created: Option<u64>, amount: u64) -> Vec<u8> {
    let mut a = hex(ICP_TYPES);
    a.push(to.len() as u8);
    a.extend(to);
    a.extend(fee.to_le_bytes());
    a.extend(memo.to_le_bytes());
    match subaccount {
        None => a.push(0),
        Some(s) => {
            a.push(1);
            a.push(s.len() as u8);
            a.extend(s);
        }
    }
    match created {
        None => a.push(0),
        Some(c) => {
            a.push(1);
            a.extend(c.to_le_bytes());
        }
    }
    a.extend(amount.to_le_bytes());
    a
}

fn cbor_text(text: &str) -> Vec<u8> {
    [cbor(3, text.len() as u64), text.as_bytes().to_vec()].concat()
}

/// A call's content as the module writes it, each field given.
fn icp_content(request_type: &str, canister: &[u8], method: &str, arg: &[u8], sender: &[u8], expiry: u64) -> Vec<u8> {
    let mut c = cbor(5, 6);
    for (key, value) in [
        ("request_type", cbor_text(request_type)),
        ("canister_id", cbor_bytes(canister)),
        ("method_name", cbor_text(method)),
        ("arg", cbor_bytes(arg)),
        ("sender", cbor_bytes(sender)),
        ("ingress_expiry", cbor(0, expiry)),
    ] {
        c.extend(cbor_text(key));
        c.extend(value);
    }
    c
}

const ICP_LEDGER: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 2, 1, 1];

fn icp_account(byte: u8) -> Vec<u8> {
    let rest = [byte; 28];
    [crate::icp::crc32(&rest).to_be_bytes().to_vec(), rest.to_vec()].concat()
}

#[test]
fn an_icp_call_is_read_with_its_facts_its_request_id_and_its_digest() {
    let _abi = abi();
    let one = read_icp(&hex(ICP_ONE.0)).unwrap();
    assert_eq!((one["requestId"].as_str(), one["hash"].as_str()), (Some(ICP_ONE.1), Some(format!("0x{}", ICP_ONE.2).as_str())));
    assert_eq!(one["to"], "8045965122222222222222222222222222222222222222222222222222222222");
    assert_eq!((one["amount"].as_str(), one["fee"].as_str()), (Some("100000000"), Some("10000")));
    assert_eq!((one["memo"].as_str(), one["createdAtTime"].as_str()), (Some("1700000000000"), Some("1700000000000000000")));
    assert_eq!(one["ingressExpiry"], "1700000240000000000");
    assert_eq!((one["canister"].as_str(), one["method"].as_str()), (Some("ryjl3-tyaaa-aaaaa-aaaba-cai"), Some("transfer")));
    assert_eq!(one["sender"], ICP_SENDER);
    let small = read_icp(&hex(ICP_SMALL.0)).unwrap();
    assert_eq!((small["requestId"].as_str(), small["hash"].as_str()), (Some(ICP_SMALL.1), Some(format!("0x{}", ICP_SMALL.2).as_str())));
    assert_eq!((small["amount"].as_str(), small["memo"].as_str()), (Some("1"), Some(u64::MAX.to_string().as_str())));
    // The tests' own writer writes what the module writes.
    let arg = icp_arg(&icp_account(0x22), 10_000, 1_700_000_000_000, None, Some(1_700_000_000_000_000_000), 100_000_000);
    let built = icp_content("call", &ICP_LEDGER, "transfer", &arg, &hex(ICP_SENDER), 1_700_000_240_000_000_000);
    assert_eq!(to_hex(&built), ICP_ONE.0);
}

#[test]
fn what_the_icp_module_never_writes_is_refused() {
    let _abi = abi();
    let to = icp_account(0x22);
    let sender = hex(ICP_SENDER);
    let arg = icp_arg(&to, 10_000, 7, None, Some(1), 5);
    let good = icp_content("call", &ICP_LEDGER, "transfer", &arg, &sender, 9);
    assert!(read_icp(&good).is_ok());
    let mut bad_sum = to.clone();
    bad_sum[0] ^= 1;
    let mut types = hex(ICP_TYPES);
    types[5] = 0x07;
    let other_types = [types, good_arg_values(&to)].concat();
    let mut seven = good.clone();
    seven[0] = 0xa7;
    let mut after = good.clone();
    after.push(0);
    for (why, content) in [
        ("an empty call", Vec::new()),
        ("a query", icp_content("query", &ICP_LEDGER, "transfer", &arg, &sender, 9)),
        ("another canister", icp_content("call", &[0, 0, 0, 0, 0, 0, 0, 1, 1, 1], "transfer", &arg, &sender, 9)),
        ("another method", icp_content("call", &ICP_LEDGER, "icrc1_transfer", &arg, &sender, 9)),
        ("an account whose checksum is wrong", icp_content("call", &ICP_LEDGER, "transfer", &icp_arg(&bad_sum, 10_000, 7, None, Some(1), 5), &sender, 9)),
        ("an account of 31 bytes", icp_content("call", &ICP_LEDGER, "transfer", &icp_arg(&to[..31], 10_000, 7, None, Some(1), 5), &sender, 9)),
        ("a subaccount", icp_content("call", &ICP_LEDGER, "transfer", &icp_arg(&to, 10_000, 7, Some(&[1; 32]), Some(1), 5), &sender, 9)),
        ("no creation time", icp_content("call", &ICP_LEDGER, "transfer", &icp_arg(&to, 10_000, 7, None, None, 5), &sender, 9)),
        ("another type table", icp_content("call", &ICP_LEDGER, "transfer", &other_types, &sender, 9)),
        ("a byte after the argument", icp_content("call", &ICP_LEDGER, "transfer", &[arg.clone(), vec![0]].concat(), &sender, 9)),
        ("an argument cut short", icp_content("call", &ICP_LEDGER, "transfer", &arg[..arg.len() - 1], &sender, 9)),
        ("an anonymous sender", icp_content("call", &ICP_LEDGER, "transfer", &arg, &[0x04], 9)),
        ("a sender not self-authenticating", icp_content("call", &ICP_LEDGER, "transfer", &arg, &[sender[..28].to_vec(), vec![0x01]].concat(), 9)),
        ("a seventh field", seven),
        ("a field renamed", {
            let mut c = good.clone();
            let at = c.windows(12).position(|w| w == b"request_type").unwrap();
            c[at..at + 12].copy_from_slice(b"request_kind");
            c
        }),
        ("a sender of 28 bytes", icp_content("call", &ICP_LEDGER, "transfer", &arg, &sender[1..], 9)),
        ("an account's length misstated", {
            let mut a = arg.clone();
            a[hex(ICP_TYPES).len()] = 0x10;
            icp_content("call", &ICP_LEDGER, "transfer", &a, &sender, 9)
        }),
        ("a subaccount marked present", {
            let mut a = arg.clone();
            a[hex(ICP_TYPES).len() + 1 + 32 + 16] = 0x01;
            icp_content("call", &ICP_LEDGER, "transfer", &a, &sender, 9)
        }),
        ("a creation time marked absent", {
            let mut a = arg.clone();
            a[hex(ICP_TYPES).len() + 1 + 32 + 16 + 1] = 0x00;
            icp_content("call", &ICP_LEDGER, "transfer", &a, &sender, 9)
        }),
        ("a byte after", after),
        ("cut short", good[..good.len() - 1].to_vec()),
    ] {
        assert_eq!(read_icp(&content), Err(KC_ERR_TRANSACTION), "{why}");
    }
    // The fields in another order: the same request id, but not the module's
    // writing.
    let mut swapped = cbor(5, 6);
    for (key, value) in [
        ("canister_id", cbor_bytes(&ICP_LEDGER)),
        ("request_type", cbor_text("call")),
        ("method_name", cbor_text("transfer")),
        ("arg", cbor_bytes(&arg)),
        ("sender", cbor_bytes(&sender)),
        ("ingress_expiry", cbor(0, 9)),
    ] {
        swapped.extend(cbor_text(key));
        swapped.extend(value);
    }
    assert_eq!(read_icp(&swapped), Err(KC_ERR_TRANSACTION), "fields in another order");
}

/// The values of a good argument, after its type table.
fn good_arg_values(to: &[u8]) -> Vec<u8> {
    let arg = icp_arg(to, 10_000, 7, None, Some(1), 5);
    arg[hex(ICP_TYPES).len()..].to_vec()
}

#[test]
fn an_icp_key_signs_only_the_digest_of_a_call_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    // A call of its own, so no other test's reading stands for it.
    let arg = icp_arg(&icp_account(0x44), 10_000, 4242, None, Some(4242), 4242);
    let content = icp_content("call", &ICP_LEDGER, "transfer", &arg, &hex(ICP_SENDER), 4242);
    let (_, digest) = crate::icp::reading(&content).unwrap();
    assert_eq!(sign(wallet, ICP_0, &digest), Err(KC_ERR_UNSHOWN), "never read");
    let mut needed = 0usize;
    unsafe { kc_icp_read_call(content.as_ptr(), content.len(), core::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(sign(wallet, ICP_0, &digest), Err(KC_ERR_UNSHOWN), "only its length asked");
    read_icp(&content).unwrap();
    assert_eq!(sign(wallet, FILECOIN_0, &digest), Err(KC_ERR_UNSHOWN), "an ICP reading is not a Filecoin one");
    let signature = sign(wallet, ICP_0, &digest).unwrap();
    let public = PublicKey::from_slice(&public_key(wallet, ICP_0, KC_PUBLIC_KEY_COMPRESSED).unwrap()).unwrap();
    Signature::from_compact(&signature[..64]).unwrap().verify(Message::from_digest(digest), &public).unwrap();
    assert_eq!(sign(wallet, ICP_0, &digest), Err(KC_ERR_UNSHOWN), "signed once");
    for at in ["m/44'/223'/3'/0/0", "m/44'/223'"] {
        assert_eq!(sign(wallet, at, &[7; 32]), Err(KC_ERR_UNSHOWN), "{at}");
    }
    assert_eq!(sign_low_r(wallet, ICP_0, &[3u8; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(wallet, ICP_0, &[3u8; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(wallet, ICP_0, b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    // An imported ICP key, opened as one, the same; a refused signature gives
    // its reading back.
    let secret = export(wallet, ICP_0).unwrap();
    let key = open_key(KC_CURVE_SECP256K1_ICP, &secret).unwrap();
    assert_eq!(sign(key, "m", &digest), Err(KC_ERR_UNSHOWN));
    read_icp(&content).unwrap();
    assert_eq!(sign(key, "m/0", &digest), Err(KC_ERR_PATH));
    assert_eq!(sign(key, "m", &digest).unwrap(), signature, "kept after a refusal, as the phrase's key signs");
    assert_eq!(sign(key, "m", &digest), Err(KC_ERR_UNSHOWN), "signed once");
    assert_eq!(sign_low_r(key, "m", &digest), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(key, "m").unwrap(), secret);
    assert_eq!(open_key(KC_CURVE_SECP256K1_ICP, &[0u8; 32]), Err(KC_ERR_KEY));
    for handle in [key, wallet] {
        assert_eq!(kc_close(handle), KC_OK);
    }
}

#[test]
fn an_icp_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let content = hex(ICP_SMALL.0);
    let mut needed = 0usize;
    assert_eq!(
        unsafe { kc_icp_read_call(content.as_ptr(), content.len(), core::ptr::null_mut(), 0, &mut needed) },
        KC_ERR_BUFFER
    );
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe { kc_icp_read_call(content.as_ptr(), content.len(), short.as_mut_ptr(), short.len(), &mut written) };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(
        unsafe { kc_icp_read_call(content.as_ptr(), content.len(), short.as_mut_ptr(), 0, core::ptr::null_mut()) },
        KC_ERR_ARGUMENT
    );
}

// --- Kaspa (O58) ------------------------------------------------------------------

fn read_kaspa(handle: u64, request: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_kaspa_read_transaction(handle, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_kaspa_read_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// Every input of [request] signed: per input, the sighash and the signature.
fn kaspa_sign(handle: u64, request: &[u8]) -> Result<Vec<([u8; 32], [u8; 64])>, i32> {
    let inputs = crate::kaspa::Request::read(request).map(|r| r.inputs.len()).unwrap_or(1);
    let mut out = vec![0u8; inputs * 96];
    let code = unsafe { kc_kaspa_sign_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len()) };
    if code != KC_OK {
        return Err(code);
    }
    Ok(out
        .chunks(96)
        .map(|c| (c[..32].try_into().unwrap(), c[32..].try_into().unwrap()))
        .collect())
}

/// What the module's `KaspaTransaction.coreRequest` writes, printed by it
/// with each input's `signingDigest`, for the abandon phrase's first account
/// (`KASPA_OWN`): five KAS spent from `11…11:1`, one paid to the key `22…22`
/// and the rest but the fee of 2,034 sompi back as change; and `33…33:0` and
/// `44…44:7`, 70,000 and 80,000 sompi, all but a fee of 4,000 paid to `22…22`.
const KASPA_ONE: (&str, &str) = ("14006d2f3434272f313131313131272f30272f302f30000001001111111111111111111111111111111111111111111111111111111111111111010000000065cd1d0000000000002200201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058acffffffffffffffff01020000e1f5050000000000002200202222222222222222222222222222222222222222222222222222222222222222ac0e7cd7170000000000002200201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac000000000000000000000000000000000000000000000000000000000000000000000000f207000000000000", "0520065f4e167f92044b5e82d77fd2d0eebfb0a6f24510e6651f2f725ba68d66");
const KASPA_TWO: (&str, [&str; 2]) = ("14006d2f3434272f313131313131272f30272f302f3000000200333333333333333333333333333333333333333333333333333333333333333300000000701101000000000000002200201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058acffffffffffffffff01444444444444444444444444444444444444444444444444444444444444444407000000803801000000000000002200201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058acffffffffffffffff010100503a02000000000000002200202222222222222222222222222222222222222222222222222222222222222222ac000000000000000000000000000000000000000000000000000000000000000000000000a00f000000000000", ["ea9be570d026a709913f69d33fbe875b8cfdffc9c5748c5df86fe2a2164a6c64", "0b0a5cee2318c7a4c62de01e5bdce6cb5a4f6ebe961c3a9649a866a0de0c6166"]);
/// The abandon phrase's first Kaspa address and its key, as the module
/// derives and spells them; and the key `22…22` as the module spells it.
const KASPA_OWN: (&str, &str) = ("kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh", "1bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058");
const KASPA_TO: &str = "kaspa:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zywrsf7452";

fn kaspa_script(key: &[u8]) -> Vec<u8> {
    [&[0x20][..], key, &[0xac]].concat()
}

/// One input: an outpoint, an amount, a script and its version, a sequence
/// and a signature count.
struct KaspaIn {
    txid: [u8; 32],
    index: u32,
    amount: u64,
    version: u16,
    script: Vec<u8>,
    sequence: u64,
    sig_ops: u8,
}

/// A request in `kc_kaspa_sign_transaction`'s layout: the tests' own writer.
#[allow(clippy::too_many_arguments)]
fn kaspa_request(
    path: &str,
    version: u16,
    inputs: &[KaspaIn],
    outputs: &[(u64, u16, Vec<u8>)],
    lock_time: u64,
    subnetwork: [u8; 20],
    gas: u64,
    fee: u64,
) -> Vec<u8> {
    let mut r = Vec::new();
    let short = |r: &mut Vec<u8>, b: &[u8]| {
        r.extend((b.len() as u16).to_le_bytes());
        r.extend(b);
    };
    short(&mut r, path.as_bytes());
    r.extend(version.to_le_bytes());
    r.extend((inputs.len() as u16).to_le_bytes());
    for i in inputs {
        r.extend(i.txid);
        r.extend(i.index.to_le_bytes());
        r.extend(i.amount.to_le_bytes());
        r.extend(i.version.to_le_bytes());
        short(&mut r, &i.script);
        r.extend(i.sequence.to_le_bytes());
        r.push(i.sig_ops);
    }
    r.extend((outputs.len() as u16).to_le_bytes());
    for (amount, version, script) in outputs {
        r.extend(amount.to_le_bytes());
        r.extend(version.to_le_bytes());
        short(&mut r, script);
    }
    r.extend(lock_time.to_le_bytes());
    r.extend(subnetwork);
    r.extend(gas.to_le_bytes());
    r.extend(fee.to_le_bytes());
    r
}

fn kaspa_in(txid: u8, index: u32, amount: u64) -> KaspaIn {
    KaspaIn {
        txid: [txid; 32],
        index,
        amount,
        version: 0,
        script: kaspa_script(&hex(KASPA_OWN.1)),
        sequence: u64::MAX,
        sig_ops: 1,
    }
}

/// [`KASPA_ONE`], at [path], as the tests' writer writes it.
fn kaspa_one(path: &str) -> Vec<u8> {
    kaspa_request(
        path,
        0,
        &[kaspa_in(0x11, 1, 500_000_000)],
        &[(100_000_000, 0, kaspa_script(&[0x22; 32])), (399_997_966, 0, kaspa_script(&hex(KASPA_OWN.1)))],
        0,
        [0; 20],
        0,
        2034,
    )
}

#[test]
fn a_kaspa_send_is_read_with_its_addresses_its_change_and_its_sighashes() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    // The tests' own writer writes what the module writes.
    assert_eq!(to_hex(&kaspa_one(KASPA_0)), KASPA_ONE.0);
    assert_eq!(crate::kaspa::address(&hex(KASPA_OWN.1)), KASPA_OWN.0);
    assert_eq!(crate::kaspa::address(&[0x22; 32]), KASPA_TO);

    let one = read_kaspa(wallet, &hex(KASPA_ONE.0)).unwrap();
    assert_eq!(one["inputs"].as_array().unwrap().len(), 1);
    assert_eq!(one["inputs"][0]["txid"], "11".repeat(32));
    assert_eq!((one["inputs"][0]["index"].as_u64(), one["inputs"][0]["amount"].as_str()), (Some(1), Some("500000000")));
    assert_eq!(one["outputs"][0]["address"], KASPA_TO);
    assert_eq!((one["outputs"][0]["amount"].as_str(), one["outputs"][0]["change"].as_bool()), (Some("100000000"), Some(false)));
    assert_eq!(one["outputs"][1]["address"], KASPA_OWN.0);
    assert_eq!((one["outputs"][1]["amount"].as_str(), one["outputs"][1]["change"].as_bool()), (Some("399997966"), Some(true)));
    assert_eq!((one["sent"].as_str(), one["spent"].as_str(), one["fee"].as_str()), (Some("100000000"), Some("500000000"), Some("2034")));
    assert_eq!(one["sighashes"], serde_json::json!([KASPA_ONE.1]));

    let two = read_kaspa(wallet, &hex(KASPA_TWO.0)).unwrap();
    assert_eq!(two["inputs"][1]["txid"], "44".repeat(32));
    assert_eq!(two["inputs"][1]["index"].as_u64(), Some(7));
    assert_eq!(two["outputs"].as_array().unwrap().len(), 1);
    assert_eq!(two["outputs"][0]["change"].as_bool(), Some(false));
    assert_eq!((two["sent"].as_str(), two["spent"].as_str(), two["fee"].as_str()), (Some("146000"), Some("150000"), Some("4000")));
    assert_eq!(two["sighashes"], serde_json::json!(KASPA_TWO.1));
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn what_the_kaspa_module_never_writes_is_refused() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let own = kaspa_script(&hex(KASPA_OWN.1));
    let to = kaspa_script(&[0x22; 32]);
    let pay = |outputs: &[(u64, u16, Vec<u8>)], inputs: &[KaspaIn], fee: u64| {
        kaspa_request(KASPA_0, 0, inputs, outputs, 0, [0; 20], 0, fee)
    };
    let one_in = || vec![kaspa_in(0x11, 1, 10_000)];
    let good = pay(&[(7_000, 0, to.clone())], &one_in(), 3_000);
    assert!(read_kaspa(wallet, &good).is_ok());
    let with_in = |edit: &dyn Fn(&mut KaspaIn)| {
        let mut inputs = one_in();
        edit(&mut inputs[0]);
        pay(&[(7_000, 0, to.clone())], &inputs, 3_000)
    };
    for (why, request) in [
        ("version 1", kaspa_request(KASPA_0, 1, &one_in(), &[(7_000, 0, to.clone())], 0, [0; 20], 0, 3_000)),
        ("no input", pay(&[(0, 0, to.clone())], &[], 0)),
        ("no output", pay(&[], &one_in(), 10_000)),
        ("a spent script of version 1", with_in(&|i| i.version = 1)),
        ("a spent script an ECDSA key's", with_in(&|i| i.script = [&[0x21][..], &[2; 33], &[0xab]].concat())),
        ("a spent script cut short", with_in(&|i| i.script.truncate(33))),
        ("a sequence", with_in(&|i| i.sequence = 0)),
        ("two signature operations", with_in(&|i| i.sig_ops = 2)),
        ("a script hash paid", pay(&[(7_000, 0, [&[0xaa, 0x20][..], &[3; 32], &[0x87]].concat())], &one_in(), 3_000)),
        ("an ECDSA key paid", pay(&[(7_000, 0, [&[0x21][..], &[2; 33], &[0xab]].concat())], &one_in(), 3_000)),
        ("a paid script of version 1", pay(&[(7_000, 1, to.clone())], &one_in(), 3_000)),
        ("a lock time", kaspa_request(KASPA_0, 0, &one_in(), &[(7_000, 0, to.clone())], 1, [0; 20], 0, 3_000)),
        ("another subnetwork", kaspa_request(KASPA_0, 0, &one_in(), &[(7_000, 0, to.clone())], 0, {
            let mut id = [0; 20];
            id[0] = 1;
            id
        }, 0, 3_000)),
        ("gas", kaspa_request(KASPA_0, 0, &one_in(), &[(7_000, 0, to.clone())], 0, [0; 20], 1, 3_000)),
        ("an outpoint twice", pay(&[(17_000, 0, to.clone())], &[kaspa_in(0x11, 1, 10_000), kaspa_in(0x11, 1, 10_000)], 3_000)),
        ("a fee a sompi more", pay(&[(7_000, 0, to.clone())], &one_in(), 3_001)),
        ("a fee a sompi less", pay(&[(7_000, 0, to.clone())], &one_in(), 2_999)),
        ("more paid than spent", pay(&[(10_001, 0, to.clone())], &one_in(), 0)),
    ] {
        assert_eq!(read_kaspa(wallet, &request), Err(KC_ERR_TRANSACTION), "{why}");
        assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_TRANSACTION), "{why}, signed");
    }
    // Valid in every other respect, and not this key's own coin: held under
    // the lock, so never read, so never signed.
    let foreign = pay(&[(7_000, 0, to.clone())], &[KaspaIn { script: to.clone(), ..kaspa_in(0x11, 1, 10_000) }], 3_000);
    assert_eq!(read_kaspa(wallet, &foreign), Err(KC_ERR_TRANSACTION), "an input of another key");
    assert_eq!(kaspa_sign(wallet, &foreign).map(|_| ()), Err(KC_ERR_UNSHOWN), "an input of another key, signed");
    for (why, request) in [
        ("nothing", Vec::new()),
        ("cut short", good[..good.len() - 1].to_vec()),
        ("a byte after", [good.clone(), vec![0]].concat()),
    ] {
        assert_eq!(read_kaspa(wallet, &request), Err(KC_ERR_ARGUMENT), "{why}");
    }
    // The change is the key's own script, found by the key.
    let change = read_kaspa(wallet, &pay(&[(7_000, 0, own.clone())], &one_in(), 3_000)).unwrap();
    assert_eq!(change["outputs"][0]["change"].as_bool(), Some(true));
    assert_eq!(change["sent"], "0");
    // Another network's path, or a key that is not Kaspa's.
    let at_bitcoin = kaspa_request("m/84'/0'/0'/0/0", 0, &one_in(), &[(7_000, 0, to.clone())], 0, [0; 20], 0, 3_000);
    assert_eq!(read_kaspa(wallet, &at_bitcoin), Err(KC_ERR_PATH));
    let at_neighbour = kaspa_request(DIGEST_0, 0, &one_in(), &[(7_000, 0, to.clone())], 0, [0; 20], 0, 3_000);
    assert_eq!(read_kaspa(wallet, &at_neighbour), Err(KC_ERR_PATH));
    let secret = export(wallet, KASPA_0).unwrap();
    for curve in [KC_CURVE_SECP256K1, KC_CURVE_SECP256K1_BITCOIN, KC_CURVE_SECP256K1_ICP] {
        let key = open_key(curve, &secret).unwrap();
        assert_eq!(read_kaspa(key, &kaspa_one("m")), Err(KC_ERR_KIND), "curve {curve}");
        assert_eq!(kc_close(key), KC_OK);
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_kaspa_key_signs_only_a_send_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    // A send of its own, so no other test's reading stands for it.
    let request = kaspa_request(
        KASPA_0,
        0,
        &[kaspa_in(0x55, 3, 90_000), kaspa_in(0x66, 0, 60_000)],
        &[(100_000, 0, kaspa_script(&[0x22; 32])), (45_000, 0, kaspa_script(&hex(KASPA_OWN.1)))],
        0,
        [0; 20],
        0,
        5_000,
    );
    assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "never read");
    let reading = read_kaspa(wallet, &request).unwrap();
    let signed = kaspa_sign(wallet, &request).unwrap();
    assert_eq!(signed.len(), 2);
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let key = keys::derive(&seed[..], &path(KASPA_0)).unwrap();
    let public = x_only(wallet, KASPA_0, None);
    assert_eq!(to_hex(&public.to_byte_array()), KASPA_OWN.1);
    let parsed = crate::kaspa::Request::read(&request).unwrap();
    for (i, (sighash, signature)) in signed.iter().enumerate() {
        assert_eq!(*sighash, crate::kaspa::sighash(&parsed, i), "input {i}");
        assert_eq!(reading["sighashes"][i], to_hex(sighash), "input {i}: the sighash read");
        schnorr::verify(&schnorr::Signature::from_byte_array(*signature), sighash, &public)
            .unwrap_or_else(|_| panic!("input {i}"));
        assert_eq!(signature[..], keys::schnorr_sign(&key, sighash, None).unwrap()[..], "input {i}");
    }
    assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "signed once");

    // A Kaspa key signs no bare digest, no low-R digest, no Schnorr digest,
    // no message — at its path or any account's.
    for at in [KASPA_0, "m/44'/111111'/3'/0/9"] {
        assert_eq!(sign(wallet, at, &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_low_r(wallet, at, &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(schnorr(wallet, at, &[7; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_personal(wallet, at, b"hello"), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert!(export(wallet, at).is_ok(), "{at}: its export is as before");
    }

    // A refused signature gives its reading back: another wallet, whose key
    // does not spend these inputs, is refused, and the one that read it signs.
    read_kaspa(wallet, &request).unwrap();
    let other = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(kaspa_sign(other, &request).map(|_| ()), Err(KC_ERR_TRANSACTION));
    assert_eq!(kaspa_sign(wallet, &request).unwrap(), signed, "kept after a refusal");
    assert_eq!(kc_close(other), KC_OK);

    // An imported Kaspa key, opened as one, the same at `m`.
    let secret = export(wallet, KASPA_0).unwrap();
    let imported = open_key(KC_CURVE_SECP256K1_KASPA, &secret).unwrap();
    let at_root = kaspa_request(
        "m",
        0,
        &[kaspa_in(0x55, 3, 90_000), kaspa_in(0x66, 0, 60_000)],
        &[(100_000, 0, kaspa_script(&[0x22; 32])), (45_000, 0, kaspa_script(&hex(KASPA_OWN.1)))],
        0,
        [0; 20],
        0,
        5_000,
    );
    assert_eq!(kaspa_sign(imported, &at_root).map(|_| ()), Err(KC_ERR_UNSHOWN));
    assert_eq!(read_kaspa(imported, &at_root).unwrap()["sighashes"], reading["sighashes"]);
    assert_eq!(kaspa_sign(imported, &at_root).unwrap(), signed, "as the phrase's key signs");
    let below = kaspa_request("m/0", 0, &[kaspa_in(0x55, 3, 90_000)], &[(85_000, 0, kaspa_script(&[0x22; 32]))], 0, [0; 20], 0, 5_000);
    assert_eq!(read_kaspa(imported, &below), Err(KC_ERR_PATH));
    assert_eq!(sign(imported, "m", &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(imported, "m", &[7; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_low_r(imported, "m", &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(imported, "m", b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(export(imported, "m").unwrap(), secret);
    assert_eq!(kc_close(imported), KC_OK);
    assert_eq!(open_key(KC_CURVE_SECP256K1_KASPA, &[0u8; 32]), Err(KC_ERR_KEY));
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_HANDLE));
}

#[test]
fn a_kaspa_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let request = kaspa_request(
        KASPA_0,
        0,
        &[kaspa_in(0x77, 2, 50_000)],
        &[(45_000, 0, kaspa_script(&[0x22; 32]))],
        0,
        [0; 20],
        0,
        5_000,
    );
    let mut needed = 0usize;
    let code = unsafe {
        kc_kaspa_read_transaction(wallet, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(code, KC_ERR_BUFFER);
    assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "only its length asked");
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe {
        kc_kaspa_read_transaction(wallet, request.as_ptr(), request.len(), short.as_mut_ptr(), short.len(), &mut written)
    };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(kaspa_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "a buffer too short");
    let code = unsafe {
        kc_kaspa_read_transaction(wallet, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, core::ptr::null_mut())
    };
    assert_eq!(code, KC_ERR_ARGUMENT);
    read_kaspa(wallet, &request).unwrap();
    // The signature's buffer must be exactly 96 bytes an input.
    for length in [0usize, 95, 97, 192] {
        let mut out = vec![0u8; length];
        let code = unsafe {
            kc_kaspa_sign_transaction(wallet, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len())
        };
        assert_eq!(code, KC_ERR_ARGUMENT, "{length} bytes");
    }
    assert_eq!(kaspa_sign(wallet, &request).unwrap().len(), 1, "the reading still kept");
    assert_eq!(kc_close(wallet), KC_OK);
}

// --- Starknet (O58) ----------------------------------------------------------------

/// What the module's `StarknetInvokeV3.toJson` and
/// `StarknetDeployAccountV3.toJson` write with no signature, printed by it
/// with each `hash`, for the legal phrase's first account: one STRK to
/// `0x123456789abcdef` at nonce 7 under three bounds; the same as the query
/// version an estimate is signed at, its bounds zero; and the account's
/// deployment as Argent 0.4.0 under the same bounds.
const STARKNET_INVOKE: (&str, &str) = (r#"{"type":"INVOKE","version":"0x3","sender_address":"0x2acb16b67ee6426b29eb415ab2ff53e729760a8e5442561d90da7d3b0fc2035","calldata":["0x1","0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x123456789abcdef","0xde0b6b3a7640000","0x0"],"signature":[],"nonce":"0x7","resource_bounds":{"l1_gas":{"max_amount":"0x0","max_price_per_unit":"0x11c37937e08000"},"l2_gas":{"max_amount":"0x16e360","max_price_per_unit":"0x3b9aca000"},"l1_data_gas":{"max_amount":"0x1f4","max_price_per_unit":"0x7d0"}},"tip":"0x0","paymaster_data":[],"account_deployment_data":[],"nonce_data_availability_mode":"L1","fee_data_availability_mode":"L1"}"#, "0x001504f0e794f456359a88ed90fbf9b094b5e9a90baa5ecc2c0695fb54276eae");
const STARKNET_QUERY: (&str, &str) = (r#"{"type":"INVOKE","version":"0x100000000000000000000000000000003","sender_address":"0x2acb16b67ee6426b29eb415ab2ff53e729760a8e5442561d90da7d3b0fc2035","calldata":["0x1","0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x123456789abcdef","0xde0b6b3a7640000","0x0"],"signature":[],"nonce":"0x7","resource_bounds":{"l1_gas":{"max_amount":"0x0","max_price_per_unit":"0x0"},"l2_gas":{"max_amount":"0x0","max_price_per_unit":"0x0"},"l1_data_gas":{"max_amount":"0x0","max_price_per_unit":"0x0"}},"tip":"0x0","paymaster_data":[],"account_deployment_data":[],"nonce_data_availability_mode":"L1","fee_data_availability_mode":"L1"}"#, "0x026454e4336821a6df3fcfed345f6af2a9320bb9d913ebde49de898c9f33e36d");
const STARKNET_DEPLOY: (&str, &str) = (r#"{"type":"DEPLOY_ACCOUNT","version":"0x3","signature":[],"nonce":"0x0","contract_address_salt":"0x1706e9c5cb95d33535d085986860b14e82ab8de0a6e259ceebfbaca8594f520","constructor_calldata":["0x0","0x1706e9c5cb95d33535d085986860b14e82ab8de0a6e259ceebfbaca8594f520","0x1"],"class_hash":"0x36078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f","resource_bounds":{"l1_gas":{"max_amount":"0x0","max_price_per_unit":"0x11c37937e08000"},"l2_gas":{"max_amount":"0x16e360","max_price_per_unit":"0x3b9aca000"},"l1_data_gas":{"max_amount":"0x1f4","max_price_per_unit":"0x7d0"}},"tip":"0x0","paymaster_data":[],"nonce_data_availability_mode":"L1","fee_data_availability_mode":"L1"}"#, "0x046f5e104f91cab1b259d488fd0feafcb28a81b83d48c8261b6d315587210d28");
/// The legal phrase's first Stark key, and its Argent accounts' addresses as
/// the module's `ArgentAccount.candidateAddresses` gives them: 0.4.0's,
/// 0.3.1's, 0.3.0's, then the Cairo 0 proxy's for 0.2.4, 0.2.3, 0.2.2 and
/// 0.2.1.
const STARKNET_KEY: &str = "0x01706e9c5cb95d33535d085986860b14e82ab8de0a6e259ceebfbaca8594f520";
const STARKNET_ADDRESSES: [&str; 7] = [
    "0x02acb16b67ee6426b29eb415ab2ff53e729760a8e5442561d90da7d3b0fc2035",
    "0x066d91161b30b80feb5f81146e090e4cafa8963b6fa4bfbc90df91eb30727398",
    "0x0138fa557e09038a3b481dc25e14780cad544171d9ea259bdf19de94b5272dc6",
    "0x0504da1e9c956f21c277fbe8c5196717d7b26e3b52458c163e057b18da2d0c80",
    "0x05c267e5d35a4968f128f12c93c290d9d7a5e85a26c1c342f0662b9bb37c8dc7",
    "0x05ece744f5715434e98619666fa249b5df5044f5ec9aba9fc4841322c99d8b10",
    "0x01382d0f862cccb46752c6f9229d5ad62ed539b413921e9792a3d48c9cd1b474",
];

fn read_starknet(handle: u64, at: &str, transaction: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_starknet_read_transaction(
            handle,
            at.as_ptr(),
            at.len(),
            transaction.as_ptr(),
            transaction.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_starknet_read_transaction(
            handle,
            at.as_ptr(),
            at.len(),
            transaction.as_ptr(),
            transaction.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// [json] with [edit] made to it.
fn starknet_edited(json: &str, edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    edit(value.as_object_mut().unwrap());
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn a_starknet_transaction_is_read_with_its_facts_and_its_hash() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(to_hex(&sk_public_key(wallet, STARKNET_0).unwrap()), &STARKNET_KEY[2..]);
    // The core's Argent addresses are the module's.
    let addresses = crate::starknet::argent_addresses(&hex(&STARKNET_KEY[2..]).try_into().unwrap());
    assert_eq!(addresses.iter().map(|a| format!("0x{}", to_hex(a))).collect::<Vec<_>>(), STARKNET_ADDRESSES);
    let invoke = read_starknet(wallet, STARKNET_0, STARKNET_INVOKE.0.as_bytes()).unwrap();
    assert_eq!(invoke["hash"], STARKNET_INVOKE.1);
    assert_eq!((invoke["kind"].as_str(), invoke["query"].as_bool(), invoke["chain"].as_str()), (Some("invoke"), Some(false), Some("SN_MAIN")));
    assert_eq!(invoke["sender"], STARKNET_ADDRESSES[0]);
    assert_eq!(invoke["nonce"], "7");
    assert_eq!(invoke["token"], "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");
    assert_eq!(invoke["recipient"], format!("0x{:0>64}", "123456789abcdef"));
    assert_eq!(invoke["amount"], "1000000000000000000");
    assert_eq!(invoke["bounds"]["l2Gas"]["maxAmount"], "1500000");
    assert_eq!(invoke["bounds"]["l1Gas"]["maxPricePerUnit"], "5000000000000000");
    // 0 × 5e15 + 1,500,000 × 16e9 + 500 × 2,000.
    assert_eq!(invoke["maxFee"], "24000000001000000");
    let query = read_starknet(wallet, STARKNET_0, STARKNET_QUERY.0.as_bytes()).unwrap();
    assert_eq!((query["hash"].as_str(), query["query"].as_bool(), query["maxFee"].as_str()), (Some(STARKNET_QUERY.1), Some(true), Some("0")));
    let deploy = read_starknet(wallet, STARKNET_0, STARKNET_DEPLOY.0.as_bytes()).unwrap();
    assert_eq!(deploy["hash"], STARKNET_DEPLOY.1);
    assert_eq!((deploy["kind"].as_str(), deploy["address"].as_str()), (Some("deployAccount"), Some(STARKNET_ADDRESSES[0])));
    assert_eq!(deploy["classHash"], "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f");
    assert_eq!(deploy["publicKey"], STARKNET_KEY);
    // A transfer from each other account of the key, read as its own: a
    // restored phrase's at 0.3.1's or 0.3.0's address, or a Cairo 0 account
    // an upgrade to a Cairo 1 class kept at its proxy's address.
    for address in &STARKNET_ADDRESSES[1..] {
        let from = starknet_edited(STARKNET_INVOKE.0, |o| {
            o.insert("sender_address".into(), format!("0x{}", address[2..].trim_start_matches('0')).into());
        });
        assert_eq!(read_starknet(wallet, STARKNET_0, &from).unwrap()["sender"], *address);
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn what_the_starknet_module_never_sends_is_refused() {
    use serde_json::{json, Value};
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let invoke = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| starknet_edited(STARKNET_INVOKE.0, edit);
    let deploy = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| starknet_edited(STARKNET_DEPLOY.0, edit);
    let calldata = |data: &[&str]| {
        starknet_edited(STARKNET_INVOKE.0, |o| {
            o.insert("calldata".into(), json!(data));
        })
    };
    let strk = "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    let transfer = "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not JSON", b"{".to_vec()),
        ("an array", b"[]".to_vec()),
        ("another type", invoke(&|o| { o.insert("type".into(), "DECLARE".into()); })),
        ("version 1", invoke(&|o| { o.insert("version".into(), "0x1".into()); })),
        ("a signature", invoke(&|o| { o.insert("signature".into(), json!(["0x1"])); })),
        ("a tip", invoke(&|o| { o.insert("tip".into(), "0x1".into()); })),
        ("paymaster data", invoke(&|o| { o.insert("paymaster_data".into(), json!(["0x1"])); })),
        ("account deployment data", invoke(&|o| { o.insert("account_deployment_data".into(), json!(["0x1"])); })),
        ("L2 data availability", invoke(&|o| { o.insert("fee_data_availability_mode".into(), "L2".into()); })),
        ("a key of its own", invoke(&|o| { o.insert("memo".into(), "0x1".into()); })),
        ("a key missing", invoke(&|o| { o.remove("tip"); })),
        ("a leading zero", invoke(&|o| { o.insert("nonce".into(), "0x07".into()); })),
        ("upper case", invoke(&|o| { o.insert("nonce".into(), "0xA".into()); })),
        ("no 0x", invoke(&|o| { o.insert("nonce".into(), "7".into()); })),
        ("a number, not a string", invoke(&|o| { o.insert("nonce".into(), json!(7)); })),
        ("the prime", invoke(&|o| { o.insert("nonce".into(), "0x800000000000011000000000000000000000000000000000000000000000001".into()); })),
        ("an amount past 64 bits", invoke(&|o| { o["resource_bounds"]["l2_gas"]["max_amount"] = "0x10000000000000000".into(); })),
        ("a price past 128 bits", invoke(&|o| { o["resource_bounds"]["l2_gas"]["max_price_per_unit"] = "0x100000000000000000000000000000000".into(); })),
        ("a bound missing", invoke(&|o| { o["resource_bounds"].as_object_mut().unwrap().remove("l1_data_gas"); })),
        ("two calls", calldata(&["0x2", strk, transfer, "0x3", "0x1", "0x1", "0x0", strk, transfer, "0x3", "0x1", "0x1", "0x0"])),
        ("another selector", calldata(&["0x1", strk, "0x1", "0x3", "0x123", "0x1", "0x0"])),
        // Seven felts each, as one transfer has, and wrong in one place only.
        ("a count of two over one call's felts", calldata(&["0x2", strk, transfer, "0x3", "0x123", "0x1", "0x0"])),
        ("a length of four over three arguments", calldata(&["0x1", strk, transfer, "0x4", "0x123", "0x1", "0x0"])),
        ("four arguments", calldata(&["0x1", strk, transfer, "0x4", "0x123", "0x1", "0x0", "0x0"])),
        ("a recipient of zero", calldata(&["0x1", strk, transfer, "0x3", "0x0", "0x1", "0x0"])),
        ("a token past the bound", calldata(&["0x1", "0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00", transfer, "0x3", "0x123", "0x1", "0x0"])),
        ("an amount's low half past 128 bits", calldata(&["0x1", strk, transfer, "0x3", "0x123", "0x100000000000000000000000000000000", "0x0"])),
        ("another key's sender", invoke(&|o| { o.insert("sender_address".into(), "0x123".into()); })),
        ("a deployment at nonce 1", deploy(&|o| { o.insert("nonce".into(), "0x1".into()); })),
        ("another class", deploy(&|o| { o.insert("class_hash".into(), "0x123".into()); })),
        ("another salt", deploy(&|o| { o.insert("contract_address_salt".into(), "0x123".into()); })),
        ("another constructor", deploy(&|o| { o.insert("constructor_calldata".into(), json!(["0x0", "0x123", "0x1"])); })),
        ("0.3.1's constructor under 0.4.0's class", deploy(&|o| { o.insert("constructor_calldata".into(), json!([STARKNET_KEY.trim_start_matches("0x0"), "0x0"])); })),
        ("an invoke's key in a deployment", deploy(&|o| { o.insert("account_deployment_data".into(), json!([])); })),
    ];
    for (why, transaction) in &cases {
        assert_eq!(read_starknet(wallet, STARKNET_0, transaction), Err(KC_ERR_TRANSACTION), "{why}");
    }
    // Another account of the phrase reads the first's transfer as another
    // key's.
    assert_eq!(read_starknet(wallet, "m/44'/9004'/0'/0/1", STARKNET_INVOKE.0.as_bytes()), Err(KC_ERR_TRANSACTION));
    assert_eq!(read_starknet(wallet, STARKNET_FREE, STARKNET_INVOKE.0.as_bytes()), Err(KC_ERR_PATH));
    assert_eq!(read_starknet(wallet, EVM_0, STARKNET_INVOKE.0.as_bytes()), Err(KC_ERR_PATH));
    let key = open_key(KC_CURVE_ED25519, &[1u8; 32]).unwrap();
    assert_eq!(read_starknet(key, STARKNET_0, STARKNET_INVOKE.0.as_bytes()), Err(KC_ERR_KIND));
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_starknet_key_signs_only_a_transaction_read_for_a_screen() {
    use starknet_crypto::Felt;
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    // A transfer of its own, so no other test's reading stands for it.
    let own = starknet_edited(STARKNET_INVOKE.0, |o| { o.insert("nonce".into(), "0x2a".into()); });
    let read = read_starknet(wallet, STARKNET_0, &own).unwrap();
    let hash: [u8; 32] = hex(&read["hash"].as_str().unwrap()[2..]).try_into().unwrap();
    assert_eq!(read["nonce"], "42");
    // Read, so signed — once, by the key it was read for.
    assert_eq!(sk_sign(wallet, "m/44'/9004'/0'/0/1", &hash), Err(KC_ERR_UNSHOWN), "another key");
    let signature = sk_sign(wallet, STARKNET_0, &hash).unwrap();
    let r = Felt::from_bytes_be(&signature[..32].try_into().unwrap());
    let s = Felt::from_bytes_be(&signature[32..].try_into().unwrap());
    let public = Felt::from_bytes_be(&sk_public_key(wallet, STARKNET_0).unwrap());
    assert!(starknet_crypto::verify(&public, &Felt::from_bytes_be(&hash), &r, &s).unwrap());
    assert_eq!(sk_sign(wallet, STARKNET_0, &hash), Err(KC_ERR_UNSHOWN), "once");
    // Never read, or only its length asked: nothing.
    let unread = starknet_edited(STARKNET_INVOKE.0, |o| { o.insert("nonce".into(), "0x2b".into()); });
    let mut needed = 0usize;
    let code = unsafe {
        kc_starknet_read_transaction(wallet, STARKNET_0.as_ptr(), STARKNET_0.len(), unread.as_ptr(), unread.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(code, KC_ERR_BUFFER);
    for n in 0..8 {
        assert_eq!(sk_sign(wallet, STARKNET_0, &stark_hash(n)), Err(KC_ERR_UNSHOWN), "hash {n}");
    }
    // Every account of the phrase's keys at the module's path, the same.
    assert_eq!(sk_sign(wallet, "m/44'/9004'/0'/0/7", &stark_hash(1)), Err(KC_ERR_UNSHOWN));
    assert_eq!(sk_sign(wallet, "m/44'/9004'/3'/0/0", &stark_hash(1)), Err(KC_ERR_UNSHOWN));
    // The query version an estimate is signed at is read and signed the same
    // way, and a deployment.
    for transaction in [STARKNET_QUERY.0, STARKNET_DEPLOY.0] {
        let read = read_starknet(wallet, STARKNET_0, transaction.as_bytes()).unwrap();
        let hash: [u8; 32] = hex(&read["hash"].as_str().unwrap()[2..]).try_into().unwrap();
        assert!(sk_sign(wallet, STARKNET_0, &hash).is_ok());
        assert_eq!(sk_sign(wallet, STARKNET_0, &hash), Err(KC_ERR_UNSHOWN));
    }
    // A path no module writes signs as before.
    assert!(sk_sign(wallet, STARKNET_FREE, &stark_hash(1)).is_ok());
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(read_starknet(wallet, STARKNET_0, &own), Err(KC_ERR_HANDLE));
}

#[test]
fn a_starknet_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let transaction = STARKNET_DEPLOY.0.as_bytes();
    let read = |out: *mut u8, cap: usize, length: *mut usize| unsafe {
        kc_starknet_read_transaction(wallet, STARKNET_0.as_ptr(), STARKNET_0.len(), transaction.as_ptr(), transaction.len(), out, cap, length)
    };
    let mut needed = 0usize;
    assert_eq!(read(core::ptr::null_mut(), 0, &mut needed), KC_ERR_BUFFER);
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    assert_eq!((read(short.as_mut_ptr(), short.len(), &mut written), written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(read(short.as_mut_ptr(), 0, core::ptr::null_mut()), KC_ERR_ARGUMENT);
    assert_eq!(kc_close(wallet), KC_OK);
}


// ------------------------------------------------- the split backup (7a)

/// Argon2id at the cheapest numbers `ShareKdf.fromJson` reads, so the tests
/// are about where the shares go, not how hard a key is to guess.
const CHEAP_LABELS: &str =
    r#"{"bid":"0123456789abcdef0123456789abcdef","at":"2026-11-14T12:00:00.000Z","m":8192,"t":1,"p":1}"#;

fn backup(handle: u64, threshold: u8, count: u8, paper: u8, password: &str, labels: &str) -> Result<serde_json::Value, i32> {
    let mut out = vec![0u8; 64 * 1024];
    let mut len = usize::MAX;
    let code = unsafe {
        kc_slip39_backup(
            handle,
            threshold,
            count,
            paper,
            password.as_ptr(),
            password.len(),
            labels.as_ptr(),
            labels.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    if code != KC_OK {
        return Err(code);
    }
    Ok(serde_json::from_slice(&out[..len]).expect("JSON"))
}

/// The bodies a store would hold: the core's fields and the caller's labels,
/// as `SealedShare.toJson` writes version 4.
fn bodies(made: &serde_json::Value, count: u8) -> serde_json::Value {
    let labels: serde_json::Value = serde_json::from_str(CHEAP_LABELS).unwrap();
    serde_json::Value::Array(
        made.as_array()
            .unwrap()
            .iter()
            .map(|s| {
                serde_json::json!({
                    "v": 4, "set": s["set"], "bid": labels["bid"], "g": s["g"], "m": s["m"],
                    "t": s["t"], "n": count, "salt": s["salt"],
                    "kdf": {"alg": "argon2id", "m": 8192, "t": 1, "p": 1},
                    "ct": s["ct"], "at": labels["at"],
                })
            })
            .collect(),
    )
}

fn check(handle: u64, shares: &serde_json::Value, paper: &str, threshold: u8, password: &str) -> Result<bool, i32> {
    let shares = serde_json::to_vec(shares).unwrap();
    let mut out = 0xa5u8;
    let code = unsafe {
        kc_slip39_check(
            handle,
            shares.as_ptr(),
            shares.len(),
            if paper.is_empty() { core::ptr::null() } else { paper.as_ptr() },
            paper.len(),
            threshold,
            password.as_ptr(),
            password.len(),
            &mut out,
        )
    };
    if code == KC_OK {
        assert!(out <= 1, "an answer of {out}");
        Ok(out == 1)
    } else {
        assert_eq!(out, 0, "a refusal left an answer");
        Err(code)
    }
}

#[test]
fn a_backup_made_in_the_core_restores_from_every_pair_and_only_the_paper_share_shows_its_words() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let made = backup(wallet, 2, 3, 1, "a long password", CHEAP_LABELS).unwrap();
    let shares = made.as_array().unwrap();
    assert_eq!(shares.len(), 3);
    for (i, s) in shares.iter().enumerate() {
        assert_eq!(s["m"], i as u64);
        assert_eq!(s["t"], 2);
        assert_eq!(s["set"], shares[0]["set"], "one set");
        assert_eq!(s.get("w").is_some(), i == 1, "words only for the paper share");
    }
    let words = shares[1]["w"].as_str().unwrap();
    let share = slip39::decode_share(words).unwrap();
    assert_eq!(share.member_index, 1);
    assert_eq!(share.set_id_hex(), shares[1]["set"].as_str().unwrap());

    let all = bodies(&made, 3);
    assert_eq!(check(wallet, &all, "", 2, "a long password"), Ok(true));
    // Two in the stores and the paper share typed back.
    let two = serde_json::Value::Array(vec![all[0].clone(), all[2].clone()]);
    assert_eq!(check(wallet, &two, words, 2, "a long password"), Ok(true));
    // One store and nothing else is short of the threshold.
    let one = serde_json::Value::Array(vec![all[0].clone()]);
    assert_eq!(check(wallet, &one, "", 2, "a long password"), Ok(false));
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_backup_restores_this_phrase_and_no_other() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    let made = backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap();
    assert!(made.as_array().unwrap().iter().all(|s| s.get("w").is_none()), "no paper, no words");
    let all = bodies(&made, 3);
    assert_eq!(check(wallet, &all, "", 2, "pw"), Ok(true));
    assert_eq!(check(other, &all, "", 2, "pw"), Ok(false), "another wallet's backup");
    assert_eq!(check(wallet, &all, "", 2, "wrong"), Ok(false), "nothing opens");
    // A share of another backup of the same phrase does not combine with these.
    let again = bodies(&backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap(), 3);
    let mixed = serde_json::Value::Array(vec![all[0].clone(), again[1].clone()]);
    assert_eq!(check(wallet, &mixed, "", 2, "pw"), Ok(false));
    // Every pair, not the first: two of this backup and a third of the other
    // restore as (0, 1) and fail as (0, 2).
    let third = serde_json::Value::Array(vec![all[0].clone(), all[1].clone(), again[2].clone()]);
    assert_eq!(check(wallet, &third, "", 2, "pw"), Ok(false), "a later pair fails");
    // An edited label is not counted, as `ShareBackup._verify` counts it:
    // one unreadable copy is not a failed backup while the others make the
    // threshold; two edited leave one, short of it.
    let mut edited = all.clone();
    edited[2]["n"] = serde_json::json!(5);
    assert_eq!(check(wallet, &edited, "", 2, "pw"), Ok(true), "the other two still make it");
    edited[1]["at"] = serde_json::json!("2026-11-15T12:00:00.000Z");
    assert_eq!(check(wallet, &edited, "", 2, "pw"), Ok(false), "one left of three");
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(kc_close(other), KC_OK);
}

#[test]
fn three_of_five_needs_every_triple() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let all = bodies(&backup(wallet, 3, 5, 255, "pw", CHEAP_LABELS).unwrap(), 5);
    assert_eq!(check(wallet, &all, "", 3, "pw"), Ok(true));
    let two = serde_json::Value::Array(all.as_array().unwrap()[..2].to_vec());
    assert_eq!(check(wallet, &two, "", 3, "pw"), Ok(false));
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn the_backup_refuses_what_share_backup_does_not_offer() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    for (t, n, paper) in [(1u8, 3u8, 255u8), (4, 3, 255), (2, 17, 255), (2, 3, 3)] {
        assert_eq!(backup(wallet, t, n, paper, "pw", CHEAP_LABELS).err(), Some(KC_ERR_ARGUMENT), "{t} of {n}, paper {paper}");
    }
    for labels in [
        r#"{"bid":null,"at":"2026-11-14T12:00:00.000Z","m":1048576,"t":1,"p":1}"#,
        r#"{"bid":"x","at":"2026-11-14T12:00:00.000Z","m":8192,"t":1,"p":1}"#,
        r#"{"bid":null,"at":"\"}","m":8192,"t":1,"p":1}"#,
        r#"not json"#,
    ] {
        assert_eq!(backup(wallet, 2, 3, 255, "pw", labels).err(), Some(KC_ERR_ARGUMENT), "{labels}");
    }
    let key = open_key(KC_CURVE_SECP256K1, &[7u8; 32]).unwrap();
    assert_eq!(backup(key, 2, 3, 255, "pw", CHEAP_LABELS).err(), Some(KC_ERR_KIND));
    assert_eq!(check(key, &serde_json::json!([]), "", 2, "pw"), Err(KC_ERR_KIND));
    assert_eq!(check(wallet, &serde_json::json!({}), "", 2, "pw"), Err(KC_ERR_ARGUMENT));
    assert_eq!(check(wallet, &serde_json::json!([]), "", 1, "pw"), Err(KC_ERR_ARGUMENT));
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).err(), Some(KC_ERR_HANDLE));
}

#[test]
fn a_short_buffer_is_told_the_length_and_written_nothing() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let mut out = vec![0xaau8; 16];
    let mut len = 0usize;
    let code = unsafe {
        kc_slip39_backup(wallet, 2, 3, 255, b"pw".as_ptr(), 2, CHEAP_LABELS.as_ptr(), CHEAP_LABELS.len(), out.as_mut_ptr(), out.len(), &mut len)
    };
    assert_eq!(code, KC_ERR_BUFFER);
    assert!(len > 16);
    assert!(out.iter().all(|b| *b == 0xaa));
    assert_eq!(kc_close(wallet), KC_OK);
}

// ------------------------------------------------ the restore in the core (7b)

/// [`kc_slip39_restore`]'s answer: the session, or the refusal with how many
/// were needed and how many read.
fn restore(bodies: &serde_json::Value, extra: &[&str], min: u8, password: &str) -> Result<u64, (i32, u8, u8)> {
    let shares = serde_json::to_vec(bodies).unwrap();
    let extra = serde_json::to_vec(&extra).unwrap();
    let (mut handle, mut needed, mut read) = (u64::MAX, 0xa5u8, 0xa5u8);
    let code = unsafe {
        kc_slip39_restore(
            shares.as_ptr(), shares.len(), extra.as_ptr(), extra.len(), min,
            password.as_ptr(), password.len(), &mut handle, &mut needed, &mut read,
        )
    };
    if code == KC_OK {
        assert_ne!(handle, 0);
        Ok(handle)
    } else {
        assert_eq!(handle, 0, "a refusal left a handle");
        Err((code, needed, read))
    }
}

fn sessions_match(a: u64, b: u64) -> Result<bool, i32> {
    let mut out = 0xa5u8;
    let code = unsafe { kc_matches_session(a, b, &mut out) };
    if code == KC_OK { Ok(out == 1) } else { assert_eq!(out, 0); Err(code) }
}

#[test]
fn a_backup_restores_into_a_session_that_is_this_wallet() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let other = open(ABANDON.as_bytes()).unwrap();
    let made = backup(wallet, 2, 3, 2, "pw", CHEAP_LABELS).unwrap();
    let all = bodies(&made, 3);
    let restored = restore(&all, &[], 0, "pw").unwrap();
    assert_eq!(sessions_match(restored, wallet), Ok(true));
    assert_eq!(sessions_match(restored, other), Ok(false));
    // Two in the stores is enough; one and the paper words too.
    let one = serde_json::Value::Array(vec![all[1].clone()]);
    let paper = made[2]["w"].as_str().unwrap();
    let from_paper = restore(&one, &[paper], 0, "pw").unwrap();
    assert_eq!(sessions_match(from_paper, wallet), Ok(true));
    // The typed words of a share the store also holds count once.
    let shouted = made[2]["w"].as_str().unwrap().to_uppercase().replace(' ', "  ");
    let only = serde_json::Value::Array(vec![]);
    assert_eq!(restore(&only, &[paper, &shouted], 0, "pw").err().map(|e| (e.0, e.2)), Some((KC_ERR_SHARE, 1)));
    for h in [wallet, other, restored, from_paper] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

#[test]
fn a_restore_that_cannot_says_why() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let all = bodies(&backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap(), 3);
    // Nothing opens: the password.
    assert_eq!(restore(&all, &[], 0, "wrong").err(), Some((KC_ERR_SHARE_PASSWORD, 2, 0)));
    // One opens and another was edited: the edit, with one read.
    let mut edited = serde_json::Value::Array(vec![all[0].clone(), all[1].clone()]);
    edited[1]["n"] = serde_json::json!(5);
    assert_eq!(restore(&edited, &[], 0, "pw").err(), Some((KC_ERR_SHARE_ALTERED, 2, 1)));
    // One alone, nothing wrong with it: too few.
    let one = serde_json::Value::Array(vec![all[0].clone()]);
    assert_eq!(restore(&one, &[], 0, "pw").err(), Some((KC_ERR_SHARE, 2, 1)));
    // A paper note's threshold raises what is needed.
    assert_eq!(restore(&all, &[], 3, "pw").err(), Some((KC_ERR_SHARE, 3, 3)));
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn every_set_is_tried_until_one_restores() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let good = bodies(&backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap(), 3);
    let stranger = bodies(&backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap(), 3);
    // Another backup's share first: (it, good 1) and (it, good 2) fail, (good
    // 1, good 2) restores.
    let mixed = serde_json::Value::Array(vec![stranger[0].clone(), good[1].clone(), good[2].clone()]);
    let restored = restore(&mixed, &[], 0, "pw").unwrap();
    assert_eq!(sessions_match(restored, wallet), Ok(true));
    // Two shares of two backups: nothing restores.
    let two = serde_json::Value::Array(vec![stranger[0].clone(), good[1].clone()]);
    assert_eq!(restore(&two, &[], 0, "pw").err(), Some((KC_ERR_SHARE, 2, 2)));
    assert_eq!(kc_close(restored), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_share_sealed_before_argon2id_still_restores() {
    let _abi = abi();
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use base64ct::{Base64, Encoding};
    // A version 2 body as the app wrote one before 11 October 2026: PBKDF2-
    // HMAC-SHA256 at 600,000 rounds, the words alone under AES-256-GCM.
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let made = backup(wallet, 2, 3, 0, "pw", CHEAP_LABELS).unwrap();
    let words = made[0]["w"].as_str().unwrap();
    let salt = [7u8; 32];
    let mut key = [0u8; 32];
    slip39::pbkdf2_hmac_sha256(b"pw", &salt, 600_000, &mut key).unwrap();
    let nonce = [9u8; 12];
    let mut plain = words.as_bytes().to_vec();
    let tag = Aes256Gcm::new(GenericArray::from_slice(&key))
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut plain)
        .unwrap();
    let mut record = nonce.to_vec();
    record.extend_from_slice(&plain);
    record.extend_from_slice(&tag);
    let old = serde_json::json!({
        "v": 2, "set": made[0]["set"], "g": 0, "m": 0, "t": 2, "n": 3,
        "salt": Base64::encode_string(&salt), "ct": Base64::encode_string(&record),
        "at": "2026-10-01T00:00:00.000Z",
    });
    let newer = bodies(&made, 3)[1].clone();
    let restored = restore(&serde_json::json!([old, newer]), &[], 0, "pw").unwrap();
    assert_eq!(sessions_match(restored, wallet), Ok(true));
    assert_eq!(kc_close(restored), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn the_restore_and_the_comparison_refuse_what_they_should() {
    let _abi = abi();
    let key = open_key(KC_CURVE_SECP256K1, &[7u8; 32]).unwrap();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(sessions_match(wallet, key), Err(KC_ERR_KIND));
    assert_eq!(sessions_match(key, wallet), Err(KC_ERR_KIND));
    assert_eq!(restore(&serde_json::json!({}), &[], 0, "pw").err().map(|e| e.0), Some(KC_ERR_ARGUMENT));
    let extra = br#"[1]"#;
    let (mut h, mut n, mut r) = (0u64, 0u8, 0u8);
    let code = unsafe { kc_slip39_restore(b"[]".as_ptr(), 2, extra.as_ptr(), extra.len(), 0, b"p".as_ptr(), 1, &mut h, &mut n, &mut r) };
    assert_eq!(code, KC_ERR_ARGUMENT);
    assert_eq!(kc_close(key), KC_OK);
    assert_eq!(kc_close(wallet), KC_OK);
}

// ------------------------------------- the vault's record made in the core (7b)

/// [`kc_seal_phrase`]'s record, or its refusal with the length it wrote.
fn seal_phrase(handle: u64, key: &[u8], cap: usize) -> Result<Vec<u8>, (i32, usize)> {
    let mut out = vec![0xa5u8; cap];
    let mut len = usize::MAX;
    let code = unsafe {
        kc_seal_phrase(handle, key.as_ptr(), key.len(),
            if cap == 0 { core::ptr::null_mut() } else { out.as_mut_ptr() }, cap, &mut len)
    };
    if code == KC_OK {
        out.truncate(len);
        Ok(out)
    } else {
        Err((code, len))
    }
}

#[test]
fn a_restored_wallet_is_sealed_as_the_vault_stores_it() {
    let _abi = abi();
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit};
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let made = backup(wallet, 2, 3, 255, "pw", CHEAP_LABELS).unwrap();
    let restored = restore(&bodies(&made, 3), &[], 0, "pw").unwrap();
    let key = [0x42u8; 32];
    let record = seal_phrase(restored, &key, 256).unwrap();
    // The layout `CryptoUtils.decryptBytes` reads, and the stored form inside:
    // lowercase words, single spaces — the phrase itself, byte for byte.
    assert_eq!(record.len(), 12 + LEGAL.len() + 16);
    let (nonce, rest) = record.split_at(12);
    let (body, tag) = rest.split_at(rest.len() - 16);
    let mut plain = body.to_vec();
    Aes256Gcm::new(GenericArray::from_slice(&key))
        .decrypt_in_place_detached(GenericArray::from_slice(nonce), b"", &mut plain, GenericArray::from_slice(tag))
        .unwrap();
    assert_eq!(plain, LEGAL.as_bytes());
    // And it is what an unlock opens: the same wallet.
    let reopened = open_sealed(&record, &key).unwrap();
    assert_eq!(sessions_match(reopened, wallet), Ok(true));
    // A fresh nonce each time: two records of one phrase differ.
    let again = seal_phrase(restored, &key, 256).unwrap();
    assert_ne!(again[..12], record[..12]);
    assert_ne!(again, record);
    // Twenty-four words too.
    let long = open(ABANDON_24.as_bytes()).unwrap();
    let long_record = seal_phrase(long, &key, 256).unwrap();
    assert_eq!(long_record.len(), 12 + ABANDON_24.len() + 16);
    let long_reopened = open_sealed(&long_record, &key).unwrap();
    assert_eq!(sessions_match(long_reopened, long), Ok(true));
    for h in [wallet, restored, reopened, long, long_reopened] {
        assert_eq!(kc_close(h), KC_OK);
    }
}

/// The 24-word phrase of all-zero entropy.
const ABANDON_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon art";

#[test]
fn the_vaults_record_refuses_what_it_should() {
    let _abi = abi();
    let wallet = open(LEGAL.as_bytes()).unwrap();
    let key = [7u8; 32];
    // A key of another length, before the session is looked at.
    assert_eq!(seal_phrase(wallet, &key[..31], 256).err().map(|e| e.0), Some(KC_ERR_ARGUMENT));
    // Too little room: the length it needs, and nothing written.
    assert_eq!(seal_phrase(wallet, &key, 20).err(), Some((KC_ERR_BUFFER, 12 + LEGAL.len() + 16)));
    assert_eq!(seal_phrase(wallet, &key, 0).err(), Some((KC_ERR_BUFFER, 12 + LEGAL.len() + 16)));
    // One imported key has no phrase.
    let one = open_key(KC_CURVE_SECP256K1, &[7u8; 32]).unwrap();
    assert_eq!(seal_phrase(one, &key, 256).err().map(|e| e.0), Some(KC_ERR_KIND));
    // A closed session.
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(seal_phrase(wallet, &key, 256).err().map(|e| e.0), Some(KC_ERR_HANDLE));
    // No room for the length.
    let code = unsafe { kc_seal_phrase(one, key.as_ptr(), 32, core::ptr::null_mut(), 0, core::ptr::null_mut()) };
    assert_eq!(code, KC_ERR_ARGUMENT);
    assert_eq!(kc_close(one), KC_OK);
}

// ------------------------- an imported key opened from its record (hole 2)

fn open_sealed_key(curve: i32, sealed: &[u8], key: &[u8]) -> Result<u64, i32> {
    let mut handle = u64::MAX;
    let code = unsafe {
        kc_open_sealed_key(curve, sealed.as_ptr(), sealed.len(), key.as_ptr(), key.len(), &mut handle)
    };
    if code == KC_OK {
        assert_ne!(handle, 0);
        Ok(handle)
    } else {
        assert_eq!(handle, 0, "a refusal left a handle");
        Err(code)
    }
}

#[test]
fn an_imported_key_opens_from_its_record_as_the_key_itself() {
    let _abi = abi();
    let account = [9u8; 32];
    let secret = [7u8; 32];
    // The record `VaultKeeper.sealKeyWithAccountKey` writes: the wallet's layout.
    let record = seal::seal(&secret, &account).unwrap();
    for curve in [KC_CURVE_SECP256K1_EVM, KC_CURVE_SECP256K1_BITCOIN, KC_CURVE_SECP256K1_TRON] {
        let from_record = open_sealed_key(curve, &record, &account).unwrap();
        let direct = open_key(curve, &secret).unwrap();
        assert_eq!(
            public_key(from_record, "m", KC_PUBLIC_KEY_COMPRESSED),
            public_key(direct, "m", KC_PUBLIC_KEY_COMPRESSED),
            "curve {curve}"
        );
        assert_eq!(kc_close(from_record), KC_OK);
        assert_eq!(kc_close(direct), KC_OK);
    }
    // An ed25519 key too, Solana's.
    let solana = open_sealed_key(KC_CURVE_ED25519_SOLANA, &record, &account).unwrap();
    assert_eq!(kc_close(solana), KC_OK);
}

#[test]
fn an_imported_keys_record_refuses_what_it_should() {
    let _abi = abi();
    let account = [9u8; 32];
    let record = seal::seal(&[7u8; 32], &account).unwrap();
    // Another account key, a changed byte, a record too short to be one.
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &record, &[8u8; 32]), Err(KC_ERR_SEAL));
    let mut changed = record.clone();
    changed[20] ^= 1;
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &changed, &account), Err(KC_ERR_SEAL));
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &record[..20], &account), Err(KC_ERR_SEAL));
    // A key of another length; an unknown curve; bytes that are no secp256k1 key.
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &record, &account[..31]), Err(KC_ERR_ARGUMENT));
    assert_eq!(open_sealed_key(9999, &record, &account), Err(KC_ERR_ARGUMENT));
    let zero = seal::seal(&[0u8; 32], &account).unwrap();
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &zero, &account), Err(KC_ERR_KEY));
    // A record of 31 bytes opens, and is not a key.
    let short = seal::seal(&[7u8; 31], &account).unwrap();
    assert_eq!(open_sealed_key(KC_CURVE_SECP256K1_EVM, &short, &account), Err(KC_ERR_ARGUMENT));
    // No room for the handle.
    let code = unsafe {
        kc_open_sealed_key(KC_CURVE_SECP256K1_EVM, record.as_ptr(), record.len(), account.as_ptr(), 32, core::ptr::null_mut())
    };
    assert_eq!(code, KC_ERR_ARGUMENT);
}

// --- Zcash, transparent (15 November 2026) ----------------------------------

/// Transparent version 5 transactions the network accepted under branch
/// `0x77190AD9`, read from zec.rocks' lightwalletd on 15 November 2026 with
/// the coin each input spends (its amount and script, from the transaction
/// that made it): (height, txid as explorers write it, the transaction, the
/// coins).
const ZCASH_CHAIN: [(u32, &str, &str, &[(u64, &str)]); 6] = [
    (3576097, "3d873b79e434e86c103c4f69a9897813c35319890fed44a5c1a4a4415af277d1", "050000800a27a726d90a1977000000000000000002e34c3418c6e43f8c73ece1555a8f8c226293b57d097fdefb7072f78cbf22d6c7010000006a4730440220672b4401664116469231df4d2154978e53460efa051257d9e00016584e92198d022073d0272895487539072353060bf1b2507a556c15b0952f2ad97f9ce9b2bb14680121026bdd6545b9c13dc72e50af158d983f5fab0a5fb302c491cd853faf9f269b2025feffffff757ccc1806cc1c478f5b7374b152c5aeb76c9092666173f9dc9a03a91933e0db010000006a47304402201cc82c566c0e78eb20cf2c0212520f15b2e62965dde24a7391b287a98cdfa04f02202c09542de6d19dcdf070eb3e837881db4abd0efe72880a57fc7439ef74b0d8fd0121026bdd6545b9c13dc72e50af158d983f5fab0a5fb302c491cd853faf9f269b2025feffffff0250da3400000000001976a914ae4cf11c7c30b1f46a7331cc40af2fcbf8c8b87388acb142a400000000001976a914cc2109154e9f1096dff0bef2bbd27e6b92dc49ed88ac000000", &[(13469626, "76a914cc2109154e9f1096dff0bef2bbd27e6b92dc49ed88ac"), (777811, "76a914cc2109154e9f1096dff0bef2bbd27e6b92dc49ed88ac")]),
    (3576102, "161456c9a6d1ca515d658dcd34e70d7adbb180ab996a159fcd61ef4cc9d00d46", "050000800a27a726d90a1977000000000000000004ad6edad41d265d280b7ca0bdd9e6235ddfced6294fcb7b86fadb415c29b28cf6000000006b483045022100d8b9218cdc086adb5cc1e626d38ba91c9a7d70543a449ef0c6fada758c3b20d60220177a9e924267dbd63b33c25bf7f2c130dbccaa6eeb6a075a1071d607a0df9dbb012103d5619b12b9b0135a0979e37c9dd6f550e33012d96c94f5aa59303b743d9f5b5effffffff590d19f0f41291c87314e9d25d50ab8c43d10fcccf1ad9c036aea54c06587815010000006b483045022100e4ae7240e24e58b1b6c151af560c8597feb5051ae6b30922ea84842850645d2a02201d8bf6de41e500914fd3832e3b2c407c31d2b6d5d320c8191c60e0fd2ca839ec012103ec57e53d52e48f6e4bec3728f70df6e9e6c7c30bee96b0cf1819468346a2a81bfffffffff83b8b3783919a8d48448db79a4d979da322d2cff54bad5e60486d83ba8e222b000000006b483045022100a6de4c4f1e17f9a72a3526477463843daa980913d4399b6c53dce9d2ee4df01602200f4081f72ae3cfa4d426acb877538c9be9708726efc9a038da09b37997132092012103d5619b12b9b0135a0979e37c9dd6f550e33012d96c94f5aa59303b743d9f5b5effffffffe7b7cae2f4853a0848ae9f3df6abc99695fa465c6f11fd63313f3cc1722c905c000000006a47304402205e34f436e44903ef11364cb370cb81e8d9699ceeed54c938287f5163c188fc8a022027e7cc355b53111ea5dcc5e89c7b965d74e781398762c673d6d1bfbabcb28058012103d5619b12b9b0135a0979e37c9dd6f550e33012d96c94f5aa59303b743d9f5b5effffffff01d20ff8f2020000001976a9149f68dd83709ae1bc8bc91d7068f1d4d6418470b688ac000000", &[(6375275029, "76a9149f68dd83709ae1bc8bc91d7068f1d4d6418470b688ac"), (6031879191, "76a914e878fb14bed2358621f76f3b3c36df2dd992797b88ac"), (238623245, "76a9149f68dd83709ae1bc8bc91d7068f1d4d6418470b688ac"), (20520377, "76a9149f68dd83709ae1bc8bc91d7068f1d4d6418470b688ac")]),
    (3576111, "3975ca1532d88c757cbcc9a5178b607c2acfdd9e86244846147d3346f50fb630", "050000800a27a726d90a197700000000a591360002db1a70e75db46e962e495284fb1c2e83a3ecc5d0c5a644187d6ee304f3358d12000000006a47304402204325343e38d5aee0373aa50a01492ef9f049dc9dbf21ed64d65a3ac551259519022018e6a899ce6983e2c0bf231a8b8343ec8f8dc61c9e4f5e493ddab5f387013d310121037f6e1d54642cd4bee21e611f25edea544933eda98421dacc7b4c8e07726ac367ffffffffa0fe2c8fd78a341021bed5ca073a508880bb75636d47e9805550869d489b01eb010000006a473044022055f56ce5e5a086e114fee4a08fec6d3d9d20ee52d6854fc83c4e7fb86e03196102203747335fa8de6770ab3e378bc83326ebbfd990a7e2092ab1d469b7058cade8db012103b93579b2a5b2c93e0d0b80d701c6543cc1943447cb247151884d610fa75b5a9dffffffff0209fe2f00000000001976a91405c36092f0e2c743c7b1d5b33816b87ce832d57688ace2c50000000000001976a914bd17cac1eb825f0e288d90597cc1e2ae9cda725588ac000000", &[(3142087, "76a914443a75185f1829c17bc8af5a6b201059ffc2590b88ac"), (63796, "76a914bd17cac1eb825f0e288d90597cc1e2ae9cda725588ac")]),
    (3576127, "7d4389c9a0338b97ab1b55e433bfe775ffa51579f78e4e9ae7f2f4c5f18b8e78", "050000800a27a726d90a1977000000000000000001ba7c09304142bf19caef19b702bb3fd0c356529b62b8f761ee4052a4d5fc802f000000006a47304402205f43067f1cd2175c156b49c0f236a06febe7aa8f835a125a337cb9d90b1c569d02207a22d05ed4123f3aafe93ff99898c63a536d43b8815e36095a605be6bd74f4a00121031d38db10de4688163fa4655c5f964566e4aa1d58fdca849a75bebb0b8e53fa07ffffffff028091e305000000001976a91437fd3fe9a78c8c5c2e21fad2c9c600087eeea77f88ac3f43082a010000001976a914f34fb16b99ccd8dc40cc703a53adc32aa4f0b1d588ac000000", &[(5098970939, "76a914f34fb16b99ccd8dc40cc703a53adc32aa4f0b1d588ac")]),
    (3576130, "2b3f346c57b701a5e51256fa91e7b4ed6f263d767031093389b84e6e79c75bdf", "050000800a27a726d90a197700000000000000000130b60ff546337d14464824869eddcf2a7c608b17a5c9bc7c758cd83215ca7539000000006a47304402200226cb46a3daf00e1c2f668538a612d32d52e2bb21ecc60c091adffd89ccda030220402cddff1eb40212b909b6c477fa49e31eb7dcc2bacca6f494c57c871c0aac80012102bbd84731eb3707cdaaed9c3d00a2d46694785140f2cbe789f4d7a1ac9315646cffffffff012dad2f00000000001976a9149f087e955c052c9dc1663fb06b6ac0c2fa869f7988ac000000", &[(3145225, "76a91405c36092f0e2c743c7b1d5b33816b87ce832d57688ac")]),
    (3576132, "c17383521eec3b3d4c9f00a7b81886988784b608145402d02c2df9a21d92e513", "050000800a27a726d90a1977000000000000000001949e385cd24712044c3c71d92a36895ffbe313ca2faaa213653cd3fed0c96a37010000006a47304402207b4740d87862bf06b078028e11ae1b0c22f4c1e330c1bdf2c71fec5b177c95810220031876d3347c0c0f3dea271b0f6cd7c5f19e19cf82e2a1c0e5afcce507b4e96e0121037d06567b3b260f5eb5a077d504d532ff366e1b50faf8649fc0c2e0cc7b4042a7ffffffff02e0673500000000001976a914cd0747314145bede5b5df8b16bc1382c7c0a1cdb88ac44453000000000001976a9144b384d3e977408c7f15833fc2cfbc0c8f860a69e88ac000000", &[(6673630, "76a9146cd1a20c1411e7a0dd25db5852e0da0fdf9221c188ac")]),
];

const ZCASH_0: &str = "m/44'/133'/0'/0/0";

/// What the module's `ZcashSpend.coreRequest` writes, printed by it with its
/// own reading's id and digests (`ZcashReading.inDart`, the ZIP-244 of
/// `tx/zip244.dart`): the abandon phrase's first account spends `ab…ab01:1`
/// (80,000 zatoshi) and `ab…ab02:2` (70,000), pays 100,000 to ZIP-320's TEX
/// and 40,000 back, for a fee of 10,000, under branch `0x77190AD9` at tip
/// 3,576,131.
const ZCASH_ONE: (&str, &str, [&str; 2]) = ("11006d2f3434272f313333272f30272f302f30af000000050000800a27a726d90a1977000000006b91360002ababababababababababababababababababababababababababababababab010100000000feffffffababababababababababababababababababababababababababababababab020200000000feffffff02a0860100000000001976a9148286bf790866805397e3a947640b77a43f0b43a588ac409c0000000000001976a9149564d9fed247986b15a2f57d0b3b032eeb28476c88ac0000008038010000000000190076a9149564d9fed247986b15a2f57d0b3b032eeb28476c88ac7011010000000000190076a9149564d9fed247986b15a2f57d0b3b032eeb28476c88ac01001027000000000000", "ea436e57a9a551ab5b50c7a55fc28915ad50c1d52bbf35c0519c781a618fed97", ["5daa3997c5ceb282edc0e05315069bf06c22987176951f248305c7a99baf82b8", "0dc4e563a824d603f96a9a339d55533a0efcf58c3a83365e9b67247455b51ba9"]);

/// The abandon phrase's first Zcash address, as `blockchain_utils`' P2PKH
/// encoder spells it under `0x1CB8` (the module's own test pinned it before
/// 2 October 2026); and ZIP-320's reference pair of a `t1` and its TEX.
const ZCASH_OWN: &str = "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F";
const ZIP320_PAIR: (&str, &str) = ("t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC", "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte");

/// The branch id the network stated on 15 November 2026.
const ZCASH_BRANCH: u32 = 0x7719_0AD9;

fn read_zcash(handle: u64, request: &[u8]) -> Result<serde_json::Value, i32> {
    let mut needed = usize::MAX;
    let code = unsafe {
        kc_zcash_read_transaction(handle, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    if code != KC_ERR_BUFFER {
        return Err(code);
    }
    let mut out = vec![0u8; needed];
    let mut written = 0usize;
    let code = unsafe {
        kc_zcash_read_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len(), &mut written)
    };
    assert_eq!((code, written), (KC_OK, needed));
    Ok(serde_json::from_slice(&out).unwrap())
}

/// Every input of [request] signed: per input, the digest and the signature.
fn zcash_sign(handle: u64, request: &[u8]) -> Result<Vec<([u8; 32], [u8; 64])>, i32> {
    let inputs = crate::zcash::Request::read(request).map(|r| r.inputs.len()).unwrap_or(1);
    let mut out = vec![0u8; inputs * 96];
    let code = unsafe { kc_zcash_sign_transaction(handle, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len()) };
    if code != KC_OK {
        return Err(code);
    }
    Ok(out
        .chunks(96)
        .map(|c| (c[..32].try_into().unwrap(), c[32..].try_into().unwrap()))
        .collect())
}

fn p2pkh(hash: &[u8]) -> Vec<u8> {
    [&[0x76, 0xa9, 0x14][..], hash, &[0x88, 0xac]].concat()
}

fn p2sh(hash: &[u8]) -> Vec<u8> {
    [&[0xa9, 0x14][..], hash, &[0x87]].concat()
}

/// The abandon phrase's first Zcash key's script.
fn zcash_own_script() -> Vec<u8> {
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let key = keys::derive(&seed[..], &path(ZCASH_0)).unwrap();
    crate::zcash::own_script(&key).to_vec()
}

/// One input as the request carries it: the outpoint, the `scriptSig`, the
/// sequence, and the coin.
#[derive(Clone)]
struct ZcashIn {
    txid: [u8; 32],
    index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
    amount: u64,
    script: Vec<u8>,
}

fn zcash_in(txid: u8, index: u32, amount: u64) -> ZcashIn {
    ZcashIn { txid: [txid; 32], index, script_sig: Vec::new(), sequence: 0xFFFF_FFFE, amount, script: zcash_own_script() }
}

/// The transaction's header and tail, each as the module writes it unless a
/// test says otherwise.
#[derive(Clone)]
struct ZcashTx {
    header: u32,
    group: u32,
    branch: u32,
    lock_time: u32,
    expiry: u32,
    tail: Vec<u8>,
}

fn zcash_tx() -> ZcashTx {
    ZcashTx { header: 0x8000_0005, group: 0x26A7_270A, branch: ZCASH_BRANCH, lock_time: 0, expiry: 3_576_172, tail: vec![0, 0, 0] }
}

/// A request in `kc_zcash_sign_transaction`'s layout: the tests' own writer.
fn zcash_request(path: &str, tx: &ZcashTx, inputs: &[ZcashIn], outputs: &[(u64, Vec<u8>, u8)], fee: u64) -> Vec<u8> {
    let mut t = Vec::new();
    for word in [tx.header, tx.group, tx.branch, tx.lock_time, tx.expiry] {
        t.extend(word.to_le_bytes());
    }
    t.push(inputs.len() as u8);
    for i in inputs {
        t.extend(i.txid);
        t.extend(i.index.to_le_bytes());
        t.push(i.script_sig.len() as u8);
        t.extend(&i.script_sig);
        t.extend(i.sequence.to_le_bytes());
    }
    t.push(outputs.len() as u8);
    for (amount, script, _) in outputs {
        t.extend(amount.to_le_bytes());
        t.push(script.len() as u8);
        t.extend(script);
    }
    t.extend(&tx.tail);
    let mut r = Vec::new();
    r.extend((path.len() as u16).to_le_bytes());
    r.extend(path.as_bytes());
    r.extend((t.len() as u32).to_le_bytes());
    r.extend(t);
    for i in inputs {
        r.extend(i.amount.to_le_bytes());
        r.extend((i.script.len() as u16).to_le_bytes());
        r.extend(&i.script);
    }
    r.extend(outputs.iter().map(|(_, _, spelt)| *spelt));
    r.extend(fee.to_le_bytes());
    r
}

/// The pushes of a pay-to-public-key-hash `scriptSig`: the signature with its
/// hash type, and the public key.
fn script_sig_pushes(script_sig: &[u8]) -> (&[u8], &[u8]) {
    let n = usize::from(script_sig[0]);
    let (signature, rest) = script_sig[1..].split_at(n);
    let m = usize::from(rest[0]);
    assert_eq!(rest.len(), 1 + m, "two pushes and nothing else");
    (signature, &rest[1..])
}

#[test]
fn zcash_digests_agree_with_transactions_the_network_accepted() {
    // The id the network gave each transaction, and every input's signature
    // verified over the digest computed here: a digest wrong in any part —
    // a personalisation, the amounts, the scripts, the branch id — verifies
    // nothing a real wallet signed.
    let mut inputs_checked = 0;
    for (height, txid, tx, coins) in ZCASH_CHAIN {
        let tx = hex(tx);
        let scripts: Vec<Vec<u8>> = coins.iter().map(|(_, s)| hex(s)).collect();
        let coins: Vec<(u64, &[u8])> = coins.iter().zip(&scripts).map(|((a, _), s)| (*a, s.as_slice())).collect();
        let (request, script_sigs) = crate::zcash::read_signed(&tx, &coins);
        let mut id = crate::zcash::txid(&request);
        id.reverse();
        assert_eq!(to_hex(&id), txid, "{height}: the id");
        for (i, script_sig) in script_sigs.iter().enumerate() {
            let (signature, public) = script_sig_pushes(script_sig);
            assert_eq!(signature.last(), Some(&0x01), "{height}/{i}: SIGHASH_ALL");
            let public = PublicKey::from_slice(public).unwrap();
            assert_eq!(p2pkh(&crate::bitcoin::hash160(&public.serialize())), scripts[i], "{height}/{i}: its own coin");
            let mut signature = Signature::from_der(&signature[..signature.len() - 1]).unwrap();
            signature.normalize_s();
            let digest = crate::zcash::sighash(&request, i);
            signature
                .verify(Message::from_digest(digest), &public)
                .unwrap_or_else(|_| panic!("{height}/{i}: the signature is over the digest computed here"));
            // And not over the digest of a coin worth a zatoshi more.
            let mut more = coins.clone();
            more[i].0 += 1;
            let (moved, _) = crate::zcash::read_signed(&tx, &more);
            assert!(signature.verify(Message::from_digest(crate::zcash::sighash(&moved, i)), &public).is_err());
            inputs_checked += 1;
        }
    }
    assert_eq!(inputs_checked, 11);
}

#[test]
fn the_tests_writer_and_the_core_read_what_the_zcash_module_writes() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let own = zcash_own_script();
    let tex_hash = base58_payload(ZIP320_PAIR.0)[2..].to_vec();
    let coin = |last: u8, index: u32, amount: u64| {
        let mut txid = [0xab; 32];
        txid[31] = last;
        ZcashIn { txid, index, ..zcash_in(0, 0, amount) }
    };
    let ours = zcash_request(
        ZCASH_0,
        &ZcashTx { expiry: 3_576_171, ..zcash_tx() },
        &[coin(1, 1, 80_000), coin(2, 2, 70_000)],
        &[(100_000, p2pkh(&tex_hash), 1), (40_000, own, 0)],
        10_000,
    );
    assert_eq!(to_hex(&ours), ZCASH_ONE.0, "the tests' writer writes what the module writes");
    // And the core reads it as the module's own ZIP-244 does.
    let reading = read_zcash(wallet, &ours).unwrap();
    assert_eq!(reading["txid"], ZCASH_ONE.1);
    assert_eq!(reading["sighashes"], serde_json::json!(ZCASH_ONE.2));
    assert_eq!(reading["outputs"][0]["address"], ZIP320_PAIR.1);
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn zcash_addresses_are_the_published_spellings() {
    assert_eq!(crate::zcash::transparent_address(crate::zcash::P2PKH_VERSION, &zcash_own_script()[3..23]), ZCASH_OWN);
    // ZIP-320's pair: the same twenty bytes under base58check and Bech32m.
    let hash = base58_payload(ZIP320_PAIR.0);
    assert_eq!(&hash[..2], &crate::zcash::P2PKH_VERSION);
    assert_eq!(crate::zcash::transparent_address(crate::zcash::P2PKH_VERSION, &hash[2..]), ZIP320_PAIR.0);
    assert_eq!(crate::zcash::tex_address(&hash[2..]), ZIP320_PAIR.1);
}

/// The 22 bytes of a `t…` address before its checksum.
fn base58_payload(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes() {
        let mut carry = ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
        for b in bytes.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let (payload, check) = bytes.split_at(bytes.len() - 4);
    assert_eq!(&Sha256::digest(Sha256::digest(payload))[..4], check);
    payload.to_vec()
}

#[test]
fn a_zcash_send_is_read_with_its_addresses_its_change_and_its_sighashes() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let own = zcash_own_script();
    let tex_hash = base58_payload(ZIP320_PAIR.0)[2..].to_vec();
    let request = zcash_request(
        ZCASH_0,
        &zcash_tx(),
        &[zcash_in(0x11, 1, 500_000_000), zcash_in(0x33, 0, 70_000)],
        &[(100_000_000, p2pkh(&tex_hash), 1), (60_000, p2sh(&[0x44; 20]), 0), (399_995_000, own.clone(), 0)],
        15_000,
    );
    let reading = read_zcash(wallet, &request).unwrap();
    assert_eq!(reading["inputs"].as_array().unwrap().len(), 2);
    assert_eq!(reading["inputs"][0]["txid"], "11".repeat(32));
    assert_eq!((reading["inputs"][0]["index"].as_u64(), reading["inputs"][0]["amount"].as_str()), (Some(1), Some("500000000")));
    assert_eq!(reading["outputs"][0]["address"], ZIP320_PAIR.1, "spelt as the person wrote it");
    assert_eq!((reading["outputs"][0]["amount"].as_str(), reading["outputs"][0]["change"].as_bool()), (Some("100000000"), Some(false)));
    assert!(reading["outputs"][1]["address"].as_str().unwrap().starts_with("t3"));
    assert_eq!(reading["outputs"][2]["address"], ZCASH_OWN);
    assert_eq!(reading["outputs"][2]["change"].as_bool(), Some(true));
    assert_eq!((reading["sent"].as_str(), reading["spent"].as_str(), reading["fee"].as_str()), (Some("100060000"), Some("500070000"), Some("15000")));
    assert_eq!(reading["expiryHeight"].as_u64(), Some(3_576_172));
    let parsed = crate::zcash::Request::read(&request).unwrap();
    let mut id = crate::zcash::txid(&parsed);
    id.reverse();
    assert_eq!(reading["txid"], to_hex(&id));
    for i in 0..2 {
        assert_eq!(reading["sighashes"][i], to_hex(&crate::zcash::sighash(&parsed, i)));
    }
    // The same outputs spelt as their scripts: a TEX only where the module
    // says the person wrote one.
    let plain = zcash_request(
        ZCASH_0,
        &zcash_tx(),
        &[zcash_in(0x11, 1, 500_000_000), zcash_in(0x33, 0, 70_000)],
        &[(100_000_000, p2pkh(&tex_hash), 0), (60_000, p2sh(&[0x44; 20]), 0), (399_995_000, own, 0)],
        15_000,
    );
    let plain = read_zcash(wallet, &plain).unwrap();
    assert_eq!(plain["outputs"][0]["address"], ZIP320_PAIR.0);
    assert_eq!(plain["txid"], reading["txid"], "the spelling is not in the transaction");
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn what_the_zcash_module_never_writes_is_refused() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let to = p2pkh(&[0x22; 20]);
    let one_in = || vec![zcash_in(0x11, 1, 10_000)];
    let pay = |tx: &ZcashTx, inputs: &[ZcashIn], outputs: &[(u64, Vec<u8>, u8)], fee: u64| {
        zcash_request(ZCASH_0, tx, inputs, outputs, fee)
    };
    let good = pay(&zcash_tx(), &one_in(), &[(5_000, to.clone(), 0)], 5_000);
    assert!(read_zcash(wallet, &good).is_ok());
    let with_tx = |edit: &dyn Fn(&mut ZcashTx)| {
        let mut tx = zcash_tx();
        edit(&mut tx);
        pay(&tx, &one_in(), &[(5_000, to.clone(), 0)], 5_000)
    };
    let with_in = |edit: &dyn Fn(&mut ZcashIn)| {
        let mut inputs = one_in();
        edit(&mut inputs[0]);
        pay(&zcash_tx(), &inputs, &[(5_000, to.clone(), 0)], 5_000)
    };
    for (why, request) in [
        ("version 4", with_tx(&|t| t.header = 0x8000_0004)),
        ("version 6", with_tx(&|t| t.header = 0x8000_0006)),
        ("no overwinter flag", with_tx(&|t| t.header = 5)),
        ("another version group", with_tx(&|t| t.group = 0x892F_2085)),
        ("a lock time", with_tx(&|t| t.lock_time = 1)),
        ("no expiry", with_tx(&|t| t.expiry = 0)),
        ("an expiry at the ceiling", with_tx(&|t| t.expiry = 500_000_000)),
        ("a Sapling spend", with_tx(&|t| t.tail = vec![1, 0, 0])),
        ("a Sapling output", with_tx(&|t| t.tail = vec![0, 1, 0])),
        ("an Orchard action", with_tx(&|t| t.tail = vec![0, 0, 1])),
        ("a byte after the Orchard count", with_tx(&|t| t.tail = vec![0, 0, 0, 0])),
        ("no input", pay(&zcash_tx(), &[], &[(5_000, to.clone(), 0)], 0)),
        ("no output", pay(&zcash_tx(), &one_in(), &[], 10_000)),
        ("a scriptSig", with_in(&|i| i.script_sig = vec![0x51])),
        ("the sequence 0xFFFFFFFF", with_in(&|i| i.sequence = 0xFFFF_FFFF)),
        ("a spent script hash", with_in(&|i| i.script = p2sh(&[3; 20]))),
        ("a spent coin of nothing", with_in(&|i| i.amount = 0)),
        ("a spent coin above the ceiling", with_in(&|i| i.amount = 21_000_000 * 100_000_000 + 1)),
        ("a key paid by its own script", pay(&zcash_tx(), &one_in(), &[(5_000, [&[0x21][..], &[2; 33], &[0xac]].concat(), 0)], 5_000)),
        ("an output of nothing", pay(&zcash_tx(), &one_in(), &[(5_000, to.clone(), 0), (0, to.clone(), 0)], 5_000)),
        ("a TEX of a script hash", pay(&zcash_tx(), &one_in(), &[(5_000, p2sh(&[3; 20]), 1)], 5_000)),
        ("a spelling of its own", pay(&zcash_tx(), &one_in(), &[(5_000, to.clone(), 2)], 5_000)),
        ("an outpoint twice", pay(&zcash_tx(), &[zcash_in(0x11, 1, 10_000), zcash_in(0x11, 1, 10_000)], &[(15_000, to.clone(), 0)], 5_000)),
        ("a fee a zatoshi more", pay(&zcash_tx(), &one_in(), &[(5_000, to.clone(), 0)], 5_001)),
        ("a fee a zatoshi less", pay(&zcash_tx(), &one_in(), &[(5_000, to.clone(), 0)], 4_999)),
        ("more paid than spent", pay(&zcash_tx(), &one_in(), &[(10_001, to.clone(), 0)], 0)),
    ] {
        assert_eq!(read_zcash(wallet, &request), Err(KC_ERR_TRANSACTION), "{why}");
        assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_TRANSACTION), "{why}, signed");
    }
    // Valid in every other respect, and not this key's own coin: held under
    // the lock, so never read, so never signed.
    let foreign = pay(&zcash_tx(), &[ZcashIn { script: to.clone(), ..zcash_in(0x11, 1, 10_000) }], &[(5_000, to.clone(), 0)], 5_000);
    assert_eq!(read_zcash(wallet, &foreign), Err(KC_ERR_TRANSACTION), "an input of another key");
    assert_eq!(zcash_sign(wallet, &foreign).map(|_| ()), Err(KC_ERR_UNSHOWN), "an input of another key, signed");
    let (input_bytes, tail_bytes) = (8 + 2 + 25, 1 + 8);
    for (why, request) in [
        ("nothing", Vec::new()),
        ("cut short", good[..good.len() - 1].to_vec()),
        ("a byte after", [good.clone(), vec![0]].concat()),
        ("no coin for the input", good[..good.len() - input_bytes - tail_bytes].to_vec()),
    ] {
        assert_eq!(read_zcash(wallet, &request), Err(KC_ERR_ARGUMENT), "{why}");
    }
    // A long CompactSize is a transaction the module did not write.
    let mut long = good.clone();
    let count_at = 2 + ZCASH_0.len() + 4 + 20;
    long.splice(count_at..count_at + 1, [0xfd, 1, 0]);
    let tx_len = u32::from_le_bytes(long[2 + ZCASH_0.len()..2 + ZCASH_0.len() + 4].try_into().unwrap()) + 2;
    long[2 + ZCASH_0.len()..2 + ZCASH_0.len() + 4].copy_from_slice(&tx_len.to_le_bytes());
    assert_eq!(read_zcash(wallet, &long), Err(KC_ERR_TRANSACTION), "a three-byte count");
    // Another network's path, or a key that is not a phrase's.
    for at in ["m/44'/0'/0'/0/0", "m/44'/133/0'/0/0", "m/49'/133'/0'/0/0", KASPA_0, DIGEST_0] {
        let request = zcash_request(at, &zcash_tx(), &one_in(), &[(5_000, to.clone(), 0)], 5_000);
        assert_eq!(read_zcash(wallet, &request).map(|_| ()), Err(KC_ERR_PATH), "{at}");
    }
    let secret = export(wallet, ZCASH_0).unwrap();
    for curve in [KC_CURVE_SECP256K1, KC_CURVE_SECP256K1_BITCOIN, KC_CURVE_SECP256K1_KASPA] {
        let key = open_key(curve, &secret).unwrap();
        assert_eq!(read_zcash(key, &zcash_request("m", &zcash_tx(), &one_in(), &[(5_000, to.clone(), 0)], 5_000)), Err(KC_ERR_KIND), "curve {curve}");
        assert_eq!(kc_close(key), KC_OK);
    }
    assert_eq!(kc_close(wallet), KC_OK);
}

#[test]
fn a_zcash_key_signs_only_a_send_read_for_a_screen() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let request = zcash_request(
        ZCASH_0,
        &zcash_tx(),
        &[zcash_in(0x55, 3, 90_000), zcash_in(0x66, 0, 60_000)],
        &[(100_000, p2pkh(&[0x22; 20]), 0), (40_000, zcash_own_script(), 0)],
        10_000,
    );
    assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "never read");
    let reading = read_zcash(wallet, &request).unwrap();
    let signed = zcash_sign(wallet, &request).unwrap();
    assert_eq!(signed.len(), 2);
    let seed = keys::seed_from_phrase(ABANDON.as_bytes(), "").unwrap();
    let key = keys::derive(&seed[..], &path(ZCASH_0)).unwrap();
    let public = keys::public_key(&key);
    let parsed = crate::zcash::Request::read(&request).unwrap();
    for (i, (sighash, signature)) in signed.iter().enumerate() {
        assert_eq!(*sighash, crate::zcash::sighash(&parsed, i), "input {i}");
        assert_eq!(reading["sighashes"][i], to_hex(sighash), "input {i}: the digest read");
        let compact = Signature::from_compact(signature).unwrap();
        compact.verify(Message::from_digest(*sighash), &public).unwrap_or_else(|_| panic!("input {i}"));
        assert!(signature[0] < 0x80, "input {i}: low R");
        let mut normal = compact;
        normal.normalize_s();
        assert_eq!(normal, compact, "input {i}: low s");
        assert_eq!(signature[..], keys::sign_digest_low_r(&key, sighash).unwrap()[..], "input {i}");
    }
    assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "signed once");

    // A Zcash key signs no bare digest, no low-R digest, no Schnorr digest,
    // no message — at its path or any account's — and exports as before.
    for at in [ZCASH_0, "m/44'/133'/3'/0/9"] {
        assert_eq!(sign(wallet, at, &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_low_r(wallet, at, &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(schnorr(wallet, at, &[7; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert_eq!(sign_personal(wallet, at, b"hello"), Err(KC_ERR_TRANSACTION_ONLY), "{at}");
        assert!(export(wallet, at).is_ok(), "{at}: its export is as before");
    }

    // A refused signature gives its reading back: another wallet, whose key
    // does not spend these inputs, is refused, and the one that read it signs.
    read_zcash(wallet, &request).unwrap();
    let other = open(LEGAL.as_bytes()).unwrap();
    assert_eq!(zcash_sign(other, &request).map(|_| ()), Err(KC_ERR_TRANSACTION));
    assert_eq!(zcash_sign(wallet, &request).unwrap(), signed, "kept after a refusal");
    assert_eq!(kc_close(other), KC_OK);

    // An imported Zcash key, opened as one, the same at `m`.
    let secret = export(wallet, ZCASH_0).unwrap();
    let imported = open_key(KC_CURVE_SECP256K1_ZCASH, &secret).unwrap();
    let inputs = [zcash_in(0x55, 3, 90_000), zcash_in(0x66, 0, 60_000)];
    let outputs = [(100_000, p2pkh(&[0x22; 20]), 0), (40_000, zcash_own_script(), 0)];
    let at_root = zcash_request("m", &zcash_tx(), &inputs, &outputs, 10_000);
    assert_eq!(zcash_sign(imported, &at_root).map(|_| ()), Err(KC_ERR_UNSHOWN));
    assert_eq!(read_zcash(imported, &at_root).unwrap()["sighashes"], reading["sighashes"]);
    assert_eq!(zcash_sign(imported, &at_root).unwrap(), signed, "as the phrase's key signs");
    let below = zcash_request("m/0", &zcash_tx(), &inputs, &outputs, 10_000);
    assert_eq!(read_zcash(imported, &below), Err(KC_ERR_PATH));
    assert_eq!(sign(imported, "m", &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(schnorr(imported, "m", &[7; 32], &[]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_low_r(imported, "m", &[7; 32]), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(sign_personal(imported, "m", b"hello"), Err(KC_ERR_TRANSACTION_ONLY));
    assert_eq!(read_kaspa(imported, &kaspa_one("m")), Err(KC_ERR_KIND), "not a Kaspa key");
    assert_eq!(export(imported, "m").unwrap(), secret);
    assert_eq!(kc_close(imported), KC_OK);
    // And a Kaspa key opened as one is not a Zcash key.
    let kaspa = open_key(KC_CURVE_SECP256K1_KASPA, &secret).unwrap();
    assert_eq!(read_zcash(kaspa, &at_root), Err(KC_ERR_KIND));
    assert_eq!(kc_close(kaspa), KC_OK);
    assert_eq!(open_key(KC_CURVE_SECP256K1_ZCASH, &[0u8; 32]), Err(KC_ERR_KEY));
    assert_eq!(kc_close(wallet), KC_OK);
    assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_HANDLE));
}

#[test]
fn a_zcash_reading_is_written_only_into_a_buffer_that_holds_it() {
    let _abi = abi();
    let wallet = open(ABANDON.as_bytes()).unwrap();
    let request = zcash_request(ZCASH_0, &zcash_tx(), &[zcash_in(0x77, 2, 50_000)], &[(40_000, p2pkh(&[0x22; 20]), 0)], 10_000);
    let mut needed = 0usize;
    let code = unsafe {
        kc_zcash_read_transaction(wallet, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(code, KC_ERR_BUFFER);
    assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "only its length asked");
    let mut short = vec![0xaau8; needed - 1];
    let mut written = 0usize;
    let code = unsafe {
        kc_zcash_read_transaction(wallet, request.as_ptr(), request.len(), short.as_mut_ptr(), short.len(), &mut written)
    };
    assert_eq!((code, written), (KC_ERR_BUFFER, needed));
    assert!(short.iter().all(|b| *b == 0xaa), "a short buffer was written to");
    assert_eq!(zcash_sign(wallet, &request).map(|_| ()), Err(KC_ERR_UNSHOWN), "a buffer too short");
    let code = unsafe {
        kc_zcash_read_transaction(wallet, request.as_ptr(), request.len(), core::ptr::null_mut(), 0, core::ptr::null_mut())
    };
    assert_eq!(code, KC_ERR_ARGUMENT);
    read_zcash(wallet, &request).unwrap();
    // The signature's buffer must be exactly 96 bytes an input.
    for length in [0usize, 95, 97, 192] {
        let mut out = vec![0u8; length];
        let code = unsafe {
            kc_zcash_sign_transaction(wallet, request.as_ptr(), request.len(), out.as_mut_ptr(), out.len())
        };
        assert_eq!(code, KC_ERR_ARGUMENT, "{length} bytes");
    }
    assert_eq!(zcash_sign(wallet, &request).map(|r| r.len()), Ok(1), "the reading still kept");
    assert_eq!(kc_close(wallet), KC_OK);
}
