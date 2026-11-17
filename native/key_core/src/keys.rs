//! The secret arithmetic, with no pointers and no table: a phrase becomes a
//! seed, a seed and a path become a key, a key signs a digest.
//!
//! Every function here is the library's, called once; what this file adds is
//! the refusals around the calls and the erasing after them.

use bip32::{ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey, Prefix};
use crypto_bigint::{ArrayEncoding, NonZero, U256};
use bip39::{Language, Mnemonic};
use curve25519_dalek::{EdwardsPoint, Scalar as EdScalar};
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, schnorr};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::Refusal;

/// A 24-word English phrase is at most 215 bytes; anything longer is not one.
pub(crate) const MAX_PHRASE_BYTES: usize = 512;

/// Twenty-five ten-digit hardened components, far past any path the wallet
/// writes; a bound so a malformed request costs nothing to refuse.
pub(crate) const MAX_PATH_BYTES: usize = 256;

/// The BIP-39 seed of an English phrase.
///
/// **Only the form the wallet stores is taken:** lowercase ASCII words joined
/// by single spaces. `Bip39MnemonicValidator` and the English word list are
/// all the app accepts on import, and that text is canonical already, so a
/// phrase in any other form is refused here rather than normalised — a
/// different normalisation from the Dart side's would be a different seed,
/// which is a different wallet, which is the one failure with no error
/// message. The checksum is checked by `bip39`.
///
/// [passphrase] is empty for every wallet the app makes; the BIP-39 vectors
/// are the only caller that passes one.
pub(crate) fn seed_from_phrase(
    phrase: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, Refusal> {
    Ok(Zeroizing::new(stored_phrase(phrase)?.to_seed_normalized(passphrase)))
}

/// [phrase] read by `bip39`, refused unless it is in the form the wallet
/// stores — see [`seed_from_phrase`].
fn stored_phrase(phrase: &[u8]) -> Result<Mnemonic, Refusal> {
    if phrase.len() > MAX_PHRASE_BYTES {
        return Err(Refusal::Phrase);
    }
    let phrase = core::str::from_utf8(phrase).map_err(|_| Refusal::Phrase)?;
    let canonical = phrase
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b == b' ')
        && phrase.split(' ').all(|word| !word.is_empty());
    if !canonical {
        return Err(Refusal::Phrase);
    }
    // `Mnemonic` holds word indices, not text, and zeroes them when dropped.
    Mnemonic::parse_in_normalized(Language::English, phrase).map_err(|_| Refusal::Phrase)
}

/// A phrase's entropy — 16 to 32 bytes — erased when dropped: what Icarus
/// builds its master key from (the owner's decision O29).
pub(crate) struct Entropy {
    bytes: Zeroizing<[u8; 32]>,
    len: usize,
}

impl Entropy {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// What a session opened on [phrase] keeps: its BIP-39 seed, with no
/// passphrase, and its entropy. Refused as [`seed_from_phrase`] refuses.
pub(crate) fn phrase_secrets(phrase: &[u8]) -> Result<(Zeroizing<[u8; 64]>, Entropy), Refusal> {
    let mnemonic = stored_phrase(phrase)?;
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    // The array carries the checksum's bits after the entropy; only `len`
    // bytes are the entropy, and the whole array is erased.
    let (array, len) = mnemonic.to_entropy_array();
    let array = Zeroizing::new(array);
    if !(16..=32).contains(&len) {
        return Err(Refusal::Internal);
    }
    let mut entropy = Entropy { bytes: Zeroizing::new([0u8; 32]), len };
    entropy.bytes[..len].copy_from_slice(&array[..len]);
    Ok((seed, entropy))
}

/// What Dart's `\s` matches — ECMAScript's white space and line terminators —
/// which `Mnemonic.fromString` (`blockchain_utils` 7.1.0, `_normalize`) splits
/// a phrase on before the seed is made of its words joined by one space.
fn is_dart_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// [phrase_secrets] for a phrase read out of a vault's record — **O32 in the
/// core** (the owner, 14 November 2026: "yes, move O32 into the core"). A record
/// an older build sealed may hold the words with other white space between
/// them, or around them; the Dart code that opened such a record split it on
/// [is_dart_space], dropped the empty pieces and made the seed of the words
/// joined by one space — the stored form. That is done here, in a buffer of
/// the record's length that is erased, and the result is held to the stored
/// form as every phrase is: **the same seed the Dart code made, so the same
/// wallet**, never a second one. Capitals, other letters and a bad checksum
/// stay refused — the Dart decoder refused them too, so no such wallet ever
/// opened.
pub(crate) fn record_phrase_secrets(record: &[u8]) -> Result<(Zeroizing<[u8; 64]>, Entropy), Refusal> {
    if record.len() > MAX_PHRASE_BYTES {
        return Err(Refusal::Phrase);
    }
    let text = core::str::from_utf8(record).map_err(|_| Refusal::Phrase)?;
    let mut canonical = Zeroizing::new(String::with_capacity(record.len()));
    for word in text.split(is_dart_space).filter(|w| !w.is_empty()) {
        if !canonical.is_empty() {
            canonical.push(' ');
        }
        canonical.push_str(word);
    }
    phrase_secrets(canonical.as_bytes())
}

/// The phrase [entropy] spells, in the one form every door of the wallet
/// stores — lowercase English words, single spaces, as `normaliseMnemonic`
/// writes them and [`stored_phrase`] reads them — in a buffer of its final
/// size that is erased when dropped (phase 7b: sealed for the vault in the
/// core). Only a phrase's lengths, 16 to 32 bytes; else [`Refusal::Phrase`].
pub(crate) fn phrase_text(entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| Refusal::Phrase)?;
    let words: Vec<&'static str> = mnemonic.words().collect();
    let length = words.iter().map(|w| w.len()).sum::<usize>() + words.len().saturating_sub(1);
    let mut text = Zeroizing::new(Vec::with_capacity(length));
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            text.push(b' ');
        }
        text.extend_from_slice(word.as_bytes());
    }
    Ok(text)
}

/// What a session opened on a phrase's [entropy] keeps — phase 7b, a split
/// backup restored in the core: the BIP-39 seed of the phrase that entropy
/// spells, with no passphrase, and the entropy itself. The phrase is never
/// written out as text here: `Mnemonic` holds word indices and zeroes them.
/// Only the lengths a wallet's phrase has, 16 or 32 bytes (12 or 24 words),
/// as `WalletShares.recover` takes them; anything else is [`Refusal::Phrase`].
pub(crate) fn entropy_secrets(entropy: &[u8]) -> Result<(Zeroizing<[u8; 64]>, Entropy), Refusal> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err(Refusal::Phrase);
    }
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| Refusal::Phrase)?;
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let mut kept = Entropy { bytes: Zeroizing::new([0u8; 32]), len: entropy.len() };
    kept.bytes[..entropy.len()].copy_from_slice(entropy);
    Ok((seed, kept))
}

/// Whether [path] is a key of the Bitcoin family — a BIP-44, 49, 84, 86 or
/// 48 account of Bitcoin, Litecoin, Dogecoin or Bitcoin Cash (SLIP-44's 0,
/// 2, 3 and 145) — whose keys sign only a transaction the core has read
/// (the owner's decision O37). Both levels hardened, as the wallet writes
/// them; Kaspa's 111111 and every other network's coin are not of it.
pub(crate) fn is_bitcoin_family(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened()
        && coin.is_hardened()
        && matches!(purpose.index(), 44 | 48 | 49 | 84 | 86)
        && matches!(coin.index(), 0 | 2 | 3 | 145)
}

/// Whether [path] is an EVM key — BIP-44's purpose and SLIP-44's coin 60,
/// both hardened, as the wallet writes its EVM accounts
/// (`m/44'/60'/0'/0/i`) — whose keys sign only a transaction, a message or
/// typed data the core has read (the owner's decision O43). TRON, the Cosmos
/// zones and the other secp256k1 networks have coins of their own.
pub(crate) fn is_evm(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 60
}

/// Whether [path] is a Cosmos zone's key — BIP-44's purpose and SLIP-44's
/// coin 118, which six of the seven zones use, or Kava's 459 — which signs
/// only the SHA-256 of a `SignDoc` the core read for a screen (O58).
pub(crate) fn is_cosmos(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened()
        && coin.is_hardened()
        && purpose.index() == 44
        && matches!(coin.index(), 118 | 459)
}

/// Whether [path] is an XRP Ledger key — BIP-44's purpose and SLIP-44's coin
/// 144 — which signs only a payment the core read for a screen (O59).
pub(crate) fn is_xrpl(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 144
}

/// Whether [path] is a TRON key — BIP-44's purpose and SLIP-44's coin 195 —
/// which signs only the SHA-256 of a transaction the core read for a screen
/// (O58).
pub(crate) fn is_tron(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 195
}

/// Whether [path] is a Stellar key — BIP-44's purpose and SLIP-44's coin 148
/// (SEP-0005) — which signs only the hash of a transaction the core read for
/// a screen (O58).
pub(crate) fn is_stellar(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 148
}

/// Whether [path] is a Kaspa key — BIP-44's purpose and SLIP-44's coin
/// 111111 — which signs only a send the core read for a screen (O58).
pub(crate) fn is_kaspa(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 111111
}

/// Whether [path] is a Zcash transparent key — BIP-44's purpose and
/// SLIP-44's coin 133 — which signs only a send the core read for a screen
/// (the owner's decision of 15 November 2026, Zcash brought back on the
/// core).
pub(crate) fn is_zcash(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 133
}

/// Whether [path] is an ICP key — BIP-44's purpose and SLIP-44's coin 223 —
/// which signs only the digest of a call the core read for a screen (O58).
pub(crate) fn is_icp(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 223
}

/// Whether [path] is a Filecoin key — BIP-44's purpose and SLIP-44's coin
/// 461 — which signs only the digest of a message the core read for a screen
/// (O58).
pub(crate) fn is_filecoin(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 461
}

/// Whether [path] is a Cardano key the module signs with — CIP-1852's
/// purpose 1852 and Cardano's coin 1815 — which signs only the hash of a
/// transaction body the core read for a screen (O58).
pub(crate) fn is_cardano(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 1852 && coin.index() == 1815
}

/// Whether [path] is a Starknet key as the module writes one — BIP-44's
/// purpose and SLIP-44's coin 9004, below Argent's second tree — which signs
/// only the hash of a transaction the core read for a screen (O58).
pub(crate) fn is_starknet(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 9004
}

/// Whether [path] is a TON key — BIP-44's purpose and SLIP-44's coin 607 —
/// which signs only the hash of a wallet v4R2 signing message the core read
/// for a screen (O58).
pub(crate) fn is_ton(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 607
}

/// Whether [path] is a Polkadot key — BIP-44's purpose and SLIP-44's coin
/// 354, ed25519 in the Ledger layout — which signs only an Asset Hub signing
/// payload the core read for a screen (O58).
pub(crate) fn is_polkadot(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 354
}

/// Whether [path] is a MultiversX key — BIP-44's purpose and SLIP-44's coin
/// 508 — which signs only a transaction's signing JSON the core read for a
/// screen (O58).
pub(crate) fn is_multiversx(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 508
}

/// Whether [path] is a Tezos key — BIP-44's purpose and SLIP-44's coin
/// 1729 — which signs only the watermarked BLAKE2b-256 of an operation group
/// the core read for a screen (O58).
pub(crate) fn is_tezos(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 1729
}

/// Whether [path] is an Algorand key — BIP-44's purpose and SLIP-44's coin
/// 283 — which signs only a transaction the core read for a screen (O58).
pub(crate) fn is_algorand(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 283
}

/// Whether [path] is a Sui key — BIP-44's purpose and SLIP-44's coin 784 —
/// which signs only the BLAKE2b-256 of an intent message the core read for a
/// screen (O58).
pub(crate) fn is_sui(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 784
}

/// Whether [path] is an Aptos or Movement key — BIP-44's purpose and
/// SLIP-44's coin 637, which both networks derive at — which signs only a
/// transaction's signing message the core read for a screen (O58).
pub(crate) fn is_aptos(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 637
}

/// Whether [path] is a NEAR key — BIP-44's purpose and SLIP-44's coin 397,
/// as the wallet's own path and the Ledger branch it looks under both are —
/// which signs only the hash of a transaction the core read for a screen
/// (O58).
pub(crate) fn is_near(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 397
}

/// Whether [path] is a Solana key — BIP-44's purpose and SLIP-44's coin 501,
/// both hardened, as every Solana layout the wallet writes is — whose keys
/// sign only a message the core read for a screen (O58).
pub(crate) fn is_solana(path: &DerivationPath) -> bool {
    let mut levels = path.iter();
    let (Some(purpose), Some(coin)) = (levels.next(), levels.next()) else {
        return false;
    };
    purpose.is_hardened() && coin.is_hardened() && purpose.index() == 44 && coin.index() == 501
}

/// A path as the wallet writes it: `m`, then `/` and a decimal index with an
/// optional `'` for each level.
///
/// **Stricter than `bip32`'s own parser, on purpose.** That parser also takes
/// `h` for hardened, a leading `+` and leading zeros. None of them is a
/// different key there, but each is a spelling the Dart side was never asked
/// about, and a path is where a typed request reaches derivation; refusing
/// what has not been compared is cheaper than finding out later that two
/// parsers read one string two ways. Indices at or above 2^31 are `bip32`'s to
/// refuse, and it does.
pub(crate) fn parse_path(path: &[u8]) -> Result<DerivationPath, Refusal> {
    if path.len() > MAX_PATH_BYTES {
        return Err(Refusal::Path);
    }
    let text = core::str::from_utf8(path).map_err(|_| Refusal::Path)?;
    let mut levels = text.split('/');
    if levels.next() != Some("m") {
        return Err(Refusal::Path);
    }
    for level in levels {
        let digits = level.strip_suffix('\'').unwrap_or(level);
        let decimal = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        if !decimal {
            return Err(Refusal::Path);
        }
    }
    text.parse().map_err(|_| Refusal::Path)
}

/// A derived private key that overwrites itself when dropped.
///
/// `secp256k1::SecretKey` is `Copy` and erases nothing on its own, and
/// `bip32` keeps its keys in plain values too. This covers the copy this crate
/// holds; the copies the libraries leave in their stack frames are what
/// [`crate::scrub::stack`] is for.
pub(crate) struct DerivedKey(SecretKey);

impl DerivedKey {
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.0
    }

    /// A key that was not derived here, for a published signing vector.
    #[cfg(test)]
    pub(crate) fn from_secret(secret: SecretKey) -> Self {
        DerivedKey(secret)
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// The secp256k1 key at [path] below [seed], by BIP-32.
pub(crate) fn derive(seed: &[u8], path: &DerivationPath) -> Result<DerivedKey, Refusal> {
    // An `Err` here is a child whose tweak is zero or not below the order:
    // BIP-32 says to skip to the next index, `bip32` refuses instead, and so
    // does this — about 2^-127 per level, and never a different key.
    let extended = ExtendedPrivateKey::<SecretKey>::derive_from_path(seed, path)
        .map_err(|_| Refusal::Derivation)?;
    Ok(DerivedKey(*extended.private_key()))
}

/// A one-key session's own secp256k1 key (O22): [secret] as a scalar, or
/// [`Refusal::Key`] when it is zero or not below the curve's order.
pub(crate) fn secp256k1_key(secret: &[u8; 32]) -> Result<DerivedKey, Refusal> {
    SecretKey::from_secret_bytes(*secret)
        .map(DerivedKey)
        .map_err(|_| Refusal::Key)
}

/// The key at [path] below [seed] and its BIP-32 chain code.
///
/// The chain code is public in the sense an xpub is: with the public key it
/// lets anyone derive the non-hardened children's public keys, which is what
/// an account's xpub is for. It is not a key — but with one of
/// those children's private keys it gives this node's, so it leaves the core
/// only beside a public key, never beside a private one.
pub(crate) fn derive_with_chain_code(
    seed: &[u8],
    path: &DerivationPath,
) -> Result<(DerivedKey, [u8; 32]), Refusal> {
    let extended = ExtendedPrivateKey::<SecretKey>::derive_from_path(seed, path)
        .map_err(|_| Refusal::Derivation)?;
    Ok((DerivedKey(*extended.private_key()), extended.attrs().chain_code))
}

/// The public key of [key].
pub(crate) fn public_key(key: &DerivedKey) -> PublicKey {
    PublicKey::from_secret_key(key.secret())
}

/// A recoverable ECDSA signature over [digest]: `r`, `s`, then the recovery
/// id (0 to 3).
///
/// RFC 6979 nonces and a low `s`, both libsecp256k1's own behaviour.
///
/// **The Dart signer's two refusals, kept.** `signEvmDigest` refuses a digest
/// of zero or one not below the curve's order, where libsecp256k1 would
/// reduce it and sign; a refusal cannot be a signature over another digest.
/// And like `Secp256k1SigningKey.signConst`, the signature is recovered before
/// it is returned: one that does not recover to [key]'s public key is an
/// internal error, never an answer.
pub(crate) fn sign_digest(key: &DerivedKey, digest: &[u8; 32]) -> Result<[u8; 65], Refusal> {
    let scalar = Scalar::from_be_bytes(*digest).map_err(|_| Refusal::Digest)?;
    if scalar == Scalar::ZERO {
        return Err(Refusal::Digest);
    }
    let message = Message::from_digest(*digest);
    let signature = RecoverableSignature::sign_ecdsa_recoverable(message, key.secret());
    match signature.recover_ecdsa(message) {
        Ok(recovered) if recovered == public_key(key) => {}
        _ => return Err(Refusal::Internal),
    }
    let (recovery_id, compact) = signature.serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&compact);
    out[64] = recovery_id.to_u8();
    Ok(out)
}

/// A low-R ECDSA signature over [digest], for a Bitcoin input: `r` then `s`,
/// 32 bytes each, low `s`, and `r` below 2^255 so that its DER form is 32
/// bytes and the whole signature at most 71 — what each input this app signs
/// is sized for when its fee is set.
///
/// **The grind is `blockchain_utils`', kept.** Its `signECDSADerConst` signs by
/// RFC 6979, and while `r`'s top bit is set signs again with 32 bytes of extra
/// nonce data that are the attempt number, big-endian: 1, 2, … . Bitcoin Core,
/// and the `secp256k1` crate's own `sign_low_r`, put the counter in the first
/// four bytes, little-endian, which grinds to a different and equally valid
/// signature; keeping the Dart side's makes every signature byte for byte the
/// one the app makes today. libsecp256k1's nonce function takes the extra
/// bytes where `blockchain_utils`' RFC 6979 does — after the key and the
/// message — which the oracle test holds to.
///
/// The digest refusals and the check before returning are [`sign_digest`]'s.
pub(crate) fn sign_digest_low_r(key: &DerivedKey, digest: &[u8; 32]) -> Result<[u8; 64], Refusal> {
    let scalar = Scalar::from_be_bytes(*digest).map_err(|_| Refusal::Digest)?;
    if scalar == Scalar::ZERO {
        return Err(Refusal::Digest);
    }
    let message = Message::from_digest(*digest);
    let mut signature = secp256k1::ecdsa::sign(message, key.secret());
    let mut attempt: u64 = 0;
    while signature.serialize_compact()[0] >= 0x80 {
        attempt += 1;
        let mut extra = [0u8; 32];
        extra[24..].copy_from_slice(&attempt.to_be_bytes());
        signature = secp256k1::ecdsa::sign_with_noncedata(message, key.secret(), &extra);
    }
    signature.verify(message, &public_key(key)).map_err(|_| Refusal::Internal)?;
    Ok(signature.serialize_compact())
}

/// A keypair that overwrites its secret when dropped, as [`DerivedKey`] does.
struct SigningKeypair(Keypair);

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// A BIP-340 Schnorr signature over [digest] with [key], tweaked first when a
/// [tweak] is given — BIP-341's key-path spend: the key negated when its point
/// has an odd `y`, then the tweak added, which is libsecp256k1's
/// `keypair_xonly_tweak_add`.
///
/// **The auxiliary bytes are `blockchain_utils`' choice, kept.** Given none,
/// its `signBip340Const` — what signs every taproot input in the app today —
/// uses SHA-256 of the digest and the key that signs (tweaked, before the
/// parity flip). BIP-340 takes any 32 bytes there; fresh randomness only
/// hardens against fault injection. Keeping the derivation keeps each
/// signature byte for byte the one the Dart signer makes, which is what the
/// oracle test holds it to.
///
/// A [tweak] not below the order (a tagged hash reaches it about 2^-128 of the
/// time) is [`Refusal::Argument`]; a tweak that sends the key to zero is
/// [`Refusal::Derivation`]. The signature is verified against the (tweaked)
/// x-only public key before it is returned.
pub(crate) fn schnorr_sign(
    key: &DerivedKey,
    digest: &[u8; 32],
    tweak: Option<&[u8; 32]>,
) -> Result<[u8; 64], Refusal> {
    let mut signing = SigningKeypair(Keypair::from_secret_key(key.secret()));
    if let Some(tweak) = tweak {
        let scalar = Scalar::from_be_bytes(*tweak).map_err(|_| Refusal::Argument)?;
        signing.0 = signing.0.add_xonly_tweak(&scalar).map_err(|_| Refusal::Derivation)?;
    }
    let mut aux = Zeroizing::new([0u8; 32]);
    {
        let secret = Zeroizing::new(signing.0.to_secret_bytes());
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(&secret[..]);
        aux.copy_from_slice(&hasher.finalize());
    }
    schnorr_sign_with_aux(&signing.0, digest, &aux)
}

/// BIP-340 over [digest] with [keypair] and the given [aux], verified before
/// it is returned. Separate from [`schnorr_sign`] so the published vectors,
/// which name their own `aux`, reach the same signing call.
pub(crate) fn schnorr_sign_with_aux(
    keypair: &Keypair,
    digest: &[u8; 32],
    aux: &[u8; 32],
) -> Result<[u8; 64], Refusal> {
    let signature = schnorr::sign_with_aux_rand(digest, keypair, aux);
    let (public, _) = keypair.x_only_public_key();
    schnorr::verify(&signature, digest, &public).map_err(|_| Refusal::Internal)?;
    Ok(signature.to_byte_array())
}

// --- ed25519, SLIP-10 ---------------------------------------------------------

/// SLIP-10's HMAC key for an ed25519 master node.
const ED25519_SEED: &[u8] = b"ed25519 seed";

/// A SLIP-10 node: the key (32 bytes), then the chain code (32), erased when
/// dropped.
pub(crate) type Slip10Node = Zeroizing<[u8; 64]>;

/// HMAC-SHA512 of [parts], one after another, under [key].
fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Result<Slip10Node, Refusal> {
    // HMAC takes a key of any length; an `Err` here is not reachable.
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| Refusal::Internal)?;
    for part in parts {
        mac.update(part);
    }
    let mut node = Zeroizing::new([0u8; 64]);
    node.copy_from_slice(&mac.finalize().into_bytes());
    Ok(node)
}

/// Refuses [path] unless every level is hardened: ed25519 has no normal
/// children under SLIP-10, and `blockchain_utils`' derivation refuses them
/// too. [`Refusal::Path`], so the caller learns it before any seed is read.
pub(crate) fn require_hardened(path: &DerivationPath) -> Result<(), Refusal> {
    if path.iter().all(|child| child.is_hardened()) {
        Ok(())
    } else {
        Err(Refusal::Path)
    }
}

/// The ed25519 node at [path] below [seed], by SLIP-10.
///
/// **Written here, not taken from a crate — the owner's decision O13**, because
/// every SLIP-10 crate builds on another ed25519 engine or its own HMAC. It is
/// the specification's two steps and nothing else: the master node is
/// HMAC-SHA512 of the seed under `"ed25519 seed"`, and each (hardened) child
/// is HMAC-SHA512 under the parent's chain code of `0x00`, the parent's key
/// and the child's index with its hardened bit, big-endian. For ed25519 the
/// left half is the key as it is — no reduction and no retry, as SLIP-10
/// says. Held to SLIP-0010's own vectors and to `blockchain_utils`.
pub(crate) fn slip10_ed25519(seed: &[u8], path: &DerivationPath) -> Result<Slip10Node, Refusal> {
    require_hardened(path)?;
    let mut node = hmac_sha512(ED25519_SEED, &[seed])?;
    for child in path.iter() {
        let (key, chain_code) = node.split_at(32);
        let next = hmac_sha512(chain_code, &[&[0u8], key, &child.to_bytes()])?;
        // Copied in place, so the parent's bytes are overwritten where they
        // lie; `next` is erased when it drops.
        node.copy_from_slice(&next[..]);
    }
    Ok(node)
}

/// A derived ed25519 key. `ed25519-dalek`'s `zeroize` feature erases its
/// secret when it drops, and the expanded key each signature makes from it.
pub(crate) struct Ed25519Key(SigningKey);

impl Ed25519Key {
    /// A key that was not derived here, for a published signing vector.
    #[cfg(test)]
    pub(crate) fn from_secret(secret: &[u8; 32]) -> Self {
        Ed25519Key(SigningKey::from_bytes(secret))
    }
}

/// A one-key session's own ed25519 key (O22): [secret] is its 32-byte seed,
/// which every 32 bytes are.
pub(crate) fn ed25519_key(secret: &[u8; 32]) -> Ed25519Key {
    Ed25519Key(SigningKey::from_bytes(secret))
}

/// The ed25519 key at [path] below [seed]: [`slip10_ed25519`]'s left half.
pub(crate) fn derive_ed25519(seed: &[u8], path: &DerivationPath) -> Result<Ed25519Key, Refusal> {
    let node = slip10_ed25519(seed, path)?;
    let secret: &[u8; 32] = node[..32].try_into().map_err(|_| Refusal::Internal)?;
    Ok(Ed25519Key(SigningKey::from_bytes(secret)))
}

/// The 32-byte public key of [key] — the bare point, without the `00` that
/// `blockchain_utils` puts in front of its compressed form.
pub(crate) fn ed25519_public_key(key: &Ed25519Key) -> [u8; 32] {
    key.0.verifying_key().to_bytes()
}

/// An Ed25519 signature over [message] (RFC 8032, pure: the message itself,
/// not a hash of it), checked against [key]'s public key before it is
/// returned, as every signature this core makes is.
///
/// Ed25519 is deterministic, so there is no choice here to keep in line with
/// the Dart side: a correct implementation gives the one signature RFC 8032
/// defines, which is what the oracle test holds `blockchain_utils` and this
/// to.
pub(crate) fn ed25519_sign(key: &Ed25519Key, message: &[u8]) -> Result<[u8; 64], Refusal> {
    let signature = key.0.sign(message);
    key.0
        .verifying_key()
        .verify_strict(message, &signature)
        .map_err(|_| Refusal::Internal)?;
    Ok(signature.to_bytes())
}

/// [key]'s 32 secret bytes, for the export screens.
pub(crate) fn ed25519_secret(key: &Ed25519Key) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key.0.to_bytes())
}

// --- Cardano: the Ledger scheme and BIP32-Ed25519 ----------------------------
//
// Written here, as SLIP-10 is: the owner's decision O17. Every Cardano crate
// builds on `cryptoxide`'s own ed25519, SHA-2 and HMAC, and none of them has
// the Ledger master key. What follows is CIP-0003's Ledger scheme and the
// Khovratovich–Law derivation in its V2 form, step for step as
// `blockchain_utils`' `Bip32KholawEd25519` and `ed25519-bip32` take them; the
// curve and the signature are `curve25519-dalek`'s and `ed25519-dalek`'s.

/// A BIP32-Ed25519 node: the extended key `kL ‖ kR` (64 bytes), then the
/// chain code (32), erased when dropped. Also what an export of it is.
pub(crate) type CardanoNode = Zeroizing<[u8; 96]>;

/// How many times the Ledger scheme's master key may be hashed again before
/// the seed is refused: each round clears the bit it waits for half the time,
/// so 2^-256 of seeds would reach this.
const LEDGER_MASTER_ROUNDS: usize = 256;

/// The master node of [seed] by CIP-0003's Ledger scheme — what Ledger and
/// BitBox02 derive, and this wallet's Cardano module: HMAC-SHA512 of the seed
/// under `"ed25519 seed"`, hashed again while bit 5 of its byte 31 is set,
/// then `kL`'s bits tweaked (the lowest three and the highest cleared, the
/// second highest set); the chain code is HMAC-SHA256 of `0x01 ‖ seed` under
/// the same key.
pub(crate) fn cardano_ledger_master(seed: &[u8]) -> Result<CardanoNode, Refusal> {
    let mut digest = hmac_sha512(ED25519_SEED, &[seed])?;
    let mut rounds = 0;
    while digest[31] & 0x20 != 0 {
        rounds += 1;
        if rounds > LEDGER_MASTER_ROUNDS {
            return Err(Refusal::Derivation);
        }
        let next = hmac_sha512(ED25519_SEED, &[&digest[..]])?;
        digest.copy_from_slice(&next[..]);
    }
    let mut node = Zeroizing::new([0u8; 96]);
    node[..64].copy_from_slice(&digest[..]);
    node[0] &= 0xf8;
    node[31] &= 0x7f;
    node[31] |= 0x40;
    let mut mac = Hmac::<Sha256>::new_from_slice(ED25519_SEED).map_err(|_| Refusal::Internal)?;
    mac.update(&[0x01]);
    mac.update(seed);
    node[64..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(node)
}

/// `kL` as the scalar it signs and derives with. Not clamped: a child's `kL`
/// is its parent's plus a multiple of 8, and only the master's bits were set.
fn cardano_scalar(node: &CardanoNode) -> EdScalar {
    let mut kl = [0u8; 32];
    kl.copy_from_slice(&node[..32]);
    let scalar = EdScalar::from_bytes_mod_order(kl);
    kl.zeroize();
    scalar
}

/// The 32-byte public key of [node]: `kL·B`.
pub(crate) fn cardano_public_key(node: &CardanoNode) -> [u8; 32] {
    let mut scalar = cardano_scalar(node);
    let point = EdwardsPoint::mul_base(&scalar);
    scalar.zeroize();
    point.compress().to_bytes()
}

/// The child of [parent] at [child], by Khovratovich–Law V2: `Z` and the
/// child's chain code are HMAC-SHA512 under the parent's chain code of
/// `0x00`/`0x01` and the extended key (hardened), or `0x02`/`0x03` and the
/// public key (normal), then the index little-endian; `kL' = kL + 8·Z[..28]`
/// and `kR' = kR + Z[32..]`, each 256-bit little-endian with the carry out
/// dropped, and the chain code the second half of the other HMAC.
///
/// A `kL'` that is zero modulo the group order is refused, as
/// `blockchain_utils` refuses it ("very unlucky index") — `ed25519-bip32`
/// argues it cannot happen.
pub(crate) fn cardano_child(parent: &CardanoNode, child: ChildNumber) -> Result<CardanoNode, Refusal> {
    let index = child.0.to_le_bytes();
    let chain_code = &parent[64..];
    let (z, link) = if child.is_hardened() {
        let key = &parent[..64];
        (
            hmac_sha512(chain_code, &[&[0x00], key, &index])?,
            hmac_sha512(chain_code, &[&[0x01], key, &index])?,
        )
    } else {
        let public = cardano_public_key(parent);
        (
            hmac_sha512(chain_code, &[&[0x02], &public, &index])?,
            hmac_sha512(chain_code, &[&[0x03], &public, &index])?,
        )
    };
    let mut node = Zeroizing::new([0u8; 96]);
    let mut carry: u16 = 0;
    for i in 0..32 {
        let eight_z = if i < 28 { u16::from(z[i]) << 3 } else { 0 };
        let sum = u16::from(parent[i]) + eight_z + carry;
        node[i] = sum as u8;
        carry = sum >> 8;
    }
    carry = 0;
    for i in 0..32 {
        let sum = u16::from(parent[32 + i]) + u16::from(z[32 + i]) + carry;
        node[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    node[64..].copy_from_slice(&link[32..]);
    let mut scalar = cardano_scalar(&node);
    let zero = scalar == EdScalar::ZERO;
    scalar.zeroize();
    if zero {
        return Err(Refusal::Derivation);
    }
    Ok(node)
}

/// The node at [path] below [seed]: the Ledger master, then each level.
/// Normal levels are allowed — CIP-1852's role and index are.
pub(crate) fn derive_cardano(seed: &[u8], path: &DerivationPath) -> Result<CardanoNode, Refusal> {
    descend_cardano(cardano_ledger_master(seed)?, path)
}

/// The node at [path] below the Icarus master of [entropy] — the same levels
/// as [`derive_cardano`] below another master key.
pub(crate) fn derive_cardano_icarus(
    entropy: &[u8],
    path: &DerivationPath,
) -> Result<CardanoNode, Refusal> {
    descend_cardano(cardano_icarus_master(entropy)?, path)
}

/// [node], then each level of [path] below it, in place.
fn descend_cardano(mut node: CardanoNode, path: &DerivationPath) -> Result<CardanoNode, Refusal> {
    for child in path.iter() {
        let next = cardano_child(&node, child)?;
        node.copy_from_slice(&next[..]);
    }
    Ok(node)
}

/// Icarus's PBKDF2 rounds (CIP-0003).
const ICARUS_ROUNDS: u32 = 4096;

/// The master node of a phrase's [entropy] by CIP-0003's Icarus scheme — what
/// Yoroi, Eternl and Daedalus derive (O19, O29), and `blockchain_utils`'
/// `CardanoIcarusMstKeyGenerator`: PBKDF2-HMAC-SHA512 with an empty password
/// and the entropy as the salt, 4,096 rounds, 96 bytes; then `kL`'s lowest
/// three bits and highest three cleared and the second highest set. The last
/// 32 bytes are the chain code.
pub(crate) fn cardano_icarus_master(entropy: &[u8]) -> Result<CardanoNode, Refusal> {
    cardano_icarus_master_with(entropy, b"")
}

/// [`cardano_icarus_master`] under CIP-0003's passphrase, the PBKDF2
/// password. The wallet sets none; CIP-0003 publishes a vector with one, so
/// the function is held to both.
pub(crate) fn cardano_icarus_master_with(
    entropy: &[u8],
    passphrase: &[u8],
) -> Result<CardanoNode, Refusal> {
    let mut node = Zeroizing::new([0u8; 96]);
    pbkdf2_hmac_sha512(passphrase, entropy, ICARUS_ROUNDS, &mut node[..])?;
    node[0] &= 0xf8;
    node[31] &= 0x1f;
    node[31] |= 0x40;
    Ok(node)
}

/// PBKDF2-HMAC-SHA512 (RFC 8018, section 5.2) of [password] and [salt] over
/// [rounds], filling [out].
///
/// **Written here, for Icarus alone**: `bip39`'s PBKDF2 is private to it, and
/// the `pbkdf2` crates in the local registry are of the generation before
/// this crate's `hmac` 0.13. It is the RFC's loop over that `hmac` and
/// nothing else — each block `T_i` the XOR of `U_1 … U_c`, `U_1` the HMAC of
/// the salt and `i` big-endian, each later `U` the HMAC of the one before.
/// Held to `bip39`'s seed, which is this function with the salt `mnemonic`
/// and 2,048 rounds, and to `blockchain_utils`' Icarus master by the app's
/// tests.
pub(crate) fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    out: &mut [u8],
) -> Result<(), Refusal> {
    // HMAC takes a key of any length; an `Err` here is not reachable.
    let prf = Hmac::<Sha512>::new_from_slice(password).map_err(|_| Refusal::Internal)?;
    for (i, block) in out.chunks_mut(64).enumerate() {
        let index = u32::try_from(i + 1).map_err(|_| Refusal::Internal)?;
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&index.to_be_bytes());
        let mut u = Zeroizing::new([0u8; 64]);
        u.copy_from_slice(&mac.finalize().into_bytes());
        let mut t = u.clone();
        for _ in 1..rounds {
            let mut mac = prf.clone();
            mac.update(&u[..]);
            u.copy_from_slice(&mac.finalize().into_bytes());
            for (t, u) in t.iter_mut().zip(u.iter()) {
                *t ^= u;
            }
        }
        block.copy_from_slice(&t[..block.len()]);
    }
    Ok(())
}

/// An Ed25519 signature over [message] by the extended key of [node]: `kL`
/// the scalar and `kR` the nonce prefix — what `blockchain_utils`'
/// `Ed25519KholawSigner` and `cryptoxide`'s `signature_extended` compute, and
/// what a Cardano witness carries. Verified against `kL·B` before it is
/// returned.
///
/// **`hazmat` because the expansion is Cardano's, not RFC 8032's:** the pair
/// does not come from SHA-512 of a seed. `ed25519-dalek` warns that a scalar
/// used with two prefixes gives the key away; here both halves come from one
/// node, so each scalar has the one prefix it was derived with.
pub(crate) fn cardano_sign(node: &CardanoNode, message: &[u8]) -> Result<[u8; 64], Refusal> {
    let mut hash_prefix = [0u8; 32];
    hash_prefix.copy_from_slice(&node[32..64]);
    let secret = ExpandedSecretKey { scalar: cardano_scalar(node), hash_prefix };
    hash_prefix.zeroize();
    let verifying = VerifyingKey::from(&secret);
    let signature = raw_sign::<Sha512>(&secret, message, &verifying);
    drop(secret);
    verifying
        .verify_strict(message, &signature)
        .map_err(|_| Refusal::Internal)?;
    Ok(signature.to_bytes())
}

// --- Starknet: Argent's derivation and the Stark curve -----------------------
//
// The owner's decisions O20 and O21: the curve, its signature and its check
// are `starknet-crypto`'s; the derivation is Argent's, written out here as
// `ArgentAccount` (the Starknet module) takes it, held to Argent X's own
// vectors and to the Dart `starknet` package.

/// The path of the Ethereum key that seeds every Argent account.
pub(crate) const ARGENT_SECRET_PATH: &str = "m/44'/60'/0'/0/0";

/// The Stark curve's order — the grind reduces into it.
const STARK_ORDER: U256 =
    U256::from_be_hex("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");

/// How many signatures with a fresh RFC 6979 seed to try before giving up:
/// each is refused about 2^-251 of the time.
const STARK_SIGN_ATTEMPTS: usize = 64;

/// The secp256k1 key at [path] below a BIP-32 seed of **any** length.
///
/// Argent seeds its second tree with the Ethereum key less its leading zero
/// bytes — 31 bytes one key in 256 — and `bip32` takes 16, 32 or 64 only. So
/// the master key is BIP-32's own HMAC-SHA512 under `"Bitcoin seed"`,
/// computed here, and handed to `bip32` as the extended key it would have
/// made; every child after it is `bip32`'s.
pub(crate) fn derive_from_any_seed(seed: &[u8], path: &DerivationPath) -> Result<DerivedKey, Refusal> {
    let master = hmac_sha512(b"Bitcoin seed", &[seed])?;
    let mut key_bytes = [0u8; 33];
    key_bytes[1..].copy_from_slice(&master[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&master[32..]);
    let extended = ExtendedKey {
        prefix: Prefix::XPRV,
        attrs: ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0),
            chain_code,
        },
        key_bytes,
    };
    key_bytes.zeroize();
    chain_code.zeroize();
    // A master key of zero or not below the order is `bip32`'s to refuse, as
    // BIP-32 says, and so is a child's.
    let mut node = ExtendedPrivateKey::<SecretKey>::try_from(extended).map_err(|_| Refusal::Derivation)?;
    for child in path.iter() {
        node = node.derive_child(child).map_err(|_| Refusal::Derivation)?;
    }
    Ok(DerivedKey(*node.private_key()))
}

/// Grinds [key_seed] into a Stark private key, as Argent and the `starknet`
/// package do (EIP-2645's grind): SHA-256 of the seed and one index byte,
/// from 0, until the digest is below the largest multiple of the curve's
/// order under 2^256, then that digest modulo the order — so every key is
/// equally likely, which reducing the seed itself would not make it.
///
/// Written here (O21): `starknet-crypto` has no grind. A 256th index is
/// refused rather than wrapped; reaching it is about 2^-1280.
pub(crate) fn stark_grind(key_seed: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let order = NonZero::new(STARK_ORDER).unwrap();
    // 2^256 mod n, then the limit 2^256 - (2^256 mod n).
    let remainder = U256::MAX.rem(&order).wrapping_add(&U256::ONE).rem(&order);
    let limit = U256::ZERO.wrapping_sub(&remainder);
    for index in 0u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update(key_seed);
        hasher.update([index]);
        let mut digest = Zeroizing::new([0u8; 32]);
        digest.copy_from_slice(&hasher.finalize());
        let mut value = U256::from_be_slice(&digest[..]);
        if value < limit {
            let mut key = value.rem(&order);
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&key.to_be_byte_array());
            value.zeroize();
            key.zeroize();
            return Ok(out);
        }
        value.zeroize();
    }
    Err(Refusal::Derivation)
}

/// The Stark private key at [path] below [seed], by Argent's derivation: the
/// key at [`ARGENT_SECRET_PATH`], less its leading zero bytes, seeds a second
/// BIP-32 tree; its key at [path] (`m/44'/9004'/0'/0/{i}` for the module) is
/// ground into the curve's order.
pub(crate) fn derive_starknet(seed: &[u8], path: &DerivationPath) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let first = derive(seed, &parse_path(ARGENT_SECRET_PATH.as_bytes())?)?;
    let secret = Zeroizing::new(first.secret().to_secret_bytes());
    drop(first);
    starknet_from_secret(&secret, path)
}

/// The second step alone, from the Ethereum key Argent calls its `secret` —
/// what Argent X's own vectors start from.
pub(crate) fn starknet_from_secret(secret: &[u8; 32], path: &DerivationPath) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let start = secret.iter().position(|b| *b != 0).unwrap_or(secret.len());
    let child = derive_from_any_seed(&secret[start..], path)?;
    let child_bytes = Zeroizing::new(child.secret().to_secret_bytes());
    drop(child);
    stark_grind(&child_bytes)
}

/// The Stark public key of [secret]: `x` of `secret·G`, 32 bytes big-endian.
pub(crate) fn starknet_public_key(secret: &[u8; 32]) -> [u8; 32] {
    starknet_crypto::get_public_key(&starknet_crypto::Felt::from_bytes_be(secret)).to_bytes_be()
}

/// A Stark ECDSA signature over the 32-byte [hash] with [secret]: `r` then
/// `s`, 32 bytes each, big-endian.
///
/// **The nonce is cairo-lang's**: RFC 6979 with no seed first, and while the
/// curve refuses that `k`, seeds 1, 2, … — what the `starknet` package's
/// `starknetSign` does. `starknet-crypto` refuses a `k` whose `s` is not
/// below 2^251 where cairo-lang tests `w = 1/s`; the two part ways about
/// 2^-54 of the time, on a signature both would have to retry or both
/// accept otherwise. A hash at or above 2^251 is not a felt the curve signs
/// ([`Refusal::Digest`]). Verified against the public key before it is
/// returned.
pub(crate) fn starknet_sign(secret: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], Refusal> {
    use starknet_crypto::{Felt, SignError};
    if hash[0] >= 0x08 {
        return Err(Refusal::Digest);
    }
    let private = Felt::from_bytes_be(secret);
    let message = Felt::from_bytes_be(hash);
    let public = starknet_crypto::get_public_key(&private);
    let mut seed: Option<Felt> = None;
    for _ in 0..STARK_SIGN_ATTEMPTS {
        let k = starknet_crypto::rfc6979_generate_k(&message, &private, seed.as_ref());
        match starknet_crypto::sign(&private, &message, &k) {
            Ok(signature) => {
                match starknet_crypto::verify(&public, &message, &signature.r, &signature.s) {
                    Ok(true) => {}
                    _ => return Err(Refusal::Internal),
                }
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&signature.r.to_bytes_be());
                out[32..].copy_from_slice(&signature.s.to_bytes_be());
                return Ok(out);
            }
            Err(SignError::InvalidK) => {
                seed = Some(seed.map_or(Felt::ONE, |s| s + Felt::ONE));
            }
            Err(_) => return Err(Refusal::Digest),
        }
    }
    Err(Refusal::Internal)
}
