//! The sealed phrase, opened here rather than in Dart (phase 6a,
//! `docs/RUST_KEY_CORE_DESIGN.md#phase-6`).
//!
//! **The layout is the wallet's** (`CryptoUtils.encryptBytes`): AES-256-GCM,
//! the 12-byte nonce in front, then the ciphertext and its 16-byte tag, no
//! associated data. A record is opened or refused; and since phase 7b one
//! is also made here, for the phrase a split backup gave back in the core
//! ([`seal`]), so that phrase is never a Dart string on its way to the vault.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use zeroize::Zeroizing;

use crate::Refusal;

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// What [sealed] holds under [key], in memory that is written over when it is
/// dropped.
///
/// **The tag is checked before anything is decrypted** — `aes-gcm` 0.10.3,
/// the release RUSTSEC-2023-0096 was fixed in — so a record this key does not
/// open never becomes plaintext, not even for a moment. A wrong key, a
/// changed byte and a record shorter than a nonce and a tag are one refusal,
/// [`Refusal::Seal`]: none of them is a phrase, and none says which.
/// [plain] sealed under [key] in the wallet's layout — the 12-byte nonce from
/// the operating system, the ciphertext, its 16-byte tag, no associated
/// data — the record [`open`] opens and `CryptoUtils.decryptBytes` reads.
///
/// **Encrypted in place in a buffer of its final size**: [plain] is copied
/// once, into the space the ciphertext takes, and is ciphertext before this
/// returns; the buffer never grows, so no copy of it is left in a freed
/// allocation. A generator that cannot answer is [`Refusal::Internal`].
pub(crate) fn seal(plain: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Refusal> {
    let mut record = vec![0u8; NONCE_BYTES + plain.len() + TAG_BYTES];
    getrandom::getrandom(&mut record[..NONCE_BYTES]).map_err(|_| Refusal::Internal)?;
    let (nonce, rest) = record.split_at_mut(NONCE_BYTES);
    let (body, tag_space) = rest.split_at_mut(plain.len());
    body.copy_from_slice(plain);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], body)
        .map_err(|_| Refusal::Internal)?;
    tag_space.copy_from_slice(&tag);
    Ok(record)
}

pub(crate) fn open(sealed: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(Refusal::Seal);
    }
    let (nonce, rest) = sealed.split_at(NONCE_BYTES);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_BYTES);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    // Decrypted in place, in a buffer of exactly this length: it never grows,
    // so no copy of the phrase is left behind in a freed allocation.
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &[],
            &mut plain[..],
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Refusal::Seal)?;
    Ok(plain)
}
