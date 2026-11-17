//! A split backup's share sealed as `lib/core/sealed_share.dart` seals one
//! — phase 7a (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`).
//!
//! **The same file, byte for byte where it matters**, so a share sealed here
//! opens in the Dart build and one sealed there opens here: the key is
//! Argon2id over the password's NFC UTF-8 bytes and a 32-byte salt of the
//! share's own, with the three numbers the body states (O63, `argon2` 0.5.3);
//! the seal is AES-256-GCM, the 12-byte nonce in front of the ciphertext and
//! its tag, no associated data; and the plaintext of a version 4 share
//! (`labelBoundVersion`) is the words under `w` with a copy of the labels the
//! share cannot vouch for — `bid`, `n`, `at` — which opening holds the
//! readable ones to.
//!
//! What a body says outside the seal — the set, the indices, the threshold —
//! is filled from the share's own words, never from the caller.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::slip39::{self, Secret};

/// The body version a share sealed here carries (`labelBoundVersion`).
pub(crate) const LABEL_BOUND_VERSION: i64 = 4;

/// The body version of an Argon2id share without its labels sealed
/// (`argon2idVersion`); opened, never written.
pub(crate) const ARGON2ID_VERSION: i64 = 3;

/// The body versions of a PBKDF2 share (`version`, `thresholdVersion`).
pub(crate) const PBKDF2_VERSION: i64 = 1;
pub(crate) const THRESHOLD_VERSION: i64 = 2;

/// `CryptoUtils.deriveKey`'s rounds.
const PBKDF2_ROUNDS: u32 = 600_000;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Argon2id's three numbers, within the bounds `ShareKdf.fromJson` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kdf {
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
}

impl Kdf {
    /// Null outside `ShareKdf.fromJson`'s bounds: 1–8 lanes, 1–16 passes,
    /// 8–256 MiB and at least 8 KiB a lane.
    pub(crate) fn checked(memory_kib: u32, iterations: u32, parallelism: u32) -> Option<Kdf> {
        if !(1..=8).contains(&parallelism)
            || !(1..=16).contains(&iterations)
            || !(8192..=262_144).contains(&memory_kib)
            || memory_kib < 8 * parallelism
        {
            return None;
        }
        Some(Kdf { memory_kib, iterations, parallelism })
    }

    fn from_json(value: Option<&Value>) -> Option<Kdf> {
        let kdf = value?.as_object()?;
        if kdf.get("alg")?.as_str()? != "argon2id" {
            return None;
        }
        let number = |k: &str| kdf.get(k)?.as_u64().and_then(|n| u32::try_from(n).ok());
        Kdf::checked(number("m")?, number("t")?, number("p")?)
    }
}

/// The 32-byte key for [password] and [salt].
pub(crate) fn derive(password: &[u8], salt: &[u8], kdf: Kdf) -> Option<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password, salt, &mut key[..]).ok()?;
    Some(key)
}

/// The labels a version 4 share seals beside its words.
pub(crate) struct Labels<'a> {
    /// The backup's 32-hex-digit name, or none.
    pub(crate) backup_id: Option<&'a str>,
    /// How many shares the backup was divided into.
    pub(crate) share_count: u8,
    /// When it was made, as the app writes it (`toIso8601String`, UTC).
    pub(crate) created_at: &'a str,
}

impl Labels<'_> {
    /// Whether they are what the app writes: a backup id of 32 lowercase hex
    /// digits, and a date of digits and `-:.TZ` — so the plaintext needs no
    /// escaping and holds nothing a reader could take for more JSON.
    pub(crate) fn well_formed(&self) -> bool {
        let id_ok = self.backup_id.is_none_or(|id| {
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        let at_ok = !self.created_at.is_empty()
            && self.created_at.len() <= 40
            && self.created_at.bytes().all(|b| b.is_ascii_digit() || b"-:.TZ".contains(&b));
        id_ok && at_ok
    }
}

/// One share, sealed: what its body says outside the seal.
pub(crate) struct Sealed {
    pub(crate) set_id: String,
    pub(crate) group_index: u8,
    pub(crate) member_index: u8,
    pub(crate) threshold: u8,
    pub(crate) salt: String,
    pub(crate) ciphertext: String,
}

/// Seals [words] under [password] with [labels] beside them.
pub(crate) fn seal(
    words: &str,
    labels: &Labels,
    password: &[u8],
    kdf: Kdf,
    random: slip39::RandomBytes,
) -> Option<Sealed> {
    if !labels.well_formed() {
        return None;
    }
    // Filled from the words themselves, as `SealedShare.seal` does.
    let share = slip39::decode_share(words).ok()?;
    if share.member_threshold < 2 || share.member_threshold > labels.share_count || share.member_index >= labels.share_count {
        return None;
    }
    let salt: Secret = random(SALT_LEN).ok()?;
    let key = derive(password, &salt, kdf)?;

    // `{"w":…,"bid":…,"n":…,"at":…}`, written into one buffer of its final
    // size so no smaller copy of the words is left behind by a reallocation.
    let bid = match labels.backup_id {
        Some(id) => format!("\"{id}\""),
        None => "null".to_string(),
    };
    let n = labels.share_count.to_string();
    let parts: [&str; 9] = [r#"{"w":""#, words, r#"","bid":"#, &bid, r#","n":"#, &n, r#","at":""#, labels.created_at, r#""}"#];
    let mut plain = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum::<usize>() + TAG_LEN));
    for p in parts {
        plain.extend_from_slice(p.as_bytes());
    }

    let nonce = random(NONCE_LEN).ok()?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key[..]));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut *plain)
        .ok()?;
    let mut record = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&plain);
    record.extend_from_slice(&tag);
    Some(Sealed {
        set_id: share.set_id_hex(),
        group_index: share.group_index,
        member_index: share.member_index,
        threshold: share.member_threshold,
        salt: Base64::encode_string(&salt),
        ciphertext: Base64::encode_string(&record),
    })
}

/// Why a body did not give its share: the four cases `slip39.dart` tells
/// apart, of which a check counts none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// Not a body this core reads, or bytes that are not a share.
    Damaged,
    /// The tag did not hold: the password, most likely.
    WrongPassword,
    /// Opened, and the labels outside disagree with the seal or the share.
    Altered,
}

/// The words a body holds under [password], with the share they decode to.
///
/// Every version this app has written: 4 and 3 (Argon2id), 2 and 1
/// (PBKDF2), as `SealedShare.fromJson` reads them.
pub(crate) fn open(body: &Map<String, Value>, password: &[u8]) -> Result<(Zeroizing<String>, slip39::Share), OpenError> {
    let version = body.get("v").and_then(Value::as_i64).ok_or(OpenError::Damaged)?;
    let text = |k: &str| body.get(k).and_then(Value::as_str);
    let small = |k: &str| body.get(k).and_then(Value::as_u64).and_then(|n| u8::try_from(n).ok());
    // Which key: Argon2id with the body's numbers (versions 3 and 4), or
    // PBKDF2-HMAC-SHA256 at 600,000 rounds (`CryptoUtils.deriveKey`), every
    // share sealed before 11 October 2026 (versions 1 and 2), which a restore
    // still opens. A version 1 body may leave out `t`: two of three, then.
    let kdf = match version {
        LABEL_BOUND_VERSION | ARGON2ID_VERSION => Some(Kdf::from_json(body.get("kdf")).ok_or(OpenError::Damaged)?),
        PBKDF2_VERSION | THRESHOLD_VERSION if body.get("kdf").is_none() => None,
        _ => return Err(OpenError::Damaged),
    };
    let threshold = match (version, body.get("t")) {
        (PBKDF2_VERSION, None) => 2,
        _ => small("t").ok_or(OpenError::Damaged)?,
    };
    let set_id = text("set").ok_or(OpenError::Damaged)?;
    let group_index = small("g").ok_or(OpenError::Damaged)?;
    let member_index = small("m").ok_or(OpenError::Damaged)?;
    let salt = Base64::decode_vec(text("salt").ok_or(OpenError::Damaged)?).map_err(|_| OpenError::Damaged)?;
    let record = Base64::decode_vec(text("ct").ok_or(OpenError::Damaged)?).map_err(|_| OpenError::Damaged)?;
    if record.len() < NONCE_LEN + TAG_LEN {
        return Err(OpenError::WrongPassword);
    }
    let key = match kdf {
        Some(kdf) => derive(password, &salt, kdf).ok_or(OpenError::Damaged)?,
        None => {
            let mut key = Zeroizing::new([0u8; 32]);
            slip39::pbkdf2_hmac_sha256(password, &salt, PBKDF2_ROUNDS, &mut key[..]).map_err(|_| OpenError::Damaged)?;
            key
        }
    };
    let (nonce, rest) = record.split_at(NONCE_LEN);
    let (sealed, tag) = rest.split_at(rest.len() - TAG_LEN);
    let mut plain = Zeroizing::new(sealed.to_vec());
    Aes256Gcm::new(GenericArray::from_slice(&key[..]))
        .decrypt_in_place_detached(GenericArray::from_slice(nonce), b"", &mut *plain, GenericArray::from_slice(tag))
        .map_err(|_| OpenError::WrongPassword)?;

    let words: Zeroizing<String> = if version == LABEL_BOUND_VERSION {
        let mut inner: Value = serde_json::from_slice(&plain).map_err(|_| OpenError::Damaged)?;
        let inner = inner.as_object_mut().ok_or(OpenError::Damaged)?;
        let words = match inner.get_mut("w") {
            Some(Value::String(w)) => Zeroizing::new(core::mem::take(w)),
            _ => return Err(OpenError::Damaged),
        };
        // The labels outside, held to the copy inside: the password worked,
        // so a difference is an edit, not a guess.
        for label in ["bid", "n", "at"] {
            let outside = body.get(label).unwrap_or(&Value::Null);
            if inner.get(label).unwrap_or(&Value::Null) != outside {
                return Err(OpenError::Altered);
            }
        }
        words
    } else {
        Zeroizing::new(String::from_utf8(plain.to_vec()).map_err(|_| OpenError::Damaged)?)
    };
    let share = slip39::decode_share(&words).map_err(|_| OpenError::Damaged)?;
    if share.set_id_hex() != set_id
        || share.group_index != group_index
        || share.member_index != member_index
        || share.member_threshold != threshold
    {
        return Err(OpenError::Altered);
    }
    Ok((words, share))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: Kdf = Kdf { memory_kib: 8192, iterations: 1, parallelism: 1 };

    fn body(sealed: &Sealed, labels: &Labels, share_count: u8) -> Map<String, Value> {
        let value = serde_json::json!({
            "v": LABEL_BOUND_VERSION,
            "set": sealed.set_id,
            "bid": labels.backup_id,
            "g": sealed.group_index,
            "m": sealed.member_index,
            "t": sealed.threshold,
            "n": share_count,
            "salt": sealed.salt,
            "kdf": {"alg": "argon2id", "m": CHEAP.memory_kib, "t": CHEAP.iterations, "p": CHEAP.parallelism},
            "ct": sealed.ciphertext,
            "at": labels.created_at,
        });
        value.as_object().unwrap().clone()
    }

    fn shares() -> Vec<Zeroizing<String>> {
        let mut random = |n| slip39::os_random(n);
        slip39::split_secret(&[3u8; 16], 1, &[(2, 3)], b"", 0, true, &mut random).unwrap().remove(0)
    }

    const LABELS: Labels<'static> = Labels {
        backup_id: Some("0123456789abcdef0123456789abcdef"),
        share_count: 3,
        created_at: "2026-11-14T12:00:00.000Z",
    };

    #[test]
    fn sealed_and_opened_with_its_labels() {
        let words = &shares()[1];
        let mut random = |n| slip39::os_random(n);
        let sealed = seal(words, &LABELS, b"correct horse", CHEAP, &mut random).unwrap();
        assert_eq!(sealed.member_index, 1);
        assert_eq!(sealed.threshold, 2);
        let (opened, share) = open(&body(&sealed, &LABELS, 3), b"correct horse").unwrap();
        assert_eq!(opened.as_str(), words.as_str());
        assert_eq!(share.member_index, 1);
    }

    #[test]
    fn a_wrong_password_is_told_apart_from_an_edit() {
        let words = &shares()[0];
        let mut random = |n| slip39::os_random(n);
        let sealed = seal(words, &LABELS, b"right", CHEAP, &mut random).unwrap();
        let good = body(&sealed, &LABELS, 3);
        assert_eq!(open(&good, b"wrong").err(), Some(OpenError::WrongPassword));
        let mut edited = good.clone();
        edited.insert("n".into(), Value::from(5));
        assert_eq!(open(&edited, b"right").err(), Some(OpenError::Altered));
        let mut lowered = good.clone();
        lowered.insert("t".into(), Value::from(1));
        assert_eq!(open(&lowered, b"right").err(), Some(OpenError::Altered));
        let mut greedy = good;
        greedy.insert("kdf".into(), serde_json::json!({"alg": "argon2id", "m": 1_048_576, "t": 1, "p": 1}));
        assert_eq!(open(&greedy, b"right").err(), Some(OpenError::Damaged));
    }

    #[test]
    fn labels_that_need_escaping_are_not_sealed() {
        let words = &shares()[0];
        let mut random = |n| slip39::os_random(n);
        let bad = Labels { backup_id: Some("\",\"w\":\"x"), share_count: 3, created_at: "2026" };
        assert!(seal(words, &bad, b"p", CHEAP, &mut random).is_none());
        let bad_at = Labels { backup_id: None, share_count: 3, created_at: "2026\"}" };
        assert!(seal(words, &bad_at, b"p", CHEAP, &mut random).is_none());
    }

    #[test]
    fn a_share_filed_under_a_smaller_backup_is_refused() {
        let words = &shares()[2];
        let mut random = |n| slip39::os_random(n);
        let two = Labels { backup_id: None, share_count: 2, created_at: "2026-11-14T12:00:00.000Z" };
        assert!(seal(words, &two, b"p", CHEAP, &mut random).is_none());
    }
}
