//! SLIP-39 in the core — phase 7a (`docs/RUST_KEY_CORE_DESIGN.md#phase-7`,
//! the owner's decision O61: this app's own `lib/core/slip39.dart`, written
//! again here).
//!
//! **Why the core does it at all.** A split backup is the phrase's entropy
//! divided into shares any threshold of which give it back. Made in Dart, the
//! entropy and every share's words were strings the Dart heap keeps and nothing
//! can write over; made here, they live in buffers erased when dropped, and
//! what leaves is sealed.
//!
//! **A port, not a new design.** Every step is the Dart file's, in its order,
//! and held to the same things: SatoshiLabs' published vectors
//! (`test/support/slip39_vectors.json`, read by this module's tests), and the
//! Dart implementation itself, both ways — shares made here recombined by
//! `slip39.dart`, and its shares recombined here (`test/key_core_slip39_test.dart`).
//! Getting a share scheme wrong gives no error, only a different valid
//! secret; that is why nothing is trusted that the vectors and the other
//! implementation have not agreed on.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::slip39_wordlist::WORDS;

/// Bytes that are part of a secret — the master secret, a share's value, a
/// round's output — erased when dropped.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

/// Every way a share, a set or an arrangement can be wrong: one case, as in
/// `slip39.dart` (`Slip39Invalid`) — the answer to each is that these are not
/// the backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Invalid;

const CHECKSUM_WORDS: usize = 3;
const METADATA_WORDS: usize = 4;
const ID_BITS: u32 = 15;
const ITERATION_EXP_BITS: u32 = 4;
const DIGEST_INDEX: u8 = 254;
const SECRET_INDEX: u8 = 255;
const DIGEST_LEN: usize = 4;
const ROUND_COUNT: u8 = 4;
const BASE_ITERATIONS: u32 = 10_000;
const CUSTOMIZATION_ORIG: &[u8] = b"shamir";
const CUSTOMIZATION_EXTENDABLE: &[u8] = b"shamir_extendable";

/// The most shares one group holds: the member index is four bits.
pub(crate) const MAX_SHARE_COUNT: usize = 16;

/// The seven metadata words and enough to carry a 128-bit secret.
const MIN_SHARE_WORDS: usize = METADATA_WORDS + CHECKSUM_WORDS + 13;

// --------------------------------------------------------------- GF(256)

/// Exponent and logarithm tables of the AES field, built as `slip39.dart`
/// builds them: each step multiplies by x + 1 and reduces by 0x11B.
struct Gf256 {
    exp: [u8; 255],
    log: [u8; 256],
}

fn gf256() -> Gf256 {
    let mut tables = Gf256 { exp: [0; 255], log: [0; 256] };
    let mut poly: u16 = 1;
    for i in 0..255u16 {
        tables.exp[i as usize] = poly as u8;
        tables.log[poly as usize] = i as u8;
        poly = (poly << 1) ^ poly;
        if poly & 0x100 != 0 {
            poly ^= 0x11B;
        }
    }
    tables
}

/// Lagrange interpolation of [shares] at [x], byte by byte.
fn interpolate(shares: &[(u8, &[u8])], x: u8) -> Result<Secret, Invalid> {
    for (i, a) in shares.iter().enumerate() {
        if shares[..i].iter().any(|b| b.0 == a.0) {
            return Err(Invalid);
        }
    }
    let length = shares.first().ok_or(Invalid)?.1.len();
    if shares.iter().any(|s| s.1.len() != length) {
        return Err(Invalid);
    }
    if let Some(at) = shares.iter().find(|s| s.0 == x) {
        return Ok(Zeroizing::new(at.1.to_vec()));
    }
    let gf = gf256();
    let log_prod: i32 = shares.iter().map(|s| i32::from(gf.log[(s.0 ^ x) as usize])).sum();
    let mut result = Zeroizing::new(vec![0u8; length]);
    for share in shares {
        let mut log_basis = log_prod - i32::from(gf.log[(share.0 ^ x) as usize]);
        for other in shares {
            log_basis -= i32::from(gf.log[(share.0 ^ other.0) as usize]);
        }
        let log_basis = log_basis.rem_euclid(255);
        for (out, &v) in result.iter_mut().zip(share.1.iter()) {
            if v != 0 {
                *out ^= gf.exp[((i32::from(gf.log[v as usize]) + log_basis) % 255) as usize];
            }
        }
    }
    Ok(result)
}

// ------------------------------------------------------------- checksum

const RS1024_GEN: [u32; 10] = [
    0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
    0x21B1F890, 0x3F3F120,
];

fn rs1024_polymod(values: impl Iterator<Item = u32>) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ v;
        for (i, g) in RS1024_GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn customization(extendable: bool) -> &'static [u8] {
    if extendable { CUSTOMIZATION_EXTENDABLE } else { CUSTOMIZATION_ORIG }
}

fn checksum_is_valid(indices: &[u16], extendable: bool) -> bool {
    let custom = customization(extendable).iter().map(|&b| u32::from(b));
    rs1024_polymod(custom.chain(indices.iter().map(|&i| u32::from(i)))) == 1
}

fn checksum_for(data: &[u16], extendable: bool) -> [u16; CHECKSUM_WORDS] {
    let custom = customization(extendable).iter().map(|&b| u32::from(b));
    let values = custom.chain(data.iter().map(|&i| u32::from(i))).chain([0, 0, 0]);
    let polymod = rs1024_polymod(values) ^ 1;
    [
        ((polymod >> 20) & 1023) as u16,
        ((polymod >> 10) & 1023) as u16,
        (polymod & 1023) as u16,
    ]
}

// ------------------------------------------------------------ encryption

/// PBKDF2-HMAC-SHA256, the RFC's loop over this crate's `hmac`, as
/// `keys::pbkdf2_hmac_sha512` is for SHA-512.
pub(crate) fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> Result<(), Invalid> {
    let prf = Hmac::<Sha256>::new_from_slice(password).map_err(|_| Invalid)?;
    for (i, block) in out.chunks_mut(32).enumerate() {
        let index = u32::try_from(i + 1).map_err(|_| Invalid)?;
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&index.to_be_bytes());
        let mut u = Zeroizing::new([0u8; 32]);
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

fn round_function(i: u8, passphrase: &[u8], exponent: u8, salt: &[u8], r: &[u8]) -> Result<Secret, Invalid> {
    let mut password = Zeroizing::new(Vec::with_capacity(1 + passphrase.len()));
    password.push(i);
    password.extend_from_slice(passphrase);
    let mut round_salt = Zeroizing::new(Vec::with_capacity(salt.len() + r.len()));
    round_salt.extend_from_slice(salt);
    round_salt.extend_from_slice(r);
    let iterations = (BASE_ITERATIONS << exponent) / u32::from(ROUND_COUNT);
    let mut out = Zeroizing::new(vec![0u8; r.len()]);
    pbkdf2_hmac_sha256(&password, &round_salt, iterations, &mut out)?;
    Ok(out)
}

/// An extendable backup's salt is empty; otherwise "shamir" and the
/// identifier, as `slip39.dart`'s `_salt`.
fn cipher_salt(identifier: u16, extendable: bool) -> Vec<u8> {
    if extendable {
        Vec::new()
    } else {
        let mut salt = CUSTOMIZATION_ORIG.to_vec();
        salt.extend_from_slice(&identifier.to_be_bytes());
        salt
    }
}

fn cipher(
    secret: &[u8],
    passphrase: &[u8],
    exponent: u8,
    identifier: u16,
    extendable: bool,
    decrypt: bool,
) -> Result<Secret, Invalid> {
    let half = secret.len() / 2;
    let mut l = Zeroizing::new(secret[..half].to_vec());
    let mut r = Zeroizing::new(secret[half..].to_vec());
    let salt = cipher_salt(identifier, extendable);
    let rounds: [u8; ROUND_COUNT as usize] = if decrypt { [3, 2, 1, 0] } else { [0, 1, 2, 3] };
    for i in rounds {
        let f = round_function(i, passphrase, exponent, &salt, &r)?;
        let next = Zeroizing::new(l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
        l = r;
        r = next;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(secret.len()));
    out.extend_from_slice(&r);
    out.extend_from_slice(&l);
    Ok(out)
}

// ---------------------------------------------------------------- shares

/// One share, decoded from its words.
pub(crate) struct Share {
    pub(crate) identifier: u16,
    pub(crate) extendable: bool,
    pub(crate) iteration_exponent: u8,
    pub(crate) group_index: u8,
    pub(crate) group_threshold: u8,
    pub(crate) group_count: u8,
    pub(crate) member_index: u8,
    pub(crate) member_threshold: u8,
    pub(crate) value: Secret,
}

impl Share {
    /// The identifier as the four hex digits every store and label uses.
    pub(crate) fn set_id_hex(&self) -> String {
        format!("{:04x}", self.identifier)
    }

    fn set_identity(&self) -> (u16, bool, u8, u8, u8) {
        (
            self.identifier,
            self.extendable,
            self.iteration_exponent,
            self.group_threshold,
            self.group_count,
        )
    }
}

fn words_to_indices(mnemonic: &str) -> Result<Zeroizing<Vec<u16>>, Invalid> {
    let mut indices = Zeroizing::new(Vec::new());
    for word in mnemonic.split_whitespace() {
        let index = WORDS.iter().position(|w| w.eq_ignore_ascii_case(word)).ok_or(Invalid)?;
        indices.push(index as u16);
    }
    Ok(indices)
}

/// Reads a share's words back into its fields, refusing before it
/// interprets: length, checksum and padding first, as `decodeShare` does.
pub(crate) fn decode_share(mnemonic: &str) -> Result<Share, Invalid> {
    let indices = words_to_indices(mnemonic)?;
    if indices.len() < MIN_SHARE_WORDS {
        return Err(Invalid);
    }
    let id_exp = (u32::from(indices[0]) << 10) | u32::from(indices[1]);
    let identifier = (id_exp >> (1 + ITERATION_EXP_BITS)) as u16;
    let extendable = (id_exp >> ITERATION_EXP_BITS) & 1 == 1;
    let iteration_exponent = (id_exp & ((1 << ITERATION_EXP_BITS) - 1)) as u8;
    if !checksum_is_valid(&indices, extendable) {
        return Err(Invalid);
    }
    let group_member = (u32::from(indices[2]) << 10) | u32::from(indices[3]);
    let group_index = ((group_member >> 16) & 0xF) as u8;
    let group_threshold = ((group_member >> 12) & 0xF) as u8 + 1;
    let group_count = ((group_member >> 8) & 0xF) as u8 + 1;
    let member_index = ((group_member >> 4) & 0xF) as u8;
    let member_threshold = (group_member & 0xF) as u8 + 1;
    if group_count < group_threshold {
        return Err(Invalid);
    }

    // The value, padded at the front to whole words; an even, whole number of
    // bytes, which is why the modulus is 16.
    let value_words = &indices[METADATA_WORDS..indices.len() - CHECKSUM_WORDS];
    let total_bits = value_words.len() * 10;
    let padding = total_bits % 16;
    if padding > 8 {
        return Err(Invalid);
    }
    let value_bytes = (total_bits - padding) / 8;
    let bit = |n: usize| -> u8 {
        let word = value_words[n / 10];
        ((word >> (9 - (n % 10))) & 1) as u8
    };
    // The padding bits are the high ones: non-zero is a value too large for
    // its own length, refused rather than trimmed.
    if (0..padding).any(|n| bit(n) != 0) {
        return Err(Invalid);
    }
    let mut value = Zeroizing::new(vec![0u8; value_bytes]);
    for (i, byte) in value.iter_mut().enumerate() {
        for b in 0..8 {
            *byte = (*byte << 1) | bit(padding + i * 8 + b);
        }
    }
    Ok(Share {
        identifier,
        extendable,
        iteration_exponent,
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
        value,
    })
}

/// Writes a share's fields back out as words — the padding at the front,
/// as `encodeShare` learned the hard way.
pub(crate) fn encode_share(share: &Share) -> Zeroizing<String> {
    let value_bits = share.value.len() * 8;
    let value_words = value_bits.div_ceil(10);
    let padding = value_words * 10 - value_bits;

    let mut indices: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::new());
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut put = |indices: &mut Vec<u16>, value: u64, width: u32| {
        acc = (acc << width) | value;
        acc_bits += width;
        while acc_bits >= 10 {
            acc_bits -= 10;
            indices.push(((acc >> acc_bits) & 1023) as u16);
            acc &= (1 << acc_bits) - 1;
        }
    };
    put(&mut indices, u64::from(share.identifier), ID_BITS);
    put(&mut indices, u64::from(share.extendable), 1);
    put(&mut indices, u64::from(share.iteration_exponent), ITERATION_EXP_BITS);
    put(&mut indices, u64::from(share.group_index), 4);
    put(&mut indices, u64::from(share.group_threshold - 1), 4);
    put(&mut indices, u64::from(share.group_count - 1), 4);
    put(&mut indices, u64::from(share.member_index), 4);
    put(&mut indices, u64::from(share.member_threshold - 1), 4);
    put(&mut indices, 0, padding as u32);
    for &byte in share.value.iter() {
        put(&mut indices, u64::from(byte), 8);
    }
    let checksum = checksum_for(&indices, share.extendable);
    indices.extend_from_slice(&checksum);
    let mut words = Zeroizing::new(String::new());
    for (n, &i) in indices.iter().enumerate() {
        if n > 0 {
            words.push(' ');
        }
        words.push_str(WORDS[i as usize]);
    }
    words
}

// -------------------------------------------------------------- recovery

fn digest_for(random: &[u8], secret: &[u8]) -> Result<[u8; DIGEST_LEN], Invalid> {
    let mut mac = Hmac::<Sha256>::new_from_slice(random).map_err(|_| Invalid)?;
    mac.update(secret);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&full[..DIGEST_LEN]);
    Ok(out)
}

fn recover_group(threshold: u8, shares: &[(u8, &[u8])]) -> Result<Secret, Invalid> {
    if threshold == 1 {
        return Ok(Zeroizing::new(shares.first().ok_or(Invalid)?.1.to_vec()));
    }
    let secret = interpolate(shares, SECRET_INDEX)?;
    let digest_share = interpolate(shares, DIGEST_INDEX)?;
    if digest_share.len() < DIGEST_LEN {
        return Err(Invalid);
    }
    let (digest, random) = digest_share.split_at(DIGEST_LEN);
    // The check that catches shares individually perfect and not of one set.
    if !bool::from(digest_for(random, &secret)?.ct_eq(digest)) {
        return Err(Invalid);
    }
    Ok(secret)
}

/// Combines [mnemonics] into the master secret, or refuses: never a secret it
/// is not sure of.
pub(crate) fn recover_secret(mnemonics: &[&str], passphrase: &[u8]) -> Result<Secret, Invalid> {
    let shares = mnemonics.iter().map(|m| decode_share(m)).collect::<Result<Vec<_>, _>>()?;
    let first = shares.first().ok_or(Invalid)?;
    if shares.iter().any(|s| s.set_identity() != first.set_identity()) {
        return Err(Invalid);
    }
    let mut groups: Vec<(u8, Vec<&Share>)> = Vec::new();
    for share in &shares {
        match groups.iter_mut().find(|g| g.0 == share.group_index) {
            Some(group) => group.1.push(share),
            None => groups.push((share.group_index, vec![share])),
        }
    }
    if groups.len() != usize::from(first.group_threshold) {
        return Err(Invalid);
    }
    let mut group_secrets: Vec<(u8, Secret)> = Vec::new();
    for (index, members) in &groups {
        let threshold = members[0].member_threshold;
        if members.iter().any(|s| s.member_threshold != threshold)
            || members.len() != usize::from(threshold)
        {
            return Err(Invalid);
        }
        let values: Vec<(u8, &[u8])> = members.iter().map(|s| (s.member_index, &s.value[..])).collect();
        group_secrets.push((*index, recover_group(threshold, &values)?));
    }
    let values: Vec<(u8, &[u8])> = group_secrets.iter().map(|(i, s)| (*i, &s[..])).collect();
    let encrypted = recover_group(first.group_threshold, &values)?;
    cipher(
        &encrypted,
        passphrase,
        first.iteration_exponent,
        first.identifier,
        first.extendable,
        true,
    )
}

// --------------------------------------------------------------- splitting

/// Random bytes: the operating system's generator for everything real
/// (O62); a test pins its own.
pub(crate) type RandomBytes<'a> = &'a mut dyn FnMut(usize) -> Result<Secret, Invalid>;

/// The operating system's random bytes (`getrandom`).
pub(crate) fn os_random(length: usize) -> Result<Secret, Invalid> {
    let mut out = Zeroizing::new(vec![0u8; length]);
    getrandom::getrandom(&mut out).map_err(|_| Invalid)?;
    Ok(out)
}

fn split_one(threshold: u8, count: u8, secret: &[u8], random: RandomBytes) -> Result<Vec<(u8, Secret)>, Invalid> {
    if threshold < 1 || threshold > count || usize::from(count) > MAX_SHARE_COUNT {
        return Err(Invalid);
    }
    if threshold == 1 {
        return Ok((0..count).map(|i| (i, Zeroizing::new(secret.to_vec()))).collect());
    }
    let random_share_count = threshold - 2;
    let mut shares: Vec<(u8, Secret)> = Vec::new();
    for i in 0..random_share_count {
        shares.push((i, random(secret.len())?));
    }
    if secret.len() < DIGEST_LEN {
        return Err(Invalid);
    }
    let random_part = random(secret.len() - DIGEST_LEN)?;
    let mut digest_share = Zeroizing::new(digest_for(&random_part, secret)?.to_vec());
    digest_share.extend_from_slice(&random_part);
    let mut base: Vec<(u8, &[u8])> = shares.iter().map(|(i, v)| (*i, &v[..])).collect();
    base.push((DIGEST_INDEX, &digest_share));
    base.push((SECRET_INDEX, secret));
    let mut made: Vec<(u8, Secret)> = Vec::new();
    for i in random_share_count..count {
        made.push((i, interpolate(&base, i)?));
    }
    drop(base);
    shares.extend(made);
    Ok(shares)
}

/// Splits [master_secret] into one list of mnemonics per group, as
/// `splitSecret` does — extendable, as the app's backups are.
pub(crate) fn split_secret(
    master_secret: &[u8],
    group_threshold: u8,
    groups: &[(u8, u8)],
    passphrase: &[u8],
    iteration_exponent: u8,
    extendable: bool,
    random: RandomBytes,
) -> Result<Vec<Vec<Zeroizing<String>>>, Invalid> {
    if master_secret.len() < 16 || master_secret.len() % 2 != 0 {
        return Err(Invalid);
    }
    if groups.is_empty() || usize::from(group_threshold) > groups.len() || group_threshold < 1 {
        return Err(Invalid);
    }
    if groups.iter().any(|&(t, c)| t == 1 && c > 1) {
        return Err(Invalid);
    }
    let id_bytes = random(2)?;
    let identifier = ((u16::from(id_bytes[0]) << 8) | u16::from(id_bytes[1])) & ((1 << ID_BITS) - 1);
    let encrypted = cipher(master_secret, passphrase, iteration_exponent, identifier, extendable, false)?;
    let group_shares = split_one(group_threshold, groups.len() as u8, &encrypted, random)?;
    let mut out = Vec::new();
    for (group_index, group_secret) in &group_shares {
        let (threshold, count) = groups[usize::from(*group_index)];
        let mut words = Vec::new();
        for (member_index, value) in split_one(threshold, count, group_secret, random)? {
            words.push(encode_share(&Share {
                identifier,
                extendable,
                iteration_exponent,
                group_index: *group_index,
                group_threshold,
                group_count: groups.len() as u8,
                member_index,
                member_threshold: threshold,
                value,
            }));
        }
        out.push(words);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SatoshiLabs' vectors, the file `test/slip39_test.dart` pins: each
    /// `[description, mnemonics, master secret hex, xprv]`, the secret empty
    /// where the set must be refused. Generated with the passphrase "TREZOR".
    fn vectors() -> Vec<(String, Vec<String>, String)> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/support/slip39_vectors.json"
        ))
        .expect("the vectors file");
        let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        value
            .as_array()
            .expect("a list")
            .iter()
            .map(|v| {
                let mnemonics = v[1].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect();
                (v[0].as_str().unwrap().to_string(), mnemonics, v[2].as_str().unwrap().to_string())
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_word_list_is_the_standards() {
        assert_eq!(WORDS.len(), 1024);
        assert_eq!(WORDS[0], "academic");
        assert_eq!(WORDS[1023], "zero");
        for w in WORDS.windows(2) {
            assert!(w[0] < w[1], "sorted and unique: {} {}", w[0], w[1]);
        }
        let mut prefixes: Vec<&str> = WORDS.iter().map(|w| &w[..4.min(w.len())]).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 1024, "unique in their first four letters");
    }

    #[test]
    fn every_published_vector() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 45);
        for (description, mnemonics, secret) in vectors {
            let refs: Vec<&str> = mnemonics.iter().map(String::as_str).collect();
            let got = recover_secret(&refs, b"TREZOR");
            if secret.is_empty() {
                assert!(got.is_err(), "{description}: must be refused");
            } else {
                assert_eq!(hex(&got.expect(&description)), secret, "{description}");
            }
        }
    }

    #[test]
    fn each_valid_vector_share_encodes_back_to_its_words() {
        for (description, mnemonics, secret) in vectors() {
            if secret.is_empty() {
                continue;
            }
            for m in &mnemonics {
                let share = decode_share(m).expect(&description);
                let words = encode_share(&share);
                let normalised: Vec<&str> = m.split_whitespace().collect();
                assert_eq!(words.as_str(), normalised.join(" "), "{description}");
            }
        }
    }

    fn counter() -> impl FnMut(usize) -> Result<Secret, Invalid> {
        let mut next: u8 = 7;
        move |n| {
            let mut out = Zeroizing::new(vec![0u8; n]);
            for b in out.iter_mut() {
                next = next.wrapping_mul(31).wrapping_add(17);
                *b = next;
            }
            Ok(out)
        }
    }

    #[test]
    fn a_split_comes_back_from_every_threshold_set() {
        for len in [16usize, 32] {
            let secret: Vec<u8> = (0..len as u8).collect();
            for (threshold, count) in [(2u8, 3u8), (3, 5), (2, 2), (5, 5)] {
                let mut random = counter();
                let groups = split_secret(&secret, 1, &[(threshold, count)], b"", 0, true, &mut random).unwrap();
                let shares = &groups[0];
                assert_eq!(shares.len(), usize::from(count));
                // Every pair, or every triple, as the backup's own check does.
                let n = shares.len();
                let mut sets: Vec<Vec<usize>> = vec![vec![]];
                for i in 0..n {
                    let mut more = Vec::new();
                    for s in &sets {
                        let mut t = s.clone();
                        t.push(i);
                        more.push(t);
                    }
                    sets.extend(more);
                }
                for set in sets.iter().filter(|s| s.len() == usize::from(threshold)) {
                    let refs: Vec<&str> = set.iter().map(|&i| shares[i].as_str()).collect();
                    assert_eq!(&recover_secret(&refs, b"").unwrap()[..], &secret[..]);
                }
                for set in sets.iter().filter(|s| !s.is_empty() && s.len() < usize::from(threshold)) {
                    let refs: Vec<&str> = set.iter().map(|&i| shares[i].as_str()).collect();
                    assert!(recover_secret(&refs, b"").is_err(), "fewer than the threshold");
                }
            }
        }
    }

    #[test]
    fn a_share_of_another_split_is_refused_by_the_digest() {
        let secret = [9u8; 16];
        let mut random = counter();
        let a = split_secret(&secret, 1, &[(2, 3)], b"", 0, true, &mut random).unwrap();
        let b = split_secret(&secret, 1, &[(2, 3)], b"", 0, true, &mut random).unwrap();
        // Different identifiers: refused as different sets.
        assert!(recover_secret(&[a[0][0].as_str(), b[0][1].as_str()], b"").is_err());
    }

    #[test]
    fn a_changed_word_fails_the_checksum() {
        let mut random = counter();
        let shares = split_secret(&[1u8; 16], 1, &[(2, 3)], b"", 0, true, &mut random).unwrap();
        let mut words: Vec<&str> = shares[0][0].split(' ').collect();
        words[6] = if words[6] == "academic" { "acid" } else { "academic" };
        assert!(decode_share(&words.join(" ")).is_err());
    }

    #[test]
    fn arrangements_the_standard_forbids() {
        let mut random = counter();
        assert!(split_secret(&[1u8; 16], 1, &[(1, 3)], b"", 0, true, &mut random).is_err());
        assert!(split_secret(&[1u8; 16], 1, &[(4, 3)], b"", 0, true, &mut random).is_err());
        assert!(split_secret(&[1u8; 16], 1, &[(2, 17)], b"", 0, true, &mut random).is_err());
        assert!(split_secret(&[1u8; 15], 1, &[(2, 3)], b"", 0, true, &mut random).is_err());
        assert!(split_secret(&[1u8; 18][..17], 1, &[(2, 3)], b"", 0, true, &mut random).is_err());
    }
}
