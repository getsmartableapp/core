//! A Tezos operation group read in the core for its review screen — "the
//! screen shows what the core read" for Tezos, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52, O58 and O60).
//!
//! A Tezos signature is over BLAKE2b-256 of the watermark `0x03` and the
//! forged group: the branch, then each operation. The core reads the group
//! whole and strictly — every zarith in its shortest form, nothing after the
//! last operation — and refuses what this wallet's own forger never writes:
//! an operation other than a reveal or a transaction, a reveal of a key that
//! is not ed25519 or with a proof, an originated account as a source, a
//! Micheline node other than an integer, a string, bytes or one of the
//! forger's eight primitives with no annotation. It returns the branch and
//! every operation, its addresses in Tezos's own spelling and its argument as
//! the forger takes one.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{Map, Value};

use crate::Refusal;
use crate::solana::base58;

type Blake2b256 = Blake2b<U32>;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

const REVEAL: u8 = 0x6b;
const TRANSACTION: u8 = 0x6c;

/// Deeper than any argument this wallet writes nests.
const MAX_DEPTH: usize = 32;

/// The forger's primitives, by their Michelson codes.
const PRIMITIVES: [(u8, &str); 8] = [
    (0x03, "False"),
    (0x05, "Left"),
    (0x06, "None"),
    (0x07, "Pair"),
    (0x08, "Right"),
    (0x09, "Some"),
    (0x0a, "True"),
    (0x0b, "Unit"),
];

/// The named entrypoints' one-byte codes.
const ENTRYPOINTS: [&str; 6] = ["default", "root", "do", "set_delegate", "remove_delegate", "deposit"];

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(n).ok_or(Refusal::Transaction)?;
        let taken = self.bytes.get(self.at..end).ok_or(Refusal::Transaction)?;
        self.at = end;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<usize, Refusal> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four")) as usize)
    }

    /// A zarith natural, in its shortest form, as a decimal string.
    fn zarith(&mut self) -> Result<String, Refusal> {
        let mut groups = Vec::new();
        loop {
            let byte = self.u8()?;
            groups.push(byte & 0x7f);
            if byte & 0x80 == 0 {
                if groups.len() > 1 && byte == 0 {
                    return refused();
                }
                break;
            }
            if groups.len() > 40 {
                return refused();
            }
        }
        Ok(decimal(&groups, 7, false))
    }

    /// A zarith integer, signed, in its shortest form, as a decimal string.
    fn zarith_signed(&mut self) -> Result<String, Refusal> {
        let first = self.u8()?;
        let negative = first & 0x40 != 0;
        let mut groups = vec![first & 0x3f];
        let mut more = first & 0x80 != 0;
        while more {
            let byte = self.u8()?;
            groups.push(byte & 0x7f);
            more = byte & 0x80 != 0;
            if !more && byte == 0 {
                return refused();
            }
            if groups.len() > 40 {
                return refused();
            }
        }
        let text = decimal(&groups, 6, negative);
        if text == "-0" {
            return refused();
        }
        Ok(text)
    }

    /// An implicit account: its curve's tag and its 20-byte hash.
    fn implicit(&mut self) -> Result<String, Refusal> {
        let prefix: &[u8] = match self.u8()? {
            0x00 => &[6, 161, 159],
            0x01 => &[6, 161, 161],
            0x02 => &[6, 161, 164],
            _ => return refused(),
        };
        Ok(base58check(prefix, self.take(20)?))
    }

    /// A destination: an implicit account, or an originated one and its
    /// padding byte.
    fn destination(&mut self) -> Result<String, Refusal> {
        match self.u8()? {
            0x00 => self.implicit(),
            0x01 => {
                let hash = self.take(20)?;
                if self.u8()? != 0 {
                    return refused();
                }
                Ok(base58check(&[2, 90, 121], hash))
            }
            _ => refused(),
        }
    }

    /// One Micheline node, as the forger takes one.
    fn micheline(&mut self, depth: usize) -> Result<Value, Refusal> {
        if depth > MAX_DEPTH {
            return refused();
        }
        let mut node = Map::new();
        match self.u8()? {
            0x00 => {
                node.insert("int".into(), Value::from(self.zarith_signed()?));
            }
            0x01 => {
                let n = self.u32()?;
                let text = std::str::from_utf8(self.take(n)?).map_err(|_| Refusal::Transaction)?;
                node.insert("string".into(), Value::from(text));
            }
            0x0a => {
                let n = self.u32()?;
                node.insert("bytes".into(), Value::from(hex(self.take(n)?)));
            }
            tag @ (0x03 | 0x05 | 0x07 | 0x09) => {
                let code = self.u8()?;
                let name = PRIMITIVES.iter().find(|(c, _)| *c == code).ok_or(Refusal::Transaction)?.1;
                node.insert("prim".into(), Value::from(name));
                let args = match tag {
                    0x03 => Vec::new(),
                    0x05 => vec![self.micheline(depth + 1)?],
                    0x07 => vec![self.micheline(depth + 1)?, self.micheline(depth + 1)?],
                    _ => {
                        // The general form, as the forger writes it: more
                        // than two arguments behind a length, no annotation.
                        let n = self.u32()?;
                        let end = self.at.checked_add(n).ok_or(Refusal::Transaction)?;
                        let mut args = Vec::new();
                        while self.at < end {
                            args.push(self.micheline(depth + 1)?);
                        }
                        if self.at != end || args.len() <= 2 || self.u32()? != 0 {
                            return refused();
                        }
                        args
                    }
                };
                if !args.is_empty() {
                    node.insert("args".into(), Value::Array(args));
                }
            }
            _ => return refused(),
        }
        Ok(Value::Object(node))
    }
}

/// [groups] — 7- or, for the first of a signed zarith, 6-bit groups, least
/// significant first — as a decimal string.
fn decimal(groups: &[u8], first_bits: u32, negative: bool) -> String {
    // Little-endian base-2^32 limbs.
    let mut limbs: Vec<u32> = vec![0];
    let mut shift = 0u32;
    for (i, group) in groups.iter().enumerate() {
        let bits = if i == 0 { first_bits } else { 7 };
        let mut value = u64::from(*group) << (shift % 32);
        let mut limb = (shift / 32) as usize;
        while value != 0 {
            if limbs.len() <= limb {
                limbs.push(0);
            }
            let sum = u64::from(limbs[limb]) | (value & 0xffff_ffff);
            limbs[limb] = sum as u32;
            value >>= 32;
            limb += 1;
        }
        shift += bits;
    }
    // Repeated division by ten.
    let mut digits = Vec::new();
    while limbs.iter().any(|l| *l != 0) {
        let mut rem = 0u64;
        for limb in limbs.iter_mut().rev() {
            let cur = rem << 32 | u64::from(*limb);
            *limb = (cur / 10) as u32;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    let mut text = String::new();
    if negative {
        text.push('-');
    }
    text.extend(digits.iter().rev().map(|d| *d as char));
    text
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Base58check of [prefix] and [payload], as Tezos spells an address.
fn base58check(prefix: &[u8], payload: &[u8]) -> String {
    use sha2::Digest as _;
    let data = [prefix, payload].concat();
    let check = sha2::Sha256::digest(sha2::Sha256::digest(&data));
    base58(&[data.as_slice(), &check[..4]].concat())
}

/// [forged] — a Tezos operation group as this wallet's forger writes it,
/// whose watermarked BLAKE2b-256 a Tezos signature is over — read for a
/// review screen, or [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(forged: &[u8]) -> Result<Value, Refusal> {
    let mut reader = Reader { bytes: forged, at: 0 };
    let branch = base58check(&[1, 52], reader.take(32)?);
    let mut operations = Vec::new();
    while reader.at < forged.len() {
        if operations.len() >= 64 {
            return refused();
        }
        let tag = reader.u8()?;
        let mut op = Map::new();
        op.insert("kind".into(), Value::from(if tag == REVEAL { "reveal" } else { "transaction" }));
        if tag != REVEAL && tag != TRANSACTION {
            return refused();
        }
        op.insert("source".into(), Value::from(reader.implicit()?));
        op.insert("fee".into(), Value::from(reader.zarith()?));
        op.insert("counter".into(), Value::from(reader.zarith()?));
        op.insert("gasLimit".into(), Value::from(reader.zarith()?));
        op.insert("storageLimit".into(), Value::from(reader.zarith()?));
        if tag == REVEAL {
            // An ed25519 key, and no proof.
            if reader.u8()? != 0x00 {
                return refused();
            }
            let key = reader.take(32)?;
            if reader.u8()? != 0x00 {
                return refused();
            }
            op.insert("publicKey".into(), Value::from(base58check(&[13, 15, 37, 217], key)));
        } else {
            op.insert("amount".into(), Value::from(reader.zarith()?));
            op.insert("destination".into(), Value::from(reader.destination()?));
            match reader.u8()? {
                0x00 => {
                    op.insert("entrypoint".into(), Value::Null);
                    op.insert("parameters".into(), Value::Null);
                }
                0xff => {
                    let entrypoint = match reader.u8()? {
                        0xff => {
                            let n = usize::from(reader.u8()?);
                            if n == 0 || n > 31 {
                                return refused();
                            }
                            let name = std::str::from_utf8(reader.take(n)?).map_err(|_| Refusal::Transaction)?;
                            // A named entrypoint is written by its code.
                            if ENTRYPOINTS.contains(&name) {
                                return refused();
                            }
                            name.to_owned()
                        }
                        code => ENTRYPOINTS.get(usize::from(code)).ok_or(Refusal::Transaction)?.to_string(),
                    };
                    let n = reader.u32()?;
                    let end = reader.at.checked_add(n).ok_or(Refusal::Transaction)?;
                    let parameters = reader.micheline(0)?;
                    if reader.at != end {
                        return refused();
                    }
                    op.insert("entrypoint".into(), Value::from(entrypoint));
                    op.insert("parameters".into(), parameters);
                }
                _ => return refused(),
            }
        }
        operations.push(Value::Object(op));
    }
    if operations.is_empty() {
        return refused();
    }
    let mut read = Map::new();
    read.insert("branch".into(), Value::from(branch));
    read.insert("operations".into(), Value::Array(operations));
    Ok(Value::Object(read))
}

/// BLAKE2b-256 of the watermark `0x03` and [forged]: the 32 bytes a Tezos
/// key signs — kept for a screen given its reading.
pub(crate) fn signing_digest(forged: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update([0x03]);
    hasher.update(forged);
    hasher.finalize().into()
}
