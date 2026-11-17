//! A Cardano transfer read in the core for its review screen — "the screen
//! shows what the core read" for Cardano, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A Cardano witness is an Ed25519-BIP32 signature over the BLAKE2b-256 of
//! the transaction body's CBOR — the transaction's id. The core reads the body
//! in the one form the module's `on_chain` writes it — a map of exactly the
//! inputs (key 0, a set: tag 258), the outputs (1), the fee (2) and the time
//! to live (3), in that order; every input a 32-byte transaction id and an
//! index, no input twice; every output a map of its address (0) and a bare
//! amount of lovelace (1), with no native asset, datum or script; every
//! length definite and every number in its shortest form, nothing after — and
//! refuses any other: a certificate, a withdrawal, a mint, metadata, a
//! collateral, a validity start. It returns the inputs, the outputs, the fee,
//! the time to live and the hash.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use blake2::digest::consts::{U28, U32};
use blake2::{Blake2b, Digest};
use serde_json::{Map, Value};

use crate::Refusal;

type Blake2b256 = Blake2b<U32>;

/// The payment key hash of an ed25519 public [key]: its BLAKE2b-224, which
/// is what an address's payment credential holds and what a witness of that
/// key answers for.
pub(crate) fn key_hash(key: &[u8; 32]) -> [u8; 28] {
    Blake2b::<U28>::digest(key).into()
}

/// The signers' paths a reading is asked for, in
/// `kc_cardano_read_transaction`'s layout: two bytes of count, then for each
/// two bytes of length and the path. None, a count past the inputs a body may
/// hold, or a layout that does not read is [`Refusal::Argument`].
pub(crate) fn signer_paths(bytes: &[u8]) -> Result<Vec<&[u8]>, Refusal> {
    let take2 = |at: usize| -> Result<usize, Refusal> {
        let two = bytes.get(at..at + 2).ok_or(Refusal::Argument)?;
        Ok(usize::from(u16::from_le_bytes([two[0], two[1]])))
    };
    let count = take2(0)?;
    if count == 0 || count > MAX_INPUTS as usize {
        return Err(Refusal::Argument);
    }
    let mut at = 2;
    let mut paths = Vec::with_capacity(count);
    for _ in 0..count {
        let length = take2(at)?;
        at += 2;
        paths.push(bytes.get(at..at + length).ok_or(Refusal::Argument)?);
        at += length;
    }
    if at != bytes.len() {
        return Err(Refusal::Argument);
    }
    Ok(paths)
}

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The most inputs, and outputs, a body is read with.
const MAX_INPUTS: u64 = 256;
const MAX_OUTPUTS: u64 = 16;

/// CBOR's set tag (Conway).
const SET: u64 = 258;

/// Canonical CBOR, as Cardano's body and Filecoin's message are read.
pub(crate) struct Reader<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(n).ok_or(Refusal::Transaction)?;
        let taken = self.bytes.get(self.at..end).ok_or(Refusal::Transaction)?;
        self.at = end;
        Ok(taken)
    }

    /// A data item's head: its major type and its argument, which must be
    /// written in the fewest bytes and be definite.
    pub(crate) fn head(&mut self) -> Result<(u8, u64), Refusal> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        let value = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return refused();
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("two")));
                if v < 0x100 {
                    return refused();
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("four")));
                if v < 0x1_0000 {
                    return refused();
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().expect("eight"));
                if v < 0x1_0000_0000 {
                    return refused();
                }
                v
            }
            _ => return refused(),
        };
        Ok((major, value))
    }

    pub(crate) fn expect(&mut self, major: u8) -> Result<u64, Refusal> {
        let (m, v) = self.head()?;
        if m != major {
            return refused();
        }
        Ok(v)
    }

    pub(crate) fn uint(&mut self) -> Result<u64, Refusal> {
        self.expect(0)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Refusal> {
        let length = self.expect(2)?;
        self.take(usize::try_from(length).map_err(|_| Refusal::Transaction)?)
    }

    /// A text string, UTF-8.
    pub(crate) fn text(&mut self) -> Result<&'a str, Refusal> {
        let length = self.expect(3)?;
        let bytes = self.take(usize::try_from(length).map_err(|_| Refusal::Transaction)?)?;
        std::str::from_utf8(bytes).map_err(|_| Refusal::Transaction)
    }

    pub(crate) fn array(&mut self) -> Result<u64, Refusal> {
        self.expect(4)
    }

    pub(crate) fn map(&mut self) -> Result<u64, Refusal> {
        self.expect(5)
    }

    /// That the map key [key] comes next.
    pub(crate) fn key(&mut self, key: u64) -> Result<(), Refusal> {
        if self.uint()? != key {
            return refused();
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [body] — a transaction body's CBOR, whose BLAKE2b-256 a Cardano witness
/// signs — read for a review screen, with that hash; or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(body: &[u8]) -> Result<(Value, [u8; 32]), Refusal> {
    let mut r = Reader { bytes: body, at: 0 };
    if r.map()? != 4 {
        return refused();
    }
    r.key(0)?;
    if r.expect(6)? != SET {
        return refused();
    }
    let count = r.array()?;
    if count == 0 || count > MAX_INPUTS {
        return refused();
    }
    let mut inputs = Vec::new();
    let mut seen = Vec::new();
    for _ in 0..count {
        if r.array()? != 2 {
            return refused();
        }
        let id = r.bytes()?;
        if id.len() != 32 {
            return refused();
        }
        let index = r.uint()?;
        if seen.contains(&(id, index)) {
            return refused();
        }
        seen.push((id, index));
        let mut input = Map::new();
        input.insert("txId".into(), Value::from(hex(id)));
        input.insert("index".into(), Value::from(index.to_string()));
        inputs.push(Value::Object(input));
    }
    r.key(1)?;
    let count = r.array()?;
    if count == 0 || count > MAX_OUTPUTS {
        return refused();
    }
    let mut outputs = Vec::new();
    for _ in 0..count {
        if r.map()? != 2 {
            return refused();
        }
        r.key(0)?;
        let address = r.bytes()?;
        if address.is_empty() || address.len() > 128 {
            return refused();
        }
        r.key(1)?;
        let lovelace = r.uint()?;
        let mut output = Map::new();
        output.insert("address".into(), Value::from(hex(address)));
        output.insert("lovelace".into(), Value::from(lovelace.to_string()));
        outputs.push(Value::Object(output));
    }
    r.key(2)?;
    let fee = r.uint()?;
    r.key(3)?;
    let ttl = r.uint()?;
    if r.at != body.len() {
        return refused();
    }
    let hash: [u8; 32] = Blake2b256::digest(body).into();
    let mut read = Map::new();
    read.insert("inputs".into(), Value::from(inputs));
    read.insert("outputs".into(), Value::from(outputs));
    read.insert("fee".into(), Value::from(fee.to_string()));
    read.insert("ttl".into(), Value::from(ttl.to_string()));
    read.insert("hash".into(), Value::from(format!("0x{}", hex(&hash))));
    Ok((Value::Object(read), hash))
}
