//! A MultiversX transaction read in the core for its review screen — "the
//! screen shows what the core read" for MultiversX, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A MultiversX signature is over the transaction's signing JSON itself. The
//! core reads it in the one spelling the module writes — no whitespace, its
//! keys in their order (`nonce`, `value`, `receiver`, `sender`, `gasPrice`,
//! `gasLimit`, `data` where there is any, `chainID`, `version`), no escape,
//! every number without a leading zero — and refuses any other: another key
//! (options, a guardian, a relayer), a version other than 1, an address that
//! is not an `erd1` bech32 of 32 bytes with its checksum, data that is not
//! canonical base64. It returns every field, the data as text where it is
//! UTF-8, and whether the chain is mainnet's.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct Reader<'a> {
    text: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// That [literal] comes next.
    fn expect(&mut self, literal: &[u8]) -> Result<(), Refusal> {
        if self.text.get(self.at..self.at + literal.len()) != Some(literal) {
            return refused();
        }
        self.at += literal.len();
        Ok(())
    }

    /// A run of decimal digits without a leading zero, at most [max] of them.
    fn digits(&mut self, max: usize) -> Result<&'a str, Refusal> {
        let start = self.at;
        while self.text.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        let run = &self.text[start..self.at];
        if run.is_empty() || run.len() > max || (run.len() > 1 && run[0] == b'0') {
            return refused();
        }
        Ok(std::str::from_utf8(run).expect("ascii"))
    }

    /// A JSON integer within 63 bits, as Dart writes one.
    fn integer(&mut self) -> Result<String, Refusal> {
        let digits = self.digits(19)?;
        let value: u64 = digits.parse().map_err(|_| Refusal::Transaction)?;
        if value > i64::MAX as u64 {
            return refused();
        }
        Ok(digits.to_owned())
    }

    /// A JSON string with no escape: its characters up to the closing quote.
    fn string(&mut self) -> Result<&'a str, Refusal> {
        self.expect(b"\"")?;
        let start = self.at;
        while let Some(&b) = self.text.get(self.at) {
            match b {
                b'"' => break,
                b'\\' | 0x00..=0x1f => return refused(),
                _ => self.at += 1,
            }
        }
        let body = std::str::from_utf8(&self.text[start..self.at]).map_err(|_| Refusal::Transaction)?;
        self.expect(b"\"")?;
        Ok(body)
    }
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(*v);
        for (i, g) in [0x3b6a_57b2u32, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3].iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// That [address] is `erd1` and a bech32 of 32 bytes, lowercase, its checksum
/// right and its padding bits zero.
fn is_address(address: &str) -> bool {
    let Some(data) = address.strip_prefix("erd1") else {
        return false;
    };
    if address.len() != 62 {
        return false;
    }
    let Some(values) = data
        .bytes()
        .map(|c| BECH32.iter().position(|b| *b == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()
    else {
        return false;
    };
    let mut check = vec![3u8, 3, 3, 0, 5, 18, 4];
    check.extend_from_slice(&values);
    if polymod(&check) != 1 {
        return false;
    }
    // 52 five-bit groups carry 260 bits: 256 of key, 4 that must be zero.
    let payload = &values[..values.len() - 6];
    payload.len() == 52 && payload[51] & 0x0f == 0
}

/// [text] decoded as canonical base64 — the standard alphabet, padded,
/// nothing that encodes differently — or None.
fn base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 || (pad > 0 && !std::ptr::eq(chunk, bytes.chunks(4).last().expect("one"))) {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { BASE64.iter().position(|b| b == c)? as u32 };
            n = n << 6 | v;
        }
        let three = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // The bits the padding drops must be zero, or another text encodes
        // the same bytes.
        if (pad == 1 && three[2] != 0) || (pad == 2 && three[1] != 0) {
            return None;
        }
        out.extend_from_slice(&three[..3 - pad]);
    }
    Some(out)
}

/// [payload] — a MultiversX transaction's signing JSON, which an ed25519
/// signature on MultiversX is over — read for a review screen, or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(payload: &[u8]) -> Result<Value, Refusal> {
    let mut r = Reader { text: payload, at: 0 };
    r.expect(b"{\"nonce\":")?;
    let nonce = r.integer()?;
    r.expect(b",\"value\":")?;
    let value = {
        r.expect(b"\"")?;
        let digits = r.digits(78)?.to_owned();
        r.expect(b"\"")?;
        digits
    };
    r.expect(b",\"receiver\":")?;
    let receiver = r.string()?;
    r.expect(b",\"sender\":")?;
    let sender = r.string()?;
    if !is_address(receiver) || !is_address(sender) {
        return refused();
    }
    r.expect(b",\"gasPrice\":")?;
    let gas_price = r.integer()?;
    r.expect(b",\"gasLimit\":")?;
    let gas_limit = r.integer()?;
    let mut data = Value::Null;
    let mut data_text = Value::Null;
    if r.text[r.at..].starts_with(b",\"data\":") {
        r.expect(b",\"data\":")?;
        let encoded = r.string()?;
        let decoded = base64(encoded).ok_or(Refusal::Transaction)?;
        data = Value::from(encoded);
        data_text = std::str::from_utf8(&decoded).map_or(Value::Null, Value::from);
    }
    r.expect(b",\"chainID\":")?;
    let chain = r.string()?;
    if chain.is_empty() || chain.len() > 16 || !chain.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return refused();
    }
    r.expect(b",\"version\":1}")?;
    if r.at != payload.len() {
        return refused();
    }
    let mut read = Map::new();
    read.insert("nonce".into(), Value::from(nonce));
    read.insert("value".into(), Value::from(value));
    read.insert("receiver".into(), Value::from(receiver));
    read.insert("sender".into(), Value::from(sender));
    read.insert("gasPrice".into(), Value::from(gas_price));
    read.insert("gasLimit".into(), Value::from(gas_limit));
    read.insert("data".into(), data);
    read.insert("dataText".into(), data_text);
    read.insert("chainId".into(), Value::from(chain));
    read.insert("mainnet".into(), Value::from(chain == "1"));
    Ok(Value::Object(read))
}
