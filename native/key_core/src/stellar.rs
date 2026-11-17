//! A Stellar transaction read in the core for its review screen — "the screen
//! shows what the core read" for Stellar, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A Stellar signature is over the SHA-256 of a `TransactionSignaturePayload`
//! — the network's id, the envelope type and the transaction in XDR — and
//! that hash is the transaction's id. The core reads the payload whole and
//! strictly — every padding byte zero, nothing after the last field — and
//! refuses what no transaction of this wallet carries: an envelope other
//! than a v1 transaction, preconditions beyond a time window, an operation
//! other than the four the module writes (creating an account, a payment, a
//! trustline and a strict-send path payment), a pool share, an issued asset
//! whose code is not one, a negative amount, or a Soroban extension. It
//! returns the network, the source, the fee, the sequence, the time window,
//! the memo and every operation, its addresses in Stellar's own spelling.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// `Public Global Stellar Network ; September 2015`'s SHA-256: the public
/// network's id.
const PUBLIC_NETWORK: &[u8] = b"Public Global Stellar Network ; September 2015";

/// Bytes read in order, as XDR writes them: big-endian, four-byte aligned.
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

    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four")))
    }

    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("eight")))
    }

    fn i64(&mut self) -> Result<i64, Refusal> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("eight")))
    }

    /// An amount: an `int64` that is not negative.
    fn amount(&mut self) -> Result<String, Refusal> {
        let value = self.i64()?;
        if value < 0 {
            return refused();
        }
        Ok(value.to_string())
    }

    /// Fixed-length opaque data, its padding zeros.
    fn fixed(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let data = self.take(n)?;
        self.padding(n)?;
        Ok(data)
    }

    /// Variable-length opaque data of at most [max] bytes, its padding zeros.
    fn var(&mut self, max: usize) -> Result<&'a [u8], Refusal> {
        let n = usize::try_from(self.u32()?).map_err(|_| Refusal::Transaction)?;
        if n > max {
            return refused();
        }
        self.fixed(n)
    }

    fn padding(&mut self, n: usize) -> Result<(), Refusal> {
        let pad = (4 - n % 4) % 4;
        if self.take(pad)?.iter().any(|b| *b != 0) {
            return refused();
        }
        Ok(())
    }

    /// An XDR `bool` in an optional: 0 or 1.
    fn present(&mut self) -> Result<bool, Refusal> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => refused(),
        }
    }
}

/// StrKey (SEP-23): base32 of a version byte, the payload and its CRC16.
fn strkey(version: u8, payload: &[u8]) -> String {
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let mut crc: u16 = 0;
    for byte in &data {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    data.extend_from_slice(&crc.to_le_bytes());
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in data {
        buffer = buffer << 8 | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// An account's key, `G…`.
fn account(key: &[u8]) -> String {
    strkey(6 << 3, key)
}

/// `AccountID`: a `PublicKey` of type ed25519.
fn account_id(reader: &mut Reader<'_>) -> Result<String, Refusal> {
    if reader.u32()? != 0 {
        return refused();
    }
    Ok(account(reader.fixed(32)?))
}

/// `MuxedAccount`: a key, `G…`, or a key and an id, `M…`.
fn muxed(reader: &mut Reader<'_>) -> Result<String, Refusal> {
    match reader.u32()? {
        0 => Ok(account(reader.fixed(32)?)),
        0x100 => {
            let id = reader.u64()?;
            let key = reader.fixed(32)?;
            let mut payload = key.to_vec();
            payload.extend_from_slice(&id.to_be_bytes());
            Ok(strkey(12 << 3, &payload))
        }
        _ => refused(),
    }
}

/// `Asset`: native, or an issued asset as `CODE:ISSUER` — its code the
/// letters and digits before its trailing zeros.
fn asset(reader: &mut Reader<'_>) -> Result<String, Refusal> {
    let width = match reader.u32()? {
        0 => return Ok("native".into()),
        1 => 4,
        2 => 12,
        _ => return refused(),
    };
    let code = reader.fixed(width)?;
    let length = code.iter().rposition(|b| *b != 0).map_or(0, |at| at + 1);
    let code = &code[..length];
    // Four letters or fewer is the short variant, five to twelve the long one.
    let fits = if width == 4 { (1..=4).contains(&length) } else { (5..=12).contains(&length) };
    if !fits || !code.iter().all(|b| b.is_ascii_alphanumeric()) {
        return refused();
    }
    let issuer = account_id(reader)?;
    Ok(format!("{}:{issuer}", std::str::from_utf8(code).expect("ascii")))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One operation: its source where it names one, and its body — one of the
/// four the module writes.
fn operation(reader: &mut Reader<'_>) -> Result<Value, Refusal> {
    let mut out = Map::new();
    let source = if reader.present()? { Value::from(muxed(reader)?) } else { Value::Null };
    out.insert("source".into(), source);
    match reader.u32()? {
        0 => {
            out.insert("type".into(), Value::from("createAccount"));
            out.insert("destination".into(), Value::from(account_id(reader)?));
            out.insert("startingBalance".into(), Value::from(reader.amount()?));
        }
        1 => {
            out.insert("type".into(), Value::from("payment"));
            out.insert("destination".into(), Value::from(muxed(reader)?));
            out.insert("asset".into(), Value::from(asset(reader)?));
            out.insert("amount".into(), Value::from(reader.amount()?));
        }
        6 => {
            out.insert("type".into(), Value::from("changeTrust"));
            out.insert("asset".into(), Value::from(asset(reader)?));
            out.insert("limit".into(), Value::from(reader.amount()?));
        }
        13 => {
            out.insert("type".into(), Value::from("pathPaymentStrictSend"));
            out.insert("sendAsset".into(), Value::from(asset(reader)?));
            out.insert("sendAmount".into(), Value::from(reader.amount()?));
            out.insert("destination".into(), Value::from(muxed(reader)?));
            out.insert("destAsset".into(), Value::from(asset(reader)?));
            out.insert("destMin".into(), Value::from(reader.amount()?));
            let count = reader.u32()?;
            if count > 5 {
                return refused();
            }
            let path: Vec<Value> =
                (0..count).map(|_| asset(reader).map(Value::from)).collect::<Result<_, _>>()?;
            out.insert("path".into(), Value::Array(path));
        }
        _ => return refused(),
    }
    Ok(Value::Object(out))
}

/// [payload] — a `TransactionSignaturePayload`, whose SHA-256 a Stellar
/// signature is over — read for a review screen, or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(payload: &[u8]) -> Result<Value, Refusal> {
    let mut reader = Reader { bytes: payload, at: 0 };
    let network = reader.take(32)?;
    // ENVELOPE_TYPE_TX: a v1 transaction.
    if reader.u32()? != 2 {
        return refused();
    }
    let source = muxed(&mut reader)?;
    let fee = reader.u32()?;
    let sequence = reader.i64()?;
    let window = match reader.u32()? {
        0 => Value::Null,
        1 => {
            let mut bounds = Map::new();
            bounds.insert("minTime".into(), Value::from(reader.u64()?.to_string()));
            bounds.insert("maxTime".into(), Value::from(reader.u64()?.to_string()));
            Value::Object(bounds)
        }
        _ => return refused(),
    };
    let mut memo = Map::new();
    match reader.u32()? {
        0 => {
            memo.insert("type".into(), Value::from("none"));
        }
        1 => {
            let text = reader.var(28)?;
            memo.insert("type".into(), Value::from("text"));
            memo.insert("bytes".into(), Value::from(hex(text)));
            memo.insert(
                "text".into(),
                std::str::from_utf8(text).map_or(Value::Null, Value::from),
            );
        }
        2 => {
            memo.insert("type".into(), Value::from("id"));
            memo.insert("id".into(), Value::from(reader.u64()?.to_string()));
        }
        kind @ (3 | 4) => {
            memo.insert("type".into(), Value::from(if kind == 3 { "hash" } else { "return" }));
            memo.insert("hash".into(), Value::from(hex(reader.fixed(32)?)));
        }
        _ => return refused(),
    }
    let count = reader.u32()?;
    if count == 0 || count > 100 {
        return refused();
    }
    let operations: Vec<Value> =
        (0..count).map(|_| operation(&mut reader)).collect::<Result<_, _>>()?;
    // The extension: none — no Soroban data.
    if reader.u32()? != 0 || reader.at != payload.len() {
        return refused();
    }
    let public: [u8; 32] = Sha256::digest(PUBLIC_NETWORK).into();
    let mut read = Map::new();
    read.insert("networkId".into(), Value::from(hex(network)));
    read.insert("publicNetwork".into(), Value::from(network == public));
    read.insert("source".into(), Value::from(source));
    read.insert("fee".into(), Value::from(fee.to_string()));
    read.insert("sequence".into(), Value::from(sequence.to_string()));
    read.insert("timeBounds".into(), window);
    read.insert("memo".into(), Value::Object(memo));
    read.insert("operations".into(), Value::Array(operations));
    Ok(Value::Object(read))
}

/// The SHA-256 of [payload]: the transaction's id, and the 32 bytes a Stellar
/// key signs — kept for a screen given its reading.
pub(crate) fn transaction_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}
