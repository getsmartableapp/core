//! An XRP Ledger payment read in the core for its review screen and signed
//! there — "the screen shows what the core read" for XRP, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52, O58 and O59).
//!
//! An XRPL signature is over the SHA-512 half of `STX\0` and the
//! transaction's signing serialisation: its fields in canonical order, with
//! the signing key and no signature. The core reads that serialisation —
//! a `Payment` of XRP, the fields the app's module writes and no others, each
//! once and in canonical order — and returns its facts: the account, the
//! destination and its tag, the amount, the fee, the sequence, the expiry and
//! the memos. Any other field — a partial payment's `SendMax`, a path, a
//! ticket, a signature — and any amount not in XRP are refused.
//!
//! **Every fact but the expiry is held** (O59): what a screen was shown is the
//! transaction without its `LastLedgerSequence`, which the module sets at the
//! signature — four ledgers, the window that cancels a send — so a review does
//! not go stale on a timer and the window after a signature stays short.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha512};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The XRP Ledger's base58 alphabet.
const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Bytes read in order; a read past the end is a refusal.
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

    fn byte(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }

    /// A field's type and field codes, each in its shortest form: a code
    /// below 16 in its nibble, one above in a byte of its own.
    fn header(&mut self) -> Result<(u8, u8), Refusal> {
        let first = self.byte()?;
        let mut kind = first >> 4;
        let mut field = first & 0x0f;
        if kind == 0 {
            kind = self.byte()?;
            if kind < 16 {
                return refused();
            }
        }
        if field == 0 {
            field = self.byte()?;
            if field < 16 {
                return refused();
            }
        }
        Ok((kind, field))
    }

    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    /// A variable-length field: its length in one, two or three bytes, then
    /// that many.
    fn vl(&mut self) -> Result<&'a [u8], Refusal> {
        let first = usize::from(self.byte()?);
        let length = match first {
            0..=192 => first,
            193..=240 => 193 + (first - 193) * 256 + usize::from(self.byte()?),
            241..=254 => {
                let second = usize::from(self.byte()?);
                12481 + (first - 241) * 65536 + second * 256 + usize::from(self.byte()?)
            }
            _ => return refused(),
        };
        self.take(length)
    }

    /// An amount of XRP, in drops: the top bit clear (not an issued
    /// currency), the next set (not negative).
    fn drops(&mut self) -> Result<u64, Refusal> {
        let value = u64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes"));
        if value >> 62 != 0b01 {
            return refused();
        }
        Ok(value & ((1 << 62) - 1))
    }
}

/// One memo: its type, its data and its format, each where it is written.
pub(crate) struct Memo<'a> {
    kind: Option<&'a [u8]>,
    data: Option<&'a [u8]>,
    format: Option<&'a [u8]>,
}

/// A payment as the core read it, and where its expiry is in the bytes.
pub(crate) struct Payment<'a> {
    flags: Option<u32>,
    sequence: u32,
    destination_tag: Option<u32>,
    pub(crate) last_ledger: Option<(u32, std::ops::Range<usize>)>,
    amount: u64,
    fee: u64,
    signing_key: &'a [u8],
    account: &'a [u8],
    destination: &'a [u8],
    memos: Vec<Memo<'a>>,
}

// Field codes, as (type, field).
const TRANSACTION_TYPE: (u8, u8) = (1, 2);
const FLAGS: (u8, u8) = (2, 2);
const SEQUENCE: (u8, u8) = (2, 4);
const DESTINATION_TAG: (u8, u8) = (2, 14);
const LAST_LEDGER_SEQUENCE: (u8, u8) = (2, 27);
const AMOUNT: (u8, u8) = (6, 1);
const FEE: (u8, u8) = (6, 8);
const SIGNING_PUB_KEY: (u8, u8) = (7, 3);
const ACCOUNT: (u8, u8) = (8, 1);
const DESTINATION: (u8, u8) = (8, 3);
const MEMOS: (u8, u8) = (15, 9);
const MEMO: (u8, u8) = (14, 10);
const MEMO_TYPE: (u8, u8) = (7, 12);
const MEMO_DATA: (u8, u8) = (7, 13);
const MEMO_FORMAT: (u8, u8) = (7, 14);
const OBJECT_END: (u8, u8) = (14, 1);
const ARRAY_END: (u8, u8) = (15, 1);

/// [blob] — a transaction's signing serialisation, the bytes after `STX\0` —
/// read as a payment of XRP. Bytes that are not one, a field the module does
/// not write, one out of canonical order or written twice, an issued
/// currency's amount, or a byte after the last field is
/// [`Refusal::Transaction`].
pub(crate) fn read(blob: &[u8]) -> Result<Payment<'_>, Refusal> {
    let mut reader = Reader { bytes: blob, at: 0 };
    let mut last: Option<(u8, u8)> = None;
    let mut kind = None;
    let mut flags = None;
    let mut sequence = None;
    let mut destination_tag = None;
    let mut last_ledger = None;
    let mut amount = None;
    let mut fee = None;
    let mut signing_key = None;
    let mut account = None;
    let mut destination = None;
    let mut memos = Vec::new();
    while !reader.done() {
        let start = reader.at;
        let code = reader.header()?;
        // Canonical order: by type, then field; and so each field once.
        if last.is_some_and(|before| before >= code) {
            return refused();
        }
        last = Some(code);
        match code {
            TRANSACTION_TYPE => {
                kind = Some(u16::from_be_bytes(reader.take(2)?.try_into().expect("two bytes")));
            }
            FLAGS => flags = Some(reader.u32()?),
            SEQUENCE => sequence = Some(reader.u32()?),
            DESTINATION_TAG => destination_tag = Some(reader.u32()?),
            LAST_LEDGER_SEQUENCE => last_ledger = Some((reader.u32()?, start..start + 6)),
            AMOUNT => amount = Some(reader.drops()?),
            FEE => fee = Some(reader.drops()?),
            SIGNING_PUB_KEY => signing_key = Some(reader.vl()?),
            ACCOUNT | DESTINATION => {
                let id = reader.vl()?;
                if id.len() != 20 {
                    return refused();
                }
                if code == ACCOUNT {
                    account = Some(id);
                } else {
                    destination = Some(id);
                }
            }
            MEMOS => loop {
                match reader.header()? {
                    ARRAY_END => break,
                    MEMO => memos.push(memo(&mut reader)?),
                    _ => return refused(),
                }
            },
            _ => return refused(),
        }
    }
    // A Payment, and every field a payment of the module's carries.
    if kind != Some(0) {
        return refused();
    }
    Ok(Payment {
        flags,
        sequence: sequence.ok_or(Refusal::Transaction)?,
        destination_tag,
        last_ledger,
        amount: amount.ok_or(Refusal::Transaction)?,
        fee: fee.ok_or(Refusal::Transaction)?,
        signing_key: signing_key.ok_or(Refusal::Transaction)?,
        account: account.ok_or(Refusal::Transaction)?,
        destination: destination.ok_or(Refusal::Transaction)?,
        memos,
    })
}

/// One `Memo` object's fields, in order, to its end marker.
fn memo<'a>(reader: &mut Reader<'a>) -> Result<Memo<'a>, Refusal> {
    let mut out = Memo { kind: None, data: None, format: None };
    let mut last: Option<(u8, u8)> = None;
    loop {
        let code = reader.header()?;
        if code == OBJECT_END {
            return Ok(out);
        }
        if last.is_some_and(|before| before >= code) {
            return refused();
        }
        last = Some(code);
        match code {
            MEMO_TYPE => out.kind = Some(reader.vl()?),
            MEMO_DATA => out.data = Some(reader.vl()?),
            MEMO_FORMAT => out.format = Some(reader.vl()?),
            _ => return refused(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// An account id as the XRP Ledger writes an address: base58check over a
/// zero byte and the twenty bytes, in the ledger's alphabet.
fn address(id: &[u8]) -> String {
    let mut payload = vec![0u8];
    payload.extend_from_slice(id);
    let check = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&check[..4]);
    let zeros = payload.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &payload[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push(ALPHABET[0] as char);
    }
    for digit in digits.iter().rev() {
        out.push(ALPHABET[usize::from(*digit)] as char);
    }
    out
}

/// [payment]'s facts for its review screen.
pub(crate) fn reading(payment: &Payment<'_>) -> Value {
    let optional = |bytes: Option<&[u8]>| bytes.map_or(Value::Null, |b| Value::from(hex(b)));
    let mut read = Map::new();
    read.insert("transactionType".into(), Value::from("Payment"));
    read.insert("flags".into(), payment.flags.map_or(Value::Null, Value::from));
    read.insert("sequence".into(), Value::from(payment.sequence));
    read.insert(
        "destinationTag".into(),
        payment.destination_tag.map_or(Value::Null, Value::from),
    );
    read.insert(
        "lastLedgerSequence".into(),
        payment.last_ledger.as_ref().map_or(Value::Null, |(n, _)| Value::from(*n)),
    );
    read.insert("amount".into(), Value::from(payment.amount.to_string()));
    read.insert("fee".into(), Value::from(payment.fee.to_string()));
    read.insert("signingPubKey".into(), Value::from(hex(payment.signing_key)));
    read.insert("account".into(), Value::from(address(payment.account)));
    read.insert("destination".into(), Value::from(address(payment.destination)));
    let memos: Vec<Value> = payment
        .memos
        .iter()
        .map(|memo| {
            let mut out = Map::new();
            out.insert("type".into(), optional(memo.kind));
            out.insert("data".into(), optional(memo.data));
            out.insert("format".into(), optional(memo.format));
            out.insert(
                "text".into(),
                memo.data
                    .and_then(|d| std::str::from_utf8(d).ok())
                    .map_or(Value::Null, Value::from),
            );
            Value::Object(out)
        })
        .collect();
    read.insert("memos".into(), Value::Array(memos));
    Value::Object(read)
}

/// What a screen shown [payment] was shown (O59): the SHA-256 of [blob]
/// without its `LastLedgerSequence`, which is set at the signature.
pub(crate) fn shown_id(blob: &[u8], payment: &Payment<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match &payment.last_ledger {
        Some((_, range)) => {
            hasher.update(&blob[..range.start]);
            hasher.update(&blob[range.end..]);
        }
        None => hasher.update(blob),
    }
    hasher.finalize().into()
}

/// The digest an XRPL signature is over: the first half of SHA-512 of `STX\0`
/// and [blob].
pub(crate) fn signing_digest(blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"STX\0");
    hasher.update(blob);
    hasher.finalize()[..32].try_into().expect("half of 64")
}
