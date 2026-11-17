//! A TRON transaction read in the core for its review screen — "the screen
//! shows what the core read" for TRON, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A TRON signature is over the SHA-256 of `raw_data`, the protobuf bytes the
//! node builds and the app's `TronChainModule` checks field by field; that
//! digest is also the transaction's id. The core reads those bytes as the
//! app's `TronRawData.fields` reads them — varint and length-delimited fields
//! only, every varint in its shortest form — and refuses what a transaction
//! this wallet signs never carries: a field of `Transaction.raw` other than
//! the reference block, the expiry, the memo, the one contract, the timestamp
//! and the fee limit; any of them twice; a contract with more than its type
//! and parameter. The contract is decoded where it is a TRX transfer or a
//! contract call, and a call's data where it is a TRC-20 `transfer`; any other
//! is its type and its bytes, read and not described.
//!
//! **Nothing secret passes through this file**: it runs before any key is
//! asked, and what it returns is a reading.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::solana::base58;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// One protobuf field: a varint's value, or a length-delimited field's bytes.
/// Shared with `src/cosmos.rs`, which reads the same wire format.
#[derive(Clone, Copy)]
pub(crate) enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// A varint at [at], in its shortest form and within 64 bits.
fn varint(bytes: &[u8], at: &mut usize) -> Result<u64, Refusal> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *bytes.get(*at).ok_or(Refusal::Transaction)?;
        *at += 1;
        if i == 9 && byte > 1 {
            return refused();
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return refused();
            }
            return Ok(value);
        }
    }
    refused()
}

/// Every field of [message], by number, in the order the bytes hold them.
pub(crate) fn fields(message: &[u8]) -> Result<Vec<(u64, Field<'_>)>, Refusal> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < message.len() {
        let tag = varint(message, &mut at)?;
        let number = tag >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return refused();
        }
        match tag & 7 {
            0 => out.push((number, Field::Varint(varint(message, &mut at)?))),
            2 => {
                let length = usize::try_from(varint(message, &mut at)?)
                    .map_err(|_| Refusal::Transaction)?;
                let end = at.checked_add(length).ok_or(Refusal::Transaction)?;
                let bytes = message.get(at..end).ok_or(Refusal::Transaction)?;
                at = end;
                out.push((number, Field::Bytes(bytes)));
            }
            _ => return refused(),
        }
    }
    Ok(out)
}

/// [fields] by number, or None where one is outside [allowed] or appears
/// twice — protobuf lets a field repeat, and the last is the one executed.
pub(crate) fn once<'a>(
    fields: Vec<(u64, Field<'a>)>,
    allowed: &[u64],
) -> Option<BTreeMap<u64, Field<'a>>> {
    let mut out = BTreeMap::new();
    for (number, field) in fields {
        if !allowed.contains(&number) || out.insert(number, field).is_some() {
            return None;
        }
    }
    Some(out)
}

/// The bytes of field [number], None where it is absent; a varint there is
/// a refusal.
pub(crate) fn bytes_at<'a>(
    fields: &BTreeMap<u64, Field<'a>>,
    number: u64,
) -> Result<Option<&'a [u8]>, Refusal> {
    match fields.get(&number) {
        None => Ok(None),
        Some(Field::Bytes(bytes)) => Ok(Some(bytes)),
        Some(Field::Varint(_)) => refused(),
    }
}

/// The varint of field [number], None where it is absent; bytes there are a
/// refusal.
pub(crate) fn varint_at(fields: &BTreeMap<u64, Field<'_>>, number: u64) -> Result<Option<u64>, Refusal> {
    match fields.get(&number) {
        None => Ok(None),
        Some(Field::Varint(value)) => Ok(Some(*value)),
        Some(Field::Bytes(_)) => refused(),
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A TRON address — `0x41` and twenty bytes — as base58check writes it, or
/// None for any other bytes.
fn address(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 21 || bytes[0] != 0x41 {
        return None;
    }
    let check = Sha256::digest(Sha256::digest(bytes));
    let mut full = bytes.to_vec();
    full.extend_from_slice(&check[..4]);
    Some(base58(&full))
}

/// 32 big-endian bytes in decimal.
fn decimal(word: &[u8]) -> String {
    let mut digits = Vec::new();
    let mut number = word.to_vec();
    loop {
        let mut remainder = 0u32;
        for byte in number.iter_mut() {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = (value / 10) as u8;
            remainder = value % 10;
        }
        digits.push(b'0' + remainder as u8);
        if number.iter().all(|b| *b == 0) {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("digits")
}

const TRANSFER_URL: &str = "type.googleapis.com/protocol.TransferContract";
const TRIGGER_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// [raw] — a transaction's `raw_data`, the bytes whose SHA-256 a TRON
/// signature is over — read for a review screen. Bytes `TronRawData.fields`
/// refuses, a field this wallet never signs for, one stated twice, or no
/// contract is [`Refusal::Transaction`].
pub(crate) fn reading(raw: &[u8]) -> Result<Value, Refusal> {
    // The reference block (1, 3, 4), the expiry (8), the memo (10), the one
    // contract (11), the timestamp (14) and the fee limit (18).
    let top = once(fields(raw)?, &[1, 3, 4, 8, 10, 11, 14, 18]).ok_or(Refusal::Transaction)?;
    let contract = bytes_at(&top, 11)?.ok_or(Refusal::Transaction)?;
    let entry = once(fields(contract)?, &[1, 2]).ok_or(Refusal::Transaction)?;
    let kind = varint_at(&entry, 1)?.ok_or(Refusal::Transaction)?;
    let parameter = bytes_at(&entry, 2)?.ok_or(Refusal::Transaction)?;
    let any = once(fields(parameter)?, &[1, 2]).ok_or(Refusal::Transaction)?;
    let url = bytes_at(&any, 1)?.ok_or(Refusal::Transaction)?;
    let value = bytes_at(&any, 2)?.ok_or(Refusal::Transaction)?;
    let url = std::str::from_utf8(url).ok();
    let data = bytes_at(&top, 10)?;

    let int = |n: u64| -> Result<Value, Refusal> {
        Ok(varint_at(&top, n)?.map_or(Value::Null, |v| Value::from(v.to_string())))
    };
    let bytes = |n: u64| -> Result<Value, Refusal> {
        Ok(bytes_at(&top, n)?.map_or(Value::Null, |b| Value::from(hex(b))))
    };
    let mut read = Map::new();
    read.insert("txid".into(), Value::from(hex(&transaction_id(raw))[2..].to_string()));
    read.insert("refBlockBytes".into(), bytes(1)?);
    read.insert("refBlockNum".into(), int(3)?);
    read.insert("refBlockHash".into(), bytes(4)?);
    read.insert("expiration".into(), int(8)?);
    read.insert("timestamp".into(), int(14)?);
    read.insert("feeLimit".into(), int(18)?);
    read.insert("data".into(), data.map_or(Value::Null, |d| Value::from(hex(d))));
    read.insert(
        "memo".into(),
        data.and_then(|d| std::str::from_utf8(d).ok()).map_or(Value::Null, Value::from),
    );
    let mut call = Map::new();
    call.insert("type".into(), Value::from(kind.to_string()));
    call.insert("typeUrl".into(), url.map_or(Value::Null, Value::from));
    call.insert("value".into(), Value::from(hex(value)));
    call.insert(
        "decoded".into(),
        url.and_then(|url| decoded(kind, url, value)).unwrap_or(Value::Null),
    );
    read.insert("contract".into(), Value::Object(call));
    Ok(Value::Object(read))
}

/// What the contract does, where it is a TRX transfer or a contract call
/// whose every field is one such a contract names, once; None otherwise.
fn decoded(kind: u64, url: &str, value: &[u8]) -> Option<Value> {
    let fields = fields(value).ok()?;
    let mut out = Map::new();
    match (kind, url) {
        (1, TRANSFER_URL) => {
            let f = once(fields, &[1, 2, 3])?;
            out.insert("kind".into(), Value::from("trxTransfer"));
            out.insert("from".into(), Value::from(address(bytes_at(&f, 1).ok()??)?));
            out.insert("to".into(), Value::from(address(bytes_at(&f, 2).ok()??)?));
            out.insert(
                "amount".into(),
                Value::from(varint_at(&f, 3).ok()?.unwrap_or(0).to_string()),
            );
        }
        (31, TRIGGER_URL) => {
            let f = once(fields, &[1, 2, 3, 4, 5, 6])?;
            let data = bytes_at(&f, 4).ok()?.unwrap_or(&[]);
            out.insert("kind".into(), Value::from("contractCall"));
            out.insert("from".into(), Value::from(address(bytes_at(&f, 1).ok()??)?));
            out.insert("contract".into(), Value::from(address(bytes_at(&f, 2).ok()??)?));
            for (name, number) in [("callValue", 3), ("callTokenValue", 5), ("tokenId", 6)] {
                out.insert(
                    name.into(),
                    Value::from(varint_at(&f, number).ok()?.unwrap_or(0).to_string()),
                );
            }
            out.insert("data".into(), Value::from(hex(data)));
            out.insert("call".into(), trc20_transfer(data).unwrap_or(Value::Null));
        }
        _ => return None,
    }
    Some(Value::Object(out))
}

/// `transfer(address,uint256)`'s call — its selector, then the recipient's
/// word, twenty bytes behind eleven zeros and a zero or TRON's `0x41`, then
/// the amount — or None.
fn trc20_transfer(data: &[u8]) -> Option<Value> {
    if data.len() != 68 || data[..4] != [0xa9, 0x05, 0x9c, 0xbb] {
        return None;
    }
    if data[4..15].iter().any(|b| *b != 0) || !matches!(data[15], 0 | 0x41) {
        return None;
    }
    let mut to = vec![0x41];
    to.extend_from_slice(&data[16..36]);
    let mut out = Map::new();
    out.insert("kind".into(), Value::from("trc20Transfer"));
    out.insert("to".into(), Value::from(address(&to)?));
    out.insert("amount".into(), Value::from(decimal(&data[36..68])));
    Some(Value::Object(out))
}

/// The SHA-256 of [raw]: the transaction's id, and the digest a TRON key
/// signs — kept for a screen given the reading of [raw].
pub(crate) fn transaction_id(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
