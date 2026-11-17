//! An ICP transfer read in the core for its review screen — "the screen
//! shows what the core read" for the Internet Computer, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! An ICP signature is secp256k1 over the SHA-256 of `\x0Aic-request` and the
//! request id — the representation-independent hash of the call's content
//! map. The core reads that content as the module writes it: a CBOR map of
//! exactly `request_type` "call", `canister_id` the ICP ledger's, `method_name`
//! "transfer", `arg`, `sender` (a self-authenticating principal) and
//! `ingress_expiry`, in that order, every CBOR head definite and shortest,
//! nothing after; and `arg` as the module's Candid writes `TransferArgs` — its
//! exact type table, then `to` an account identifier whose CRC32 is right,
//! `fee`, `memo`, no `from_subaccount`, a `created_at_time`, `amount`. It
//! takes the request id and the digest itself. It refuses any other call, any
//! other canister, a subaccount, a request with a nonce.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::cardano::Reader;
use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The ICP ledger's principal, `ryjl3-tyaaa-aaaaa-aaaba-cai`.
const LEDGER: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 2, 1, 1];

/// A record field's or a variant's number on the wire.
fn field_hash(name: &str) -> u32 {
    name.bytes().fold(0u32, |h, b| h.wrapping_mul(223).wrapping_add(u32::from(b)))
}

fn leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `TransferArgs`' type table as the module writes it, after `DIDL`: six
/// types — `vec nat8`, `record { e8s : nat64 }`, `opt 0`,
/// `record { timestamp_nanos : nat64 }`, `opt 3`, and the record, its fields
/// by hash — then one argument of type 5.
fn transfer_types() -> Vec<u8> {
    let mut fields = [
        (field_hash("to"), 0x00u8),
        (field_hash("fee"), 0x01),
        (field_hash("memo"), 0x78),
        (field_hash("from_subaccount"), 0x02),
        (field_hash("created_at_time"), 0x04),
        (field_hash("amount"), 0x01),
    ];
    fields.sort();
    let mut out = vec![0x06, 0x6d, 0x7b, 0x6c, 0x01];
    out.extend(leb128(u64::from(field_hash("e8s"))));
    out.extend([0x78, 0x6e, 0x00, 0x6c, 0x01]);
    out.extend(leb128(u64::from(field_hash("timestamp_nanos"))));
    out.extend([0x78, 0x6e, 0x03, 0x6c, 0x06]);
    for (hash, kind) in fields {
        out.extend(leb128(u64::from(hash)));
        out.push(kind);
    }
    out.extend([0x01, 0x05]);
    out
}

/// CRC32 (IEEE), as an account identifier's first four bytes are of the
/// rest.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { crc >> 1 ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `TransferArgs` [arg] carries: the recipient, the fee, the memo, the
/// creation time and the amount.
fn transfer(arg: &[u8]) -> Result<Map<String, Value>, Refusal> {
    let types = transfer_types();
    let head = [&b"DIDL"[..], &types[..]].concat();
    let Some(values) = arg.strip_prefix(&head[..]) else {
        return refused();
    };
    let mut r = Reader { bytes: values, at: 0 };
    let nat64 = |r: &mut Reader| -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(r.take(8)?.try_into().expect("eight")))
    };
    // Values in field-hash order: to, fee, memo, from_subaccount,
    // created_at_time, amount.
    let mut order = [
        (field_hash("to"), "to"),
        (field_hash("fee"), "fee"),
        (field_hash("memo"), "memo"),
        (field_hash("from_subaccount"), "from_subaccount"),
        (field_hash("created_at_time"), "created_at_time"),
        (field_hash("amount"), "amount"),
    ];
    order.sort();
    let mut read = Map::new();
    for (_, name) in order {
        match name {
            "to" => {
                // A blob of 32 bytes: its length as LEB128, one byte.
                if r.take(1)? != [0x20] {
                    return refused();
                }
                let account = r.take(32)?;
                if u32::from_be_bytes(account[..4].try_into().expect("four")) != crc32(&account[4..]) {
                    return refused();
                }
                read.insert("to".into(), Value::from(hex(account)));
            }
            "fee" => {
                read.insert("fee".into(), Value::from(nat64(&mut r)?.to_string()));
            }
            "memo" => {
                read.insert("memo".into(), Value::from(nat64(&mut r)?.to_string()));
            }
            // None: this wallet sends from the default subaccount.
            "from_subaccount" => {
                if r.take(1)? != [0x00] {
                    return refused();
                }
            }
            "created_at_time" => {
                if r.take(1)? != [0x01] {
                    return refused();
                }
                read.insert("createdAtTime".into(), Value::from(nat64(&mut r)?.to_string()));
            }
            _ => {
                read.insert("amount".into(), Value::from(nat64(&mut r)?.to_string()));
            }
        }
    }
    if r.at != values.len() {
        return refused();
    }
    Ok(read)
}

/// [content] — an ICP call's content map as CBOR — read for a review screen,
/// with the digest its signature is over; or [`Refusal::Transaction`] for one
/// this wallet never signs.
pub(crate) fn reading(content: &[u8]) -> Result<(Value, [u8; 32]), Refusal> {
    let mut r = Reader { bytes: content, at: 0 };
    if r.map()? != 6 {
        return refused();
    }
    let mut pairs: Vec<[u8; 64]> = Vec::with_capacity(6);
    let mut pair = |key: &str, value: &[u8]| {
        let mut p = [0u8; 64];
        p[..32].copy_from_slice(&Sha256::digest(key.as_bytes()));
        p[32..].copy_from_slice(&Sha256::digest(value));
        pairs.push(p);
    };
    let key = |r: &mut Reader, name: &str| -> Result<(), Refusal> {
        if r.text()? != name {
            return refused();
        }
        Ok(())
    };
    key(&mut r, "request_type")?;
    let request_type = r.text()?;
    if request_type != "call" {
        return refused();
    }
    pair("request_type", request_type.as_bytes());
    key(&mut r, "canister_id")?;
    let canister = r.bytes()?;
    if canister != LEDGER {
        return refused();
    }
    pair("canister_id", canister);
    key(&mut r, "method_name")?;
    let method = r.text()?;
    if method != "transfer" {
        return refused();
    }
    pair("method_name", method.as_bytes());
    key(&mut r, "arg")?;
    let arg = r.bytes()?;
    let args = transfer(arg)?;
    pair("arg", arg);
    key(&mut r, "sender")?;
    let sender = r.bytes()?;
    // A self-authenticating principal: a SHA-224 and the tag 2.
    if sender.len() != 29 || sender[28] != 0x02 {
        return refused();
    }
    pair("sender", sender);
    key(&mut r, "ingress_expiry")?;
    let expiry = r.uint()?;
    pair("ingress_expiry", &leb128(expiry));
    if r.at != content.len() {
        return refused();
    }
    pairs.sort();
    let mut h = Sha256::new();
    for p in &pairs {
        h.update(p);
    }
    let request_id: [u8; 32] = h.finalize().into();
    let digest: [u8; 32] = Sha256::digest([&b"\x0aic-request"[..], &request_id[..]].concat()).into();
    let mut read = args;
    read.insert("canister".into(), Value::from("ryjl3-tyaaa-aaaaa-aaaba-cai"));
    read.insert("method".into(), Value::from("transfer"));
    read.insert("sender".into(), Value::from(hex(sender)));
    read.insert("ingressExpiry".into(), Value::from(expiry.to_string()));
    read.insert("requestId".into(), Value::from(hex(&request_id)));
    read.insert("hash".into(), Value::from(format!("0x{}", hex(&digest))));
    Ok((Value::Object(read), digest))
}
