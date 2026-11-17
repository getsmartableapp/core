//! A Cosmos SDK transaction read in the core for its review screen — "the
//! screen shows what the core read" for the seven Cosmos zones, after step 2f
//! of `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A `SIGN_MODE_DIRECT` signature is over the SHA-256 of a `SignDoc`: the
//! transaction's body and auth info as bytes, the chain id and the account
//! number. The core reads the `SignDoc` whole, in the wire format the app's
//! `CosmosTx` writes and `src/tron.rs` reads — varint and length-delimited
//! fields only, every varint in its shortest form — and refuses what no
//! transaction of this wallet carries: an extension option, a tip, an
//! unordered or timed-out body by time, a signer of several keys, a field any of
//! these messages does not name, or one of their singular fields twice. It
//! returns the chain, the account number, every message — a bank `MsgSend`
//! decoded — the memo, the timeout height, each signer's key, mode and
//! sequence, and the fee.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::tron::{Field, bytes_at, fields, hex, varint_at};

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

const MSG_SEND: &str = "/cosmos.bank.v1beta1.MsgSend";
const SECP256K1_KEY: &str = "/cosmos.crypto.secp256k1.PubKey";

/// [message]'s fields by number: [singular] each once, [repeated] in order.
/// A number in neither, or a singular one twice, is None.
#[allow(clippy::type_complexity)]
fn split<'a>(
    message: &'a [u8],
    singular: &[u64],
    repeated: &[u64],
) -> Result<Option<(BTreeMap<u64, Field<'a>>, BTreeMap<u64, Vec<Field<'a>>>)>, Refusal> {
    let mut one = BTreeMap::new();
    let mut many: BTreeMap<u64, Vec<Field<'a>>> = BTreeMap::new();
    for (number, field) in fields(message)? {
        if repeated.contains(&number) {
            many.entry(number).or_default().push(field);
        } else if !singular.contains(&number) || one.insert(number, field).is_some() {
            return Ok(None);
        }
    }
    Ok(Some((one, many)))
}

/// [split], where a field outside the message is a refusal.
#[allow(clippy::type_complexity)]
fn strict<'a>(
    message: &'a [u8],
    singular: &[u64],
    repeated: &[u64],
) -> Result<(BTreeMap<u64, Field<'a>>, BTreeMap<u64, Vec<Field<'a>>>), Refusal> {
    split(message, singular, repeated)?.ok_or(Refusal::Transaction)
}

/// A protobuf `string`: UTF-8, or a refusal.
fn text(bytes: &[u8]) -> Result<&str, Refusal> {
    std::str::from_utf8(bytes).map_err(|_| Refusal::Transaction)
}

/// The elements of repeated field [number], each a message's bytes.
fn elements<'a>(many: &BTreeMap<u64, Vec<Field<'a>>>, number: u64) -> Result<Vec<&'a [u8]>, Refusal> {
    many.get(&number)
        .map(|list| {
            list.iter()
                .map(|f| match f {
                    Field::Bytes(b) => Ok(*b),
                    Field::Varint(_) => refused(),
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

/// `cosmos.base.v1beta1.Coin`: its denomination and amount.
fn coin(bytes: &[u8]) -> Result<Value, Refusal> {
    let (one, _) = strict(bytes, &[1, 2], &[])?;
    let mut out = Map::new();
    out.insert("denom".into(), Value::from(text(bytes_at(&one, 1)?.unwrap_or(&[]))?));
    out.insert("amount".into(), Value::from(text(bytes_at(&one, 2)?.unwrap_or(&[]))?));
    Ok(Value::Object(out))
}

/// A message's `Any`, and what it does where it is a bank `MsgSend` whose
/// every field is one a send names.
fn message(bytes: &[u8]) -> Result<Value, Refusal> {
    let (any, _) = strict(bytes, &[1, 2], &[])?;
    let url = text(bytes_at(&any, 1)?.unwrap_or(&[]))?;
    let value = bytes_at(&any, 2)?.unwrap_or(&[]);
    let mut out = Map::new();
    out.insert("typeUrl".into(), Value::from(url));
    out.insert("value".into(), Value::from(hex(value)));
    let decoded = if url == MSG_SEND {
        send(value)
    } else {
        None
    };
    out.insert("decoded".into(), decoded.unwrap_or(Value::Null));
    Ok(Value::Object(out))
}

fn send(value: &[u8]) -> Option<Value> {
    let (one, many) = split(value, &[1, 2], &[3]).ok()??;
    let from = text(bytes_at(&one, 1).ok()?.unwrap_or(&[])).ok()?;
    let to = text(bytes_at(&one, 2).ok()?.unwrap_or(&[])).ok()?;
    let amount: Vec<Value> = elements(&many, 3)
        .ok()?
        .into_iter()
        .map(coin)
        .collect::<Result<_, _>>()
        .ok()?;
    let mut out = Map::new();
    out.insert("kind".into(), Value::from("send"));
    out.insert("from".into(), Value::from(from));
    out.insert("to".into(), Value::from(to));
    out.insert("amount".into(), Value::Array(amount));
    Some(Value::Object(out))
}

/// `cosmos.tx.v1beta1.SignerInfo`: its key, its single sign mode and its
/// sequence. The mode of a signer of several keys is refused.
fn signer(bytes: &[u8]) -> Result<Value, Refusal> {
    let (one, _) = strict(bytes, &[1, 2, 3], &[])?;
    let mut out = Map::new();
    match bytes_at(&one, 1)? {
        None => {
            out.insert("publicKeyType".into(), Value::Null);
            out.insert("publicKey".into(), Value::Null);
        }
        Some(any) => {
            let (any, _) = strict(any, &[1, 2], &[])?;
            let url = text(bytes_at(&any, 1)?.unwrap_or(&[]))?;
            let value = bytes_at(&any, 2)?.unwrap_or(&[]);
            out.insert("publicKeyType".into(), Value::from(url));
            let key = if url == SECP256K1_KEY {
                let (key, _) = strict(value, &[1], &[])?;
                hex(bytes_at(&key, 1)?.unwrap_or(&[]))
            } else {
                hex(value)
            };
            out.insert("publicKey".into(), Value::from(key));
        }
    }
    let mode = match bytes_at(&one, 2)? {
        None => 0,
        Some(info) => {
            let (info, _) = strict(info, &[1], &[])?;
            match bytes_at(&info, 1)? {
                None => 0,
                Some(single) => {
                    let (single, _) = strict(single, &[1], &[])?;
                    varint_at(&single, 1)?.unwrap_or(0)
                }
            }
        }
    };
    out.insert("signMode".into(), Value::from(mode.to_string()));
    out.insert("sequence".into(), Value::from(varint_at(&one, 3)?.unwrap_or(0).to_string()));
    Ok(Value::Object(out))
}

/// `cosmos.tx.v1beta1.Fee`: its coins, gas limit, payer and granter.
fn fee(bytes: &[u8]) -> Result<Value, Refusal> {
    let (one, many) = strict(bytes, &[2, 3, 4], &[1])?;
    let mut out = Map::new();
    let amount: Vec<Value> = elements(&many, 1)?.into_iter().map(coin).collect::<Result<_, _>>()?;
    out.insert("amount".into(), Value::Array(amount));
    out.insert("gasLimit".into(), Value::from(varint_at(&one, 2)?.unwrap_or(0).to_string()));
    for (name, number) in [("payer", 3), ("granter", 4)] {
        let value = match bytes_at(&one, number)? {
            None => Value::Null,
            Some(b) => Value::from(text(b)?),
        };
        out.insert(name.into(), value);
    }
    Ok(Value::Object(out))
}

/// [sign_doc] — a `SignDoc`, the bytes whose SHA-256 a `SIGN_MODE_DIRECT`
/// signature is over — read for a review screen. Bytes the app's reader
/// refuses, or a field no transaction of this wallet carries, is
/// [`Refusal::Transaction`].
pub(crate) fn reading(sign_doc: &[u8]) -> Result<Value, Refusal> {
    let (doc, _) = strict(sign_doc, &[1, 2, 3, 4], &[])?;
    let body = bytes_at(&doc, 1)?.unwrap_or(&[]);
    let auth = bytes_at(&doc, 2)?.unwrap_or(&[]);
    let chain = match bytes_at(&doc, 3)? {
        None => Value::Null,
        Some(b) => Value::from(text(b)?),
    };

    // TxBody: the messages, the memo, a timeout height — and none of the
    // extension options, `unordered` or `timeout_timestamp`.
    let (body_one, body_many) = strict(body, &[2, 3], &[1])?;
    let messages: Vec<Value> =
        elements(&body_many, 1)?.into_iter().map(message).collect::<Result<_, _>>()?;
    let memo = text(bytes_at(&body_one, 2)?.unwrap_or(&[]))?;
    let timeout = varint_at(&body_one, 3)?;

    // AuthInfo: the signers and the fee — and no tip.
    let (auth_one, auth_many) = strict(auth, &[2], &[1])?;
    let signers: Vec<Value> =
        elements(&auth_many, 1)?.into_iter().map(signer).collect::<Result<_, _>>()?;
    let fee = match bytes_at(&auth_one, 2)? {
        None => Value::Null,
        Some(b) => fee(b)?,
    };

    let mut read = Map::new();
    read.insert("chainId".into(), chain);
    read.insert(
        "accountNumber".into(),
        Value::from(varint_at(&doc, 4)?.unwrap_or(0).to_string()),
    );
    read.insert("messages".into(), Value::Array(messages));
    read.insert("memo".into(), Value::from(memo));
    read.insert(
        "timeoutHeight".into(),
        timeout.map_or(Value::Null, |t| Value::from(t.to_string())),
    );
    read.insert("signers".into(), Value::Array(signers));
    read.insert("fee".into(), fee);
    Ok(Value::Object(read))
}

/// The SHA-256 of [sign_doc]: the digest a Cosmos zone's key signs — kept for
/// a screen given its reading.
pub(crate) fn sign_doc_id(sign_doc: &[u8]) -> [u8; 32] {
    Sha256::digest(sign_doc).into()
}
