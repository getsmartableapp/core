//! A Filecoin transfer read in the core for its review screen — "the screen
//! shows what the core read" for Filecoin, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A Filecoin signature is secp256k1, recoverable, over the BLAKE2b-256 of the
//! message's CID — a CIDv1, dag-cbor, whose multihash is the BLAKE2b-256 of
//! the message's CBOR. The core reads the CBOR in the one form the module
//! writes — an array of exactly ten: version 0, the recipient, the sender, the
//! nonce, the value, the gas limit, the fee cap, the premium, method 0 and no
//! parameters; both addresses `f1` (protocol 1, 20 bytes); every big integer
//! Filecoin's own way, empty for zero, a sign byte of 0 and its magnitude in
//! the fewest bytes otherwise; every CBOR length definite and every number in
//! its shortest form, nothing after — and refuses any other: another version,
//! a method call, parameters, an `f0`, `f2`, `f3` or `f4` address, a negative
//! amount. It returns every field, both addresses as `f1…`, the CID as
//! `bafy…`, and the digest the signature is over.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use blake2::digest::consts::{U32, U4};
use blake2::{Blake2b, Digest};
use serde_json::{Map, Value};

use crate::cardano::Reader;
use crate::Refusal;

type Blake2b256 = Blake2b<U32>;
type Blake2b32 = Blake2b<U4>;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// A CIDv1's header for dag-cbor and a 32-byte BLAKE2b-256 multihash.
const CID_PREFIX: [u8; 6] = [0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20];

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, unpadded: what `f1` addresses and CIDs are
/// written in.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for b in bytes {
        buffer = buffer << 8 | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[(buffer >> bits & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[(buffer << (5 - bits) & 31) as usize] as char);
    }
    out
}

/// An `f1` address from its bytes — protocol 1 and a 20-byte payload — or
/// none for any other.
fn f1(address: &[u8]) -> Result<String, Refusal> {
    if address.len() != 21 || address[0] != 1 {
        return refused();
    }
    let checksum: [u8; 4] = Blake2b32::digest(address).into();
    Ok(format!("f1{}", base32(&[&address[1..], &checksum[..]].concat())))
}

/// A Filecoin big integer, non-negative and within 128 bits: empty for zero,
/// otherwise a sign byte of 0 and the magnitude with no leading zero.
fn big(bytes: &[u8]) -> Result<u128, Refusal> {
    let Some((sign, magnitude)) = bytes.split_first() else {
        return Ok(0);
    };
    if *sign != 0 || magnitude.is_empty() || magnitude[0] == 0 || magnitude.len() > 16 {
        return refused();
    }
    Ok(magnitude.iter().fold(0u128, |v, b| v << 8 | u128::from(*b)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [message] — a Filecoin message's CBOR — read for a review screen, with the
/// digest its signature is over; or [`Refusal::Transaction`] for one this
/// wallet never signs.
pub(crate) fn reading(message: &[u8]) -> Result<(Value, [u8; 32]), Refusal> {
    let mut r = Reader { bytes: message, at: 0 };
    if r.array()? != 10 || r.uint()? != 0 {
        return refused();
    }
    let to = f1(r.bytes()?)?;
    let from = f1(r.bytes()?)?;
    let nonce = r.uint()?;
    let value = big(r.bytes()?)?;
    let gas_limit = r.uint()?;
    if gas_limit > i64::MAX as u64 {
        return refused();
    }
    let fee_cap = big(r.bytes()?)?;
    let premium = big(r.bytes()?)?;
    // A plain transfer: method 0, no parameters.
    if r.uint()? != 0 || !r.bytes()?.is_empty() || r.at != message.len() {
        return refused();
    }
    let cid = [&CID_PREFIX[..], &Blake2b256::digest(message)[..]].concat();
    let digest: [u8; 32] = Blake2b256::digest(&cid).into();
    let mut read = Map::new();
    read.insert("to".into(), Value::from(to));
    read.insert("from".into(), Value::from(from));
    read.insert("nonce".into(), Value::from(nonce.to_string()));
    read.insert("value".into(), Value::from(value.to_string()));
    read.insert("gasLimit".into(), Value::from(gas_limit.to_string()));
    read.insert("gasFeeCap".into(), Value::from(fee_cap.to_string()));
    read.insert("gasPremium".into(), Value::from(premium.to_string()));
    read.insert("cid".into(), Value::from(format!("b{}", base32(&cid))));
    read.insert("hash".into(), Value::from(format!("0x{}", hex(&digest))));
    Ok((Value::Object(read), digest))
}
