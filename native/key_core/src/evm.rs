//! An EVM transaction's unsigned bytes, read before they are signed — "sign
//! what you see", step 2c of `docs/RUST_KEY_CORE_DESIGN.md` (the owner's
//! decisions P3, O33 and O34).
//!
//! The app hands the core two things: the bytes the transaction library
//! encoded, which are what the signature covers, and the transaction as the
//! app built it, in [`Expected`]'s layout, written by the app's own code rather
//! than by that library. The core reads the first with `alloy-rlp`, holds each
//! field to the second, and only then hashes and signs — so a library or a
//! payload that changes the recipient, the amount, the call, the network, the
//! gas limit or a fee between the app's transaction and the signature is
//! refused here rather than signed.
//!
//! **Nothing secret passes through this file**: it is read before the table's
//! lock is taken, and what it returns is a hash.

use alloy_rlp::Header;
use sha3::{Digest, Keccak256};

use crate::Refusal;

/// What [`Expected`] is before the call data: a kind byte, the chain id, the
/// recipient's presence byte and address, then four 32-byte big-endian
/// numbers — the value, the gas limit and two fees.
pub(crate) const EXPECTED_FIXED_BYTES: usize = 1 + 32 + 1 + 20 + 32 + 32 + 32 + 32;

/// A legacy transaction signed under EIP-155: `rlp([nonce, gasPrice, gas, to,
/// value, data, chainId, 0, 0])`.
pub(crate) const KIND_LEGACY: u8 = 0;

/// An EIP-1559 transaction: `0x02 || rlp([chainId, nonce, maxPriorityFee,
/// maxFee, gas, to, value, data, accessList])`.
pub(crate) const KIND_EIP1559: u8 = 2;

/// The transaction as the app built it, in the layout
/// `kc_secp256k1_sign_evm_transaction` documents. The nonce is not in it: the
/// app does not choose it and the review does not show it, so the core does
/// not hold it to anything.
pub(crate) struct Expected<'a> {
    pub(crate) kind: u8,
    pub(crate) chain_id: &'a [u8; 32],
    pub(crate) to: Option<&'a [u8; 20]>,
    pub(crate) value: &'a [u8; 32],
    pub(crate) gas_limit: &'a [u8; 32],
    /// The gas price of a legacy transaction, the priority fee of an EIP-1559
    /// one.
    pub(crate) fee: &'a [u8; 32],
    /// The maximum fee of an EIP-1559 transaction; zero for a legacy one.
    pub(crate) max_fee: &'a [u8; 32],
    pub(crate) data: &'a [u8],
}

impl<'a> Expected<'a> {
    /// [bytes] read in the documented layout; a kind or a presence byte that
    /// is not one of the defined values, or fewer bytes than the fixed part,
    /// is [`Refusal::Argument`] — a defect on the app's side, not a
    /// transaction to judge.
    pub(crate) fn read(bytes: &'a [u8]) -> Result<Self, Refusal> {
        if bytes.len() < EXPECTED_FIXED_BYTES {
            return Err(Refusal::Argument);
        }
        let kind = bytes[0];
        if kind != KIND_LEGACY && kind != KIND_EIP1559 {
            return Err(Refusal::Argument);
        }
        let word = |at: usize| -> &'a [u8; 32] { bytes[at..at + 32].try_into().expect("in range") };
        let to = match bytes[33] {
            0 if bytes[34..54].iter().all(|b| *b == 0) => None,
            1 => Some(bytes[34..54].try_into().expect("in range")),
            _ => return Err(Refusal::Argument),
        };
        Ok(Self {
            kind,
            chain_id: word(1),
            to,
            value: word(54),
            gas_limit: word(86),
            fee: word(118),
            max_fee: word(150),
            data: &bytes[EXPECTED_FIXED_BYTES..],
        })
    }
}

/// What a reading gave a screen (2f-1b, the owner's decision O53): the facts a
/// signature is then held to — the kind, the network, the recipient, the
/// value and the call data exactly — and the most it may pay for gas; **and
/// the account the reading was for**, which alone may sign it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Shown {
    /// The address of the key the reading was taken for.
    from: [u8; 20],
    kind: u8,
    chain_id: [u8; 32],
    to: Option<[u8; 20]>,
    value: [u8; 32],
    /// Keccak-256 of the call data: held exactly, kept short.
    data: [u8; 32],
    fee_cap: [u8; 64],
}

impl Shown {
    /// [expected] as a reading for the key at [from] gave it.
    pub(crate) fn of(expected: &Expected<'_>, from: [u8; 20]) -> Self {
        Self {
            from,
            kind: expected.kind,
            chain_id: *expected.chain_id,
            to: expected.to.copied(),
            value: *expected.value,
            data: Keccak256::digest(expected.data).into(),
            fee_cap: fee_cap(expected),
        }
    }

    /// Whether [expected], signed by the key at [from], is the transaction
    /// this showed, at a fee no higher than its cap: the gas limit and the
    /// price may move, the signer and the rest may not.
    pub(crate) fn covers(&self, expected: &Expected<'_>, from: [u8; 20]) -> bool {
        let read = Self::of(expected, from);
        self.from == read.from
            && self.kind == read.kind
            && self.chain_id == read.chain_id
            && self.to == read.to
            && self.value == read.value
            && self.data == read.data
            && read.fee_cap <= self.fee_cap
    }
}

/// The most [expected] can pay for gas: its gas limit times the most a unit
/// may cost — the gas price of a legacy transaction, the maximum fee of an
/// EIP-1559 one — as 64 big-endian bytes, so no product overflows.
pub(crate) fn fee_cap(expected: &Expected<'_>) -> [u8; 64] {
    let price = if expected.kind == KIND_EIP1559 { expected.max_fee } else { expected.fee };
    let limbs = |word: &[u8; 32]| -> [u64; 4] {
        // Least significant first.
        core::array::from_fn(|i| u64::from_be_bytes(word[32 - 8 * (i + 1)..32 - 8 * i].try_into().expect("eight")))
    };
    let (a, b) = (limbs(expected.gas_limit), limbs(price));
    let mut product = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let sum = u128::from(product[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
            product[i + j] = sum as u64;
            carry = sum >> 64;
        }
        product[i + 4] = carry as u64;
    }
    let mut out = [0u8; 64];
    for (i, limb) in product.iter().enumerate() {
        out[64 - 8 * (i + 1)..64 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// The EVM address of [key]: the last twenty bytes of Keccak-256 over its
/// uncompressed public key, without the leading `0x04`.
pub(crate) fn address(key: &crate::keys::DerivedKey) -> [u8; 20] {
    let public = crate::keys::public_key(key).serialize_uncompressed();
    Keccak256::digest(&public[1..])[12..].try_into().expect("twenty")
}

/// [expected] read for the review screen (2f-1, O49) for the key at [from]:
/// that account, the transaction's own facts, and its call data as
/// `calldata.rs` reads it, as JSON. Numbers are
/// 32-byte words in hex, addresses twenty bytes in lower-case hex, each with
/// `0x`; a field that does not apply is `null`.
pub(crate) fn reading(expected: &Expected<'_>, from: &[u8; 20]) -> serde_json::Value {
    use serde_json::json;
    let (reading, call) = crate::calldata::read(expected.data, 0);
    json!({
        "from": hex(from),
        "kind": expected.kind,
        "chainId": hex(expected.chain_id),
        "to": expected.to.map(|to| hex(to)),
        "value": hex(expected.value),
        "gasLimit": hex(expected.gas_limit),
        "fee": hex(expected.fee),
        "maxFee": hex(expected.max_fee),
        "data": hex(expected.data),
        "feeCap": hex(&fee_cap(expected)),
        "call": node(reading, call.as_ref(), expected.data.get(..4)),
    })
}

/// A call's reading: how far it was believed, its selector, and what it
/// decoded to.
fn node(
    reading: crate::calldata::Reading,
    call: Option<&crate::calldata::Call>,
    selector: Option<&[u8]>,
) -> serde_json::Value {
    use crate::calldata::Reading;
    serde_json::json!({
        "reading": match reading {
            Reading::None => "none",
            Reading::Decoded => "decoded",
            Reading::TooDeep => "tooDeep",
            Reading::Unknown => "unknown",
            Reading::Malformed => "malformed",
        },
        "selector": selector.map(hex),
        "call": call.map(call_json),
    })
}

fn call_json(call: &crate::calldata::Call) -> serde_json::Value {
    use crate::calldata::Kind;
    let address = |a: &Option<[u8; 20]>| a.as_ref().map(|a| hex(a));
    serde_json::json!({
        "kind": match call.kind {
            Kind::Approve => "approve",
            Kind::Revoke => "revoke",
            Kind::ApproveAll => "approveAll",
            Kind::RevokeAll => "revokeAll",
            Kind::IncreaseAllowance => "increaseAllowance",
            Kind::Transfer => "transfer",
            Kind::TransferFrom => "transferFrom",
            Kind::Batch => "batch",
        },
        "spender": address(&call.spender),
        "recipient": address(&call.recipient),
        "from": address(&call.from),
        "amount": call.amount.as_ref().map(|a| hex(a)),
        "unlimited": call.unlimited,
        "grants": call.grants,
        "children": call.children.iter().map(|child| {
            let mut entry = node(child.reading, child.call.as_ref(), child.selector.as_ref().map(|s| &s[..]));
            entry["target"] = address(&child.target).into();
            entry
        }).collect::<Vec<_>>(),
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

/// The Keccak-256 of [unsigned], once [unsigned] has been read as an EVM
/// transaction in one of the two forms the app's library writes and found to
/// be [expected] in every field the review covers. Anything else is
/// [`Refusal::Transaction`]: another transaction type, bytes that are not
/// canonical RLP, a field more or less, a non-empty access list, a chain id
/// of zero, a legacy transaction without EIP-155, or a difference from
/// [expected].
pub(crate) fn transaction_digest(unsigned: &[u8], expected: &Expected<'_>) -> Result<[u8; 32], Refusal> {
    let read = read_transaction(unsigned)?;
    let same = read.kind == expected.kind
        && is_number(read.chain_id, expected.chain_id)
        && match (read.to, expected.to) {
            (None, None) => true,
            (Some(read), Some(expected)) => read == &expected[..],
            _ => false,
        }
        && is_number(read.value, expected.value)
        && is_number(read.gas_limit, expected.gas_limit)
        && is_number(read.fee, expected.fee)
        && is_number(read.max_fee, expected.max_fee)
        && read.data == expected.data;
    if !same {
        return Err(Refusal::Transaction);
    }
    Ok(Keccak256::digest(unsigned).into())
}

/// The digest a personal message is signed over (EIP-191, version `E`, 2e):
/// Keccak-256 of `"\x19Ethereum Signed Message:\n"`, [message]'s length in
/// decimal, and [message] — the bytes the review showed, as they are.
pub(crate) fn personal_message_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// What an unsigned transaction says, as slices of it: numbers in RLP's
/// minimal big-endian form.
struct Read<'a> {
    kind: u8,
    chain_id: &'a [u8],
    to: Option<&'a [u8]>,
    value: &'a [u8],
    gas_limit: &'a [u8],
    fee: &'a [u8],
    max_fee: &'a [u8],
    data: &'a [u8],
}

fn read_transaction(unsigned: &[u8]) -> Result<Read<'_>, Refusal> {
    let (kind, mut rest) = match unsigned.first() {
        Some(&KIND_EIP1559) => (KIND_EIP1559, &unsigned[1..]),
        // A legacy transaction is the list itself, and a list's first byte is
        // 0xc0 or above. 0x01 (EIP-2930), 0x03, 0x04 and Celo's 0x7b are
        // types the app does not write, and are refused rather than read.
        Some(byte) if *byte >= 0xc0 => (KIND_LEGACY, unsigned),
        _ => return Err(Refusal::Transaction),
    };
    let mut list = Header::decode_bytes(&mut rest, true).map_err(|_| Refusal::Transaction)?;
    if !rest.is_empty() {
        // Bytes after the transaction would be signed over and never read.
        return Err(Refusal::Transaction);
    }
    let read = if kind == KIND_EIP1559 {
        let chain_id = number(&mut list)?;
        nonce(&mut list)?;
        let fee = number(&mut list)?;
        let max_fee = number(&mut list)?;
        let gas_limit = number(&mut list)?;
        let to = recipient(&mut list)?;
        let value = number(&mut list)?;
        let data = string(&mut list)?;
        let access_list = Header::decode_bytes(&mut list, true).map_err(|_| Refusal::Transaction)?;
        if !access_list.is_empty() {
            // The review shows no access list, and the app never sets one.
            return Err(Refusal::Transaction);
        }
        Read { kind, chain_id, to, value, gas_limit, fee, max_fee, data }
    } else {
        nonce(&mut list)?;
        let fee = number(&mut list)?;
        let gas_limit = number(&mut list)?;
        let to = recipient(&mut list)?;
        let value = number(&mut list)?;
        let data = string(&mut list)?;
        let chain_id = number(&mut list)?;
        // EIP-155's pre-image ends in two zeros where the signature will go.
        if !number(&mut list)?.is_empty() || !number(&mut list)?.is_empty() {
            return Err(Refusal::Transaction);
        }
        Read { kind, chain_id, to, value, gas_limit, fee, max_fee: &[], data }
    };
    if !list.is_empty() || read.chain_id.is_empty() {
        // A field more than the form has, or a transaction any chain would
        // take.
        return Err(Refusal::Transaction);
    }
    Ok(read)
}

/// One RLP string.
fn string<'a>(list: &mut &'a [u8]) -> Result<&'a [u8], Refusal> {
    Header::decode_bytes(list, false).map_err(|_| Refusal::Transaction)
}

/// One RLP number: at most 32 bytes, and no leading zero — zero itself is the
/// empty string.
fn number<'a>(list: &mut &'a [u8]) -> Result<&'a [u8], Refusal> {
    let bytes = string(list)?;
    if bytes.len() > 32 || bytes.first() == Some(&0) {
        return Err(Refusal::Transaction);
    }
    Ok(bytes)
}

/// The nonce, read for its form alone: at most 64 bits.
fn nonce(list: &mut &[u8]) -> Result<(), Refusal> {
    if number(list)?.len() > 8 {
        return Err(Refusal::Transaction);
    }
    Ok(())
}

/// The recipient: twenty bytes, or none for a contract's creation.
fn recipient<'a>(list: &mut &'a [u8]) -> Result<Option<&'a [u8]>, Refusal> {
    match string(list)? {
        [] => Ok(None),
        address if address.len() == 20 => Ok(Some(address)),
        _ => Err(Refusal::Transaction),
    }
}

/// Whether the minimal big-endian [read] is the 32-byte big-endian [expected].
fn is_number(read: &[u8], expected: &[u8; 32]) -> bool {
    let pad = 32 - read.len();
    expected[..pad].iter().all(|b| *b == 0) && expected[pad..] == *read
}
