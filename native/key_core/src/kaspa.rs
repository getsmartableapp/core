//! A Kaspa send read and signed in the core — "the screen shows what the core
//! read" for Kaspa, after step 2f of `docs/RUST_KEY_CORE_DESIGN.md` (the
//! owner's decisions O52 and O58).
//!
//! A Kaspa input is signed by BIP-340 over its own sighash: BIP-143-shaped,
//! but every hash BLAKE2b-256 keyed with `TransactionSigningHash`, every
//! field little-endian, script lengths full 64-bit values, and the payload's
//! hash thirty-two zeros on the native subnetwork. The core is handed the
//! transaction the module built — the request [`kc_kaspa_sign_transaction`]
//! documents — reads it in the one shape the module writes (version 0, every
//! spent and paid script a Schnorr key's `push(32) OP_CHECKSIG`, script
//! version 0, the sequence `u64::MAX`, one signature operation per input, no
//! lock time, the native subnetwork, no gas), holds the fee to the inputs'
//! sum less the outputs', computes each input's sighash itself and spells
//! each output's address itself, CashAddr as Kaspa writes it.
//!
//! **Nothing secret passes through this file but in [`sign`]**, which is
//! handed the key: what [`Request::read`] and [`reading`] return is a
//! reading.

use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::keys::{self, DerivedKey};
use crate::Refusal;

/// A layout that does not read.
fn malformed<T>() -> Result<T, Refusal> {
    Err(Refusal::Argument)
}

/// A transaction this wallet does not build.
fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(n).ok_or(Refusal::Argument)?;
        let taken = self.bytes.get(self.at..end).ok_or(Refusal::Argument)?;
        self.at = end;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Refusal> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    /// Two bytes of length, then that many.
    fn short_bytes(&mut self) -> Result<&'a [u8], Refusal> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// An input: the outpoint it spends and what that output held.
pub(crate) struct Input<'a> {
    /// The previous transaction's id, as the indexer writes it, and the
    /// output's index in it.
    pub(crate) txid: &'a [u8],
    pub(crate) index: u32,
    pub(crate) amount: u64,
    pub(crate) script: &'a [u8],
}

pub(crate) struct Output<'a> {
    pub(crate) amount: u64,
    pub(crate) script: &'a [u8],
}

/// A request read and held to everything that needs no key.
pub(crate) struct Request<'a> {
    /// The path of the key every input is signed with: the account's, or `m`
    /// for an imported key.
    pub(crate) path: &'a [u8],
    pub(crate) inputs: Vec<Input<'a>>,
    pub(crate) outputs: Vec<Output<'a>>,
}

/// The one sequence the module writes: no relative lock.
const SEQUENCE: u64 = u64::MAX;

/// `SIGHASH_ALL`, the one type the module signs.
const SIGHASH_ALL: u8 = 0x01;

/// The x-only key of a Schnorr key's script, `0x20 key 0xac`, or none.
fn schnorr_key(script: &[u8]) -> Option<&[u8]> {
    match script {
        [0x20, key @ .., 0xac] if key.len() == 32 => Some(key),
        _ => None,
    }
}

impl<'a> Request<'a> {
    /// [bytes] in [`kc_kaspa_sign_transaction`]'s layout. A layout that does
    /// not read is [`Refusal::Argument`]; a transaction the module does not
    /// build is [`Refusal::Transaction`].
    pub(crate) fn read(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let mut r = Reader { bytes, at: 0 };
        let path = r.short_bytes()?;
        let version = r.u16()?;
        let input_count = usize::from(r.u16()?);
        let mut inputs = Vec::with_capacity(input_count);
        let mut sequences_and_ops_hold = true;
        let mut scripts_hold = true;
        for _ in 0..input_count {
            let txid = r.take(32)?;
            let index = r.u32()?;
            let amount = r.u64()?;
            let script_version = r.u16()?;
            let script = r.short_bytes()?;
            let sequence = r.u64()?;
            let sig_op_count = r.u8()?;
            sequences_and_ops_hold &= sequence == SEQUENCE && sig_op_count == 1;
            scripts_hold &= script_version == 0 && schnorr_key(script).is_some();
            inputs.push(Input { txid, index, amount, script });
        }
        let output_count = usize::from(r.u16()?);
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let amount = r.u64()?;
            let script_version = r.u16()?;
            let script = r.short_bytes()?;
            scripts_hold &= script_version == 0 && schnorr_key(script).is_some();
            outputs.push(Output { amount, script });
        }
        let lock_time = r.u64()?;
        let subnetwork = r.take(20)?;
        let gas = r.u64()?;
        let fee = r.u64()?;
        if r.at != bytes.len() {
            return malformed();
        }
        if version != 0
            || inputs.is_empty()
            || outputs.is_empty()
            || !sequences_and_ops_hold
            || !scripts_hold
            || lock_time != 0
            || subnetwork.iter().any(|b| *b != 0)
            || gas != 0
        {
            return refused();
        }
        // No outpoint twice: the network refuses a transaction that spends one
        // output twice, and the module never writes one.
        for (i, a) in inputs.iter().enumerate() {
            if inputs[..i].iter().any(|b| b.txid == a.txid && b.index == a.index) {
                return refused();
            }
        }
        let spent: u128 = inputs.iter().map(|i| u128::from(i.amount)).sum();
        let paid: u128 = outputs.iter().map(|o| u128::from(o.amount)).sum();
        if spent < paid || spent - paid != u128::from(fee) {
            return refused();
        }
        Ok(Self { path, inputs, outputs })
    }

    /// The fee: the inputs' sum less the outputs'.
    fn fee(&self) -> u128 {
        self.spent() - self.outputs.iter().map(|o| u128::from(o.amount)).sum::<u128>()
    }

    fn spent(&self) -> u128 {
        self.inputs.iter().map(|i| u128::from(i.amount)).sum()
    }
}

/// What a reading of the request [bytes] is kept under, and a signature held
/// to: its SHA-256.
pub(crate) fn request_id(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// BLAKE2b-256 keyed with `TransactionSigningHash`, of [parts] one after
/// another.
fn signing_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Blake2bMac::<U32>::new_with_salt_and_personal(b"TransactionSigningHash", &[], &[])
        .expect("a 22-byte key is within BLAKE2b's 64");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The sighash of [request]'s input [index], as the module's
/// `KaspaTransaction.signingDigest` writes it.
pub(crate) fn sighash(request: &Request<'_>, index: usize) -> [u8; 32] {
    let mut outpoints = Vec::new();
    let mut sequences = Vec::new();
    let mut sig_op_counts = Vec::new();
    for input in &request.inputs {
        outpoints.extend_from_slice(input.txid);
        outpoints.extend_from_slice(&input.index.to_le_bytes());
        sequences.extend_from_slice(&SEQUENCE.to_le_bytes());
        sig_op_counts.push(1u8);
    }
    let mut outputs = Vec::new();
    for output in &request.outputs {
        outputs.extend_from_slice(&output.amount.to_le_bytes());
        outputs.extend_from_slice(&0u16.to_le_bytes());
        outputs.extend_from_slice(&(output.script.len() as u64).to_le_bytes());
        outputs.extend_from_slice(output.script);
    }
    let input = &request.inputs[index];
    signing_hash(&[
        &0u16.to_le_bytes(),
        &signing_hash(&[&outpoints]),
        &signing_hash(&[&sequences]),
        &signing_hash(&[&sig_op_counts]),
        input.txid,
        &input.index.to_le_bytes(),
        &0u16.to_le_bytes(),
        &(input.script.len() as u64).to_le_bytes(),
        input.script,
        &input.amount.to_le_bytes(),
        &SEQUENCE.to_le_bytes(),
        &[1],
        &signing_hash(&[&outputs]),
        &0u64.to_le_bytes(),
        &[0u8; 20],
        &0u64.to_le_bytes(),
        &[0u8; 32],
        &[SIGHASH_ALL],
    ])
}

/// The script of [key]'s x-only public key: what this account's addresses
/// lock to.
pub(crate) fn own_script(key: &DerivedKey) -> [u8; 34] {
    let mut script = [0u8; 34];
    script[0] = 0x20;
    script[1..33].copy_from_slice(&keys::public_key(key).serialize()[1..]);
    script[33] = 0xac;
    script
}

/// That every input of [request] spends [own] — the script of the key that
/// signs it. A difference is [`Refusal::Transaction`].
pub(crate) fn hold_to_key(request: &Request<'_>, own: &[u8; 34]) -> Result<(), Refusal> {
    if request.inputs.iter().any(|input| input.script != own) {
        return refused();
    }
    Ok(())
}

// --------------------------------------------------------------- addresses

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// CashAddr's 40-bit polymod, which Kaspa kept.
fn polymod(values: impl IntoIterator<Item = u8>) -> u64 {
    const GENERATOR: [u64; 5] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
    let mut checksum: u64 = 1;
    for value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x07_ffff_ffff) << 5) ^ u64::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum ^ 1
}

/// `kaspa:` and the CashAddr of a Schnorr key's x-only [key]: version 0, the
/// key, eight characters of checksum.
pub(crate) fn address(key: &[u8]) -> String {
    let mut words = Vec::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for byte in core::iter::once(0u8).chain(key.iter().copied()) {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((accumulator >> bits) & 31) as u8);
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits > 0 {
        words.push(((accumulator << (5 - bits)) & 31) as u8);
    }
    let prefix = b"kaspa";
    let checksum = polymod(
        prefix
            .iter()
            .map(|c| c & 31)
            .chain([0])
            .chain(words.iter().copied())
            .chain([0; 8]),
    );
    let mut out = String::from("kaspa:");
    for word in words.iter().copied().chain((0..8).map(|i| ((checksum >> (5 * (7 - i))) & 31) as u8)) {
        out.push(char::from(CHARSET[usize::from(word)]));
    }
    out
}

// --------------------------------------------------------------- reading

/// What a review screen shows of [request], once [`hold_to_key`] held it:
/// every input's outpoint and amount; every output in order with its address
/// — spelt here — its amount, and whether it is the account's change (it pays
/// [own], the signing key's script); the sum sent to others, the sum spent,
/// the fee, and every input's sighash.
pub(crate) fn reading(request: &Request<'_>, own: &[u8; 34]) -> Value {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    let inputs: Vec<Value> = request
        .inputs
        .iter()
        .map(|input| {
            let mut entry = Map::new();
            entry.insert("txid".into(), Value::String(hex(input.txid)));
            entry.insert("index".into(), Value::from(input.index));
            entry.insert("amount".into(), Value::String(input.amount.to_string()));
            Value::Object(entry)
        })
        .collect();
    let mut sent: u128 = 0;
    let outputs: Vec<Value> = request
        .outputs
        .iter()
        .map(|output| {
            let change = output.script == own;
            if !change {
                sent += u128::from(output.amount);
            }
            let key = schnorr_key(output.script).expect("held: a Schnorr key's script");
            let mut entry = Map::new();
            entry.insert("address".into(), Value::String(address(key)));
            entry.insert("amount".into(), Value::String(output.amount.to_string()));
            entry.insert("change".into(), Value::Bool(change));
            Value::Object(entry)
        })
        .collect();
    let sighashes: Vec<Value> =
        (0..request.inputs.len()).map(|i| Value::String(hex(&sighash(request, i)))).collect();
    let mut out = Map::new();
    out.insert("inputs".into(), Value::Array(inputs));
    out.insert("outputs".into(), Value::Array(outputs));
    out.insert("sent".into(), Value::String(sent.to_string()));
    out.insert("spent".into(), Value::String(request.spent().to_string()));
    out.insert("fee".into(), Value::String(request.fee().to_string()));
    out.insert("sighashes".into(), Value::Array(sighashes));
    Value::Object(out)
}

/// Per input, its sighash and the BIP-340 signature over it.
pub(crate) type Signed = [u8; 96];

/// Every input of [request] signed with [key], once [`hold_to_key`] holds:
/// each spends [key]'s own script.
pub(crate) fn sign(request: &Request<'_>, key: &DerivedKey) -> Result<Vec<Signed>, Refusal> {
    hold_to_key(request, &own_script(key))?;
    let mut signed = Vec::with_capacity(request.inputs.len());
    for index in 0..request.inputs.len() {
        let sighash = sighash(request, index);
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&sighash);
        out[32..].copy_from_slice(&keys::schnorr_sign(key, &sighash, None)?);
        signed.push(out);
    }
    Ok(signed)
}
