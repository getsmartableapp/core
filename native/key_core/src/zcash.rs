//! A Zcash send read and signed in the core — "the screen shows what the core
//! read" for Zcash's transparent pool, brought back on the owner's decision of
//! 15 November 2026 (transparent addresses only; its keys, its reading and its
//! signature here and nowhere else).
//!
//! A transparent Zcash input is signed by ECDSA over its ZIP-244 signature
//! digest: a tree of BLAKE2b-256 hashes, each personalised with its own
//! sixteen bytes, the root's last four the consensus branch id. The core is
//! handed the request [`crate::kc_zcash_sign_transaction`] documents — the
//! unsigned version 5 transaction exactly as ZIP-225 serialises it, every
//! `scriptSig` empty, then the coin each input spends — reads it in the one
//! shape the module writes (version 5 under the overwinter flag, version
//! group `0x26A7270A`, no lock time, an expiry height, the sequence
//! `0xFFFFFFFE`, pay-to-public-key-hash or pay-to-script-hash outputs, no
//! Sapling and no Orchard part), holds the fee to the inputs' sum less the
//! outputs', computes each input's signature digest and the transaction's id
//! itself, and spells each output's address itself: `t1…`, `t3…`, or the
//! ZIP-320 `tex1…` form of a `t1` where the module says the person wrote one.
//!
//! **Nothing secret passes through this file but in [`sign`]**, which is
//! handed the key: what [`Request::read`] and [`reading`] return is a
//! reading.

use blake2::digest::core_api::{Buffer, UpdateCore, VariableOutputCore};
use blake2::Blake2bVarCore;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::bitcoin::hash160;
use crate::keys::{self, DerivedKey};
use crate::solana::base58;
use crate::Refusal;

/// A layout that does not read.
fn malformed<T>() -> Result<T, Refusal> {
    Err(Refusal::Argument)
}

/// A transaction this wallet does not build.
fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// `fOverwintered` and version 5 (ZIP-225).
const HEADER: u32 = 0x8000_0005;

/// ZIP-225's version group id for every version 5 transaction.
const VERSION_GROUP_ID: u32 = 0x26A7_270A;

/// The one sequence the module writes: `0xFFFFFFFE`, which keeps the lock time
/// meaningful (it is zero here) rather than switching it off.
const SEQUENCE: u32 = 0xFFFF_FFFE;

/// `SIGHASH_ALL`, the one type the module signs.
const SIGHASH_ALL: u8 = 0x01;

/// 21 million ZEC in zatoshi: the consensus ceiling on any amount.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Zcash consensus: an expiry height is below 500,000,000.
const EXPIRY_CEILING: u32 = 500_000_000;

/// A `t1…` address's two version bytes.
pub(crate) const P2PKH_VERSION: [u8; 2] = [0x1C, 0xB8];

/// A `t3…` address's two version bytes.
pub(crate) const P2SH_VERSION: [u8; 2] = [0x1C, 0xBD];

/// How the module says the person wrote a recipient: the transparent address
/// its script spells, or ZIP-320's TEX form of a `t1`.
const SPELT_TRANSPARENT: u8 = 0;
const SPELT_TEX: u8 = 1;

/// More inputs or outputs than this is a request the module never writes.
const MAX_ENTRIES: usize = 0xFC;

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

    /// Bitcoin's CompactSize, in its one canonical spelling. The module never
    /// writes a count above [`MAX_ENTRIES`] nor a script above 252 bytes, so
    /// a longer form is a transaction it did not write.
    fn compact(&mut self) -> Result<usize, Refusal> {
        let first = self.u8()?;
        if usize::from(first) > MAX_ENTRIES {
            return refused();
        }
        Ok(usize::from(first))
    }
}

/// An input: the outpoint it spends and what that output held.
pub(crate) struct Input<'a> {
    /// The previous transaction's id in the transaction's own byte order, and
    /// the output's index in it.
    pub(crate) prevout: &'a [u8],
    sequence: u32,
    pub(crate) amount: u64,
    pub(crate) script: &'a [u8],
}

impl Input<'_> {
    fn txid(&self) -> &[u8] {
        &self.prevout[..32]
    }

    fn index(&self) -> u32 {
        u32::from_le_bytes(self.prevout[32..36].try_into().expect("four bytes"))
    }
}

pub(crate) struct Output<'a> {
    pub(crate) amount: u64,
    pub(crate) script: &'a [u8],
    tex: bool,
}

/// A request read and held to everything that needs no key.
pub(crate) struct Request<'a> {
    /// The path of the key every input is signed with.
    pub(crate) path: &'a [u8],
    branch_id: u32,
    lock_time: u32,
    expiry_height: u32,
    pub(crate) inputs: Vec<Input<'a>>,
    pub(crate) outputs: Vec<Output<'a>>,
}

/// The 20-byte key hash of a pay-to-public-key-hash script,
/// `OP_DUP OP_HASH160 push(20) hash OP_EQUALVERIFY OP_CHECKSIG`, or none.
fn p2pkh_hash(script: &[u8]) -> Option<&[u8]> {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => Some(hash),
        _ => None,
    }
}

/// The 20-byte script hash of a pay-to-script-hash script,
/// `OP_HASH160 push(20) hash OP_EQUAL`, or none.
fn p2sh_hash(script: &[u8]) -> Option<&[u8]> {
    match script {
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => Some(hash),
        _ => None,
    }
}

impl<'a> Request<'a> {
    /// [bytes] in [`crate::kc_zcash_sign_transaction`]'s layout. A layout
    /// that does not read is [`Refusal::Argument`]; a transaction the module
    /// does not build is [`Refusal::Transaction`].
    pub(crate) fn read(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let mut r = Reader { bytes, at: 0 };
        let path = r.short_bytes()?;
        let tx_len = usize::try_from(r.u32()?).map_err(|_| Refusal::Argument)?;
        let tx = r.take(tx_len)?;
        let mut t = Reader { bytes: tx, at: 0 };
        let header = t.u32()?;
        let group = t.u32()?;
        let branch_id = t.u32()?;
        let lock_time = t.u32()?;
        let expiry_height = t.u32()?;
        let input_count = t.compact()?;
        let mut prevouts = Vec::with_capacity(input_count);
        let mut inputs_hold = true;
        for _ in 0..input_count {
            let prevout = t.take(36)?;
            let script_sig = t.compact()?;
            t.take(script_sig)?;
            let sequence = t.u32()?;
            inputs_hold &= script_sig == 0 && sequence == SEQUENCE;
            prevouts.push((prevout, sequence));
        }
        let output_count = t.compact()?;
        let mut outputs = Vec::with_capacity(output_count);
        let mut outputs_hold = true;
        for _ in 0..output_count {
            let amount = t.u64()?;
            let length = t.compact()?;
            let script = t.take(length)?;
            outputs_hold &= amount > 0
                && amount <= MAX_MONEY
                && (p2pkh_hash(script).is_some() || p2sh_hash(script).is_some());
            outputs.push(Output { amount, script, tex: false });
        }
        // No Sapling spend, no Sapling output, no Orchard action: the three
        // counts, and nothing after them.
        let shielded = [t.compact()?, t.compact()?, t.compact()?];
        if t.at != tx.len() {
            return refused();
        }
        let mut inputs = Vec::with_capacity(input_count);
        for (prevout, sequence) in prevouts {
            let amount = r.u64()?;
            let script = r.short_bytes()?;
            inputs_hold &= amount > 0 && amount <= MAX_MONEY && p2pkh_hash(script).is_some();
            inputs.push(Input { prevout, sequence, amount, script });
        }
        for output in &mut outputs {
            match r.u8()? {
                SPELT_TRANSPARENT => {}
                SPELT_TEX => {
                    outputs_hold &= p2pkh_hash(output.script).is_some();
                    output.tex = true;
                }
                _ => return refused(),
            }
        }
        let fee = r.u64()?;
        if r.at != bytes.len() {
            return malformed();
        }
        if header != HEADER
            || group != VERSION_GROUP_ID
            || lock_time != 0
            || expiry_height == 0
            || expiry_height >= EXPIRY_CEILING
            || inputs.is_empty()
            || outputs.is_empty()
            || !inputs_hold
            || !outputs_hold
            || shielded != [0, 0, 0]
        {
            return refused();
        }
        // No outpoint twice: the network refuses a transaction that spends one
        // output twice, and the module never writes one.
        for (i, a) in inputs.iter().enumerate() {
            if inputs[..i].iter().any(|b| b.prevout == a.prevout) {
                return refused();
            }
        }
        let spent: u128 = inputs.iter().map(|i| u128::from(i.amount)).sum();
        let paid: u128 = outputs.iter().map(|o| u128::from(o.amount)).sum();
        if spent < paid || spent - paid != u128::from(fee) || u128::from(fee) > u128::from(MAX_MONEY) {
            return refused();
        }
        Ok(Self { path, branch_id, lock_time, expiry_height, inputs, outputs })
    }

    fn spent(&self) -> u128 {
        self.inputs.iter().map(|i| u128::from(i.amount)).sum()
    }

    /// The fee: the inputs' sum less the outputs'.
    fn fee(&self) -> u128 {
        self.spent() - self.outputs.iter().map(|o| u128::from(o.amount)).sum::<u128>()
    }
}

/// What a reading of the request [bytes] is kept under, and a signature held
/// to: its SHA-256.
pub(crate) fn request_id(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// --------------------------------------------------------------- ZIP-244

/// BLAKE2b-256 personalised with [persona], unkeyed, of [parts] one after
/// another. Unkeyed is BLAKE2's parameter block with a key length of zero and
/// no key block — not `Blake2bMac` with an empty key, which hashes a block of
/// zeros first.
fn blake2b_256(persona: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut core = Blake2bVarCore::new_with_params(&[], persona, 0, 32);
    let mut buffer = Buffer::<Blake2bVarCore>::default();
    for part in parts {
        buffer.digest_blocks(part, |blocks| core.update_blocks(blocks));
    }
    let mut full = Default::default();
    core.finalize_variable_core(&mut buffer, &mut full);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// A script with its CompactSize length, as a transaction carries it.
fn with_length(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len() + 1);
    out.push(u8::try_from(script.len()).expect("held: at most 252 bytes"));
    out.extend_from_slice(script);
    out
}

fn header_digest(request: &Request<'_>) -> [u8; 32] {
    blake2b_256(
        b"ZTxIdHeadersHash",
        &[
            &HEADER.to_le_bytes(),
            &VERSION_GROUP_ID.to_le_bytes(),
            &request.branch_id.to_le_bytes(),
            &request.lock_time.to_le_bytes(),
            &request.expiry_height.to_le_bytes(),
        ],
    )
}

fn prevouts_digest(request: &Request<'_>) -> [u8; 32] {
    let all: Vec<u8> = request.inputs.iter().flat_map(|i| i.prevout.iter().copied()).collect();
    blake2b_256(b"ZTxIdPrevoutHash", &[&all])
}

fn sequence_digest(request: &Request<'_>) -> [u8; 32] {
    let all: Vec<u8> = request.inputs.iter().flat_map(|i| i.sequence.to_le_bytes()).collect();
    blake2b_256(b"ZTxIdSequencHash", &[&all])
}

fn outputs_digest(request: &Request<'_>) -> [u8; 32] {
    let mut all = Vec::new();
    for output in &request.outputs {
        all.extend_from_slice(&output.amount.to_le_bytes());
        all.extend_from_slice(&with_length(output.script));
    }
    blake2b_256(b"ZTxIdOutputsHash", &[&all])
}

/// The Sapling and Orchard digests of a transaction with neither: each the
/// hash of nothing under its own personalisation.
fn empty_shielded_digests() -> ([u8; 32], [u8; 32]) {
    (blake2b_256(b"ZTxIdSaplingHash", &[]), blake2b_256(b"ZTxIdOrchardHash", &[]))
}

/// The root: `ZcashTxHash_` and the branch id, of the four parts.
fn root(request: &Request<'_>, transparent: &[u8; 32]) -> [u8; 32] {
    let mut persona = *b"ZcashTxHash_\0\0\0\0";
    persona[12..].copy_from_slice(&request.branch_id.to_le_bytes());
    let (sapling, orchard) = empty_shielded_digests();
    blake2b_256(&persona, &[&header_digest(request), transparent, &sapling, &orchard])
}

/// The transaction's id (ZIP-244 §T): its digest, in the transaction's own
/// byte order — reversed for display. It commits to no `scriptSig`, so it is
/// the id of the signed transaction too.
pub(crate) fn txid(request: &Request<'_>) -> [u8; 32] {
    let transparent = blake2b_256(
        b"ZTxIdTranspaHash",
        &[&prevouts_digest(request), &sequence_digest(request), &outputs_digest(request)],
    );
    root(request, &transparent)
}

/// The signature digest of [request]'s input [index] under `SIGHASH_ALL`
/// (ZIP-244 §S.2): the amounts and the scripts of every coin spent, and this
/// input's own, beside the transaction's prevouts, sequences and outputs.
pub(crate) fn sighash(request: &Request<'_>, index: usize) -> [u8; 32] {
    let amounts: Vec<u8> = request.inputs.iter().flat_map(|i| i.amount.to_le_bytes()).collect();
    let scripts: Vec<u8> = request.inputs.iter().flat_map(|i| with_length(i.script)).collect();
    let input = &request.inputs[index];
    let txin = blake2b_256(
        b"Zcash___TxInHash",
        &[input.prevout, &input.amount.to_le_bytes(), &with_length(input.script), &input.sequence.to_le_bytes()],
    );
    let transparent = blake2b_256(
        b"ZTxIdTranspaHash",
        &[
            &[SIGHASH_ALL],
            &prevouts_digest(request),
            &blake2b_256(b"ZTxTrAmountsHash", &[&amounts]),
            &blake2b_256(b"ZTxTrScriptsHash", &[&scripts]),
            &sequence_digest(request),
            &outputs_digest(request),
            &txin,
        ],
    );
    root(request, &transparent)
}

// --------------------------------------------------------------- the key

/// The pay-to-public-key-hash script of [key]'s compressed public key: what
/// this account's `t1` address locks to.
pub(crate) fn own_script(key: &DerivedKey) -> [u8; 25] {
    let mut script = [0u8; 25];
    script[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    script[3..23].copy_from_slice(&hash160(&keys::public_key(key).serialize()));
    script[23..].copy_from_slice(&[0x88, 0xac]);
    script
}

/// That every input of [request] spends [own] — the script of the key that
/// signs it. A difference is [`Refusal::Transaction`].
pub(crate) fn hold_to_key(request: &Request<'_>, own: &[u8; 25]) -> Result<(), Refusal> {
    if request.inputs.iter().any(|input| input.script != own) {
        return refused();
    }
    Ok(())
}

// --------------------------------------------------------------- addresses

/// Base58check of a two-byte [version] and a 20-byte [hash]: `t1…` or `t3…`.
pub(crate) fn transparent_address(version: [u8; 2], hash: &[u8]) -> String {
    let data = [&version[..], hash].concat();
    let check = Sha256::digest(Sha256::digest(&data));
    base58(&[data.as_slice(), &check[..4]].concat())
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in [0x3b6a_57b2u32, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3].iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// ZIP-320's TEX address of a 20-byte key [hash]: Bech32m under `tex`.
pub(crate) fn tex_address(hash: &[u8]) -> String {
    let mut words = Vec::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for byte in hash {
        accumulator = (accumulator << 8) | u32::from(*byte);
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
    let hrp = b"tex";
    let mut values: Vec<u8> = hrp.iter().map(|c| c >> 5).collect();
    values.push(0);
    values.extend(hrp.iter().map(|c| c & 31));
    values.extend_from_slice(&words);
    values.extend_from_slice(&[0; 6]);
    let checksum = bech32_polymod(&values) ^ 0x2bc8_30a3;
    let mut out = String::from("tex1");
    for word in words.iter().copied().chain((0..6).map(|i| ((checksum >> (5 * (5 - i))) & 31) as u8)) {
        out.push(char::from(BECH32[usize::from(word)]));
    }
    out
}

/// The address [output] pays, as the person wrote it.
fn output_address(output: &Output<'_>) -> String {
    match (p2pkh_hash(output.script), p2sh_hash(output.script)) {
        (Some(hash), _) if output.tex => tex_address(hash),
        (Some(hash), _) => transparent_address(P2PKH_VERSION, hash),
        (None, Some(hash)) => transparent_address(P2SH_VERSION, hash),
        (None, None) => unreachable!("held: every output pays a key hash or a script hash"),
    }
}

// --------------------------------------------------------------- reading

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [bytes] reversed and in hex: a transaction id as explorers write it.
fn display_hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

/// What a review screen shows of [request], once [`hold_to_key`] held it:
/// every input's outpoint and amount; every output in order with its address
/// — spelt here — its amount, and whether it is the account's change (it pays
/// [own], the signing key's script); the sum sent to others, the sum spent,
/// the fee, the expiry height, the transaction's id and every input's
/// signature digest.
pub(crate) fn reading(request: &Request<'_>, own: &[u8; 25]) -> Value {
    let inputs: Vec<Value> = request
        .inputs
        .iter()
        .map(|input| {
            let mut entry = Map::new();
            entry.insert("txid".into(), Value::String(display_hex(input.txid())));
            entry.insert("index".into(), Value::from(input.index()));
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
            let mut entry = Map::new();
            entry.insert("address".into(), Value::String(output_address(output)));
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
    out.insert("expiryHeight".into(), Value::from(request.expiry_height));
    out.insert("txid".into(), Value::String(display_hex(&txid(request))));
    out.insert("sighashes".into(), Value::Array(sighashes));
    Value::Object(out)
}

/// Per input, its signature digest and the low-R ECDSA signature over it.
pub(crate) type Signed = [u8; 96];

/// Every input of [request] signed with [key], once [`hold_to_key`] holds:
/// each spends [key]'s own script. Low `R` and low `s`, as every Bitcoin
/// family input this app signs ([`keys::sign_digest_low_r`]), so each
/// signature is at most 71 bytes in DER.
pub(crate) fn sign(request: &Request<'_>, key: &DerivedKey) -> Result<Vec<Signed>, Refusal> {
    hold_to_key(request, &own_script(key))?;
    let mut signed = Vec::with_capacity(request.inputs.len());
    for index in 0..request.inputs.len() {
        let sighash = sighash(request, index);
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&sighash);
        out[32..].copy_from_slice(&keys::sign_digest_low_r(key, &sighash)?);
        signed.push(out);
    }
    Ok(signed)
}

/// A signed transparent version 5 transaction off the chain, read for its
/// digests whatever its sequences, lock time and expiry — the tests' way to
/// hold [`txid`] and [`sighash`] to transactions the network accepted, with
/// [coins] the amount and script of the coin each input spends. Every
/// input's `scriptSig` is returned beside it.
#[cfg(test)]
pub(crate) fn read_signed<'a>(tx: &'a [u8], coins: &[(u64, &'a [u8])]) -> (Request<'a>, Vec<&'a [u8]>) {
    let mut t = Reader { bytes: tx, at: 0 };
    let header = t.u32().unwrap();
    assert_eq!((header, t.u32().unwrap()), (HEADER, VERSION_GROUP_ID));
    let branch_id = t.u32().unwrap();
    let lock_time = t.u32().unwrap();
    let expiry_height = t.u32().unwrap();
    let mut inputs = Vec::new();
    let mut script_sigs = Vec::new();
    for (amount, script) in coins.iter().take(t.compact().unwrap()) {
        let prevout = t.take(36).unwrap();
        let length = t.compact().unwrap();
        script_sigs.push(t.take(length).unwrap());
        inputs.push(Input { prevout, sequence: t.u32().unwrap(), amount: *amount, script });
    }
    assert_eq!(inputs.len(), coins.len());
    let mut outputs = Vec::new();
    for _ in 0..t.compact().unwrap() {
        let amount = t.u64().unwrap();
        let length = t.compact().unwrap();
        outputs.push(Output { amount, script: t.take(length).unwrap(), tex: false });
    }
    assert_eq!(&tx[t.at..], &[0, 0, 0], "transparent only");
    (Request { path: b"", branch_id, lock_time, expiry_height, inputs, outputs }, script_sigs)
}
