//! A Bitcoin-family transaction read and signed in the core — "sign what you
//! see", step 2d of `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions
//! O35–O40): Bitcoin, Litecoin, Dogecoin and Bitcoin Cash.
//!
//! The app hands the core the unsigned transaction its library built, what
//! each input spends, the key and script kind of each, and the transaction as
//! the app built it — its outputs, which are change, and the fee. The core
//! reads the transaction, holds it to all of that, computes every sighash
//! itself and only then signs; a digest computed in Dart is never what it
//! signs here.
//!
//! The sighashes are written for every hash type, so the published vectors
//! hold them whole (O36, O40); [`Request`] admits `ALL`, `DEFAULT` for a
//! taproot key path and `ALL|FORKID` on Bitcoin Cash, and nothing else.
//!
//! **Nothing secret passes through the reading and hashing here**: they run
//! before the table's lock is taken. [`sign`] is handed the keys, one input at
//! a time, by `kc_bitcoin_sign_transaction`.

use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar};
use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::keys::{self, DerivedKey};

// ---------------------------------------------------------------- reading

/// Bytes read in order. A read past the end, a non-canonical length or a
/// count that cannot fit is [`Reader::refusal`].
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    refusal: Refusal,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], refusal: Refusal) -> Self {
        Self { bytes, at: 0, refusal }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(n).ok_or(self.refusal)?;
        let taken = self.bytes.get(self.at..end).ok_or(self.refusal)?;
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

    /// Bitcoin's CompactSize, refused where it is not the shortest form, as
    /// Bitcoin Core refuses it.
    fn compact(&mut self) -> Result<u64, Refusal> {
        let (value, least) = match self.u8()? {
            0xfd => (u64::from(self.u16()?), 0xfd),
            0xfe => (u64::from(self.u32()?), 0x1_0000),
            0xff => (self.u64()?, 0x1_0000_0000),
            byte => return Ok(u64::from(byte)),
        };
        if value < least {
            return Err(self.refusal);
        }
        Ok(value)
    }

    /// A count of items at least [smallest] bytes each, which the bytes left
    /// must be able to hold — so no count can ask for more than is there.
    fn count(&mut self, smallest: usize) -> Result<usize, Refusal> {
        let count = usize::try_from(self.compact()?).map_err(|_| self.refusal)?;
        if count > (self.bytes.len() - self.at) / smallest {
            return Err(self.refusal);
        }
        Ok(count)
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], Refusal> {
        let length = usize::try_from(self.compact()?).map_err(|_| self.refusal)?;
        self.take(length)
    }

    fn short_bytes(&mut self) -> Result<&'a [u8], Refusal> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// One input as the transaction carries it.
pub(crate) struct Input<'a> {
    /// The spent output: its transaction's id, then its index, as serialized.
    pub(crate) outpoint: &'a [u8],
    pub(crate) script_sig: &'a [u8],
    pub(crate) sequence: &'a [u8],
}

/// One output: its amount, its script, and the two as serialized.
pub(crate) struct Output<'a> {
    pub(crate) value: u64,
    pub(crate) script: &'a [u8],
    pub(crate) serialized: &'a [u8],
}

/// A transaction as serialized, in either form: with or without segwit's
/// marker and witnesses.
pub(crate) struct Transaction<'a> {
    version: &'a [u8],
    /// The counts, inputs and outputs: what a txid hashes between the version
    /// and the lock time.
    body: &'a [u8],
    pub(crate) inputs: Vec<Input<'a>>,
    pub(crate) outputs: Vec<Output<'a>>,
    locktime: &'a [u8],
    pub(crate) has_witness: bool,
}

impl<'a> Transaction<'a> {
    /// [bytes], whole: a transaction with no input, or with anything after
    /// its lock time, is [`Refusal::Transaction`].
    pub(crate) fn read(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let mut reader = Reader::new(bytes, Refusal::Transaction);
        let version = reader.take(4)?;
        let has_witness = bytes.get(4) == Some(&0) && bytes.get(5) == Some(&1);
        if has_witness {
            reader.take(2)?;
        }
        let body_start = reader.at;
        let input_count = reader.count(41)?;
        if input_count == 0 {
            return Err(Refusal::Transaction);
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(Input {
                outpoint: reader.take(36)?,
                script_sig: reader.var_bytes()?,
                sequence: reader.take(4)?,
            });
        }
        let output_count = reader.count(9)?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let start = reader.at;
            let value = reader.u64()?;
            let script = reader.var_bytes()?;
            outputs.push(Output { value, script, serialized: &bytes[start..reader.at] });
        }
        let body = &bytes[body_start..reader.at];
        if has_witness {
            for _ in 0..input_count {
                let items = reader.count(1)?;
                for _ in 0..items {
                    reader.var_bytes()?;
                }
            }
        }
        let locktime = reader.take(4)?;
        if !reader.done() {
            return Err(Refusal::Transaction);
        }
        Ok(Self { version, body, inputs, outputs, locktime, has_witness })
    }

    /// The transaction's id, in the byte order an outpoint carries it: the
    /// double SHA-256 of the form without witnesses.
    pub(crate) fn txid(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.version);
        hasher.update(self.body);
        hasher.update(self.locktime);
        sha256(&hasher.finalize())
    }
}

// --------------------------------------------------------------- hashing

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// What a reading of the request [bytes] is kept under, and a signature held
/// to (2f-3): its SHA-256.
pub(crate) fn request_id(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// RIPEMD-160 of SHA-256: a key's or a script's hash in an address.
pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// BIP-340's tagged hash: SHA-256 of the tag's hash twice, then [parts].
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag = sha256(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [&[0xfd][..], &(n as u16).to_le_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[0xfe][..], &(n as u32).to_le_bytes()].concat(),
        _ => [&[0xff][..], &(n as u64).to_le_bytes()].concat(),
    }
}

const SIGHASH_ALL: u32 = 0x01;
const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_FORKID: u32 = 0x40;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// The next operation of [script] from [at]: its opcode and where the one
/// after it starts, or nothing where the script ends or a push runs past
/// its end — Bitcoin Core's `GetScriptOp`.
fn next_op(script: &[u8], at: usize) -> Option<(u8, usize)> {
    let opcode = *script.get(at)?;
    let mut next = at + 1;
    let size = match opcode {
        0x01..=0x4b => usize::from(opcode),
        0x4c..=0x4e => {
            let width = [1usize, 2, 4][usize::from(opcode - 0x4c)];
            let bytes = script.get(next..next + width)?;
            next += width;
            bytes.iter().rev().fold(0usize, |size, b| (size << 8) | usize::from(*b))
        }
        _ => 0,
    };
    if script.len() - next < size {
        return None;
    }
    Some((opcode, next + size))
}

/// [script] with each `OP_CODESEPARATOR` it executes taken out, as the legacy
/// sighash serializes a script code.
fn without_code_separators(script: &[u8]) -> Vec<u8> {
    let mut separators = Vec::new();
    let mut at = 0;
    while let Some((opcode, next)) = next_op(script, at) {
        if opcode == 0xab {
            separators.push(at);
        }
        at = next;
    }
    script
        .iter()
        .enumerate()
        .filter(|(i, _)| !separators.contains(i))
        .map(|(_, b)| *b)
        .collect()
}

/// The legacy sighash of input [index] — Bitcoin Core's `SignatureHash` for
/// a script that is not a witness program, every hash type, the
/// `SIGHASH_SINGLE` case with no matching output answering one, as Core does.
pub(crate) fn legacy_sighash(
    tx: &Transaction<'_>,
    index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> [u8; 32] {
    let base = hash_type & 0x1f;
    let none = base == SIGHASH_NONE;
    let single = base == SIGHASH_SINGLE;
    let anyone = hash_type & SIGHASH_ANYONECANPAY != 0;
    if index >= tx.inputs.len() || (single && index >= tx.outputs.len()) {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(tx.version);
    let signed: Vec<usize> = if anyone { vec![index] } else { (0..tx.inputs.len()).collect() };
    preimage.extend(compact_size(signed.len()));
    for i in signed {
        let input = &tx.inputs[i];
        preimage.extend_from_slice(input.outpoint);
        if i == index {
            let code = without_code_separators(script_code);
            preimage.extend(compact_size(code.len()));
            preimage.extend(code);
        } else {
            preimage.push(0);
        }
        if i != index && (none || single) {
            preimage.extend_from_slice(&[0; 4]);
        } else {
            preimage.extend_from_slice(input.sequence);
        }
    }
    let output_count = if none { 0 } else if single { index + 1 } else { tx.outputs.len() };
    preimage.extend(compact_size(output_count));
    for (o, output) in tx.outputs.iter().take(output_count).enumerate() {
        if single && o != index {
            preimage.extend_from_slice(&[0xff; 8]);
            preimage.push(0);
        } else {
            preimage.extend_from_slice(output.serialized);
        }
    }
    preimage.extend_from_slice(tx.locktime);
    preimage.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&preimage)
}

/// BIP-143's sighash of input [index], which spends [amount] — and, with
/// `SIGHASH_FORKID` in [hash_type], Bitcoin Cash's, which is the same
/// algorithm with that bit set. Every hash type.
pub(crate) fn segwit_v0_sighash(
    tx: &Transaction<'_>,
    index: usize,
    script_code: &[u8],
    amount: u64,
    hash_type: u32,
) -> [u8; 32] {
    let base = hash_type & 0x1f;
    let anyone = hash_type & SIGHASH_ANYONECANPAY != 0;
    let zero = [0u8; 32];
    let prevouts = if anyone {
        zero
    } else {
        sha256d(&tx.inputs.iter().flat_map(|i| i.outpoint.iter().copied()).collect::<Vec<_>>())
    };
    let sequences = if anyone || base == SIGHASH_SINGLE || base == SIGHASH_NONE {
        zero
    } else {
        sha256d(&tx.inputs.iter().flat_map(|i| i.sequence.iter().copied()).collect::<Vec<_>>())
    };
    let outputs = if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        sha256d(&tx.outputs.iter().flat_map(|o| o.serialized.iter().copied()).collect::<Vec<_>>())
    } else if base == SIGHASH_SINGLE && index < tx.outputs.len() {
        sha256d(tx.outputs[index].serialized)
    } else {
        zero
    };
    let input = &tx.inputs[index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(tx.version);
    preimage.extend_from_slice(&prevouts);
    preimage.extend_from_slice(&sequences);
    preimage.extend_from_slice(input.outpoint);
    preimage.extend(compact_size(script_code.len()));
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(input.sequence);
    preimage.extend_from_slice(&outputs);
    preimage.extend_from_slice(tx.locktime);
    preimage.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&preimage)
}

/// BIP-341's signature message for a key-path spend of input [index], with no
/// annex: [spent] is every input's spent amount and script, in order. A hash
/// type BIP-341 does not define, or `SIGHASH_SINGLE` with no matching output,
/// is [`Refusal::Transaction`].
pub(crate) fn taproot_signature_message(
    tx: &Transaction<'_>,
    index: usize,
    spent: &[(u64, &[u8])],
    hash_type: u8,
) -> Result<Vec<u8>, Refusal> {
    if !matches!(hash_type, 0x00..=0x03 | 0x81..=0x83) || spent.len() != tx.inputs.len() {
        return Err(Refusal::Transaction);
    }
    let output_type = if hash_type == 0 { 1 } else { hash_type & 3 };
    let anyone = hash_type & 0x80 != 0;
    if output_type == 3 && index >= tx.outputs.len() {
        return Err(Refusal::Transaction);
    }
    let input = tx.inputs.get(index).ok_or(Refusal::Transaction)?;
    let mut message = vec![hash_type];
    message.extend_from_slice(tx.version);
    message.extend_from_slice(tx.locktime);
    if !anyone {
        let mut outpoints = Sha256::new();
        let mut amounts = Sha256::new();
        let mut scripts = Sha256::new();
        let mut sequences = Sha256::new();
        for (input, (amount, script)) in tx.inputs.iter().zip(spent) {
            outpoints.update(input.outpoint);
            amounts.update(amount.to_le_bytes());
            scripts.update(compact_size(script.len()));
            scripts.update(script);
            sequences.update(input.sequence);
        }
        message.extend_from_slice(&outpoints.finalize());
        message.extend_from_slice(&amounts.finalize());
        message.extend_from_slice(&scripts.finalize());
        message.extend_from_slice(&sequences.finalize());
    }
    if output_type == 1 {
        let mut outputs = Sha256::new();
        for output in &tx.outputs {
            outputs.update(output.serialized);
        }
        message.extend_from_slice(&outputs.finalize());
    }
    message.push(0); // spend type: a key path, no annex
    if anyone {
        let (amount, script) = spent[index];
        message.extend_from_slice(input.outpoint);
        message.extend_from_slice(&amount.to_le_bytes());
        message.extend(compact_size(script.len()));
        message.extend_from_slice(script);
        message.extend_from_slice(input.sequence);
    } else {
        message.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if output_type == 3 {
        message.extend_from_slice(&sha256(tx.outputs[index].serialized));
    }
    Ok(message)
}

/// BIP-341's sighash: the `TapSighash` tagged hash of epoch zero and
/// [`taproot_signature_message`].
pub(crate) fn taproot_sighash(
    tx: &Transaction<'_>,
    index: usize,
    spent: &[(u64, &[u8])],
    hash_type: u8,
) -> Result<[u8; 32], Refusal> {
    let message = taproot_signature_message(tx, index, spent, hash_type)?;
    Ok(tagged_hash(b"TapSighash", &[&[0], &message]))
}

// ---------------------------------------------------------------- scripts

/// How an input the wallet signs is locked, and so which sighash it takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    /// P2PKH of the compressed key.
    P2pkh,
    /// P2PKH of the uncompressed key — an imported key's older address.
    P2pkhUncompressed,
    /// P2WPKH inside P2SH (BIP-49).
    P2shP2wpkh,
    /// P2WPKH (BIP-84).
    P2wpkh,
    /// A taproot key path with no script tree (BIP-86).
    P2trKeyPath,
}

impl Kind {
    fn from_byte(byte: u8) -> Result<Self, Refusal> {
        Ok(match byte {
            0 => Kind::P2pkh,
            1 => Kind::P2pkhUncompressed,
            2 => Kind::P2shP2wpkh,
            3 => Kind::P2wpkh,
            4 => Kind::P2trKeyPath,
            _ => return Err(Refusal::Argument),
        })
    }

    fn is_legacy(self) -> bool {
        matches!(self, Kind::P2pkh | Kind::P2pkhUncompressed)
    }

    /// As the app's `CoreBitcoinKind` names it.
    fn name(self) -> &'static str {
        match self {
            Kind::P2pkh => "p2pkh",
            Kind::P2pkhUncompressed => "p2pkhUncompressed",
            Kind::P2shP2wpkh => "p2shP2wpkh",
            Kind::P2wpkh => "p2wpkh",
            Kind::P2trKeyPath => "p2trKeyPath",
        }
    }
}

fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
    [&[0x76, 0xa9, 0x14][..], hash, &[0x88, 0xac]].concat()
}

fn p2wpkh(hash: &[u8; 20]) -> Vec<u8> {
    [&[0x00, 0x14][..], hash].concat()
}

/// BIP-86's output key for [key]: the x-only key tweaked by its own
/// `TapTweak` hash, with no script tree. Also returns the tweak, which the
/// signature takes.
pub(crate) fn taproot_output_key(key: &PublicKey) -> Result<([u8; 32], [u8; 32]), Refusal> {
    let (internal, _) = key.x_only_public_key();
    let tweak = tagged_hash(b"TapTweak", &[&internal.to_byte_array()]);
    let scalar = Scalar::from_be_bytes(tweak).map_err(|_| Refusal::Derivation)?;
    let (output, _) = internal.add_tweak(&scalar).map_err(|_| Refusal::Derivation)?;
    Ok((output.to_byte_array(), tweak))
}


/// The output script [kind] locks to [key], or a refusal where it does not.
/// No kind signed here takes a witness script; the request carries an empty one.
fn script_for(kind: Kind, key: &PublicKey, _witness_script: &[u8]) -> Result<Vec<u8>, Refusal> {
    let compressed = key.serialize();
    Ok(match kind {
        Kind::P2pkh => p2pkh(&hash160(&compressed)),
        Kind::P2pkhUncompressed => p2pkh(&hash160(&key.serialize_uncompressed())),
        Kind::P2shP2wpkh => {
            let redeem = p2wpkh(&hash160(&compressed));
            [&[0xa9, 0x14][..], &hash160(&redeem), &[0x87]].concat()
        }
        Kind::P2wpkh => p2wpkh(&hash160(&compressed)),
        Kind::P2trKeyPath => [&[0x51, 0x20][..], &taproot_output_key(key)?.0].concat(),
    })
}

// ---------------------------------------------------------------- request

/// Bitcoin, Litecoin and Dogecoin share their sighashes; Bitcoin Cash signs
/// with `SIGHASH_FORKID`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Flavour {
    Bitcoin,
    BitcoinCash,
}

/// One input the wallet signs: what it spends and with which key.
pub(crate) struct SignedInput<'a> {
    pub(crate) amount: u64,
    pub(crate) spent_script: &'a [u8],
    pub(crate) kind: Kind,
    pub(crate) path: &'a [u8],
    pub(crate) witness_script: &'a [u8],
}

/// One output as the app built it; change names the key it pays.
pub(crate) struct ExpectedOutput<'a> {
    pub(crate) value: u64,
    pub(crate) script: &'a [u8],
    pub(crate) change: Option<(Kind, &'a [u8], &'a [u8])>,
}

/// A request read and held to everything that needs no key: the layout
/// `kc_bitcoin_sign_transaction` documents.
pub(crate) struct Request<'a> {
    pub(crate) flavour: Flavour,
    pub(crate) transaction: Transaction<'a>,
    pub(crate) inputs: Vec<SignedInput<'a>>,
    pub(crate) outputs: Vec<ExpectedOutput<'a>>,
}

impl<'a> Request<'a> {
    /// [bytes] in the documented layout. A layout that does not read, an
    /// unknown flavour or kind, or a field given to a kind that takes none,
    /// is [`Refusal::Argument`]; a transaction that is not the one described
    /// is [`Refusal::Transaction`].
    pub(crate) fn read(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let mut reader = Reader::new(bytes, Refusal::Argument);
        let flavour = match reader.u8()? {
            0 => Flavour::Bitcoin,
            1 => Flavour::BitcoinCash,
            _ => return Err(Refusal::Argument),
        };
        let unsigned_length = reader.u32()? as usize;
        let transaction = Transaction::read(reader.take(unsigned_length)?)?;
        let mut inputs = Vec::with_capacity(transaction.inputs.len());
        let mut previous = Vec::with_capacity(transaction.inputs.len());
        for _ in 0..transaction.inputs.len() {
            let amount = reader.u64()?;
            let spent_script = reader.short_bytes()?;
            let kind = Kind::from_byte(reader.u8()?)?;
            let path = reader.short_bytes()?;
            let witness_script = reader.short_bytes()?;
            let previous_length = reader.u32()? as usize;
            previous.push(reader.take(previous_length)?);
            if !witness_script.is_empty() {
                return Err(Refusal::Argument);
            }
            if flavour == Flavour::BitcoinCash && !kind.is_legacy() {
                return Err(Refusal::Argument);
            }
            inputs.push(SignedInput { amount, spent_script, kind, path, witness_script });
        }
        let output_count = usize::from(reader.u16()?);
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let value = reader.u64()?;
            let script = reader.short_bytes()?;
            let change_kind = reader.u8()?;
            let path = reader.short_bytes()?;
            let witness_script = reader.short_bytes()?;
            let change = if change_kind == 0xff {
                if !path.is_empty() || !witness_script.is_empty() {
                    return Err(Refusal::Argument);
                }
                None
            } else {
                let kind = Kind::from_byte(change_kind)?;
                if !witness_script.is_empty() {
                    return Err(Refusal::Argument);
                }
                Some((kind, path, witness_script))
            };
            outputs.push(ExpectedOutput { value, script, change });
        }
        let fee = reader.u64()?;
        if !reader.done() {
            return Err(Refusal::Argument);
        }
        let request = Self { flavour, transaction, inputs, outputs };
        request.hold(&previous, fee)?;
        Ok(request)
    }

    /// Everything that needs no key, each failure [`Refusal::Transaction`]:
    /// the unsigned form, the previous transactions, the outputs and the fee.
    fn hold(&self, previous: &[&[u8]], fee: u64) -> Result<(), Refusal> {
        let tx = &self.transaction;
        if tx.has_witness
            || tx.outputs.is_empty()
            || tx.inputs.iter().any(|input| !input.script_sig.is_empty())
        {
            return Err(Refusal::Transaction);
        }
        for ((input, signed), previous) in tx.inputs.iter().zip(&self.inputs).zip(previous) {
            // A legacy signature does not cover the amount, so a legacy
            // input's is read from the transaction it spends (O38); Bitcoin
            // Cash's FORKID sighash covers it, as segwit's do.
            let required = signed.kind.is_legacy() && self.flavour == Flavour::Bitcoin;
            if previous.is_empty() {
                if required {
                    return Err(Refusal::Transaction);
                }
                continue;
            }
            let spent = Transaction::read(previous)?;
            let vout = u32::from_le_bytes(input.outpoint[32..36].try_into().expect("four bytes"));
            let output = spent.outputs.get(vout as usize).ok_or(Refusal::Transaction)?;
            if spent.txid()[..] != input.outpoint[..32]
                || output.value != signed.amount
                || output.script != signed.spent_script
            {
                return Err(Refusal::Transaction);
            }
        }
        // The outputs are the app's, each once, in whatever order the
        // library put them.
        let mut unmatched: Vec<&Output<'_>> = tx.outputs.iter().collect();
        if unmatched.len() != self.outputs.len() {
            return Err(Refusal::Transaction);
        }
        for expected in &self.outputs {
            let found = unmatched
                .iter()
                .position(|o| o.value == expected.value && o.script == expected.script)
                .ok_or(Refusal::Transaction)?;
            unmatched.swap_remove(found);
        }
        let spent: u128 = self.inputs.iter().map(|i| u128::from(i.amount)).sum();
        let paid: u128 = tx.outputs.iter().map(|o| u128::from(o.value)).sum();
        if spent < paid || spent - paid != u128::from(fee) {
            return Err(Refusal::Transaction);
        }
        Ok(())
    }

    /// Every spent amount and script, in input order: what BIP-341 commits to.
    fn spent(&self) -> Vec<(u64, &[u8])> {
        self.inputs.iter().map(|i| (i.amount, i.spent_script)).collect()
    }
}

/// Per input, its sighash and the signature over it: `r ‖ s` (low `s`, `r`
/// ground low) or a BIP-340 signature with BIP-86's tweak.
pub(crate) type Signed = [u8; 96];

/// That each change output of [request] pays the wallet's key at its path,
/// and each input spends its key's script — the checks that need a key, the
/// key [key_at] gives for a path. A difference is [`Refusal::Transaction`].
pub(crate) fn hold_to_keys(
    request: &Request<'_>,
    key_at: &dyn Fn(&[u8]) -> Result<DerivedKey, Refusal>,
) -> Result<(), Refusal> {
    for output in &request.outputs {
        if let Some((kind, path, witness_script)) = output.change {
            let key = key_at(path)?;
            if script_for(kind, &keys::public_key(&key), witness_script)? != output.script {
                return Err(Refusal::Transaction);
            }
        }
    }
    for input in &request.inputs {
        let key = key_at(input.path)?;
        if script_for(input.kind, &keys::public_key(&key), input.witness_script)? != input.spent_script {
            return Err(Refusal::Transaction);
        }
    }
    Ok(())
}

/// What a review screen shows of [request] — "the screen shows what the core
/// read", step 2f-3 — once [`hold_to_keys`] held it: the flavour, the
/// transaction's id, every input's outpoint, amount and kind, every output in
/// the transaction's order with its value, its script and whether it is the
/// wallet's change (its key's, found at its path), the sum spent and the
/// fee. Ids are hex in the order explorers print them; amounts, decimal.
pub(crate) fn reading(request: &Request<'_>) -> serde_json::Value {
    use serde_json::{Map, Value};
    fn hex(bytes: impl IntoIterator<Item = u8>) -> String {
        bytes.into_iter().map(|b| format!("{b:02x}")).collect()
    }
    let tx = &request.transaction;
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .zip(&request.inputs)
        .map(|(input, signed)| {
            let mut entry = Map::new();
            entry.insert("txid".into(), Value::String(hex(input.outpoint[..32].iter().rev().copied())));
            let vout = u32::from_le_bytes(input.outpoint[32..36].try_into().expect("four bytes"));
            entry.insert("vout".into(), Value::from(vout));
            entry.insert("amount".into(), Value::String(signed.amount.to_string()));
            entry.insert("kind".into(), Value::String(signed.kind.name().into()));
            Value::Object(entry)
        })
        .collect();
    // Each output matched to the app's as `hold` matched them, in the
    // transaction's order: change is what the app named and the key proved.
    let mut unmatched: Vec<&ExpectedOutput<'_>> = request.outputs.iter().collect();
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .map(|output| {
            let at = unmatched
                .iter()
                .position(|e| e.value == output.value && e.script == output.script)
                .expect("held: every output is the app's");
            let expected = unmatched.swap_remove(at);
            let mut entry = Map::new();
            entry.insert("value".into(), Value::String(output.value.to_string()));
            entry.insert("script".into(), Value::String(format!("0x{}", hex(output.script.iter().copied()))));
            entry.insert("change".into(), Value::Bool(expected.change.is_some()));
            Value::Object(entry)
        })
        .collect();
    let spent: u128 = request.inputs.iter().map(|i| u128::from(i.amount)).sum();
    let paid: u128 = tx.outputs.iter().map(|o| u128::from(o.value)).sum();
    let mut out = Map::new();
    out.insert(
        "flavour".into(),
        Value::String(match request.flavour {
            Flavour::Bitcoin => "bitcoin",
            Flavour::BitcoinCash => "bitcoinCash",
        }
        .into()),
    );
    out.insert("txid".into(), Value::String(hex(tx.txid().iter().rev().copied())));
    out.insert("inputs".into(), Value::Array(inputs));
    out.insert("outputs".into(), Value::Array(outputs));
    out.insert("spent".into(), Value::String(spent.to_string()));
    out.insert("fee".into(), Value::String((spent - paid).to_string()));
    Value::Object(out)
}

/// Signs every input of [request] with the key [key_at] gives for its path,
/// once [`hold_to_keys`] holds: each change output pays the wallet's key at
/// its path and each input spends its key's script. A difference is
/// [`Refusal::Transaction`].
pub(crate) fn sign(
    request: &Request<'_>,
    key_at: &dyn Fn(&[u8]) -> Result<DerivedKey, Refusal>,
) -> Result<Vec<Signed>, Refusal> {
    hold_to_keys(request, key_at)?;
    let tx = &request.transaction;
    let spent = request.spent();
    let mut signed = Vec::with_capacity(request.inputs.len());
    for (index, input) in request.inputs.iter().enumerate() {
        let key = key_at(input.path)?;
        let public = keys::public_key(&key);
        let mut out = [0u8; 96];
        let signature = match (input.kind, request.flavour) {
            (Kind::P2trKeyPath, _) => {
                let sighash = taproot_sighash(tx, index, &spent, 0x00)?;
                let (_, tweak) = taproot_output_key(&public)?;
                out[..32].copy_from_slice(&sighash);
                keys::schnorr_sign(&key, &sighash, Some(&tweak))?
            }
            (kind, flavour) => {
                let sighash = match (kind, flavour) {
                    (Kind::P2pkh | Kind::P2pkhUncompressed, Flavour::Bitcoin) => {
                        legacy_sighash(tx, index, input.spent_script, SIGHASH_ALL)
                    }
                    (Kind::P2pkh | Kind::P2pkhUncompressed, Flavour::BitcoinCash) => {
                        segwit_v0_sighash(
                            tx,
                            index,
                            input.spent_script,
                            input.amount,
                            SIGHASH_ALL | SIGHASH_FORKID,
                        )
                    }
                    (Kind::P2shP2wpkh | Kind::P2wpkh, _) => {
                        let code = p2pkh(&hash160(&public.serialize()));
                        segwit_v0_sighash(tx, index, &code, input.amount, SIGHASH_ALL)
                    }
                    (Kind::P2trKeyPath, _) => unreachable!("matched above"),
                };
                out[..32].copy_from_slice(&sighash);
                keys::sign_digest_low_r(&key, &sighash)?
            }
        };
        out[32..].copy_from_slice(&signature);
        signed.push(out);
    }
    Ok(signed)
}
