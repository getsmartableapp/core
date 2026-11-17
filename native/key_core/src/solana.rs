//! A Solana message read in the core for its review screen — "sign what you
//! see" for Solana, after step 2f of `docs/RUST_KEY_CORE_DESIGN.md` (the
//! owner's decisions O52 and O58).
//!
//! An ed25519 signature on Solana is over the message bytes themselves, so
//! what the core reads here is what it signs: the header, the accounts, the
//! recent blockhash, every instruction and, for a version 0 message, the
//! address-lookup tables it borrows accounts from — read as the app's
//! `SolanaReadMessage.parse` reads it, refusing what that refuses. Beside the
//! structure, the instructions of the programs a send of this wallet's uses
//! are decoded: a System transfer, the SPL Token and Token-2022 transfers,
//! `transferChecked`, `closeAccount` and `syncNative`, the Associated Token
//! Account program's create — its address held to the owner and mint it names
//! — the compute budget, and a memo. Any other instruction is its program and
//! its bytes, read and not described.
//!
//! **Nothing secret passes through this file**: it runs before the table's
//! lock is taken, and what it returns is a reading.

use curve25519_dalek::edwards::CompressedEdwardsY;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Refusal;

const SYSTEM: [u8; 32] = [0; 32];
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED_TOKEN: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

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

    /// Solana's compact-u16: seven bits a byte, at most three bytes, in its
    /// shortest form — as the app's reader reads it.
    fn compact(&mut self) -> Result<usize, Refusal> {
        let mut value = 0usize;
        for i in 0..3 {
            let byte = self.byte()?;
            value |= usize::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return refused();
                }
                return if value > 0xffff { refused() } else { Ok(value) };
            }
        }
        refused()
    }
}

/// The Bitcoin alphabet's base58, as Solana writes an address.
pub(crate) fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    // Base 58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
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
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| ALPHABET[usize::from(*d)] as char));
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One instruction as the message stores it: indexes, not addresses.
struct Instruction<'a> {
    program: usize,
    accounts: Vec<usize>,
    data: &'a [u8],
}

/// [message] — the bytes after a transaction's signature table, the bytes an
/// ed25519 signature on Solana is over — read for a review screen. A message
/// the app's reader refuses — a version other than 0, a header that does not
/// match its accounts, a count past the end, a program or account index
/// outside the message, a byte after the last field — is
/// [`Refusal::Transaction`].
pub(crate) fn reading(message: &[u8]) -> Result<Value, Refusal> {
    let mut r = Reader { bytes: message, at: 0 };
    let mut versioned = false;
    if message.first().is_some_and(|b| b & 0x80 != 0) {
        if r.byte()? & 0x7f != 0 {
            return refused();
        }
        versioned = true;
    }
    let required = usize::from(r.byte()?);
    let readonly_signed = usize::from(r.byte()?);
    let readonly_unsigned = usize::from(r.byte()?);
    let key_count = r.compact()?;
    let mut keys: Vec<&[u8]> = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(r.take(32)?);
    }
    if key_count == 0
        || required == 0
        || required > key_count
        || readonly_signed >= required
        || readonly_unsigned > key_count - required
    {
        return refused();
    }
    let blockhash = r.take(32)?;
    let instruction_count = r.compact()?;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program = usize::from(r.byte()?);
        // A program is never borrowed from a lookup table.
        if program >= key_count {
            return refused();
        }
        let account_count = r.compact()?;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(usize::from(r.byte()?));
        }
        let length = r.compact()?;
        instructions.push(Instruction { program, accounts, data: r.take(length)? });
    }
    let mut lookups = Vec::new();
    let mut borrowed = 0usize;
    if versioned {
        let table_count = r.compact()?;
        for _ in 0..table_count {
            let table = r.take(32)?;
            let writable_count = r.compact()?;
            let writable: Vec<u8> = r.take(writable_count)?.to_vec();
            let readonly_count = r.compact()?;
            let readonly: Vec<u8> = r.take(readonly_count)?.to_vec();
            borrowed += writable.len() + readonly.len();
            let mut entry = Map::new();
            entry.insert("table".into(), Value::String(base58(table)));
            entry.insert("writable".into(), Value::from(writable));
            entry.insert("readonly".into(), Value::from(readonly));
            lookups.push(Value::Object(entry));
        }
    }
    if r.at != message.len() {
        return refused();
    }
    let total = key_count + borrowed;
    if instructions.iter().any(|i| i.accounts.iter().any(|a| *a >= total)) {
        return refused();
    }
    let read: Vec<Value> = instructions
        .iter()
        .map(|instruction| {
            let mut entry = Map::new();
            entry.insert("program".into(), Value::String(base58(keys[instruction.program])));
            entry.insert(
                "accounts".into(),
                Value::from(instruction.accounts.iter().map(|a| *a as u64).collect::<Vec<_>>()),
            );
            entry.insert("data".into(), Value::String(hex(instruction.data)));
            entry.insert("decoded".into(), decoded(&keys, instruction).unwrap_or(Value::Null));
            Value::Object(entry)
        })
        .collect();
    let mut out = Map::new();
    out.insert("versioned".into(), Value::Bool(versioned));
    out.insert("header".into(), Value::from(vec![required as u64, readonly_signed as u64, readonly_unsigned as u64]));
    out.insert("accounts".into(), Value::Array(keys.iter().map(|k| Value::String(base58(k))).collect()));
    out.insert("feePayer".into(), Value::String(base58(keys[0])));
    out.insert("blockhash".into(), Value::String(base58(blockhash)));
    out.insert("instructions".into(), Value::Array(read));
    out.insert("lookups".into(), Value::Array(lookups));
    Ok(Value::Object(out))
}

/// What [instruction] does, where its program is one a send of this wallet's
/// uses and every account it needs is written into the message — or none.
fn decoded(keys: &[&[u8]], instruction: &Instruction<'_>) -> Option<Value> {
    let program = base58(keys[instruction.program]);
    // An account by its place in the instruction, written into the message.
    let account = |at: usize| -> Option<String> {
        let index = *instruction.accounts.get(at)?;
        keys.get(index).map(|k| base58(k))
    };
    let data = instruction.data;
    let u64_at = |at: usize| -> Option<u64> {
        data.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().expect("eight")))
    };
    let mut out = Map::new();
    let mut put = |key: &str, value: Value| {
        out.insert(key.into(), value);
    };
    if keys[instruction.program] == &SYSTEM[..] {
        // `Transfer`: the u32 tag 2, then the lamports.
        if data.len() != 12 || data[..4] != [2, 0, 0, 0] {
            return None;
        }
        put("kind", "systemTransfer".into());
        put("from", account(0)?.into());
        put("to", account(1)?.into());
        put("lamports", u64_at(4)?.to_string().into());
    } else if program == TOKEN || program == TOKEN_2022 {
        match (data.first()?, data.len()) {
            (3, 9) => {
                put("kind", "tokenTransfer".into());
                put("source", account(0)?.into());
                put("destination", account(1)?.into());
                put("owner", account(2)?.into());
                put("amount", u64_at(1)?.to_string().into());
            }
            (12, 10) => {
                put("kind", "tokenTransferChecked".into());
                put("source", account(0)?.into());
                put("mint", account(1)?.into());
                put("destination", account(2)?.into());
                put("owner", account(3)?.into());
                put("amount", u64_at(1)?.to_string().into());
                put("decimals", Value::from(data[9]));
            }
            (9, 1) => {
                put("kind", "closeAccount".into());
                put("account", account(0)?.into());
                put("destination", account(1)?.into());
                put("owner", account(2)?.into());
            }
            (17, 1) => {
                put("kind", "syncNative".into());
                put("account", account(0)?.into());
            }
            _ => return None,
        }
        put("tokenProgram", program.clone().into());
    } else if program == ASSOCIATED_TOKEN {
        let idempotent = match data {
            [] | [0] => false,
            [1] => true,
            _ => return None,
        };
        let (owner, mint, token_program) = (
            *keys.get(*instruction.accounts.get(2)?)?,
            *keys.get(*instruction.accounts.get(3)?)?,
            *keys.get(*instruction.accounts.get(5)?)?,
        );
        put("kind", "createTokenAccount".into());
        put("idempotent", Value::Bool(idempotent));
        put("payer", account(0)?.into());
        put("account", account(1)?.into());
        put("owner", base58(owner).into());
        put("mint", base58(mint).into());
        put("tokenProgram", base58(token_program).into());
        // The account it creates is the one the owner and mint derive:
        // anything else is somebody else's address dressed as the recipient's.
        let derived = associated_token_address(owner, token_program, mint);
        put("derived", Value::Bool(derived.as_ref().map(|d| base58(d)) == account(1)));
    } else if program == COMPUTE_BUDGET {
        match (data.first()?, data.len()) {
            (2, 5) => {
                put("kind", "computeUnitLimit".into());
                put("units", Value::from(u32::from_le_bytes(data[1..5].try_into().expect("four"))));
            }
            (3, 9) => {
                put("kind", "computeUnitPrice".into());
                put("microLamports", u64_at(1)?.to_string().into());
            }
            _ => return None,
        }
    } else if program == MEMO {
        put("kind", "memo".into());
        put("text", std::str::from_utf8(data).map_or(Value::Null, |t| Value::String(t.into())));
    } else {
        return None;
    }
    Some(Value::Object(out))
}

/// The associated token account of [owner] for [mint] under [token_program]:
/// the program address `find_program_address([owner, token_program, mint],
/// associated token program)` gives — the first bump from 255 down whose
/// hash is not a point on the curve.
fn associated_token_address(owner: &[u8], token_program: &[u8], mint: &[u8]) -> Option<[u8; 32]> {
    let program = base58_decode(ASSOCIATED_TOKEN)?;
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        hasher.update(owner);
        hasher.update(token_program);
        hasher.update(mint);
        hasher.update([bump]);
        hasher.update(program);
        hasher.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = hasher.finalize().into();
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Some(candidate);
        }
    }
    None
}

/// A 32-byte address from its base58 — for this file's own constants.
fn base58_decode(text: &str) -> Option<[u8; 32]> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out = [0u8; 32];
    for c in text.bytes() {
        let mut carry = ALPHABET.iter().position(|a| *a == c)? as u32;
        for byte in out.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(out)
}

/// What a reading of [message] is kept under, and a signature held to: its
/// SHA-256.
pub(crate) fn message_id(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}
