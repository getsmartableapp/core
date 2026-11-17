//! A Sui transaction read in the core for its review screen — "the screen
//! shows what the core read" for Sui, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52, O58 and O60).
//!
//! A Sui signature is over BLAKE2b-256 of an intent message: the intent's
//! three bytes — a transaction, version 0, Sui — then the `TransactionData`'s
//! BCS. The core reads the message whole and strictly — every ULEB128 in its
//! shortest form, nothing after the expiry — and refuses what no transaction
//! of this wallet carries: another intent, a kind other than a programmable
//! transaction, and any programme but the transfer the module writes — the
//! amount split off the gas coin and the coin handed to the recipient, both
//! pure inputs — and an expiry. It returns the sender, the recipient, the
//! amount, the gas coins, owner, price and budget, and the transaction's
//! digest as Sui's explorers name it.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{Map, Value};

use crate::Refusal;
use crate::solana::base58;

type Blake2b256 = Blake2b<U32>;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The intent of a transaction to sign: scope 0, version 0, app 0 (Sui).
const INTENT: [u8; 3] = [0, 0, 0];

/// At most this many gas coins: Sui's own limit for one transaction.
const MAX_GAS_COINS: u32 = 256;

/// Bytes read in order, as BCS writes them: little-endian integers, ULEB128
/// lengths and variants, no padding.
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

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Refusal> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two")))
    }

    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight")))
    }

    /// A ULEB128 within 32 bits, in its shortest form, as BCS requires.
    fn uleb(&mut self) -> Result<u32, Refusal> {
        let mut value: u64 = 0;
        for i in 0..5 {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return refused();
                }
                return u32::try_from(value).map_err(|_| Refusal::Transaction);
            }
        }
        refused()
    }

    /// That the next ULEB128 is [expected].
    fn expect(&mut self, expected: u32) -> Result<(), Refusal> {
        if self.uleb()? != expected {
            return refused();
        }
        Ok(())
    }

    /// A pure input of [n] bytes: `CallArg::Pure` and its length.
    fn pure(&mut self, n: u32) -> Result<&'a [u8], Refusal> {
        self.expect(0)?;
        self.expect(n)?;
        self.take(n as usize)
    }

    /// `Argument::Input(index)`.
    fn input(&mut self, index: u16) -> Result<(), Refusal> {
        self.expect(1)?;
        if self.u16()? != index {
            return refused();
        }
        Ok(())
    }
}

/// An address or object id as Sui writes it in full: `0x` and 64 lowercase
/// hex digits.
fn address(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// [message] — a Sui intent message, whose BLAKE2b-256 a Sui signature is
/// over — read for a review screen, or [`Refusal::Transaction`] for one this
/// wallet never signs.
pub(crate) fn reading(message: &[u8]) -> Result<Value, Refusal> {
    let mut reader = Reader { bytes: message, at: 0 };
    if reader.take(3)? != INTENT {
        return refused();
    }
    // TransactionData::V1, TransactionKind::ProgrammableTransaction.
    reader.expect(0)?;
    reader.expect(0)?;
    // Two inputs: the amount, then the recipient, both pure.
    reader.expect(2)?;
    let amount = u64::from_le_bytes(reader.pure(8)?.try_into().expect("eight"));
    let recipient = address(reader.pure(32)?);
    // Two commands: SplitCoins(GasCoin, [Input(0)]), then
    // TransferObjects([NestedResult(0, 0)], Input(1)).
    reader.expect(2)?;
    reader.expect(2)?;
    reader.expect(0)?;
    reader.expect(1)?;
    reader.input(0)?;
    reader.expect(1)?;
    reader.expect(1)?;
    reader.expect(3)?;
    if reader.u16()? != 0 || reader.u16()? != 0 {
        return refused();
    }
    reader.input(1)?;
    let sender = address(reader.take(32)?);
    // GasData: its coins, owner, price and budget.
    let count = reader.uleb()?;
    if count == 0 || count > MAX_GAS_COINS {
        return refused();
    }
    let mut coins = Vec::new();
    for _ in 0..count {
        let id = address(reader.take(32)?);
        let version = reader.u64()?;
        reader.expect(32)?;
        let digest = base58(reader.take(32)?);
        let mut coin = Map::new();
        coin.insert("objectId".into(), Value::from(id));
        coin.insert("version".into(), Value::from(version.to_string()));
        coin.insert("digest".into(), Value::from(digest));
        coins.push(Value::Object(coin));
    }
    let owner = address(reader.take(32)?);
    let price = reader.u64()?;
    let budget = reader.u64()?;
    // TransactionExpiration::None.
    reader.expect(0)?;
    if reader.at != message.len() {
        return refused();
    }
    let mut read = Map::new();
    read.insert("sender".into(), Value::from(sender));
    read.insert("recipient".into(), Value::from(recipient));
    read.insert("amount".into(), Value::from(amount.to_string()));
    read.insert("gasPayment".into(), Value::Array(coins));
    read.insert("gasOwner".into(), Value::from(owner));
    read.insert("gasPrice".into(), Value::from(price.to_string()));
    read.insert("gasBudget".into(), Value::from(budget.to_string()));
    read.insert("transactionDigest".into(), Value::from(base58(&transaction_digest(&message[3..]))));
    Ok(Value::Object(read))
}

/// BLAKE2b-256 of [message], the intent message: the 32 bytes a Sui key
/// signs — kept for a screen given its reading.
pub(crate) fn signing_digest(message: &[u8]) -> [u8; 32] {
    Blake2b256::digest(message).into()
}

/// The transaction's digest, as Sui and its explorers name it: BLAKE2b-256
/// of `TransactionData::` and [data], the transaction's BCS.
fn transaction_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(b"TransactionData::");
    hasher.update(data);
    hasher.finalize().into()
}
