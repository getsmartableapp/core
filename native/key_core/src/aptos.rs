//! An Aptos or Movement transaction read in the core for its review screen —
//! "the screen shows what the core read" for the Move networks, after step 2f
//! of `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! An Aptos signature is over the signing message itself: SHA3-256 of
//! `APTOS::RawTransaction`, then the `RawTransaction`'s BCS. Movement runs the
//! same framework and signs the same message; the chain id inside tells them
//! apart. The core reads the message whole and strictly — every ULEB128 in its
//! shortest form, nothing after the chain id — and refuses what no
//! transaction of this wallet carries: another domain (a multi-agent or
//! fee-payer transaction), a payload other than an entry function, and an
//! entry function other than `0x1::aptos_account::transfer` with no type
//! arguments and its two arguments, an address and a `u64`. It returns the
//! sender, the sequence number, the function, the recipient, the amount, the
//! gas ceiling and price, the expiry and the chain.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};
use sha3::{Digest, Sha3_256};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The domain a `RawTransaction`'s signing message begins with.
const DOMAIN: &[u8] = b"APTOS::RawTransaction";

/// `TransactionPayload::EntryFunction`, by its variant index.
const ENTRY_FUNCTION: u32 = 2;

/// Bytes read in order, as BCS writes them: little-endian integers, ULEB128
/// lengths, no padding.
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

    /// An `Identifier`: a ULEB128 length and that many bytes.
    fn identifier(&mut self) -> Result<&'a [u8], Refusal> {
        let n = usize::try_from(self.uleb()?).map_err(|_| Refusal::Transaction)?;
        self.take(n)
    }
}

/// An address as Aptos writes it in full: `0x` and 64 lowercase hex digits.
fn address(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// [message] — an Aptos `RawTransaction`'s signing message, which an
/// ed25519 signature on Aptos and Movement is over — read for a review
/// screen, or [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(message: &[u8]) -> Result<Value, Refusal> {
    let mut reader = Reader { bytes: message, at: 0 };
    let domain: [u8; 32] = Sha3_256::digest(DOMAIN).into();
    if reader.take(32)? != domain {
        return refused();
    }
    let sender = address(reader.take(32)?);
    let sequence = reader.u64()?;
    if reader.uleb()? != ENTRY_FUNCTION {
        return refused();
    }
    let mut framework = [0u8; 32];
    framework[31] = 1;
    if reader.take(32)? != framework
        || reader.identifier()? != b"aptos_account"
        || reader.identifier()? != b"transfer"
    {
        return refused();
    }
    // No type arguments; two arguments, each its BCS behind a length.
    if reader.uleb()? != 0 || reader.uleb()? != 2 {
        return refused();
    }
    if reader.uleb()? != 32 {
        return refused();
    }
    let recipient = address(reader.take(32)?);
    if reader.uleb()? != 8 {
        return refused();
    }
    let amount = reader.u64()?;
    let max_gas = reader.u64()?;
    let gas_price = reader.u64()?;
    let expiration = reader.u64()?;
    let chain = reader.u8()?;
    if reader.at != message.len() {
        return refused();
    }
    let mut read = Map::new();
    read.insert("sender".into(), Value::from(sender));
    read.insert("sequenceNumber".into(), Value::from(sequence.to_string()));
    read.insert("function".into(), Value::from("0x1::aptos_account::transfer"));
    read.insert("recipient".into(), Value::from(recipient));
    read.insert("amount".into(), Value::from(amount.to_string()));
    read.insert("maxGasAmount".into(), Value::from(max_gas.to_string()));
    read.insert("gasUnitPrice".into(), Value::from(gas_price.to_string()));
    read.insert("expirationTimestampSecs".into(), Value::from(expiration.to_string()));
    read.insert("chainId".into(), Value::from(chain));
    Ok(Value::Object(read))
}
