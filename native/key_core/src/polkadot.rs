//! A Polkadot Asset Hub transfer read in the core for its review screen —
//! "the screen shows what the core read" for Polkadot, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! An ed25519 signature on Asset Hub is over the extrinsic's signing payload
//! itself — the call, the extensions it carries and what the runtime adds —
//! where that payload is at most 256 bytes, which this one always is. The
//! core reads it whole and strictly — every compact in its shortest form,
//! nothing after the metadata hash — and refuses what the module never
//! writes: a call other than `Balances.transfer_keep_alive` (pallet 10, call
//! 3) to an account id, an immortal era, an asset paying the fee, a metadata
//! hash. It returns the destination, the amount, the era, the nonce, the tip,
//! the runtime's versions, the genesis and the era's block, and whether the
//! genesis is Asset Hub's.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// Polkadot Asset Hub's genesis hash.
const ASSET_HUB_GENESIS: [u8; 32] = [
    0x68, 0xd5, 0x6f, 0x15, 0xf8, 0x5d, 0x31, 0x36, 0x97, 0x0e, 0xc1, 0x69, 0x46, 0x04, 0x0b, 0xc1,
    0x75, 0x26, 0x54, 0xe9, 0x06, 0x14, 0x7f, 0x7e, 0x43, 0xe9, 0xd5, 0x39, 0xd7, 0xc3, 0xde, 0x2f,
];

/// The Balances pallet on Asset Hub, and its `transfer_keep_alive`.
const BALANCES: u8 = 10;
const TRANSFER_KEEP_ALIVE: u8 = 3;

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

    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four")))
    }

    /// A SCALE compact integer of at most [max_bytes] bytes, in its shortest
    /// form.
    fn compact(&mut self, max_bytes: usize) -> Result<u128, Refusal> {
        let first = self.u8()?;
        let value = match first & 0b11 {
            0b00 => u128::from(first >> 2),
            0b01 => {
                let v = u128::from(u16::from_le_bytes([first, self.u8()?]) >> 2);
                if v < 1 << 6 {
                    return refused();
                }
                v
            }
            0b10 => {
                let rest = self.take(3)?;
                let v = u128::from(u32::from_le_bytes([first, rest[0], rest[1], rest[2]]) >> 2);
                if v < 1 << 14 {
                    return refused();
                }
                v
            }
            _ => {
                let n = usize::from(first >> 2) + 4;
                if n > max_bytes {
                    return refused();
                }
                let bytes = self.take(n)?;
                if bytes[n - 1] == 0 {
                    return refused();
                }
                let v = bytes.iter().rev().fold(0u128, |v, b| v << 8 | u128::from(*b));
                if v < 1 << 30 {
                    return refused();
                }
                v
            }
        };
        Ok(value)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// [payload] — an Asset Hub extrinsic's signing payload, which an ed25519
/// signature on Polkadot is over — read for a review screen for the key
/// whose public half is [signer], which alone may sign it; or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(payload: &[u8], signer: &[u8; 32]) -> Result<Value, Refusal> {
    let mut r = Reader { bytes: payload, at: 0 };
    if r.u8()? != BALANCES || r.u8()? != TRANSFER_KEEP_ALIVE {
        return refused();
    }
    // `MultiAddress::Id`.
    if r.u8()? != 0 {
        return refused();
    }
    let dest = hex(r.take(32)?);
    let amount = r.compact(16)?;
    // A mortal era: its period a power of two from 4 to 65,536, its phase
    // inside it.
    let era = u16::from_le_bytes(r.take(2)?.try_into().expect("two"));
    let shift = u32::from(era & 0xf);
    if era & 0xff == 0 || shift == 0 {
        return refused();
    }
    let period: u64 = 2 << shift;
    let quantize = (period >> 12).max(1);
    let phase = u64::from(era >> 4) * quantize;
    if phase >= period {
        return refused();
    }
    let nonce = r.compact(4)?;
    if nonce > u128::from(u32::MAX) {
        return refused();
    }
    let tip = r.compact(16)?;
    // No asset pays the fee; the metadata hash's mode is off.
    if r.u8()? != 0 || r.u8()? != 0 {
        return refused();
    }
    let spec = r.u32()?;
    let transaction = r.u32()?;
    let genesis = r.take(32)?;
    let block = hex(r.take(32)?);
    // No metadata hash.
    if r.u8()? != 0 || r.at != payload.len() {
        return refused();
    }
    let mut era_read = Map::new();
    era_read.insert("period".into(), Value::from(period.to_string()));
    era_read.insert("phase".into(), Value::from(phase.to_string()));
    let mut read = Map::new();
    read.insert("signer".into(), Value::from(hex(signer)));
    read.insert("call".into(), Value::from("Balances.transfer_keep_alive"));
    read.insert("dest".into(), Value::from(dest));
    read.insert("amount".into(), Value::from(amount.to_string()));
    read.insert("era".into(), Value::Object(era_read));
    read.insert("nonce".into(), Value::from(nonce.to_string()));
    read.insert("tip".into(), Value::from(tip.to_string()));
    read.insert("specVersion".into(), Value::from(spec.to_string()));
    read.insert("transactionVersion".into(), Value::from(transaction.to_string()));
    read.insert("genesisHash".into(), Value::from(hex(genesis)));
    read.insert("blockHash".into(), Value::from(block));
    read.insert("assetHub".into(), Value::from(genesis == ASSET_HUB_GENESIS));
    Ok(Value::Object(read))
}
