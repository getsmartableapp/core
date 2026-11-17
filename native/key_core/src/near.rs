//! A NEAR transaction read in the core for its review screen — "the screen
//! shows what the core read" for NEAR, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! A NEAR signature is over the SHA-256 of a transaction's Borsh bytes, and
//! that hash is the transaction's id. The core reads the bytes whole and
//! strictly — nothing after the last action — and refuses what no transaction
//! of this wallet carries: an account id NEAR would not take, a key other than
//! an ed25519 one, no action, or an action other than a transfer of NEAR. It
//! returns the signer, its key, the nonce, the receiver, the block, every
//! transfer's deposit and the transaction's hash.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading or a digest.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::solana::base58;
use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// NEAR's `Action` variant for a transfer: its index, the whole of its tag.
const TRANSFER: u8 = 3;

/// At most this many actions: NEAR's own limit for one receipt.
const MAX_ACTIONS: u32 = 100;

/// Bytes read in order, as Borsh writes them: little-endian, no tags, no
/// padding.
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

    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight")))
    }

    fn u128(&mut self) -> Result<u128, Refusal> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().expect("sixteen")))
    }

    /// An `AccountId`: a Borsh string NEAR would take as one.
    fn account_id(&mut self) -> Result<String, Refusal> {
        let n = usize::try_from(self.u32()?).map_err(|_| Refusal::Transaction)?;
        if !(2..=64).contains(&n) {
            return refused();
        }
        let text = std::str::from_utf8(self.take(n)?).map_err(|_| Refusal::Transaction)?;
        if !is_account_id(text) {
            return refused();
        }
        Ok(text.to_owned())
    }
}

/// NEAR's account id rule, as the module's `NearAccountId.isValid` writes it:
/// parts between dots, each of lowercase letters and digits, joined by single
/// `-` or `_`, beginning and ending with a letter or a digit. Its length is
/// checked by the caller.
fn is_account_id(text: &str) -> bool {
    text.split('.').all(|part| {
        let bytes = part.as_bytes();
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        !bytes.is_empty()
            && alnum(bytes[0])
            && alnum(bytes[bytes.len() - 1])
            && bytes.iter().all(|b| alnum(*b) || *b == b'-' || *b == b'_')
            && bytes.windows(2).all(|w| alnum(w[0]) || alnum(w[1]))
    })
}

/// [transaction] — a NEAR `Transaction`'s Borsh bytes, whose SHA-256 a NEAR
/// signature is over — read for a review screen, or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(transaction: &[u8]) -> Result<Value, Refusal> {
    let mut reader = Reader { bytes: transaction, at: 0 };
    let signer = reader.account_id()?;
    // `PublicKey`: its type, 0 for ed25519, then the key.
    if reader.u8()? != 0 {
        return refused();
    }
    let key = reader.take(32)?;
    let nonce = reader.u64()?;
    let receiver = reader.account_id()?;
    let block = reader.take(32)?;
    let count = reader.u32()?;
    if count == 0 || count > MAX_ACTIONS {
        return refused();
    }
    let mut actions = Vec::new();
    for _ in 0..count {
        if reader.u8()? != TRANSFER {
            return refused();
        }
        let mut action = Map::new();
        action.insert("type".into(), Value::from("transfer"));
        action.insert("deposit".into(), Value::from(reader.u128()?.to_string()));
        actions.push(Value::Object(action));
    }
    if reader.at != transaction.len() {
        return refused();
    }
    let mut read = Map::new();
    read.insert("signerId".into(), Value::from(signer));
    read.insert("publicKey".into(), Value::from(format!("ed25519:{}", base58(key))));
    read.insert("nonce".into(), Value::from(nonce.to_string()));
    read.insert("receiverId".into(), Value::from(receiver));
    read.insert("blockHash".into(), Value::from(base58(block)));
    read.insert("actions".into(), Value::Array(actions));
    read.insert("hash".into(), Value::from(base58(&transaction_hash(transaction))));
    Ok(Value::Object(read))
}

/// The SHA-256 of [transaction]: its id, and the 32 bytes a NEAR key signs —
/// kept for a screen given its reading.
pub(crate) fn transaction_hash(transaction: &[u8]) -> [u8; 32] {
    Sha256::digest(transaction).into()
}
