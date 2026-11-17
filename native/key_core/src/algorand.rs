//! An Algorand transaction read in the core for its review screen — "the
//! screen shows what the core read" for Algorand, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! An Algorand signature is over `TX` and the transaction's canonical
//! msgpack, the message itself. The core reads the message whole and strictly
//! — canonical as the module's writer writes it, so that the bytes are the
//! only encoding of what they say: every integer and length in its shortest
//! form, every map's keys text in ascending byte order and each once, no map
//! value that canonical encoding omits (a zero, an empty string or byte
//! string, a nil), no float, negative integer, boolean or extension, nothing
//! after the map. It refuses a transaction without a 32-byte sender or a type,
//! and one that hands this account away — a rekey, or a close of the account
//! or of an asset holding — which no transaction of this wallet carries. It
//! returns the transaction's id, whether its genesis is mainnet's, and every
//! field, each value tagged with its kind.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};
use sha2::{Digest, Sha512_256};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// Algorand mainnet's genesis hash (`wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=`).
const MAINNET_GENESIS: [u8; 32] = [
    0xc0, 0x61, 0xc4, 0xd8, 0xfc, 0x1d, 0xbd, 0xde, 0xd2, 0xd7, 0x60, 0x4b, 0xe4, 0x56, 0x8e, 0x3f,
    0x6d, 0x04, 0x19, 0x87, 0xac, 0x37, 0xbd, 0xe4, 0xb6, 0x20, 0xb5, 0xab, 0x39, 0x24, 0x8a, 0xdf,
];

/// Deeper than any transaction nests.
const MAX_DEPTH: usize = 16;

/// One value as canonical msgpack holds it.
enum Item<'a> {
    Uint(u64),
    Text(&'a str),
    Bytes(&'a [u8]),
    Array(Vec<Item<'a>>),
    Map(Vec<(&'a str, Item<'a>)>),
    Nil,
}

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

    fn be(&mut self, n: usize) -> Result<u64, Refusal> {
        Ok(self.take(n)?.iter().fold(0u64, |v, b| v << 8 | u64::from(*b)))
    }

    fn text(&mut self, n: usize) -> Result<&'a str, Refusal> {
        std::str::from_utf8(self.take(n)?).map_err(|_| Refusal::Transaction)
    }

    /// The next value, canonical: [in_array] allows a nil, which a map value
    /// never is.
    fn value(&mut self, depth: usize, in_array: bool) -> Result<Item<'a>, Refusal> {
        if depth > MAX_DEPTH {
            return refused();
        }
        let head = self.byte()?;
        Ok(match head {
            0x00..=0x7f => Item::Uint(u64::from(head)),
            0x80..=0x8f => self.map(usize::from(head & 0x0f), depth)?,
            0x90..=0x9f => self.array(usize::from(head & 0x0f), depth)?,
            0xa0..=0xbf => Item::Text(self.text(usize::from(head & 0x1f))?),
            0xc0 if in_array => Item::Nil,
            0xc4 => {
                let n = usize::from(self.byte()?);
                Item::Bytes(self.take(n)?)
            }
            0xc5 => {
                let n = self.be(2)? as usize;
                if n <= 0xff {
                    return refused();
                }
                Item::Bytes(self.take(n)?)
            }
            0xcc => match self.be(1)? {
                v if v >= 0x80 => Item::Uint(v),
                _ => return refused(),
            },
            0xcd => match self.be(2)? {
                v if v > 0xff => Item::Uint(v),
                _ => return refused(),
            },
            0xce => match self.be(4)? {
                v if v > 0xffff => Item::Uint(v),
                _ => return refused(),
            },
            0xcf => match self.be(8)? {
                v if v > 0xffff_ffff => Item::Uint(v),
                _ => return refused(),
            },
            0xd9 => {
                let n = usize::from(self.byte()?);
                if n < 32 {
                    return refused();
                }
                Item::Text(self.text(n)?)
            }
            0xda => {
                let n = self.be(2)? as usize;
                if n <= 0xff {
                    return refused();
                }
                Item::Text(self.text(n)?)
            }
            0xdc => {
                let n = self.be(2)? as usize;
                if n < 16 {
                    return refused();
                }
                self.array(n, depth)?
            }
            0xde => {
                let n = self.be(2)? as usize;
                if n < 16 {
                    return refused();
                }
                self.map(n, depth)?
            }
            _ => return refused(),
        })
    }

    fn array(&mut self, n: usize, depth: usize) -> Result<Item<'a>, Refusal> {
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(self.value(depth + 1, true)?);
        }
        Ok(Item::Array(items))
    }

    fn map(&mut self, n: usize, depth: usize) -> Result<Item<'a>, Refusal> {
        let mut entries: Vec<(&'a str, Item<'a>)> = Vec::new();
        for _ in 0..n {
            let key = match self.value(depth + 1, false)? {
                Item::Text(key) => key,
                _ => return refused(),
            };
            if entries.last().is_some_and(|(last, _)| last.as_bytes() >= key.as_bytes()) {
                return refused();
            }
            let value = self.value(depth + 1, false)?;
            // What canonical encoding omits is never written.
            let omitted = match &value {
                Item::Uint(0) | Item::Nil => true,
                Item::Text(text) => text.is_empty(),
                Item::Bytes(bytes) => bytes.is_empty(),
                _ => false,
            };
            if omitted {
                return refused();
            }
            entries.push((key, value));
        }
        Ok(Item::Map(entries))
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

/// [item] as the reading writes it: each value tagged with its kind.
fn json(item: &Item<'_>) -> Value {
    let tagged = |tag: &str, value: Value| {
        let mut out = Map::new();
        out.insert(tag.into(), value);
        Value::Object(out)
    };
    match item {
        Item::Uint(v) => tagged("uint", Value::from(v.to_string())),
        Item::Text(t) => tagged("text", Value::from(*t)),
        Item::Bytes(b) => tagged("bytes", Value::from(hex(b))),
        Item::Array(items) => tagged("array", Value::Array(items.iter().map(json).collect())),
        Item::Map(entries) => {
            let mut out = Map::new();
            for (key, value) in entries {
                out.insert((*key).into(), json(value));
            }
            tagged("map", Value::Object(out))
        }
        Item::Nil => Value::Null,
    }
}

/// RFC 4648 base32 without padding, as Algorand writes an id.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = buffer << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// [message] — `TX` and an Algorand transaction's canonical msgpack, which an
/// ed25519 signature on Algorand is over — read for a review screen, or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(message: &[u8]) -> Result<Value, Refusal> {
    let Some(body) = message.strip_prefix(b"TX") else {
        return refused();
    };
    let mut reader = Reader { bytes: body, at: 0 };
    let transaction = reader.value(0, false)?;
    if reader.at != body.len() {
        return refused();
    }
    let Item::Map(entries) = &transaction else {
        return refused();
    };
    let field = |name: &str| entries.iter().find(|(key, _)| *key == name).map(|(_, value)| value);
    if !matches!(field("snd"), Some(Item::Bytes(key)) if key.len() == 32)
        || !matches!(field("type"), Some(Item::Text(_)))
        || ["rekey", "close", "aclose"].iter().any(|grant| field(grant).is_some())
    {
        return refused();
    }
    let mainnet = matches!(field("gh"), Some(Item::Bytes(hash)) if *hash == MAINNET_GENESIS);
    let id: [u8; 32] = Sha512_256::digest(message).into();
    let mut read = Map::new();
    read.insert("id".into(), Value::from(base32(&id)));
    read.insert("mainnet".into(), Value::from(mainnet));
    read.insert("transaction".into(), json(&transaction));
    Ok(Value::Object(read))
}
