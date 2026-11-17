//! A TON transfer read in the core for its review screen — "the screen shows
//! what the core read" for TON, after step 2f of `docs/RUST_KEY_CORE_DESIGN.md`
//! (the owner's decisions O52 and O58).
//!
//! A wallet v4R2 signature is over the representation hash of its signing
//! message: a cell holding the subwallet, the expiry (`valid_until`), the seqno,
//! the opcode 0 and, for each of up to four outgoing messages, its send mode and
//! a reference to the message. The module hands that cell over as a bag of
//! cells (BOC); the core parses the bag strictly — one root, nothing absent, no
//! exotic cell, no level, every completion tag canonical, references only
//! forward, every cell reached, its CRC32C right where it carries one — takes
//! the root's hash itself and reads what the module writes: a message with
//! `ihr_disabled`, from no address, to a standard address, carrying coins and
//! no extra currency, no fees, no time, no state init, and a body that is
//! nothing, a text comment, or a TEP-74 jetton `transfer` whose forward payload
//! is nothing, a comment or a STON.fi v1 `swap`. Anything else is refused.
//!
//! It returns the wallet's subwallet, expiry and seqno, every message — its
//! mode, bounce flag, destination, value and body as read — and the hash.
//!
//! **Nothing secret passes through this file**: it reads before any key is
//! asked, and what it returns is a reading.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// A bag of cells' magic.
const BOC_MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// The most cells, and bytes, a transfer's bag is read with.
const MAX_CELLS: usize = 128;
const MAX_BYTES: usize = 16 * 1024;

/// A text comment's opcode, a jetton's `transfer` (TEP-74), STON.fi router
/// v1's `swap`.
const COMMENT: u64 = 0;
const JETTON_TRANSFER: u64 = 0x0f8a_7ea5;
const STONFI_SWAP: u64 = 0x2593_8561;

/// One ordinary cell: its data as serialised — the completion tag included
/// where its bits do not fill the last byte — how many bits that is, its
/// descriptor's second byte, and its references.
struct Cell {
    data: Vec<u8>,
    bits: usize,
    d2: u8,
    refs: Vec<usize>,
}

impl Cell {
    fn bit(&self, at: usize) -> bool {
        self.data[at / 8] & (0x80 >> (at % 8)) != 0
    }
}

/// CRC32C (Castagnoli), as a bag of cells is checked with.
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

struct Bytes<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(n).ok_or(Refusal::Transaction)?;
        let taken = self.bytes.get(self.at..end).ok_or(Refusal::Transaction)?;
        self.at = end;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    /// A big-endian unsigned number of [n] bytes, at most eight.
    fn uint(&mut self, n: usize) -> Result<usize, Refusal> {
        let mut v: u64 = 0;
        for b in self.take(n)? {
            v = v << 8 | u64::from(*b);
        }
        usize::try_from(v).map_err(|_| Refusal::Transaction)
    }
}

/// [boc] parsed: its cells in the order serialised, the root first.
fn parse(boc: &[u8]) -> Result<Vec<Cell>, Refusal> {
    if boc.len() > MAX_BYTES {
        return refused();
    }
    let mut r = Bytes { bytes: boc, at: 0 };
    if r.take(4)? != BOC_MAGIC {
        return refused();
    }
    let flags = r.u8()?;
    let has_index = flags & 0x80 != 0;
    let has_crc = flags & 0x40 != 0;
    let size = usize::from(flags & 0x07);
    // No cache bits, the two reserved flags clear, a reference of 1 to 4 bytes.
    if flags & 0x38 != 0 || !(1..=4).contains(&size) {
        return refused();
    }
    let offset = usize::from(r.u8()?);
    if !(1..=8).contains(&offset) {
        return refused();
    }
    let count = r.uint(size)?;
    let roots = r.uint(size)?;
    let absent = r.uint(size)?;
    let total = r.uint(offset)?;
    if count == 0 || count > MAX_CELLS || roots != 1 || absent != 0 {
        return refused();
    }
    if r.uint(size)? != 0 {
        return refused();
    }
    let mut index = Vec::new();
    if has_index {
        for _ in 0..count {
            index.push(r.uint(offset)?);
        }
    }
    let start = r.at;
    let mut cells = Vec::with_capacity(count);
    for i in 0..count {
        let d1 = r.u8()?;
        let d2 = r.u8()?;
        // Ordinary, level 0, no stored hashes, at most four references.
        let refs = usize::from(d1 & 0x07);
        if d1 & 0xf8 != 0 || refs > 4 {
            return refused();
        }
        let length = usize::from(d2).div_ceil(2);
        let data = r.take(length)?.to_vec();
        let bits = if d2 % 2 == 0 {
            8 * length
        } else {
            // The completion tag: a 1 and then zeros, after at least one bit.
            let last = data[length - 1];
            let zeros = last.trailing_zeros() as usize;
            if last == 0 || zeros == 7 {
                return refused();
            }
            8 * (length - 1) + 7 - zeros
        };
        let mut children = Vec::with_capacity(refs);
        for _ in 0..refs {
            let child = r.uint(size)?;
            // Only forward, as a bag is written in topological order.
            if child <= i || child >= count {
                return refused();
            }
            children.push(child);
        }
        if has_index && index[i] != r.at - start {
            return refused();
        }
        cells.push(Cell { data, bits, d2, refs: children });
    }
    if r.at - start != total {
        return refused();
    }
    if has_crc {
        let sum = r.take(4)?;
        if u32::from_le_bytes(sum.try_into().expect("four")) != crc32c(&boc[..r.at - 4]) {
            return refused();
        }
    }
    if r.at != boc.len() {
        return refused();
    }
    // Every cell reached from the root.
    let mut reached = vec![false; count];
    reached[0] = true;
    for i in 0..count {
        if reached[i] {
            for child in &cells[i].refs {
                reached[*child] = true;
            }
        }
    }
    if reached.contains(&false) {
        return refused();
    }
    Ok(cells)
}

/// Every cell's representation hash and depth, from the leaves up: the
/// descriptors, the data, each reference's depth and then each one's hash.
fn hashes(cells: &[Cell]) -> Vec<[u8; 32]> {
    let mut hash = vec![[0u8; 32]; cells.len()];
    let mut depth = vec![0u16; cells.len()];
    for i in (0..cells.len()).rev() {
        let cell = &cells[i];
        let mut h = Sha256::new();
        h.update([cell.refs.len() as u8, cell.d2]);
        h.update(&cell.data);
        for child in &cell.refs {
            h.update(depth[*child].to_be_bytes());
        }
        for child in &cell.refs {
            h.update(hash[*child]);
        }
        hash[i] = h.finalize().into();
        depth[i] = cell.refs.iter().map(|c| depth[*c] + 1).max().unwrap_or(0);
    }
    hash
}

/// A read position in one cell.
struct Slice<'a> {
    cells: &'a [Cell],
    cell: usize,
    bit: usize,
    reference: usize,
}

impl<'a> Slice<'a> {
    fn of(cells: &'a [Cell], cell: usize) -> Self {
        Slice { cells, cell, bit: 0, reference: 0 }
    }

    fn here(&self) -> &'a Cell {
        &self.cells[self.cell]
    }

    fn bits_left(&self) -> usize {
        self.here().bits - self.bit
    }

    fn refs_left(&self) -> usize {
        self.here().refs.len() - self.reference
    }

    fn at_end(&self) -> bool {
        self.bits_left() == 0 && self.refs_left() == 0
    }

    fn bit(&mut self) -> Result<bool, Refusal> {
        if self.bits_left() == 0 {
            return refused();
        }
        let b = self.here().bit(self.bit);
        self.bit += 1;
        Ok(b)
    }

    /// An unsigned number of [n] bits, at most 128.
    fn uint(&mut self, n: usize) -> Result<u128, Refusal> {
        if self.bits_left() < n {
            return refused();
        }
        let mut v = 0u128;
        for _ in 0..n {
            v = v << 1 | u128::from(self.bit()?);
        }
        Ok(v)
    }

    fn reference(&mut self) -> Result<usize, Refusal> {
        let child = *self.here().refs.get(self.reference).ok_or(Refusal::Transaction)?;
        self.reference += 1;
        Ok(child)
    }

    /// `Coins` — a `VarUInteger 16`: four bits of length, then that many
    /// bytes, in its shortest form.
    fn coins(&mut self) -> Result<u128, Refusal> {
        let length = self.uint(4)? as usize;
        let value = self.uint(8 * length)?;
        if length > 0 && value >> (8 * (length - 1)) == 0 {
            return refused();
        }
        Ok(value)
    }

    /// `addr_std$10`, with no anycast: `workchain:hex`.
    fn address(&mut self) -> Result<String, Refusal> {
        if self.uint(2)? != 0b10 || self.bit()? {
            return refused();
        }
        let workchain = self.uint(8)? as u8 as i8;
        let mut account = String::with_capacity(64);
        for _ in 0..32 {
            account.push_str(&format!("{:02x}", self.uint(8)?));
        }
        Ok(format!("{workchain}:{account}"))
    }

    /// `addr_none$00` or an `addr_std`.
    fn address_or_none(&mut self) -> Result<Option<String>, Refusal> {
        if self.bits_left() >= 2 && !self.here().bit(self.bit) && !self.here().bit(self.bit + 1) {
            self.bit += 2;
            return Ok(None);
        }
        self.address().map(Some)
    }
}

fn number(v: u128) -> Value {
    Value::from(v.to_string())
}

/// A text comment's text after its opcode: whole bytes, on through one
/// reference at a time, never an empty cell, and UTF-8.
fn comment_text(mut s: Slice) -> Result<String, Refusal> {
    let mut text = Vec::new();
    loop {
        let bits = s.bits_left();
        if bits == 0 || bits % 8 != 0 || s.refs_left() > 1 {
            return refused();
        }
        for _ in 0..bits / 8 {
            text.push(s.uint(8)? as u8);
        }
        if s.refs_left() == 0 {
            break;
        }
        s = Slice::of(s.cells, s.reference()?);
    }
    String::from_utf8(text).map_err(|_| Refusal::Transaction)
}

/// A jetton transfer's forward payload, the cell it refers to: a comment or
/// STON.fi v1's `swap`.
fn forward_payload(cells: &[Cell], cell: usize) -> Result<Value, Refusal> {
    let mut s = Slice::of(cells, cell);
    let mut read = Map::new();
    match s.uint(32)? as u64 {
        COMMENT => {
            read.insert("kind".into(), Value::from("comment"));
            read.insert("text".into(), Value::from(comment_text(s)?));
        }
        STONFI_SWAP => {
            read.insert("kind".into(), Value::from("stonfiSwap"));
            read.insert("askJettonWallet".into(), Value::from(s.address()?));
            read.insert("minAsk".into(), number(s.coins()?));
            read.insert("receiver".into(), Value::from(s.address()?));
            let referral = if s.bit()? { Value::from(s.address()?) } else { Value::Null };
            read.insert("referral".into(), referral);
            if !s.at_end() {
                return refused();
            }
        }
        _ => return refused(),
    }
    Ok(Value::Object(read))
}

/// A message's body: nothing, a comment or a jetton's `transfer`.
fn body(mut s: Slice) -> Result<Value, Refusal> {
    let mut read = Map::new();
    if s.at_end() {
        read.insert("kind".into(), Value::from("none"));
        return Ok(Value::Object(read));
    }
    match s.uint(32)? as u64 {
        COMMENT => {
            read.insert("kind".into(), Value::from("comment"));
            read.insert("text".into(), Value::from(comment_text(s)?));
        }
        JETTON_TRANSFER => {
            read.insert("kind".into(), Value::from("jettonTransfer"));
            read.insert("queryId".into(), number(s.uint(64)?));
            read.insert("amount".into(), number(s.coins()?));
            read.insert("destination".into(), Value::from(s.address()?));
            read.insert(
                "responseDestination".into(),
                s.address_or_none()?.map_or(Value::Null, Value::from),
            );
            // No custom payload.
            if s.bit()? {
                return refused();
            }
            read.insert("forwardTonAmount".into(), number(s.coins()?));
            let forward = if s.bit()? {
                let cell = s.reference()?;
                forward_payload(s.cells, cell)?
            } else {
                Value::Null
            };
            if !s.at_end() {
                return refused();
            }
            read.insert("forwardPayload".into(), forward);
        }
        _ => return refused(),
    }
    Ok(Value::Object(read))
}

/// One outgoing message, as `TonHelper.internal` writes it.
fn message(cells: &[Cell], cell: usize, mode: u128) -> Result<Value, Refusal> {
    let mut s = Slice::of(cells, cell);
    // `int_msg_info$0`, `ihr_disabled`, the bounce flag, not `bounced`.
    if s.bit()? || !s.bit()? {
        return refused();
    }
    let bounce = s.bit()?;
    if s.bit()? {
        return refused();
    }
    // From no address: the wallet's own is the network's to fill.
    if s.address_or_none()?.is_some() {
        return refused();
    }
    let destination = s.address()?;
    let value = s.coins()?;
    // No extra currency, no fees, no logical time or creation time, no state
    // init.
    if s.bit()?
        || s.coins()? != 0
        || s.coins()? != 0
        || s.uint(64)? != 0
        || s.uint(32)? != 0
        || s.bit()?
    {
        return refused();
    }
    let read_body = if s.bit()? {
        let child = s.reference()?;
        if !s.at_end() {
            return refused();
        }
        body(Slice::of(cells, child))?
    } else {
        body(s)?
    };
    let mut read = Map::new();
    read.insert("mode".into(), number(mode));
    read.insert("bounce".into(), Value::from(bounce));
    read.insert("destination".into(), Value::from(destination));
    read.insert("value".into(), number(value));
    read.insert("body".into(), read_body);
    Ok(Value::Object(read))
}

/// [boc] — a wallet v4R2 signing message as a bag of cells, whose root's hash
/// a TON signature is over — read for a review screen for the key whose
/// public half is [public_key], which alone may sign it, with that hash; or
/// [`Refusal::Transaction`] for one this wallet never signs.
pub(crate) fn reading(boc: &[u8], public_key: &[u8; 32]) -> Result<(Value, [u8; 32]), Refusal> {
    let cells = parse(boc)?;
    let hash = hashes(&cells)[0];
    let mut s = Slice::of(&cells, 0);
    let subwallet = s.uint(32)?;
    let valid_until = s.uint(32)?;
    let seqno = s.uint(32)?;
    // v4R2's opcode for a plain send.
    if s.uint(8)? != 0 {
        return refused();
    }
    let count = s.refs_left();
    if count == 0 || count > 4 || s.bits_left() != 8 * count {
        return refused();
    }
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let mode = s.uint(8)?;
        let cell = s.reference()?;
        messages.push(message(&cells, cell, mode)?);
    }
    let mut read = Map::new();
    read.insert("wallet".into(), Value::from("v4R2"));
    read.insert(
        "publicKey".into(),
        Value::from(format!("0x{}", public_key.iter().map(|b| format!("{b:02x}")).collect::<String>())),
    );
    read.insert("subwalletId".into(), number(subwallet));
    read.insert("validUntil".into(), number(valid_until));
    read.insert("seqno".into(), number(seqno));
    read.insert("messages".into(), Value::from(messages));
    read.insert("hash".into(), Value::from(format!("0x{}", hash.iter().map(|b| format!("{b:02x}")).collect::<String>())));
    Ok((Value::Object(read), hash))
}
