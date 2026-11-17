//! An EVM transaction's call data read for the review screen — "the screen
//! shows what the core read", step 2f-1 of `docs/RUST_KEY_CORE_DESIGN.md`
//! (the owner's decisions O49–O51).
//!
//! **The app's `lib/core/calldata.dart`, rule for rule**, which is the oracle:
//! the calls that can empty a wallet — approvals and their revocations, an
//! operator's approval, an allowance's increase, transfers — and the wrappers
//! that carry other calls, each read only as far as it is certain. What is
//! read is returned as facts; the sentences a person reads are the app's,
//! written from these facts.
//!
//! **The same five answers as the app** (`CalldataReading`): no call data, a
//! call decoded, a nesting not followed past [`MAX_DEPTH`], a selector there
//! is no ABI for, and bytes that contradict their own encoding. The app reads
//! hex and so also calls half a byte or a non-hex digit malformed; the core is
//! handed bytes, where neither can occur.
//!
//! **Nothing secret passes through this file.**

/// How deep a wrapper is followed before reading stops (`_maxDepth`).
pub(crate) const MAX_DEPTH: usize = 3;
/// A batch claiming more calls than this is not read (`_maxChildren`).
pub(crate) const MAX_CHILDREN: usize = 32;

/// How far a piece of call data could be believed (`CalldataReading`), in
/// the app's order, which is its severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    None,
    Decoded,
    TooDeep,
    Unknown,
    Malformed,
}

/// Which recognised call it is (`CalldataKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Approve,
    Revoke,
    ApproveAll,
    RevokeAll,
    IncreaseAllowance,
    Transfer,
    TransferFrom,
    Batch,
}

/// A decoded call: what it is, and the facts the app's summary is made of.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) kind: Kind,
    /// Who is granted power, for the approval kinds.
    pub(crate) spender: Option<[u8; 20]>,
    /// Where value goes, for the transfer kinds.
    pub(crate) recipient: Option<[u8; 20]>,
    /// Whose tokens `transferFrom` moves.
    pub(crate) from: Option<[u8; 20]>,
    /// The amount in base units, big-endian, where the call names one.
    pub(crate) amount: Option<[u8; 32]>,
    /// A blanket permission rather than a figure: at or above 2^128, or
    /// `setApprovalForAll(…, true)`.
    pub(crate) unlimited: bool,
    /// The calls that hand over control rather than move a stated amount; for
    /// a batch, whether any call it carries does.
    pub(crate) grants: bool,
    /// The calls a batch carries, in its order, the unreadable ones kept.
    pub(crate) children: Vec<Child>,
}

/// One call inside a batch (`DecodedChild`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Child {
    pub(crate) reading: Reading,
    pub(crate) call: Option<Call>,
    /// The contract it runs against, when the wrapper names one; none means
    /// the transaction's own recipient.
    pub(crate) target: Option<[u8; 20]>,
    /// Its own first four bytes, when it has four.
    pub(crate) selector: Option<[u8; 4]>,
}

impl Call {
    /// Whether anything below contradicts its own encoding
    /// (`hasMalformedChild`): only malformed climbs.
    fn has_malformed_child(&self) -> bool {
        self.children.iter().any(|c| {
            c.reading == Reading::Malformed || c.call.as_ref().is_some_and(Call::has_malformed_child)
        })
    }

    fn leaf(kind: Kind) -> Self {
        Self {
            kind,
            spender: None,
            recipient: None,
            from: None,
            amount: None,
            unlimited: false,
            grants: false,
            children: Vec::new(),
        }
    }
}

/// The selectors [`parse`] understands (`_known`).
const KNOWN: [[u8; 4]; 11] = [
    [0x09, 0x5e, 0xa7, 0xb3], // approve(address,uint256)
    [0xa2, 0x2c, 0xb4, 0x65], // setApprovalForAll(address,bool)
    [0x39, 0x50, 0x93, 0x51], // increaseAllowance(address,uint256)
    [0xa9, 0x05, 0x9c, 0xbb], // transfer(address,uint256)
    [0x23, 0xb8, 0x72, 0xdd], // transferFrom(address,address,uint256)
    [0xac, 0x96, 0x50, 0xd8], // multicall(bytes[])
    [0x5a, 0xe4, 0x01, 0xdc], // multicall(uint256,bytes[])
    [0x1f, 0x04, 0x64, 0xd1], // multicall(bytes32,bytes[])
    [0x25, 0x2d, 0xba, 0x42], // aggregate((address,bytes)[])
    [0x82, 0xad, 0x56, 0xcb], // aggregate3((address,bool,bytes)[])
    [0xbc, 0xe3, 0x8b, 0xd7], // tryAggregate(bool,(address,bytes)[])
];

/// [data] read at [depth] (`_read`): how far it could be believed, and the
/// call it decoded to.
pub(crate) fn read(data: &[u8], depth: usize) -> (Reading, Option<Call>) {
    if data.is_empty() {
        return (Reading::None, None);
    }
    if data.len() < 4 {
        return (Reading::Malformed, None);
    }
    if depth >= MAX_DEPTH {
        return (Reading::TooDeep, None);
    }
    if let Some(call) = parse(data, depth) {
        let reading = if call.has_malformed_child() { Reading::Malformed } else { Reading::Decoded };
        return (reading, Some(call));
    }
    let selector: [u8; 4] = data[..4].try_into().expect("four bytes");
    if KNOWN.contains(&selector) { (Reading::Malformed, None) } else { (Reading::Unknown, None) }
}

fn parse(data: &[u8], depth: usize) -> Option<Call> {
    let args = &data[4..];
    match data[..4] {
        // approve(address spender, uint256 amount)
        [0x09, 0x5e, 0xa7, 0xb3] => {
            let (spender, amount) = (address(args, 0)?, word(args, 32)?);
            if is_zero(amount) {
                return Some(Call {
                    spender: Some(spender),
                    amount: Some(*amount),
                    ..Call::leaf(Kind::Revoke)
                });
            }
            Some(Call {
                spender: Some(spender),
                amount: Some(*amount),
                unlimited: is_unlimited(amount),
                grants: true,
                ..Call::leaf(Kind::Approve)
            })
        }
        // setApprovalForAll(address operator, bool approved)
        [0xa2, 0x2c, 0xb4, 0x65] => {
            let (operator, approved) = (address(args, 0)?, boolean(args, 32)?);
            Some(if approved {
                Call { spender: Some(operator), unlimited: true, grants: true, ..Call::leaf(Kind::ApproveAll) }
            } else {
                Call { spender: Some(operator), ..Call::leaf(Kind::RevokeAll) }
            })
        }
        // increaseAllowance(address spender, uint256 addedValue)
        [0x39, 0x50, 0x93, 0x51] => {
            let (spender, added) = (address(args, 0)?, word(args, 32)?);
            Some(Call {
                spender: Some(spender),
                amount: Some(*added),
                unlimited: is_unlimited(added),
                grants: true,
                ..Call::leaf(Kind::IncreaseAllowance)
            })
        }
        // transfer(address to, uint256 amount)
        [0xa9, 0x05, 0x9c, 0xbb] => {
            let (to, amount) = (address(args, 0)?, word(args, 32)?);
            Some(Call { recipient: Some(to), amount: Some(*amount), ..Call::leaf(Kind::Transfer) })
        }
        // transferFrom(address from, address to, uint256 amount)
        [0x23, 0xb8, 0x72, 0xdd] => {
            let (from, to, amount) = (address(args, 0)?, address(args, 32)?, word(args, 64)?);
            Some(Call {
                recipient: Some(to),
                from: Some(from),
                amount: Some(*amount),
                ..Call::leaf(Kind::TransferFrom)
            })
        }
        // Uniswap's router family: the calls run on this same contract.
        // multicall(bytes[])
        [0xac, 0x96, 0x50, 0xd8] => batch(bytes_array(args, 0)?, depth),
        // multicall(uint256 deadline, bytes[]), multicall(bytes32, bytes[])
        [0x5a, 0xe4, 0x01, 0xdc] | [0x1f, 0x04, 0x64, 0xd1] => batch(bytes_array(args, 1)?, depth),
        // Multicall3, whose entries each name their own target.
        // aggregate((address,bytes)[])
        [0x25, 0x2d, 0xba, 0x42] => batch(call_array(args, 0, false)?, depth),
        // aggregate3((address,bool,bytes)[])
        [0x82, 0xad, 0x56, 0xcb] => batch(call_array(args, 0, true)?, depth),
        // tryAggregate(bool requireSuccess, (address,bytes)[])
        [0xbc, 0xe3, 0x8b, 0xd7] => {
            boolean(args, 0)?;
            batch(call_array(args, 1, false)?, depth)
        }
        // Universal Router's `execute` stays unread, as in the app: its
        // `bytes[]` carries command payloads, not calls.
        _ => None,
    }
}

/// A wrapper and the calls it carries (`_batch` and `_batchOf`).
fn batch(calls: Vec<(&[u8], Option<[u8; 20]>)>, depth: usize) -> Option<Call> {
    let children: Vec<Child> = calls
        .into_iter()
        .map(|(body, target)| {
            let (reading, call) = read(body, depth + 1);
            let selector = body.get(..4).map(|s| s.try_into().expect("four bytes"));
            Child { reading, call, target, selector }
        })
        .collect();
    let grants = children.iter().any(|c| c.call.as_ref().is_some_and(|call| call.grants));
    Some(Call { grants, children, ..Call::leaf(Kind::Batch) })
}

/// An ABI `bytes[]` whose offset sits in head word [head] (`_bytesArray`).
fn bytes_array(args: &[u8], head: usize) -> Option<Vec<(&[u8], Option<[u8; 20]>)>> {
    let base = offset(args, head * 32)?;
    let count = length(args, base)?;
    if count > MAX_CHILDREN {
        return None;
    }
    // Element offsets are measured from just after the count word.
    let from = base + 32;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let rel = offset(args, from + i * 32)?;
        out.push((bytes_at(args, from + rel)?, None));
    }
    Some(out)
}

/// An ABI array of `(address, bytes)` or `(address, bool, bytes)` tuples
/// (`_callArray`).
fn call_array(args: &[u8], head: usize, has_flag: bool) -> Option<Vec<(&[u8], Option<[u8; 20]>)>> {
    let base = offset(args, head * 32)?;
    let count = length(args, base)?;
    if count > MAX_CHILDREN {
        return None;
    }
    let from = base + 32;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let tuple = from + offset(args, from + i * 32)?;
        let target = address(args, tuple);
        // The flag is read, not stepped over.
        if has_flag {
            boolean(args, tuple + 32)?;
        }
        // The tuple is dynamic: its last member is an offset from its start.
        let rel = offset(args, tuple + if has_flag { 64 } else { 32 });
        let (target, rel) = (target?, rel?);
        out.push((bytes_at(args, tuple + rel)?, Some(target)));
    }
    Some(out)
}

/// The `bytes` at [at]: a length word, then that many bytes (`_bytesAt`).
fn bytes_at(args: &[u8], at: usize) -> Option<&[u8]> {
    let len = length(args, at)?;
    let start = at.checked_add(32)?;
    args.get(start..start.checked_add(len)?)
}

/// A word read as a dynamic offset: within [args], and word-aligned
/// (`_offsetAt`).
fn offset(args: &[u8], at: usize) -> Option<usize> {
    length(args, at).filter(|value| value % 32 == 0)
}

/// A word read as a length or a count, which must not exceed [args]'s length
/// (`_lengthAt`).
fn length(args: &[u8], at: usize) -> Option<usize> {
    let w = word(args, at)?;
    if w[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let value = u64::from_be_bytes(w[24..].try_into().expect("eight bytes"));
    usize::try_from(value).ok().filter(|value| *value <= args.len())
}

/// An ABI `bool`: exactly zero or one (`_boolAt`).
fn boolean(args: &[u8], at: usize) -> Option<bool> {
    let w = word(args, at)?;
    if w[..31].iter().any(|b| *b != 0) {
        return None;
    }
    match w[31] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// An address: the low twenty bytes of a word whose top twelve are zero
/// (`_addressAt`).
fn address(args: &[u8], at: usize) -> Option<[u8; 20]> {
    let w = word(args, at)?;
    if w[..12].iter().any(|b| *b != 0) {
        return None;
    }
    Some(w[12..].try_into().expect("twenty bytes"))
}

fn word(args: &[u8], at: usize) -> Option<&[u8; 32]> {
    args.get(at..at.checked_add(32)?)?.try_into().ok()
}

fn is_zero(word: &[u8; 32]) -> bool {
    word.iter().all(|b| *b == 0)
}

/// At or above 2^128 (`effectivelyUnlimited`).
fn is_unlimited(word: &[u8; 32]) -> bool {
    word[..16].iter().any(|b| *b != 0)
}
