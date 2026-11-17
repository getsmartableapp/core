//! EIP-712 typed data read and hashed in the core — "sign what you see", step
//! 2e-1 of `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O41–O45).
//!
//! The app hands the core the JSON its review read, and the core computes
//! `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))` itself, by
//! the EIP; no digest computed in Dart is signed on this path.
//!
//! **What it takes is what the app's `Eip712.validate` takes, and no more**,
//! so a payload the review showed is read the same way here or refused:
//! the same limits (a payload capped before it is parsed, then depth,
//! fields, array entries, total fields and dynamic bytes), and one canonical
//! spelling for every value (O44). Where the app's encoder departed from the
//! EIP — the struct behind a nested array (O45) — both now follow the EIP;
//! and a document whose primary type is `EIP712Domain` signs its domain
//! alone, as MetaMask's `eth-sig-util` signs it, with an empty message (O46).
//!
//! **Nothing secret passes through this file**: it runs before the table's
//! lock is taken, and what it returns is a hash.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};

use crate::Refusal;

/// The most JSON the core parses: a payload holding a `bytes` value at the
/// app's limit, written as hex, fits with room for its structure.
pub(crate) const MAX_INPUT_BYTES: usize = 512 * 1024;
/// The app's limits (`Eip712.maxDepth` and the rest), here too.
const MAX_DEPTH: usize = 12;
const MAX_FIELDS: usize = 100;
const MAX_ARRAY_ENTRIES: usize = 1024;
const MAX_TOTAL_FIELDS: usize = 10_000;
const MAX_DYNAMIC_BYTES: usize = 128 * 1024;

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::TypedData)
}

/// The digest an EIP-712 signature is over, for [json]: the document the
/// app's review read. Anything the app's validator would refuse, or that
/// spells a value in any but its canonical form, is [`Refusal::TypedData`].
pub(crate) fn digest(json: &[u8]) -> Result<[u8; 32], Refusal> {
    let value = parse(json)?;
    TypedData::read(&value)?.digest()
}

/// [json] as JSON, within the size the core parses.
fn parse(json: &[u8]) -> Result<Value, Refusal> {
    if json.len() > MAX_INPUT_BYTES {
        return refused();
    }
    serde_json::from_slice(json).map_err(|_| Refusal::TypedData)
}

/// How many of the values a page sent that are not signed are named in a
/// reading; the rest are counted.
const MAX_UNSIGNED_NAMED: usize = 20;

/// What a review screen shows of [json] — "the screen shows what the core
/// read", step 2f-2 (the owner's decisions O54–O56) — and its digest, which
/// a signature is then held to.
///
/// **What is signed, and nothing else** (O56): the domain and the message as
/// lists of their declared fields in the type's order, each with its name,
/// its type and its value as it is hashed — an address and bytes as
/// lower-case hex, a number in decimal, a struct as its own list of fields,
/// an array as a list of values. Beside them, the values the page sent that
/// the type does not declare, which are not signed: up to twenty of their
/// places, sorted, and how many there are. And the permit, when the document
/// is one of the standard permits exactly (O55). And [signer], the address of
/// the key the reading is for, which alone may sign it.
pub(crate) fn reading(json: &[u8], signer: &[u8; 20]) -> Result<(Value, [u8; 32]), Refusal> {
    let value = parse(json)?;
    let data = TypedData::read(&value)?;
    let digest = data.digest()?;
    let domain = data.read_struct("EIP712Domain", data.domain)?;
    let message =
        if data.signs_domain_only() { Vec::new() } else { data.read_struct(data.primary, data.message)? };
    let mut unsigned = Vec::new();
    data.unsigned_in("EIP712Domain", data.domain, "domain", &mut unsigned)?;
    if !data.signs_domain_only() {
        data.unsigned_in(data.primary, data.message, "message", &mut unsigned)?;
    }
    unsigned.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let unsigned_count = unsigned.len();
    unsigned.truncate(MAX_UNSIGNED_NAMED);
    let permit = data.permit();
    let mut out = Map::new();
    out.insert("primaryType".into(), Value::String(data.primary.into()));
    out.insert("domainOnly".into(), Value::Bool(data.signs_domain_only()));
    out.insert("digest".into(), Value::String(hex(&digest)));
    out.insert("domain".into(), Value::Array(domain));
    out.insert("message".into(), Value::Array(message));
    out.insert("unsigned".into(), Value::Array(unsigned.into_iter().map(Value::String).collect()));
    out.insert("unsignedCount".into(), Value::from(unsigned_count));
    out.insert("permit".into(), permit.unwrap_or(Value::Null));
    out.insert("signer".into(), Value::String(hex(signer)));
    Ok((Value::Object(out), digest))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A field of a struct type: its name and its type.
struct Field<'a> {
    name: &'a str,
    kind: &'a str,
}

struct TypedData<'a> {
    types: BTreeMap<&'a str, Vec<Field<'a>>>,
    primary: &'a str,
    domain: &'a Map<String, Value>,
    message: &'a Map<String, Value>,
    /// Each struct's type hash, once: the type string walks every struct it
    /// reaches, and a payload may hash thousands of instances of one type.
    type_hashes: RefCell<BTreeMap<&'a str, [u8; 32]>>,
}

impl<'a> TypedData<'a> {
    /// The document, checked as `Eip712.validate` checks it, in its order.
    fn read(value: &'a Value) -> Result<Self, Refusal> {
        let document = value.as_object().ok_or(Refusal::TypedData)?;
        let raw_types = document.get("types").and_then(Value::as_object).ok_or(Refusal::TypedData)?;
        let primary = match document.get("primaryType") {
            Some(Value::String(name)) if !name.is_empty() => name.as_str(),
            _ => return refused(),
        };
        if !raw_types.contains_key(primary) {
            return refused();
        }
        if !matches!(raw_types.get("EIP712Domain"), Some(Value::Array(_))) {
            return refused();
        }
        let (Some(Value::Object(domain)), Some(Value::Object(message))) =
            (document.get("domain"), document.get("message"))
        else {
            return refused();
        };
        let mut types = BTreeMap::new();
        for (name, fields) in raw_types {
            let fields = fields.as_array().ok_or(Refusal::TypedData)?;
            if fields.len() > MAX_FIELDS {
                return refused();
            }
            let mut names = BTreeSet::new();
            let mut read = Vec::with_capacity(fields.len());
            for field in fields {
                let field = field.as_object().ok_or(Refusal::TypedData)?;
                let (Some(Value::String(field_name)), Some(Value::String(kind))) =
                    (field.get("name"), field.get("type"))
                else {
                    return refused();
                };
                if field_name.is_empty() || !names.insert(field_name.as_str()) {
                    return refused();
                }
                read.push(Field { name: field_name, kind });
            }
            types.insert(name.as_str(), read);
        }
        let data = Self { types, primary, domain, message, type_hashes: RefCell::default() };
        for fields in data.types.values() {
            for field in fields {
                data.check_type_name(field.kind)?;
            }
        }
        // A document that signs its domain alone hashes no message, so it
        // carries none (O46): anything there would be shown and not signed.
        if data.signs_domain_only() && !message.is_empty() {
            return refused();
        }
        let mut budget = 0usize;
        data.validate_struct("EIP712Domain", domain, 0, &mut budget)?;
        if !data.signs_domain_only() {
            data.validate_struct(primary, message, 0, &mut budget)?;
        }
        Ok(data)
    }

    /// `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))`, or the
    /// domain's alone (O46).
    fn digest(&self) -> Result<[u8; 32], Refusal> {
        let domain = self.hash_struct("EIP712Domain", self.domain)?;
        if self.signs_domain_only() {
            return Ok(keccak(&[&[0x19, 0x01], &domain]));
        }
        let message = self.hash_struct(self.primary, self.message)?;
        Ok(keccak(&[&[0x19, 0x01], &domain, &message]))
    }

    /// Whether the primary type is the domain's: the digest is then
    /// `keccak256(0x19 0x01 ‖ domainSeparator)` (O46).
    fn signs_domain_only(&self) -> bool {
        self.primary == "EIP712Domain"
    }

    fn fields_of(&self, name: &str) -> Option<&Vec<Field<'a>>> {
        self.types.get(name)
    }

    fn is_struct(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// That a type name is one there is a word for: array suffixes, each
    /// empty or a canonical length up to the limit, around a struct or a
    /// primitive.
    fn check_type_name(&self, kind: &str) -> Result<(), Refusal> {
        let mut bare = kind;
        while let Some(rest) = bare.strip_suffix(']') {
            let open = rest.rfind('[').ok_or(Refusal::TypedData)?;
            let size = &rest[open + 1..];
            if !size.is_empty() {
                match canonical_count(size) {
                    Some(n) if n <= MAX_ARRAY_ENTRIES => {}
                    _ => return refused(),
                }
            }
            bare = &rest[..open];
        }
        if self.is_struct(bare)
            || matches!(bare, "string" | "bytes" | "bool" | "address")
            || numeric_bits(bare).is_some()
            || bytes_width(bare).is_some()
        {
            Ok(())
        } else {
            refused()
        }
    }

    fn validate_struct(
        &self,
        name: &str,
        data: &Map<String, Value>,
        depth: usize,
        budget: &mut usize,
    ) -> Result<(), Refusal> {
        if depth > MAX_DEPTH {
            return refused();
        }
        for field in self.fields_of(name).ok_or(Refusal::TypedData)? {
            spend(budget)?;
            self.validate_value(field.kind, data.get(field.name), depth, budget)?;
        }
        Ok(())
    }

    fn validate_value(
        &self,
        kind: &str,
        value: Option<&Value>,
        depth: usize,
        budget: &mut usize,
    ) -> Result<(), Refusal> {
        if let Some(rest) = kind.strip_suffix(']') {
            let open = rest.rfind('[').ok_or(Refusal::TypedData)?;
            let element = &rest[..open];
            let size = &rest[open + 1..];
            let Some(Value::Array(entries)) = value else {
                return refused();
            };
            if entries.len() > MAX_ARRAY_ENTRIES
                || (!size.is_empty() && canonical_count(size) != Some(entries.len()))
            {
                return refused();
            }
            for entry in entries {
                spend(budget)?;
                self.validate_value(element, Some(entry), depth + 1, budget)?;
            }
            return Ok(());
        }
        if self.is_struct(kind) {
            let Some(Value::Object(inner)) = value else {
                return refused();
            };
            return self.validate_struct(kind, inner, depth + 1, budget);
        }
        match (kind, value) {
            ("string", Some(Value::String(text))) => {
                if text.len() > MAX_DYNAMIC_BYTES { refused() } else { Ok(()) }
            }
            ("bool", Some(Value::Bool(_))) => Ok(()),
            ("address", Some(Value::String(text))) => {
                if is_address(text) { Ok(()) } else { refused() }
            }
            ("bytes", Some(Value::String(text))) => hex_bytes(text).map(|_| ()),
            ("string" | "bool" | "address" | "bytes", _) => refused(),
            _ => {
                if let Some(bits) = numeric_bits(kind) {
                    let number = read_number(value)?;
                    return if fits(&number, bits, kind.starts_with("int")) { Ok(()) } else { refused() };
                }
                if let Some(width) = bytes_width(kind) {
                    let Some(Value::String(text)) = value else {
                        return refused();
                    };
                    return if hex_bytes(text)?.len() == width { Ok(()) } else { refused() };
                }
                refused()
            }
        }
    }

    /// `keccak256(typeHash ‖ encodeData(data))`.
    fn hash_struct(&self, name: &str, data: &Map<String, Value>) -> Result<[u8; 32], Refusal> {
        let type_hash = self.type_hash(name)?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&type_hash);
        for field in self.fields_of(name).ok_or(Refusal::TypedData)? {
            encoded.extend_from_slice(&self.encode_value(field.kind, data.get(field.name))?);
        }
        Ok(keccak(&[&encoded]))
    }

    fn type_hash(&self, name: &str) -> Result<[u8; 32], Refusal> {
        let (key, _) = self.types.get_key_value(name).ok_or(Refusal::TypedData)?;
        if let Some(hash) = self.type_hashes.borrow().get(key) {
            return Ok(*hash);
        }
        let hash = keccak(&[self.encode_type(name)?.as_bytes()]);
        self.type_hashes.borrow_mut().insert(key, hash);
        Ok(hash)
    }

    /// The type string: [name]'s own, then every struct it reaches — through
    /// arrays of any depth (O45) — sorted by name as the app sorts strings,
    /// by UTF-16 code unit.
    fn encode_type(&self, name: &str) -> Result<String, Refusal> {
        let mut seen = self.dependencies(name);
        seen.remove(name);
        let mut dependencies: Vec<&str> = seen.into_iter().collect();
        dependencies.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let mut out = String::new();
        for type_name in std::iter::once(name).chain(dependencies) {
            let fields = self.fields_of(type_name).ok_or(Refusal::TypedData)?;
            out.push_str(type_name);
            out.push('(');
            for (i, field) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(field.kind);
                out.push(' ');
                out.push_str(field.name);
            }
            out.push(')');
        }
        Ok(out)
    }

    /// Every struct [kind] reaches, itself included: the app's
    /// `_dependencies`, walked with a list rather than by recursion — a
    /// payload may declare thousands of types in a chain, through arrays the
    /// data leaves empty, and a recursion that deep would end the process
    /// rather than refuse.
    fn dependencies(&self, kind: &str) -> BTreeSet<&str> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![kind];
        while let Some(kind) = pending.pop() {
            // Array suffixes off, every one of them (O45), as the app's
            // `(\[\d*\])+$` takes them.
            let mut bare = kind;
            while let Some(rest) = bare.strip_suffix(']') {
                match rest.rfind('[') {
                    Some(open) if rest[open + 1..].bytes().all(|b| b.is_ascii_digit()) => {
                        bare = &rest[..open];
                    }
                    _ => break,
                }
            }
            let Some((name, fields)) = self.types.get_key_value(bare) else {
                continue;
            };
            if seen.insert(*name) {
                pending.extend(fields.iter().map(|field| field.kind));
            }
        }
        seen
    }

    fn encode_value(&self, kind: &str, value: Option<&Value>) -> Result<[u8; 32], Refusal> {
        if let Some(rest) = kind.strip_suffix(']') {
            let open = rest.rfind('[').ok_or(Refusal::TypedData)?;
            let element = &rest[..open];
            let mut joined = Vec::new();
            if let Some(Value::Array(entries)) = value {
                for entry in entries {
                    joined.extend_from_slice(&self.encode_value(element, Some(entry))?);
                }
            }
            return Ok(keccak(&[&joined]));
        }
        if self.is_struct(kind) {
            let Some(Value::Object(inner)) = value else {
                return refused();
            };
            return self.hash_struct(kind, inner);
        }
        let mut word = [0u8; 32];
        match (kind, value) {
            ("string", Some(Value::String(text))) => return Ok(keccak(&[text.as_bytes()])),
            ("bytes", Some(Value::String(text))) => return Ok(keccak(&[&hex_bytes(text)?])),
            ("bool", Some(Value::Bool(flag))) => {
                word[31] = u8::from(*flag);
                return Ok(word);
            }
            ("address", Some(Value::String(text))) => {
                word[12..].copy_from_slice(&hex_bytes(text)?);
                return Ok(word);
            }
            _ => {}
        }
        if numeric_bits(kind).is_some() {
            return Ok(read_number(value)?.word());
        }
        if bytes_width(kind).is_some() {
            let Some(Value::String(text)) = value else {
                return refused();
            };
            let bytes = hex_bytes(text)?;
            word[..bytes.len()].copy_from_slice(&bytes);
            return Ok(word);
        }
        refused()
    }
}

// --- What a screen shows (2f-2) ------------------------------------------------

impl TypedData<'_> {
    /// [data]'s declared fields, in [name]'s order, each as its name, its type
    /// and its value as hashed. Called on a document [`TypedData::read`]
    /// checked, so every value is there and of its type.
    fn read_struct(&self, name: &str, data: &Map<String, Value>) -> Result<Vec<Value>, Refusal> {
        let mut fields = Vec::new();
        for field in self.fields_of(name).ok_or(Refusal::TypedData)? {
            let mut entry = Map::new();
            entry.insert("name".into(), Value::String(field.name.into()));
            entry.insert("type".into(), Value::String(field.kind.into()));
            entry.insert("value".into(), self.read_value(field.kind, data.get(field.name))?);
            fields.push(Value::Object(entry));
        }
        Ok(fields)
    }

    fn read_value(&self, kind: &str, value: Option<&Value>) -> Result<Value, Refusal> {
        if let Some(rest) = kind.strip_suffix(']') {
            let open = rest.rfind('[').ok_or(Refusal::TypedData)?;
            let Some(Value::Array(entries)) = value else {
                return refused();
            };
            let element = &rest[..open];
            return entries
                .iter()
                .map(|entry| self.read_value(element, Some(entry)))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array);
        }
        if self.is_struct(kind) {
            let Some(Value::Object(inner)) = value else {
                return refused();
            };
            return self.read_struct(kind, inner).map(Value::Array);
        }
        match (kind, value) {
            ("string", Some(Value::String(text))) => return Ok(Value::String(text.clone())),
            ("bool", Some(Value::Bool(flag))) => return Ok(Value::Bool(*flag)),
            ("address" | "bytes", Some(Value::String(text))) => return Ok(Value::String(hex(&hex_bytes(text)?))),
            _ => {}
        }
        if numeric_bits(kind).is_some() {
            return Ok(Value::String(read_number(value)?.decimal()));
        }
        if bytes_width(kind).is_some() {
            if let Some(Value::String(text)) = value {
                return Ok(Value::String(hex(&hex_bytes(text)?)));
            }
        }
        refused()
    }

    /// The place, from [at], of every value in [data] — and in each struct it
    /// holds, through arrays — that [name] does not declare: sent by the page,
    /// and not signed.
    fn unsigned_in(
        &self,
        name: &str,
        data: &Map<String, Value>,
        at: &str,
        out: &mut Vec<String>,
    ) -> Result<(), Refusal> {
        let fields = self.fields_of(name).ok_or(Refusal::TypedData)?;
        for key in data.keys() {
            if !fields.iter().any(|field| field.name == key) {
                out.push(format!("{at}.{key}"));
            }
        }
        for field in fields {
            if let Some(value) = data.get(field.name) {
                self.unsigned_value(field.kind, value, &format!("{at}.{}", field.name), out)?;
            }
        }
        Ok(())
    }

    fn unsigned_value(&self, kind: &str, value: &Value, at: &str, out: &mut Vec<String>) -> Result<(), Refusal> {
        if let Some(rest) = kind.strip_suffix(']') {
            let open = rest.rfind('[').ok_or(Refusal::TypedData)?;
            if let Value::Array(entries) = value {
                for (i, entry) in entries.iter().enumerate() {
                    self.unsigned_value(&rest[..open], entry, &format!("{at}[{i}]"), out)?;
                }
            }
            return Ok(());
        }
        if let (true, Value::Object(inner)) = (self.is_struct(kind), value) {
            self.unsigned_in(kind, inner, at, out)?;
        }
        Ok(())
    }

    /// The document as a standard permit (O55), or none: matched on its whole
    /// type string, which is what the permit's contract verifies — a page that
    /// calls its own struct `Permit` is not read as one. The type string being
    /// the standard's, every field it names is there, and of its type.
    fn permit(&self) -> Option<Value> {
        if self.signs_domain_only() {
            return None;
        }
        let own = self.encode_type(self.primary).ok()?;
        let (kind, _) = PERMITS.iter().find(|(_, type_string)| own == *type_string)?;
        let message = self.message;
        let address = |map: &Map<String, Value>, key: &str| match map.get(key) {
            Some(Value::String(text)) => hex_bytes(text).ok().map(|bytes| Value::String(hex(&bytes))),
            _ => None,
        };
        let number = |map: &Map<String, Value>, key: &str| read_number(map.get(key)).ok();
        let item = |token: Value, amount: Number, expiration: Option<Number>| {
            let mut entry = Map::new();
            entry.insert("token".into(), token);
            entry.insert("unlimited".into(), Value::Bool(!amount.below_power(128)));
            entry.insert("amount".into(), Value::String(amount.decimal()));
            entry.insert("expiration".into(), expiration.map_or(Value::Null, |n| Value::String(n.decimal())));
            Value::Object(entry)
        };
        fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
            match value {
                Some(Value::Object(inner)) => Some(inner),
                _ => None,
            }
        }
        // A batch of none is no permit.
        fn list(value: Option<&Value>) -> Option<&Vec<Value>> {
            match value {
                Some(Value::Array(entries)) if !entries.is_empty() => Some(entries),
                _ => None,
            }
        }
        // EIP-2612's and DAI's token is the domain's verifying contract,
        // declared as an address: the token itself checks the signature.
        let token = || {
            let declared = self.fields_of("EIP712Domain")?;
            let as_address =
                declared.iter().any(|f| f.name == "verifyingContract" && f.kind == "address") && !self.is_struct("address");
            if as_address { address(self.domain, "verifyingContract") } else { None }
        };
        let (items, deadline) = match *kind {
            "erc2612" => (vec![item(token()?, number(message, "value")?, None)], Some(number(message, "deadline")?)),
            "daiPermit" => {
                // `allowed: false` sets the allowance to zero: a revocation,
                // and no permit to describe. `allowed: true` is the largest
                // allowance, whatever else the message says; `expiry: 0` is
                // none.
                if message.get("allowed") != Some(&Value::Bool(true)) {
                    return None;
                }
                let expiry = number(message, "expiry")?;
                let deadline = if expiry.is_zero() { Number::max() } else { expiry };
                (vec![item(token()?, Number::max(), None)], Some(deadline))
            }
            "permit2Single" => {
                // The allowance's expiration, not `sigDeadline`: one is how
                // long the signature may be submitted, the other how long the
                // allowance lasts.
                let details = object(message.get("details"))?;
                let expiration = number(details, "expiration")?;
                let token = address(details, "token")?;
                (vec![item(token, number(details, "amount")?, Some(expiration.clone()))], Some(expiration))
            }
            "permit2Batch" => {
                let mut items = Vec::new();
                for entry in list(message.get("details"))? {
                    let details = object(Some(entry))?;
                    items.push(item(
                        address(details, "token")?,
                        number(details, "amount")?,
                        Some(number(details, "expiration")?),
                    ));
                }
                (items, None)
            }
            "permit2Transfer" => {
                let permitted = object(message.get("permitted"))?;
                (
                    vec![item(address(permitted, "token")?, number(permitted, "amount")?, None)],
                    Some(number(message, "deadline")?),
                )
            }
            _ => {
                let mut items = Vec::new();
                for entry in list(message.get("permitted"))? {
                    let permitted = object(Some(entry))?;
                    items.push(item(address(permitted, "token")?, number(permitted, "amount")?, None));
                }
                (items, Some(number(message, "deadline")?))
            }
        };
        let mut out = Map::new();
        out.insert("kind".into(), Value::String((*kind).into()));
        out.insert("spender".into(), address(message, "spender")?);
        out.insert("items".into(), Value::Array(items));
        out.insert("deadline".into(), deadline.map_or(Value::Null, |n| Value::String(n.decimal())));
        Some(Value::Object(out))
    }
}

/// The permits a review reads (O55), each by the whole type string its
/// contract verifies: EIP-2612's, DAI's, and Permit2's four
/// (`PermitHash.sol`).
const PERMITS: [(&str, &str); 6] = [
    ("erc2612", "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
    ("daiPermit", "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)"),
    (
        "permit2Single",
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
         PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
    ),
    (
        "permit2Batch",
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
         PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
    ),
    (
        "permit2Transfer",
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)\
         TokenPermissions(address token,uint256 amount)",
    ),
    (
        "permit2BatchTransfer",
        "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)\
         TokenPermissions(address token,uint256 amount)",
    ),
];

fn spend(budget: &mut usize) -> Result<(), Refusal> {
    *budget += 1;
    if *budget > MAX_TOTAL_FIELDS { refused() } else { Ok(()) }
}

/// A positive count with no leading zero, sign or space (O44).
fn canonical_count(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    text.parse().ok()
}

/// Bits for `uintN`/`intN` — N a multiple of 8 from 8 to 256, written with no
/// leading zero, or bare for 256 — or nothing.
fn numeric_bits(kind: &str) -> Option<usize> {
    let digits = kind.strip_prefix("uint").or_else(|| kind.strip_prefix("int"))?;
    if digits.is_empty() {
        return Some(256);
    }
    let bits = canonical_count(digits)?;
    (bits >= 8 && bits <= 256 && bits % 8 == 0).then_some(bits)
}

/// Bytes for `bytesN`, N from 1 to 32 with no leading zero.
fn bytes_width(kind: &str) -> Option<usize> {
    let width = canonical_count(kind.strip_prefix("bytes")?)?;
    (1..=32).contains(&width).then_some(width)
}

/// `0x` and exactly forty hex digits, as `Eip712.isAddressText`.
fn is_address(text: &str) -> bool {
    text.len() == 42
        && text.starts_with("0x")
        && text.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

/// `0x` and an even number of hex digits, at most the dynamic limit.
fn hex_bytes(text: &str) -> Result<Vec<u8>, Refusal> {
    let digits = text.strip_prefix("0x").ok_or(Refusal::TypedData)?.as_bytes();
    if digits.len() % 2 != 0 || digits.len() / 2 > MAX_DYNAMIC_BYTES {
        return refused();
    }
    let nibble = |b: u8| -> Result<u8, Refusal> {
        (b as char).to_digit(16).map(|d| d as u8).ok_or(Refusal::TypedData)
    };
    digits
        .chunks(2)
        .map(|pair| Ok(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// A number as the app reads it, at most 256 bits of magnitude: its sign,
/// and its magnitude as four 64-bit limbs, least significant first.
#[derive(Clone)]
struct Number {
    negative: bool,
    limbs: [u64; 4],
}

impl Number {
    /// 2^256 − 1: what DAI's `allowed: true` grants.
    fn max() -> Self {
        Self { negative: false, limbs: [u64::MAX; 4] }
    }

    /// In decimal, with a `-` before a negative one; zero is `0`.
    fn decimal(&self) -> String {
        let mut limbs = self.limbs;
        let mut digits = Vec::new();
        loop {
            // limbs /= 10, most significant first; the remainder is a digit.
            let mut remainder = 0u128;
            for limb in limbs.iter_mut().rev() {
                let value = (remainder << 64) | u128::from(*limb);
                *limb = (value / 10) as u64;
                remainder = value % 10;
            }
            digits.push(b'0' + remainder as u8);
            if limbs.iter().all(|l| *l == 0) {
                break;
            }
        }
        if self.negative && !self.is_zero() {
            digits.push(b'-');
        }
        digits.reverse();
        String::from_utf8(digits).expect("ASCII")
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|l| *l == 0)
    }

    /// Whether the magnitude is below `2^bits`.
    fn below_power(&self, bits: usize) -> bool {
        if bits >= 256 {
            return true;
        }
        let (limb, bit) = (bits / 64, bits % 64);
        if self.limbs[limb] >> bit != 0 {
            return false;
        }
        self.limbs[limb + 1..].iter().all(|l| *l == 0)
    }

    /// Whether the magnitude is exactly `2^bits`.
    fn is_power(&self, bits: usize) -> bool {
        let mut power = [0u64; 4];
        if bits >= 256 {
            return false;
        }
        power[bits / 64] = 1 << (bits % 64);
        self.limbs == power
    }

    /// The 32-byte word: big-endian, two's complement for a negative number.
    fn word(&self) -> [u8; 32] {
        let mut limbs = self.limbs;
        if self.negative && !self.is_zero() {
            // 2^256 − magnitude: invert, then add one.
            let mut carry = true;
            for limb in &mut limbs {
                *limb = !*limb;
                if carry {
                    let (sum, overflow) = limb.overflowing_add(1);
                    *limb = sum;
                    carry = overflow;
                }
            }
        }
        let mut out = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }
}

/// Whether [number] fits the type: `[0, 2^bits)` unsigned, `[−2^(bits−1),
/// 2^(bits−1))` signed.
fn fits(number: &Number, bits: usize, signed: bool) -> bool {
    if number.is_zero() {
        return true;
    }
    if !signed {
        return !number.negative && number.below_power(bits);
    }
    if number.negative {
        number.below_power(bits - 1) || number.is_power(bits - 1)
    } else {
        number.below_power(bits - 1)
    }
}

/// [value] read as a number in its one canonical spelling (O44): a JSON
/// integer within 64 bits signed — the range the app's JSON reader keeps as
/// an integer — or text: an optional `-`, then decimal digits or `0x`/`0X`
/// and hex digits. A magnitude of 2^256 or more is refused: no type holds it.
fn read_number(value: Option<&Value>) -> Result<Number, Refusal> {
    match value {
        Some(Value::Number(n)) => {
            let n = n.as_i64().ok_or(Refusal::TypedData)?;
            Ok(Number { negative: n < 0, limbs: [n.unsigned_abs(), 0, 0, 0] })
        }
        Some(Value::String(text)) => {
            let (negative, body) = match text.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, text.as_str()),
            };
            let (radix, digits) = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                Some(hex) => (16u64, hex),
                None => (10u64, body),
            };
            if digits.is_empty() {
                return refused();
            }
            let mut limbs = [0u64; 4];
            for c in digits.chars() {
                let digit = c.to_digit(radix as u32).ok_or(Refusal::TypedData)? as u64;
                // limbs = limbs × radix + digit, refused on overflow past 2^256.
                let mut carry = digit as u128;
                for limb in &mut limbs {
                    let product = (*limb as u128) * (radix as u128) + carry;
                    *limb = product as u64;
                    carry = product >> 64;
                }
                if carry != 0 {
                    return refused();
                }
            }
            Ok(Number { negative, limbs })
        }
        _ => refused(),
    }
}

/// [name]'s type string in [json], for the tests.
#[cfg(test)]
pub(crate) fn type_string(json: &[u8], name: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_slice(json).map_err(|_| Refusal::TypedData)?;
    TypedData::read(&value)?.encode_type(name)
}
