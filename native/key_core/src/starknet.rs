//! A Starknet transaction read in the core for its review screen — "the
//! screen shows what the core read" for Starknet, after step 2f of
//! `docs/RUST_KEY_CORE_DESIGN.md` (the owner's decisions O52 and O58).
//!
//! An account signs a v3 transaction's hash: Poseidon over its prefix, its
//! version, its sender, the fee fields, the chain id, the nonce and its data,
//! as the module's `StarknetInvokeV3` and `StarknetDeployAccountV3` compose it.
//! The core reads the transaction as the module will send it — the JSON body
//! of `starknet_addInvokeTransaction` or `starknet_addDeployAccountTransaction`
//! with no signature yet — in the one shape the module writes: version 3, or
//! the query version an estimate is signed at; no tip, no paymaster data, no
//! account deployment data, L1 data availability; an invoke of exactly one
//! ERC-20 `transfer` through `__execute__`; a deployment of one of the Argent
//! classes the module deploys. It takes the hash itself, on mainnet's chain
//! id, and holds the transaction to the signing key: an invoke's sender is
//! that key's Argent account, a deployment's salt and constructor are that
//! key's.
//!
//! **Nothing secret passes through this file**: it is handed the key's public
//! half, and what it returns is a reading.

use serde_json::{Map, Value};
use starknet_crypto::{pedersen_hash, poseidon_hash_many, Felt};

use crate::Refusal;

fn refused<T>() -> Result<T, Refusal> {
    Err(Refusal::Transaction)
}

/// The field's prime, `2^251 + 17·2^192 + 1`, big-endian.
const PRIME: [u8; 32] = {
    let mut p = [0u8; 32];
    p[0] = 0x08;
    p[7] = 0x11;
    p[31] = 0x01;
    p
};

/// `2^251 − 256`: no contract address is at or above it.
const ADDRESS_BOUND: [u8; 32] = {
    let mut b = [0xffu8; 32];
    b[0] = 0x07;
    b[31] = 0x00;
    b
};

/// The query version, `2^128 + 3`: a transaction an estimate is signed at,
/// which the sequencer never executes.
const QUERY_VERSION: [u8; 32] = {
    let mut q = [0u8; 32];
    q[15] = 0x01;
    q[31] = 0x03;
    q
};

/// `starknet_keccak("transfer")`.
const TRANSFER_SELECTOR: &str = "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e";

/// The Argent classes the module deploys and signs from, with the shape of
/// their constructors: 0.4.0's `[0, key, 1]` (an owner of the Starknet
/// variant, no guardian), 0.3.1's and 0.3.0's `[key, 0]`. From the module's
/// `ArgentAccount`, which holds them to mainnet.
const ARGENT_V040: &str = "0x36078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";
const ARGENT_V031: &str = "0x29927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b";
const ARGENT_V030: &str = "0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003";

/// Argent's Cairo 0 accounts, 0.2.1 to 0.2.4: a proxy class whose constructor
/// names the implementation and calls its `initialize(owner, guardian)` —
/// `[implementation, initialize, 2, key, 0]`. **Never deployed here, and
/// signed from once upgraded**: an upgrade to a Cairo 1 class keeps the
/// proxy's address, which the module finds on a restored phrase and signs
/// from. From the module's `ArgentAccount.cairo0`.
const ARGENT_CAIRO0_PROXY: &str = "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918";
const ARGENT_CAIRO0_IMPLEMENTATIONS: [&str; 4] = [
    "0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2",
    "0x1a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f",
    "0x3e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328",
    "0x7e28fb0161d10d1cf7fe1f13e7ca57bce062731a3bd04494dfd2d0412699727",
];
/// `starknet_keccak("initialize")`.
const INITIALIZE_SELECTOR: &str = "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463";

fn short_string(text: &str) -> Felt {
    let mut bytes = [0u8; 32];
    bytes[32 - text.len()..].copy_from_slice(text.as_bytes());
    Felt::from_bytes_be(&bytes)
}

fn below(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

/// A felt as the module writes one: `0x`, lowercase hex, no leading zero but
/// `0x0`, below the prime.
fn felt(value: &Value) -> Result<[u8; 32], Refusal> {
    let Some(text) = value.as_str() else { return refused() };
    let Some(digits) = text.strip_prefix("0x") else { return refused() };
    if digits.is_empty()
        || digits.len() > 64
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return refused();
    }
    let mut out = [0u8; 32];
    let padded = format!("{digits:0>64}");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).map_err(|_| Refusal::Transaction)?;
    }
    if !below(&out, &PRIME) {
        return refused();
    }
    Ok(out)
}

fn felts(value: &Value) -> Result<Vec<[u8; 32]>, Refusal> {
    let Some(list) = value.as_array() else { return refused() };
    list.iter().map(felt).collect()
}

fn hex64(bytes: &[u8; 32]) -> String {
    let mut out = String::from("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// [bytes] — a big-endian number — in decimal.
fn decimal(bytes: &[u8; 32]) -> String {
    let mut digits = Vec::new();
    let mut number = bytes.to_vec();
    while number.iter().any(|b| *b != 0) {
        let mut remainder = 0u32;
        for byte in number.iter_mut() {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = (value / 10) as u8;
            remainder = value % 10;
        }
        digits.push(b'0' + remainder as u8);
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.reverse();
    String::from_utf8(digits).expect("ASCII digits")
}

/// That [object] holds exactly [keys].
fn exactly(object: &Map<String, Value>, keys: &[&str]) -> Result<(), Refusal> {
    if object.len() != keys.len() || !keys.iter().all(|k| object.contains_key(*k)) {
        return refused();
    }
    Ok(())
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> &'a Value {
    &object[key]
}

fn empty_list(value: &Value) -> Result<(), Refusal> {
    match value.as_array() {
        Some(list) if list.is_empty() => Ok(()),
        _ => refused(),
    }
}

/// One resource's bound: an amount within 64 bits and a price within 128.
struct Bound {
    max_amount: u64,
    max_price: u128,
}

fn bound(value: &Value) -> Result<Bound, Refusal> {
    let Some(object) = value.as_object() else { return refused() };
    exactly(object, &["max_amount", "max_price_per_unit"])?;
    let amount = felt(field(object, "max_amount"))?;
    let price = felt(field(object, "max_price_per_unit"))?;
    if amount[..24].iter().any(|b| *b != 0) || price[..16].iter().any(|b| *b != 0) {
        return refused();
    }
    Ok(Bound {
        max_amount: u64::from_be_bytes(amount[24..].try_into().expect("eight bytes")),
        max_price: u128::from_be_bytes(price[16..].try_into().expect("sixteen bytes")),
    })
}

struct Bounds {
    l1_gas: Bound,
    l2_gas: Bound,
    l1_data_gas: Bound,
}

fn bounds(value: &Value) -> Result<Bounds, Refusal> {
    let Some(object) = value.as_object() else { return refused() };
    exactly(object, &["l1_gas", "l2_gas", "l1_data_gas"])?;
    Ok(Bounds {
        l1_gas: bound(field(object, "l1_gas"))?,
        l2_gas: bound(field(object, "l2_gas"))?,
        l1_data_gas: bound(field(object, "l1_data_gas"))?,
    })
}

impl Bounds {
    /// Poseidon of the tip — none — and the three packed bounds: each
    /// resource's name in the top 64 bits, its amount in the next 64, its
    /// price in the last 128.
    fn fee_fields_hash(&self) -> Felt {
        let packed = |name: &str, b: &Bound| {
            let mut bytes = [0u8; 32];
            bytes[8 - name.len()..8].copy_from_slice(name.as_bytes());
            bytes[8..16].copy_from_slice(&b.max_amount.to_be_bytes());
            bytes[16..].copy_from_slice(&b.max_price.to_be_bytes());
            Felt::from_bytes_be(&bytes)
        };
        poseidon_hash_many(&[
            Felt::ZERO,
            packed("L1_GAS", &self.l1_gas),
            packed("L2_GAS", &self.l2_gas),
            packed("L1_DATA", &self.l1_data_gas),
        ])
    }

    /// The most the transaction can be charged: each amount times its
    /// price, summed, exactly.
    fn max_fee(&self) -> [u8; 32] {
        let product = |b: &Bound| Felt::from(b.max_amount) * Felt::from(b.max_price);
        (product(&self.l1_gas) + product(&self.l2_gas) + product(&self.l1_data_gas)).to_bytes_be()
    }

    fn reading(&self) -> Value {
        let one = |b: &Bound| {
            let mut m = Map::new();
            m.insert("maxAmount".into(), Value::String(b.max_amount.to_string()));
            m.insert("maxPricePerUnit".into(), Value::String(b.max_price.to_string()));
            Value::Object(m)
        };
        let mut m = Map::new();
        m.insert("l1Gas".into(), one(&self.l1_gas));
        m.insert("l2Gas".into(), one(&self.l2_gas));
        m.insert("l1DataGas".into(), one(&self.l1_data_gas));
        Value::Object(m)
    }
}

/// `pedersen(…pedersen(pedersen(0, e0), e1)…, n)`: Starknet's hash on
/// elements.
fn hash_on_elements(elements: &[Felt]) -> Felt {
    let mut h = Felt::ZERO;
    for e in elements {
        h = pedersen_hash(&h, e);
    }
    pedersen_hash(&h, &Felt::from(elements.len() as u64))
}

/// Where a contract of [class] deployed by nobody with [salt] and
/// [constructor] is: `hash_on_elements("STARKNET_CONTRACT_ADDRESS", 0, salt,
/// class, hash_on_elements(constructor)) mod (2^251 − 256)`.
pub(crate) fn contract_address(class: &Felt, salt: &Felt, constructor: &[Felt]) -> [u8; 32] {
    let h = hash_on_elements(&[
        short_string("STARKNET_CONTRACT_ADDRESS"),
        Felt::ZERO,
        *salt,
        *class,
        hash_on_elements(constructor),
    ]);
    let bytes = h.to_bytes_be();
    if below(&bytes, &ADDRESS_BOUND) {
        bytes
    } else {
        (h - Felt::from_bytes_be(&ADDRESS_BOUND)).to_bytes_be()
    }
}

fn argent_classes() -> [([u8; 32], fn(&Felt) -> Vec<Felt>); 3] {
    let class = |hex: &str| felt(&Value::String(hex.into())).expect("a pinned class hash");
    [
        (class(ARGENT_V040), |key| vec![Felt::ZERO, *key, Felt::ONE]),
        (class(ARGENT_V031), |key| vec![*key, Felt::ZERO]),
        (class(ARGENT_V030), |key| vec![*key, Felt::ZERO]),
    ]
}

/// The addresses [public_key]'s Argent accounts are at — the module's
/// `ArgentAccount.candidateAddresses`, in its order: one for each Cairo 1
/// class it deploys, then one for each Cairo 0 implementation, the account an
/// upgrade keeps at its proxy's address.
pub(crate) fn argent_addresses(public_key: &[u8; 32]) -> Vec<[u8; 32]> {
    let key = Felt::from_bytes_be(public_key);
    let felt_of = |hex: &str| Felt::from_bytes_be(&felt(&Value::String(hex.into())).expect("a pinned felt"));
    let mut addresses: Vec<[u8; 32]> = argent_classes()
        .iter()
        .map(|(class, constructor)| contract_address(&Felt::from_bytes_be(class), &key, &constructor(&key)))
        .collect();
    let proxy = felt_of(ARGENT_CAIRO0_PROXY);
    for implementation in ARGENT_CAIRO0_IMPLEMENTATIONS {
        let constructor = [felt_of(implementation), felt_of(INITIALIZE_SELECTOR), Felt::from(2u64), key, Felt::ZERO];
        addresses.push(contract_address(&proxy, &key, &constructor));
    }
    addresses
}

/// [transaction] — a v3 body as the module sends it, unsigned — read and
/// held to the signing key whose Stark public key is [public_key]: the
/// reading, and the hash its signature is over.
pub(crate) fn reading(transaction: &[u8], public_key: &[u8; 32]) -> Result<(Value, [u8; 32]), Refusal> {
    let value: Value = serde_json::from_slice(transaction).map_err(|_| Refusal::Transaction)?;
    let Some(object) = value.as_object() else { return refused() };
    let version = felt(object.get("version").unwrap_or(&Value::Null))?;
    let query = match version {
        v if v == QUERY_VERSION => true,
        v if v == felt(&Value::String("0x3".into()))? => false,
        _ => return refused(),
    };
    empty_list(object.get("signature").unwrap_or(&Value::Null))?;
    if felt(object.get("tip").unwrap_or(&Value::Null))? != [0u8; 32] {
        return refused();
    }
    empty_list(object.get("paymaster_data").unwrap_or(&Value::Null))?;
    for mode in ["nonce_data_availability_mode", "fee_data_availability_mode"] {
        if object.get(mode).and_then(Value::as_str) != Some("L1") {
            return refused();
        }
    }
    let bounds = bounds(object.get("resource_bounds").unwrap_or(&Value::Null))?;
    let chain = short_string("SN_MAIN");
    let key = Felt::from_bytes_be(public_key);
    let mut out = Map::new();
    let hash = match object.get("type").and_then(Value::as_str) {
        Some("INVOKE") => {
            exactly(
                object,
                &[
                    "type",
                    "version",
                    "sender_address",
                    "calldata",
                    "signature",
                    "nonce",
                    "resource_bounds",
                    "tip",
                    "paymaster_data",
                    "account_deployment_data",
                    "nonce_data_availability_mode",
                    "fee_data_availability_mode",
                ],
            )?;
            empty_list(field(object, "account_deployment_data"))?;
            let sender = felt(field(object, "sender_address"))?;
            if !argent_addresses(public_key).contains(&sender) {
                return refused();
            }
            let nonce = felt(field(object, "nonce"))?;
            let calldata = felts(field(object, "calldata"))?;
            // `__execute__`'s one call: `[1, token, transfer, 3, recipient,
            // low, high]`.
            let transfer = felt(&Value::String(TRANSFER_SELECTOR.into()))?;
            let one = Felt::ONE.to_bytes_be();
            let three = Felt::from(3u64).to_bytes_be();
            let [count, token, selector, length, recipient, low, high] = calldata[..] else {
                return refused();
            };
            if count != one || selector != transfer || length != three {
                return refused();
            }
            for address in [token, recipient] {
                if address == [0u8; 32] || !below(&address, &ADDRESS_BOUND) {
                    return refused();
                }
            }
            if low[..16].iter().any(|b| *b != 0) || high[..16].iter().any(|b| *b != 0) {
                return refused();
            }
            let mut amount = [0u8; 32];
            amount[..16].copy_from_slice(&high[16..]);
            amount[16..].copy_from_slice(&low[16..]);
            let elements: Vec<Felt> = calldata.iter().map(Felt::from_bytes_be).collect();
            let hash = poseidon_hash_many(&[
                short_string("invoke"),
                Felt::from_bytes_be(&version),
                Felt::from_bytes_be(&sender),
                bounds.fee_fields_hash(),
                poseidon_hash_many(&[]),
                chain,
                Felt::from_bytes_be(&nonce),
                Felt::ZERO,
                poseidon_hash_many(&[]),
                poseidon_hash_many(&elements),
            ]);
            out.insert("kind".into(), Value::String("invoke".into()));
            out.insert("sender".into(), Value::String(hex64(&sender)));
            out.insert("nonce".into(), Value::String(decimal(&nonce)));
            out.insert("token".into(), Value::String(hex64(&token)));
            out.insert("recipient".into(), Value::String(hex64(&recipient)));
            out.insert("amount".into(), Value::String(decimal(&amount)));
            hash
        }
        Some("DEPLOY_ACCOUNT") => {
            exactly(
                object,
                &[
                    "type",
                    "version",
                    "signature",
                    "nonce",
                    "contract_address_salt",
                    "constructor_calldata",
                    "class_hash",
                    "resource_bounds",
                    "tip",
                    "paymaster_data",
                    "nonce_data_availability_mode",
                    "fee_data_availability_mode",
                ],
            )?;
            // An account is deployed once, at nonce zero.
            if felt(field(object, "nonce"))? != [0u8; 32] {
                return refused();
            }
            let salt = felt(field(object, "contract_address_salt"))?;
            let class = felt(field(object, "class_hash"))?;
            let constructor = felts(field(object, "constructor_calldata"))?;
            let Some((_, shape)) = argent_classes().into_iter().find(|(c, _)| *c == class) else {
                return refused();
            };
            let expected: Vec<[u8; 32]> = shape(&key).iter().map(Felt::to_bytes_be).collect();
            if salt != *public_key || constructor != expected {
                return refused();
            }
            let elements: Vec<Felt> = constructor.iter().map(Felt::from_bytes_be).collect();
            let address = contract_address(&Felt::from_bytes_be(&class), &key, &elements);
            let hash = poseidon_hash_many(&[
                short_string("deploy_account"),
                Felt::from_bytes_be(&version),
                Felt::from_bytes_be(&address),
                bounds.fee_fields_hash(),
                poseidon_hash_many(&[]),
                chain,
                Felt::ZERO,
                Felt::ZERO,
                poseidon_hash_many(&elements),
                Felt::from_bytes_be(&class),
                Felt::from_bytes_be(&salt),
            ]);
            out.insert("kind".into(), Value::String("deployAccount".into()));
            out.insert("address".into(), Value::String(hex64(&address)));
            out.insert("classHash".into(), Value::String(hex64(&class)));
            out.insert("publicKey".into(), Value::String(hex64(public_key)));
            hash
        }
        _ => return refused(),
    };
    let hash = hash.to_bytes_be();
    out.insert("query".into(), Value::Bool(query));
    out.insert("chain".into(), Value::String("SN_MAIN".into()));
    out.insert("bounds".into(), bounds.reading());
    out.insert("maxFee".into(), Value::String(decimal(&bounds.max_fee())));
    out.insert("hash".into(), Value::String(hex64(&hash)));
    Ok((Value::Object(out), hash))
}
