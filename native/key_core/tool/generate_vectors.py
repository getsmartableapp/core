"""Writes src/vectors.rs: published BIP-39, BIP-32, BIP-340, SLIP-10, RFC 8032,
Cardano, Bitcoin sighash, EIP-712 and EIP-191 vectors, as Rust data.

The vectors come from files that are not this crate's dependencies, so a
mistake shared by `bip39`/`bip32`/`secp256k1`/`ed25519-dalek` and their own
test copies, or by the core's own SLIP-10 and Cardano code, cannot pass here:

  - BIP-39: trezor/python-mnemonic's English vectors (passphrase "TREZOR"), as
    the Dart `bip39` 1.0.6 package ships them in `test/vectors.json`.
  - BIP-32: bitcoinjs's `fixtures.json`, as the Dart `bip32` 2.0.0 package
    ships it in `test/fixtures.json`. Its first two sets are BIP-32's own test
    vectors 1 and 2; the third is bitcoinjs's.
  - BIP-340: the four signing vectors (index 0 to 3) as RustCrypto's `k256`
    0.14.0 carries them in `src/schnorr.rs` — another implementation of the
    curve, never built into this crate.
  - SLIP-10 ed25519: the specification's test vectors 1 and 2 for ed25519,
    from `slip-0010.md` as raw.githubusercontent.com/satoshilabs/slips/master
    served it on 28 October 2026 (27,049 bytes, SHA-256
    dbd5a324f2a6014bf78fc8cfa85833e4a16256a02283b93d648fccba18ed1ce7) —
    downloaded on the owner's decision O16, kept outside the repository. The
    core's SLIP-10 is its own code (O13), so these are what it answers to.
  - RFC 8032: the five Ed25519 vectors of section 7.1 as Cryspen's
    `libcrux-ed25519` 0.0.9 carries them in `tests/ed25519.rs` — another
    implementation of the curve, never built into this crate.
  - Cardano's Ledger master key: CIP-0003's three vectors, from
    `CIP-0003/Ledger_BitBox02.md` as raw.githubusercontent.com/
    cardano-foundation/CIPs/master served it on 28 October 2026 (3,095 bytes,
    SHA-256 164975c4556ae04fa00377f431e37be35b6fdd2b84b0fd7843a859093c3fe62f),
    downloaded on the owner's decision O18 and kept outside the repository.
  - Cardano's Icarus master key: CIP-0003's two vectors, from
    `CIP-0003/Icarus.md` as raw.githubusercontent.com/cardano-foundation/
    CIPs/master served it on 30 October 2026 (2,794 bytes, SHA-256
    f83da5fbdc6865a0de83edb7219208908e109b2a50671c8a9682d7c3d1179a85),
    downloaded at the owner's request of the same day and kept outside the
    repository. The core's Icarus master and its PBKDF2 are its own code
    (phase 6c), so these are what they answer to.
  - BIP32-Ed25519 (Khovratovich–Law V2) and the extended-key signature:
    `ed25519-bip32` 0.5.0's `src/tests.rs` — a hardened child of a known node,
    and that child's signature of "Hello World" — from the `.crate` file
    downloaded on O18 (14,867 bytes, SHA-256 equal to crates.io's index),
    read and never built; it signs with `cryptoxide`, another implementation.
  - BIP-143: the specification's own three examples — P2WPKH, P2WPKH in P2SH,
    and P2WSH in P2SH under six hash types — as `bitcoin` 0.32.102 carries
    them in `src/crypto/sighash.rs`, from the local cache, read and never
    built (the owner's decision O36 took no `bitcoin` crate).
  - BIP-341: `bip-0341/wallet-test-vectors.json` as raw.githubusercontent.com/
    bitcoin/bips/master served it on 30 October 2026 (29,296 bytes, SHA-256
    403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f) — the
    key-path spends, their signature messages, sighashes, tweaks and
    witnesses, and the output keys of the cases with no script tree.
  - Bitcoin's legacy sighash: Bitcoin Core's `src/test/data/sighash.json` as
    raw.githubusercontent.com/bitcoin/bitcoin/master served it on 30 October
    2026 (210,483 bytes, SHA-256
    52cf23c2076e7f129c71d5508631d3e5ae3be1b1cb0585c0e23bbb4bb373e924).
  - Bitcoin Cash's sighash: Bitcoin Cash Node's `src/test/data/sighash.json`
    as gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/raw/master served it on
    30 October 2026 (486,149 bytes, SHA-256
    f48615ba2c609fbd8a291c2ba9d781e3a60a672712bec56cd3fcb1bea9381510): each
    case answered with the fork flag and without.
    Those three were downloaded on the owner's decision O40 and kept outside
    the repository.
  - EIP-712: the typed-data cases of `alloy-dyn-abi` 1.7.3's
    `src/eip712/typed_data.rs` (28,960 bytes, SHA-256
    925234bee184a26be2cb80160e91ece851c053dec251a513ee9b070f0002ca50) —
    another implementation, from the local cache, read and never built (the
    owner's decision O42). Four it hashes are hashed here to the same digest;
    three are refused here: one alloy refuses too (a primitive's name as the
    primary type), one alloy refuses as circular and the app as incomplete,
    and one alloy hashes over the domain's present fields where the app holds
    the domain to its declared type (`salt` declared and absent). The fourth
    case whose primary type is `EIP712Domain` is written out apart: alloy,
    as MetaMask's `eth-sig-util`, leaves the message's hash out of that
    digest, and since the owner's decision O46 so do the app and the core.
  - EIP-191: `alloy-primitives` 1.7.3's hash of "Hello World"
    (`src/utils/mod.rs`, 17,358 bytes, SHA-256
    6da64989609cd506ebaa08275bd8b09c0cdc24f80126fe57f9a58c4ccf3cc759, from
    web3.js's documentation), and web3.js's signature of "Some data" with the
    address it recovers to (`src/signature/sig.rs`, 31,681 bytes, SHA-256
    dba3d0376a8cc6ed0d2871d3810fa7b9e08e2600ad4b797b92e512c3d5336a22). The
    key that signed it is web3.js's documented test key, as
    `alloy-signer-local` 2.5.0 carries it in `src/lib.rs` (10,725 bytes,
    SHA-256 007698b7c67bb2ab28160997af4eb4ed1d68e073db86e55349265950338bb63a);
    the test holds the key to that address before it holds the signature to
    the published one. All three from the local cache, read and never built.

Of the two `sighash.json` files every fifth case is written out — every
fifth with the fork flag and every tenth without, for Bitcoin Cash Node's —
so the file stays reviewable; `--all` writes every case, for a run held to
the whole of both. Those files print their hashes the way Bitcoin Core
prints a uint256, byte-reversed; they are written here in the order the
hash's bytes come out.

Each BIP-39 vector's master xprv is base58check-decoded here, its checksum
checked, and its 32-byte key written out, so the Rust test compares key bytes
rather than asking the crate under test to parse an xprv.

Usage:
  python3 -I tool/generate_vectors.py \
      ~/.pub-cache/hosted/pub.dev/bip39-1.0.6/test/vectors.json \
      ~/.pub-cache/hosted/pub.dev/bip32-2.0.0/test/fixtures.json \
      ~/.cargo/registry/src/index.crates.io-*/k256-0.14.0/src/schnorr.rs \
      <scratch>/slip-0010.md \
      ~/.cargo/registry/src/index.crates.io-*/libcrux-ed25519-0.0.9/tests/ed25519.rs \
      <scratch>/Ledger_BitBox02.md \
      <scratch>/ed25519-bip32-0.5.0/src/tests.rs \
      <scratch>/Icarus.md \
      ~/.cargo/registry/src/index.crates.io-*/bitcoin-0.32.102/src/crypto/sighash.rs \
      <scratch>/bip341-wallet-test-vectors.json \
      <scratch>/core-sighash.json \
      <scratch>/bchn-sighash.json \
      ~/.cargo/registry/src/index.crates.io-*/alloy-dyn-abi-1.7.3/src/eip712/typed_data.rs \
      ~/.cargo/registry/src/index.crates.io-*/alloy-primitives-1.7.3/src/utils/mod.rs \
      ~/.cargo/registry/src/index.crates.io-*/alloy-primitives-1.7.3/src/signature/sig.rs \
      ~/.cargo/registry/src/index.crates.io-*/alloy-signer-local-2.5.0/src/lib.rs \
      [--all] > src/vectors.rs
"""

import hashlib
import json
import re
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_decode(text):
    number = 0
    for char in text:
        number = number * 58 + ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if digest[:4] != checksum:
        raise ValueError(f"bad checksum: {text}")
    return payload


def xprv_key(text):
    payload = b58check_decode(text)
    # version 4, depth 1, parent fingerprint 4, child number 4, chain code 32,
    # then 0x00 and the 32-byte key.
    if len(payload) != 78 or payload[45] != 0:
        raise ValueError(f"not an xprv: {text}")
    return payload[46:].hex()


def bip340_vectors(path):
    """(secret key, public key, aux, message, signature) of each SignVector."""
    text = open(path).read()
    block = text[text.index("const BIP340_SIGN_VECTORS"):]
    block = block[: block.index("];")]
    field = r'{}:\s*hex!\(\s*"([0-9A-Fa-f\s]+)"\s*\)'
    names = ["secret_key", "public_key", "aux_rand", "message", "signature"]
    pattern = r"SignVector\s*\{\s*index:\s*(\d+),\s*" + r",\s*".join(
        field.format(name) for name in names
    )
    rows = []
    for match in re.finditer(pattern, block):
        index = int(match.group(1))
        if index != len(rows):
            raise ValueError(f"vector {index} out of order")
        rows.append(tuple("".join(match.group(i).split()).lower() for i in range(2, 7)))
    if len(rows) != 4:
        raise ValueError(f"expected the four signing vectors, read {len(rows)}")
    return rows


def slip10_ed25519_vectors(path):
    """(seed, path, chain code, private key, public key) of the two ed25519
    test vectors; the public key without SLIP-10's leading 00."""
    text = open(path).read()
    rows = []
    for number in (1, 2):
        heading = f"### Test vector {number} for ed25519"
        block = text[text.index(heading) + len(heading):]
        block = block[: block.index("\n### ")]
        seed = re.search(r"Seed \(hex\): ([0-9a-f]+)", block).group(1)
        for chain in re.finditer(
            r"\* Chain (\S+)\s*"
            r"\* fingerprint: [0-9a-f]+\s*"
            r"\* chain code: ([0-9a-f]{64})\s*"
            r"\* private: ([0-9a-f]{64})\s*"
            r"\* public: ([0-9a-f]{66})",
            block,
        ):
            at = chain.group(1).replace("<sub>H</sub>", "'")
            public = chain.group(4)
            if not public.startswith("00"):
                raise ValueError(f"an ed25519 public key without its 00: {public}")
            rows.append((seed, at, chain.group(2), chain.group(3), public[2:]))
    if len(rows) != 12:
        raise ValueError(f"expected twelve ed25519 chains, read {len(rows)}")
    return rows


def rfc8032_vectors(path):
    """(secret key, public key, message, signature) of RFC 8032's section 7.1."""
    text = open(path).read()
    consts = dict(re.findall(r'const (\w+)\s*:\s*&str\s*=\s*"([0-9a-f]*)";', text))
    rows = []
    for n in range(1, 6):
        rows.append(tuple(consts[f"{name}_{n}"] for name in ("SK", "VK", "M", "SIG")))
    first = rows[0]
    if first[0] != "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60":
        raise ValueError("TEST 1 is not RFC 8032's")
    return rows


def cip_0003_vectors(path, count, scheme):
    """(phrase, passphrase, 96-byte master node) of one of CIP-0003's pages:
    each vector a <details> block of fenced values — the phrase, a passphrase
    when the block names one, and the master key last."""
    text = open(path).read()
    blocks = text.split("<details>")[1:]
    rows = []
    for block in blocks:
        fences = re.findall(r"```\n\s*(.*?)\n\s*```", block, re.S)
        phrase = fences[0].strip()
        passphrase = ""
        if "passphrase" in block.split("recovery phrase", 1)[1]:
            raw = fences[1].strip()
            if not raw.endswith(" (as utf8 bytes)"):
                raise ValueError(f"an unexpected passphrase: {raw!r}")
            passphrase = raw[: -len(" (as utf8 bytes)")]
        master = fences[-1].strip()
        if not re.fullmatch(r"[0-9a-f]{192}", master):
            raise ValueError(f"not a 96-byte master key: {master!r}")
        rows.append((phrase, passphrase, master))
    if len(rows) != count:
        raise ValueError(f"expected CIP-0003's {count} {scheme} vectors, read {len(rows)}")
    return rows


def cardano_ledger_vectors(path):
    """(phrase, passphrase, 96-byte master node) of CIP-0003's Ledger scheme."""
    return cip_0003_vectors(path, 3, "Ledger")


def cardano_icarus_vectors(path):
    """(phrase, passphrase, 96-byte master node) of CIP-0003's Icarus scheme."""
    return cip_0003_vectors(path, 2, "Icarus")


def ed25519_bip32_vectors(path):
    """(parent node, index, child node, message, child's signature) of
    `ed25519-bip32`'s own tests."""
    text = open(path).read()
    def array(name):
        body = re.search(r"const " + name + r": \[u8; [A-Z_0-9]+\] = \[(.*?)\];", text, re.S)
        return bytes(int(b, 16) for b in re.findall(r"0x([0-9a-f]{2})", body.group(1))).hex()
    message = re.search(r'const MSG: &\'static \[u8\] = b"([^"]*)";', text).group(1)
    index = re.search(r"derive_xprv_eq\(&prv, (0x[0-9a-f]+), D1_H0\)", text).group(1)
    row = (array("D1"), int(index, 16), array("D1_H0"), message.encode().hex(),
           array("D1_H0_SIGNATURE"))
    if len(row[0]) != 192 or len(row[2]) != 192 or len(row[4]) != 128:
        raise ValueError("not the sizes of two nodes and a signature")
    return [row]


def rust_hex(text):
    """A hex literal as Rust source writes it: quotes, `\\` and whitespace
    out."""
    return re.sub(r'[\s\\"]', "", text)


def bip143_vectors(path):
    """(transaction, script code, input index, amount, hash type, sighash)"""
    source = open(path).read()
    literal = r'"((?:[0-9a-fA-F]|\\\s*)+)"'
    rows = []
    for name, index in (("fn bip143_p2wpkh()", 1),
                        ("fn bip143_p2wpkh_nested_in_p2sh()", 0)):
        block = source[source.index(name):]
        block = block[:block.index("#[test]")]
        tx = rust_hex(re.search(r"hex!\(\s*" + literal, block).group(1))
        program = rust_hex(re.search(r"ScriptBuf::from_hex\(\s*" + literal, block).group(1))
        assert program.startswith("0014") and len(program) == 44, program
        amount = int(re.search(r"Amount::from_sat\(([\d_]+)\)", block).group(1).replace("_", ""))
        sighash = re.search(r'"([0-9a-f]{64})"\s*\.parse::<SegwitV0Sighash>', block).group(1)
        # BIP-143: a P2WPKH program's script code is P2PKH of its key hash.
        rows.append((tx, "76a914" + program[4:] + "88ac", index, amount, 0x01, sighash))
    block = source[source.index("fn bip143_p2wsh_nested_in_p2sh_data()"):]
    tx = rust_hex(re.search(r"hex!\(\s*" + literal, block).group(1))
    witness_script = rust_hex(re.search(r"ScriptBuf::from_hex\(\s*" + literal, block).group(1))
    amount = int(re.search(r"Amount::from_sat\(([\d_]+)\)", block).group(1).replace("_", ""))
    first = re.search(r'"([0-9a-f]{64})"\s*\.parse::<SegwitV0Sighash>', block).group(1)
    rows.append((tx, witness_script, 0, amount, 0x01, first))
    types = {"None": 0x02, "Single": 0x03, "AllPlusAnyoneCanPay": 0x81,
             "NonePlusAnyoneCanPay": 0x82, "SinglePlusAnyoneCanPay": 0x83}
    for kind, sighash in re.findall(
            r'bip143_p2wsh_nested_in_p2sh_sighash_\w+, (\w+), "([0-9a-f]{64})"', source):
        rows.append((tx, witness_script, 0, amount, types[kind], sighash))
    assert len(rows) == 8, rows
    return rows


def bip341_vectors(path):
    data = json.load(open(path))
    spending = data["keyPathSpending"][0]
    tx = spending["given"]["rawUnsignedTx"]
    spent = [(u["amountSats"], u["scriptPubKey"]) for u in spending["given"]["utxosSpent"]]
    inputs = []
    for case in spending["inputSpending"]:
        given, step = case["given"], case["intermediary"]
        inputs.append((given["txinIndex"], given["hashType"], given["internalPrivkey"],
                       given["merkleRoot"] or "", step["sigMsg"], step["sigHash"],
                       step["tweak"], step["tweakedPrivkey"], case["expected"]["witness"][0]))
    outputs = [(c["given"]["internalPubkey"], c["intermediary"]["tweak"],
                c["intermediary"]["tweakedPubkey"], c["expected"]["scriptPubKey"])
               for c in data["scriptPubKey"] if c["given"]["scriptTree"] is None]
    return tx, spent, inputs, outputs


def reversed_hex(text):
    return bytes.fromhex(text)[::-1].hex()


def legacy_sighash_vectors(path, every):
    """(transaction, script, input index, hash type, sighash) from Bitcoin
    Core's file, every [every]th case."""
    rows = [r for r in json.load(open(path)) if len(r) == 5]
    return [(tx, script, index, hash_type & 0xFFFFFFFF, reversed_hex(sighash))
            for tx, script, index, hash_type, sighash in rows[::every]]


def forkid_sighash_vectors(path, every):
    """(transaction, script, input index, hash type, with the fork flag,
    without) from Bitcoin Cash Node's file: the cases carrying
    SIGHASH_FORKID every [every]th, the others every second [every]th."""
    rows = [r for r in json.load(open(path)) if len(r) == 6]
    forkid = [r for r in rows if r[3] & 0x40]
    plain = [r for r in rows if not r[3] & 0x40]
    chosen = forkid[::every] + (plain[::2 * every] if every > 1 else plain)
    return [(tx, script, index, hash_type & 0xFFFFFFFF, reversed_hex(regular), reversed_hex(legacy))
            for tx, script, index, hash_type, regular, legacy in chosen]


def json_macro(source, test):
    """The `json!({...})` of the Rust test [test], parsed: its body is JSON as
    written, and its digest the first 64-digit hex literal after it, if any."""
    block = source[source.index(f"fn {test}()"):]
    block = block[:block.index("#[test]")] if "#[test]" in block else block
    start = block.index("json!(") + len("json!(")
    depth = 0
    for end in range(start, len(block)):
        depth += {"{": 1, "}": -1}.get(block[end], 0)
        if depth == 0:
            break
    document = json.loads(block[start:end + 1])
    digest = re.search(r'"([0-9a-f]{64})"', block[end:])
    return json.dumps(document, separators=(",", ":")), digest and digest.group(1)


EIP712_HASHED = ("test_encode_custom_array_type", "test_hash_typed_message_with_data",
                 "test_hash_custom_data_type", "test_hash_nested_struct_array")
EIP712_REFUSED = ("primitive_primary_type_returns_error", "test_hash_recursive_types",
                  "test_full_domain")


def eip712_vectors(path):
    source = open(path).read()
    hashed = [(name, *json_macro(source, name)) for name in EIP712_HASHED]
    assert all(digest for _, _, digest in hashed), hashed
    refused = [(name, json_macro(source, name)[0]) for name in EIP712_REFUSED]
    assert "CircularDependency" in source[source.index("fn test_hash_recursive_types()"):][:4000]
    minimal = json_macro(source, "test_minimal_message")
    assert json.loads(minimal[0])["primaryType"] == "EIP712Domain"
    return hashed, refused, minimal


def eip191_vectors(utils_path, signature_path, signer_path):
    utils = open(utils_path).read()
    block = utils[utils.index("fn test_hash_message()"):]
    hello = re.search(r'let msg = "([^"]+)";', block).group(1)
    hello_hash = re.search(r'b256!\("0x([0-9a-f]{64})"\)', block).group(1)
    signature = open(signature_path).read()
    block = signature[signature.index("fn recover_web3_signature()"):]
    signed = re.search(r'Signature::from_str\(\s*"([0-9a-f]{130})"', block).group(1)
    address = re.search(r'address!\("0x([0-9a-fA-F]{40})"\)', block).group(1)
    message = re.search(r'recover_address_from_msg\("([^"]+)"\)', block).group(1)
    signer = open(signer_path).read()
    keys = set(re.findall(r'"([0-9a-f]{64})"\.parse\(\)', signer))
    assert keys == {"4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"}, keys
    return (hello, hello_hash), (keys.pop(), address, message, signed)


def main(bip39_path, bip32_path, bip340_path, slip10_path, rfc8032_path,
         ledger_path, kholaw_path, icarus_path, bip143_path, bip341_path,
         core_sighash_path, bchn_sighash_path, eip712_path, eip191_utils_path,
         eip191_signature_path, eip191_signer_path, every=5):
    bip39 = json.load(open(bip39_path))["english"]
    bip32 = json.load(open(bip32_path))["valid"]

    out = []
    out.append("//! Generated by `tool/generate_vectors.py`; do not edit by hand.")
    out.append("//! Sources and method: that script's docstring.")
    out.append("")
    out.append("/// (entropy, phrase, seed with passphrase \"TREZOR\", master key)")
    out.append(f"pub(crate) const BIP39_TREZOR: [(&str, &str, &str, &str); {len(bip39)}] = [")
    for entropy, phrase, seed, xprv in bip39:
        out.append(f'    ("{entropy}", "{phrase}", "{seed}", "{xprv_key(xprv)}"),')
    out.append("];")
    out.append("")

    sets = [v for v in bip32 if v["network"] == "bitcoin" and "seed" in v["master"]]
    rows = []
    for vector in sets:
        seed = vector["master"]["seed"]
        rows.append((seed, "m", vector["master"]["privKey"], vector["master"]["pubKey"]))
        for child in vector["children"]:
            if "path" not in child:
                continue
            rows.append((seed, child["path"], child["privKey"], child["pubKey"]))
    out.append("/// (seed, path, private key, compressed public key)")
    out.append(f"pub(crate) const BIP32: [(&str, &str, &str, &str); {len(rows)}] = [")
    for seed, path, key, public in rows:
        out.append(f'    ("{seed}", "{path}", "{key}", "{public}"),')
    out.append("];")
    out.append("")

    schnorr = bip340_vectors(bip340_path)
    out.append("/// (secret key, x-only public key, aux, message, signature)")
    out.append(
        f"pub(crate) const BIP340: [(&str, &str, &str, &str, &str); {len(schnorr)}] = ["
    )
    for row in schnorr:
        out.append("    (" + ", ".join(f'"{value}"' for value in row) + "),")
    out.append("];")
    out.append("")

    slip10 = slip10_ed25519_vectors(slip10_path)
    out.append("/// (seed, path, chain code, private key, public key without SLIP-10's 00)")
    out.append(
        f"pub(crate) const SLIP10_ED25519: [(&str, &str, &str, &str, &str); {len(slip10)}] = ["
    )
    for row in slip10:
        out.append("    (" + ", ".join(f'"{value}"' for value in row) + "),")
    out.append("];")
    out.append("")

    rfc8032 = rfc8032_vectors(rfc8032_path)
    out.append("/// (secret key, public key, message, signature)")
    out.append(f"pub(crate) const RFC8032: [(&str, &str, &str, &str); {len(rfc8032)}] = [")
    for row in rfc8032:
        out.append("    (" + ", ".join(f'"{value}"' for value in row) + "),")
    out.append("];")
    out.append("")

    ledger = cardano_ledger_vectors(ledger_path)
    out.append("/// (phrase, passphrase, master node: kL ‖ kR ‖ chain code)")
    out.append(f"pub(crate) const CARDANO_LEDGER: [(&str, &str, &str); {len(ledger)}] = [")
    for row in ledger:
        out.append("    (" + ", ".join(f'"{value}"' for value in row) + "),")
    out.append("];")
    out.append("")

    kholaw = ed25519_bip32_vectors(kholaw_path)
    out.append("/// (parent node, child index, child node, message, the child's signature)")
    out.append(f"pub(crate) const CARDANO_BIP32: [(&str, u32, &str, &str, &str); {len(kholaw)}] = [")
    for parent, index, child, message, signature in kholaw:
        out.append(f'    ("{parent}", 0x{index:08x}, "{child}", "{message}", "{signature}"),')
    out.append("];")
    out.append("")

    icarus = cardano_icarus_vectors(icarus_path)
    out.append("/// (phrase, passphrase, master node: kL ‖ kR ‖ chain code)")
    out.append(f"pub(crate) const CARDANO_ICARUS: [(&str, &str, &str); {len(icarus)}] = [")
    for row in icarus:
        out.append("    (" + ", ".join(f'"{value}"' for value in row) + "),")
    out.append("];")
    out.append("")

    bip143 = bip143_vectors(bip143_path)
    out.append("/// (transaction, script code, input index, amount, hash type, sighash)")
    out.append(f"pub(crate) const BIP143: [(&str, &str, usize, u64, u32, &str); {len(bip143)}] = [")
    for tx, code, index, amount, hash_type, sighash in bip143:
        out.append(f'    ("{tx}", "{code}", {index}, {amount}, 0x{hash_type:02x}, "{sighash}"),')
    out.append("];")
    out.append("")

    tx, spent, inputs, outputs = bip341_vectors(bip341_path)
    out.append("/// BIP-341's key-path spending: the unsigned transaction")
    out.append(f'pub(crate) const BIP341_TRANSACTION: &str = "{tx}";')
    out.append("/// (amount, script) of each output it spends")
    out.append(f"pub(crate) const BIP341_SPENT: [(u64, &str); {len(spent)}] = [")
    for amount, script in spent:
        out.append(f'    ({amount}, "{script}"),')
    out.append("];")
    out.append("/// (input, hash type, internal key, merkle root or \"\", signature message,")
    out.append("/// sighash, tweak, tweaked key, the witness's signature)")
    out.append(f"pub(crate) const BIP341_INPUTS: [(usize, u8, &str, &str, &str, &str, &str, &str, &str); {len(inputs)}] = [")
    for row in inputs:
        index, hash_type, *rest = row
        out.append(f"    ({index}, 0x{hash_type:02x}, " + ", ".join(f'"{v}"' for v in rest) + "),")
    out.append("];")
    out.append("/// (internal x-only key, tweak, output key, output script), no script tree")
    out.append(f"pub(crate) const BIP341_OUTPUTS: [(&str, &str, &str, &str); {len(outputs)}] = [")
    for row in outputs:
        out.append("    (" + ", ".join(f'"{v}"' for v in row) + "),")
    out.append("];")
    out.append("")

    legacy = legacy_sighash_vectors(core_sighash_path, every)
    out.append("/// Bitcoin Core: (transaction, script, input index, hash type, sighash)")
    out.append(f"pub(crate) const LEGACY_SIGHASH: [(&str, &str, usize, u32, &str); {len(legacy)}] = [")
    for tx, script, index, hash_type, sighash in legacy:
        out.append(f'    ("{tx}", "{script}", {index}, 0x{hash_type:08x}, "{sighash}"),')
    out.append("];")
    out.append("")

    forkid = forkid_sighash_vectors(bchn_sighash_path, every)
    out.append("/// Bitcoin Cash Node: (transaction, script, input index, hash type,")
    out.append("/// sighash with the fork flag, without it)")
    out.append(f"pub(crate) const FORKID_SIGHASH: [(&str, &str, usize, u32, &str, &str); {len(forkid)}] = [")
    for tx, script, index, hash_type, regular, legacy in forkid:
        out.append(f'    ("{tx}", "{script}", {index}, 0x{hash_type:08x}, "{regular}", "{legacy}"),')
    out.append("];")
    out.append("")

    hashed, refused, minimal = eip712_vectors(eip712_path)
    out.append("/// alloy-dyn-abi: (test, typed data, the digest signed)")
    out.append(f"pub(crate) const EIP712_HASHED: [(&str, &str, &str); {len(hashed)}] = [")
    for name, document, digest in hashed:
        out.append(f'    ("{name}", r#"{document}"#, "{digest}"),')
    out.append("];")
    out.append("/// alloy-dyn-abi: (test, typed data the app's validator refuses)")
    out.append(f"pub(crate) const EIP712_REFUSED: [(&str, &str); {len(refused)}] = [")
    for name, document in refused:
        out.append(f'    ("{name}", r#"{document}"#),')
    out.append("];")
    out.append("/// alloy-dyn-abi's `test_minimal_message`: (typed data, alloy's digest,")
    out.append("/// which leaves the message's hash out)")
    out.append(f'pub(crate) const EIP712_DOMAIN_ONLY: (&str, &str) = (r#"{minimal[0]}"#, "{minimal[1]}");')
    out.append("")

    (hello, hello_hash), (key, address, message, signed) = eip191_vectors(
        eip191_utils_path, eip191_signature_path, eip191_signer_path)
    out.append("/// alloy-primitives: (message, its EIP-191 digest)")
    out.append(f'pub(crate) const EIP191_HASH: (&str, &str) = ("{hello}", "{hello_hash}");')
    out.append("/// web3.js: (key, its address, message, signature r ‖ s ‖ v)")
    out.append(f'pub(crate) const EIP191_SIGNED: (&str, &str, &str, &str) = ("{key}", "{address}", "{message}", "{signed}");')
    print("\n".join(out))


if __name__ == "__main__":
    arguments = [a for a in sys.argv[1:] if a != "--all"]
    main(*arguments[:16], every=1 if "--all" in sys.argv else 5)
