/*
 * The library the APK would carry, called the way the Dart binding calls it,
 * on the device: it loads under bionic's linker, opens BIP-39's canonical
 * phrase, gives the key test/derivation_vectors_test.dart pins for the first
 * Ethereum account, the ed25519 key of its first Solana account, the Cardano
 * key of its first payment address and the Stark key of its first Argent
 * account, signs with each, and refuses everything once closed. It also opens
 * that phrase from the record the wallet seals it in (phase 6a) and refuses
 * the record with one byte changed; and gives the pinned Icarus key of its
 * first Cardano address and tells the phrase from another (phase 6c); and
 * signs EIP-155's example transaction as the EIP publishes it, refusing it
 * held to another recipient (2c), and only once it has been read for a
 * screen, once (2f-1b); signs web3.js's example message as
 * web3.js publishes it, and EIP-712's example over the digest the EIP
 * publishes, refusing typed data that does not read (2e); and refuses a bare
 * digest at an EVM path or of a key opened as EVM's, signing one at a path
 * no network uses (2e-3); and signs a TRON transfer's digest only once the
 * transfer was read for a screen, once (O58); and signs an XRP payment only
 * once it was read for a screen, its expiry set at the signature, and no
 * digest at XRP's path (O59); and reads EIP-155's example for
 * a review screen, its recipient
 * among the facts, asking the length first (2f-1); and signs EIP-712's
 * example only once a screen was given its reading, once (2f-2).
 *
 * Exits 0 only if all of that holds. Built and run by test_on_emulator.sh,
 * and against the simulator's library by test_on_ios_simulator.sh.
 */
#include <stdio.h>
#include <string.h>

#include "key_core.h"

static const char PHRASE[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about";
static const char PATH[] = "m/44'/60'/0'/0/0";
/* A path no network uses: a secp256k1 key whose digests the core still signs.
 * TRON's and the Cosmos zones' sign only what the core read since O58. */
static const char DIGEST_PATH[] = "m/1'/2'/3'/4/5";
static const char COSMOS_PATH[] = "m/44'/118'/0'/0/0";
static const char TRON_PATH[] = "m/44'/195'/0'/0/0";
static const char XRP_PATH[] = "m/44'/144'/0'/0/0";
/* xrpl_dart's signing serialisation of a payment of 1 XRP, LastLedgerSequence
 * 104; src/tests.rs holds the same. */
static const char XRPL_PAYMENT[] =
    "1200002400000005201b000000686140000000000f424068400000000000000c732102"
    "989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f8114a3"
    "c6b1ee4a49d9f2af3b3802974744fba924164a8314b5f762798a53d543a014caf8b297"
    "cff8f2f937e8";
/* test/derivation_vectors_test.dart, account 0 of this phrase. */
static const char PINNED_KEY[] =
    "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
static const char SOLANA_PATH[] = "m/44'/501'/0'/0'";
/* As blockchain_utils derives it; dart/test/key_core_oracle_test.dart holds
 * both sides to it (Solana's address HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk). */
static const char PINNED_SOLANA_KEY[] =
    "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7";
static const char CARDANO_PATH[] = "m/1852'/1815'/0'/0/0";
/* As blockchain_utils derives it by the Ledger scheme; the oracle test holds
 * both sides to it. */
static const char PINNED_CARDANO_KEY[] =
    "cd2b047d1a803eee059769cffb3dfd0a4b9327e55bc78aa962d9bd4f720db0b2";
/* As blockchain_utils derives it by the Icarus scheme, from the entropy;
 * src/tests.rs and the oracle test hold both sides to it. */
static const char PINNED_ICARUS_KEY[] =
    "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a";
/* EIP-155's example: its signing data, and the r of its signature by the key
 * 0x4646...46. src/tests.rs holds the same. */
static const char EIP155_UNSIGNED[] =
    "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6"
    "b3a764000080018080";
static const char EIP155_R[] =
    "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276";
/* web3.js's documented key, and the r of its signature of "Some data" as a
 * personal message (alloy-primitives carries both); src/tests.rs holds the
 * same. */
static const char WEB3_KEY[] =
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
static const char WEB3_SOME_DATA_R[] =
    "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd";
/* EIP-712's example, Cow's mail to Bob, and the digest the EIP publishes. */
static const char EIP712_SPEC_MAIL[] =
    "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},"
    "{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\","
    "\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":"
    "\"address\"}],\"Person\":[{\"name\":\"name\",\"type\":\"string\"},"
    "{\"name\":\"wallet\",\"type\":\"address\"}],\"Mail\":[{\"name\":"
    "\"from\",\"type\":\"Person\"},{\"name\":\"to\",\"type\":\"Person\"},"
    "{\"name\":\"contents\",\"type\":\"string\"}]},\"primaryType\":\"Mail\","
    "\"domain\":{\"name\":\"Ether Mail\",\"version\":\"1\",\"chainId\":1,"
    "\"verifyingContract\":\"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\"},"
    "\"message\":{\"from\":{\"name\":\"Cow\",\"wallet\":"
    "\"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826\"},\"to\":{\"name\":\"Bob\","
    "\"wallet\":\"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB\"},\"contents\":"
    "\"Hello, Bob!\"}}";
static const char EIP712_SPEC_DIGEST[] =
    "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";
/* BIP-143's second example, P2SH-P2WPKH, as a kc_bitcoin_sign_transaction
 * request (layout: src/lib.rs): the unsigned transaction, its one input of
 * 10 BTC under the example's key, its two outputs, a fee of 3,400 satoshis.
 * The sighash is the example's own; src/tests.rs holds the same. */
static const char BIP143_P2SH_P2WPKH_REQUEST[] =
    "00770000000100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac"
    "4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539"
    "a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fe"
    "a7ad0402e8bd8ad6d77c88ac9204000000ca9a3b000000001700a9144733f37cf4db86fb"
    "c2efed2500b4f4e49f312023870201006d0000000000000200b8b4eb0b00000000190076"
    "a914a457b684d7f0d539a46a45bbc043f35b59d0d96388acff000000000008af2f000000"
    "00190076a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88acff00000000480d00"
    "0000000000";
static const char BIP143_P2SH_P2WPKH_KEY[] =
    "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf";
static const char BIP143_P2SH_P2WPKH_SIGHASH[] =
    "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
/* Another checksum-valid phrase, BIP-39's second vector. */
static const char OTHER_PHRASE[] =
    "legal winner thank year wave sausage worth useful legal winner thank "
    "yellow";
static const char STARKNET_PATH[] = "m/44'/9004'/0'/0/0";
/* As the Starknet module derives it (ArgentAccount, in Dart); the app's
 * test/key_core_modules_test.dart holds both sides to it. */
static const char PINNED_STARKNET_KEY[] =
    "001f03432e214578b6ac859bd1d282e948a615bef54feaf8da02141d42a5f5fa";

/* The phrase sealed by the wallet's own code (pointycastle, as
 * CryptoUtils.encryptBytes calls it) under the key 01 02 ... 20, with the
 * nonce a0 a1 ... ab fixed; src/tests.rs holds the same record. */
static const uint8_t SEALED_KEY[32] = {
    1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
static const char SEALED_HEX[] =
    "a0a1a2a3a4a5a6a7a8a9aaabd8b35c0899da34241e6cc30595ea4ea436b5d1773c070ea4"
    "4639b4933621b61550b3f8a68bbdde144c14a1f7c259200778d411aaa8f490f52986e29e"
    "a6596948cd20c28aca4422d1bbf2279a66b595ffacfd77251c993c56a890a94f933502bf"
    "e7efb90e57e9e5f4b30022347a";

#define CHECK(condition, what)                 \
  do {                                         \
    if (!(condition)) {                        \
      fprintf(stderr, "FAIL: %s\n", what);     \
      return 1;                                \
    }                                          \
  } while (0)

static int from_hex(const char *text, uint8_t *out, size_t length) {
  for (size_t i = 0; i < length; i++) {
    unsigned int byte;
    if (sscanf(text + 2 * i, "%2x", &byte) != 1) return 0;
    out[i] = (uint8_t)byte;
  }
  return 1;
}

static void to_hex(const uint8_t *bytes, size_t length, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    out[2 * i] = digits[bytes[i] >> 4];
    out[2 * i + 1] = digits[bytes[i] & 15];
  }
  out[2 * length] = '\0';
}

int main(void) {
  const uint8_t *phrase = (const uint8_t *)PHRASE;
  const uint8_t *path = (const uint8_t *)PATH;
  size_t path_len = strlen(PATH);
  uint64_t handle = 0;
  const uint8_t *solana = (const uint8_t *)SOLANA_PATH;
  size_t solana_len = strlen(SOLANA_PATH);
  uint8_t key[32], public_key[33], signature[65], digest[32];
  uint8_t ed25519_key[32], ed25519_signature[64], second[64];
  const uint8_t *cardano = (const uint8_t *)CARDANO_PATH;
  size_t cardano_len = strlen(CARDANO_PATH);
  uint8_t cardano_key[32], cardano_node[96];
  const uint8_t *starknet = (const uint8_t *)STARKNET_PATH;
  size_t starknet_len = strlen(STARKNET_PATH);
  uint8_t stark_key[32], stark_signature[64], stark_second[64];
  char hex[65];

  CHECK(kc_abi_version() == KC_ABI_VERSION, "the ABI version");
  CHECK(kc_open(phrase, strlen(PHRASE), &handle) == KC_OK && handle != 0,
        "open");

  CHECK(kc_secp256k1_export_private_key(handle, path, path_len, key,
                                        sizeof key) == KC_OK,
        "export");
  to_hex(key, sizeof key, hex);
  memset(key, 0, sizeof key);
  CHECK(strcmp(hex, PINNED_KEY) == 0, "the pinned key");
  memset(hex, 0, sizeof hex);

  uint8_t sealed[(sizeof SEALED_HEX - 1) / 2];
  uint64_t from_seal = 0;
  CHECK(from_hex(SEALED_HEX, sealed, sizeof sealed), "the sealed record");
  CHECK(kc_open_sealed(sealed, sizeof sealed, SEALED_KEY, sizeof SEALED_KEY,
                       &from_seal) == KC_OK &&
            from_seal != 0,
        "open the sealed phrase");
  CHECK(kc_secp256k1_export_private_key(from_seal, path, path_len, key,
                                        sizeof key) == KC_OK,
        "export from the sealed phrase");
  to_hex(key, sizeof key, hex);
  memset(key, 0, sizeof key);
  CHECK(strcmp(hex, PINNED_KEY) == 0, "the sealed phrase's key is the pinned one");
  memset(hex, 0, sizeof hex);
  CHECK(kc_close(from_seal) == KC_OK, "close the sealed phrase");
  sealed[sizeof sealed - 1] ^= 1; /* the tag's last byte */
  CHECK(kc_open_sealed(sealed, sizeof sealed, SEALED_KEY, sizeof SEALED_KEY,
                       &from_seal) == KC_ERR_SEAL &&
            from_seal == 0,
        "a changed tag refused as a seal");

  CHECK(kc_secp256k1_public_key(handle, path, path_len,
                                KC_PUBLIC_KEY_COMPRESSED, public_key,
                                sizeof public_key) == KC_OK &&
            (public_key[0] == 2 || public_key[0] == 3),
        "the public key");

  memset(digest, 7, sizeof digest);
  CHECK(kc_secp256k1_sign_digest(handle, path, path_len, digest, sizeof digest,
                                 signature, sizeof signature) ==
            KC_ERR_TRANSACTION_ONLY,
        "an EVM key signs no bare digest (O43)");
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)DIGEST_PATH,
                                 strlen(DIGEST_PATH), digest, sizeof digest,
                                 signature, sizeof signature) == KC_OK &&
            signature[64] <= 3,
        "a signature at a path no network uses");
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)COSMOS_PATH,
                                 strlen(COSMOS_PATH), digest, sizeof digest,
                                 signature, sizeof signature) ==
            KC_ERR_UNSHOWN,
        "a Cosmos zone's key refuses a digest no screen was shown");
  /* O58: a TRON key signs only the SHA-256 of a transaction read for a
     screen, once — the reading's txid. */
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)TRON_PATH,
                                 strlen(TRON_PATH), digest, sizeof digest,
                                 signature, sizeof signature) ==
            KC_ERR_UNSHOWN,
        "a TRON key refuses a digest no screen was shown");
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)"m/44'/461'/0'/0/0",
                                 17, digest, sizeof digest, signature,
                                 sizeof signature) == KC_ERR_UNSHOWN,
        "a Filecoin key refuses a digest no screen was shown");
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)"m/44'/223'/0'/0/0",
                                 17, digest, sizeof digest, signature,
                                 sizeof signature) == KC_ERR_UNSHOWN,
        "an ICP key refuses a digest no screen was shown");
  CHECK(kc_secp256k1_schnorr_sign(handle, (const uint8_t *)"m/44'/111111'/0'/0/0",
                                  20, digest, sizeof digest, NULL, 0, signature,
                                  64) == KC_ERR_TRANSACTION_ONLY,
        "a Kaspa key signs no bare digest");
  CHECK(kc_secp256k1_sign_digest_low_r(handle, (const uint8_t *)"m/44'/133'/0'/0/0",
                                       17, digest, sizeof digest, signature,
                                       64) == KC_ERR_TRANSACTION_ONLY,
        "a Zcash key signs no bare digest");
  {
    static const char url[] = "type.googleapis.com/protocol.TransferContract";
    static uint8_t raw[16 + 2 + 2 + 2 + 2 + 45 + 2 + 23 + 23 + 2 + 2];
    static char reading[2048];
    size_t at = 0, needed = 0, written = 0;
    static const uint8_t head[16] = {0x0a, 0x02, 0xab, 0xcd, 0x22, 0x08,
                                     0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                     0x11, 0x11, 0x40, 0x01};
    memcpy(raw + at, head, sizeof head); /* reference block, expiry */
    at += sizeof head;
    raw[at++] = 0x5a; /* the contract, 101 bytes */
    raw[at++] = 0x65;
    raw[at++] = 0x08; /* TransferContract */
    raw[at++] = 0x01;
    raw[at++] = 0x12; /* its parameter, 97 bytes */
    raw[at++] = 0x61;
    raw[at++] = 0x0a;
    raw[at++] = 45;
    memcpy(raw + at, url, 45);
    at += 45;
    raw[at++] = 0x12; /* the value, 48 bytes */
    raw[at++] = 0x30;
    raw[at++] = 0x0a;
    raw[at++] = 0x15;
    raw[at++] = 0x41;
    memset(raw + at, 0x51, 20);
    at += 20;
    raw[at++] = 0x12;
    raw[at++] = 0x15;
    raw[at++] = 0x41;
    memset(raw + at, 0x52, 20);
    at += 20;
    raw[at++] = 0x18; /* 5 sun */
    raw[at++] = 0x05;
    raw[at++] = 0x70; /* the timestamp */
    raw[at++] = 0x01;
    CHECK(at == sizeof raw, "a TRON transfer written");
    CHECK(kc_tron_read_transaction(raw, sizeof raw, NULL, 0, &needed) ==
                  KC_ERR_BUFFER &&
              needed > 0 && needed < sizeof reading,
          "the TRON reading's length asked first");
    CHECK(kc_tron_read_transaction(raw, sizeof raw, (uint8_t *)reading,
                                   sizeof reading - 1, &written) == KC_OK &&
              written == needed,
          "the TRON transfer read for a screen");
    reading[written] = 0;
    const char *txid = strstr(reading, "\"txid\":\"");
    uint8_t tron_digest[32];
    CHECK(strstr(reading, "\"trxTransfer\"") &&
              strstr(reading, "\"amount\":\"5\"") && txid &&
              from_hex(txid + 8, tron_digest, sizeof tron_digest),
          "its transfer, its amount and its id among the facts");
    CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)TRON_PATH,
                                   strlen(TRON_PATH), tron_digest,
                                   sizeof tron_digest, signature,
                                   sizeof signature) == KC_OK &&
              kc_secp256k1_sign_digest(handle, (const uint8_t *)TRON_PATH,
                                       strlen(TRON_PATH), tron_digest,
                                       sizeof tron_digest, signature,
                                       sizeof signature) == KC_ERR_UNSHOWN,
          "the TRON transfer signed once");
  }
  /* O59: an XRP key signs no digest, and only a payment read for a screen,
     once — its expiry set at the signature. */
  CHECK(kc_secp256k1_sign_digest(handle, (const uint8_t *)XRP_PATH,
                                 strlen(XRP_PATH), digest, sizeof digest,
                                 signature, sizeof signature) ==
            KC_ERR_TRANSACTION_ONLY,
        "an XRP key signs no bare digest");
  {
    uint8_t payment[sizeof XRPL_PAYMENT / 2];
    static char reading[2048];
    uint8_t xrpl_signature[64];
    size_t needed = 0, written = 0;
    CHECK(from_hex(XRPL_PAYMENT, payment, sizeof payment),
          "the XRP payment written");
    CHECK(kc_xrpl_sign_transaction(handle, (const uint8_t *)XRP_PATH,
                                   strlen(XRP_PATH), payment, sizeof payment,
                                   xrpl_signature, sizeof xrpl_signature) ==
              KC_ERR_UNSHOWN,
          "an XRP payment refused before its reading");
    CHECK(kc_xrpl_read_transaction(payment, sizeof payment, NULL, 0,
                                   &needed) == KC_ERR_BUFFER &&
              kc_xrpl_read_transaction(payment, sizeof payment,
                                       (uint8_t *)reading, sizeof reading - 1,
                                       &written) == KC_OK &&
              written == needed,
          "the XRP payment read for a screen, its length first");
    reading[written] = 0;
    CHECK(strstr(reading, "\"destination\":\"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh\"") &&
              strstr(reading, "\"amount\":\"1000000\""),
          "its destination and its amount among the facts");
    payment[13] = 0x6c; /* LastLedgerSequence 104 -> 108, at the signature */
    CHECK(kc_xrpl_sign_transaction(handle, (const uint8_t *)XRP_PATH,
                                   strlen(XRP_PATH), payment, sizeof payment,
                                   xrpl_signature,
                                   sizeof xrpl_signature) == KC_OK &&
              kc_xrpl_sign_transaction(handle, (const uint8_t *)XRP_PATH,
                                       strlen(XRP_PATH), payment,
                                       sizeof payment, xrpl_signature,
                                       sizeof xrpl_signature) ==
                  KC_ERR_UNSHOWN,
          "the XRP payment signed once, its expiry moved");
  }

  CHECK(kc_ed25519_public_key(handle, solana, solana_len, ed25519_key,
                              sizeof ed25519_key) == KC_OK,
        "the ed25519 public key");
  to_hex(ed25519_key, sizeof ed25519_key, hex);
  CHECK(strcmp(hex, PINNED_SOLANA_KEY) == 0, "the pinned ed25519 key");
  /* O58: a Solana key signs only a message read for a screen, once, and a
     Stellar or a NEAR key below only a transaction's hash read, and an Aptos
     key only a message read, a Sui key only an intent digest read, and an
     Algorand key only a transaction read, a Tezos key only a group's digest
     read, and a MultiversX key only a transaction read;
     every other
     ed25519 network as before (a path no network uses, below). */
  CHECK(kc_ed25519_sign(handle, solana, solana_len, digest, sizeof digest,
                        ed25519_signature, sizeof ed25519_signature) ==
            KC_ERR_UNSHOWN,
        "a Solana key refuses bytes no screen was shown");
  {
    static uint8_t message[3 + 1 + 3 * 32 + 32 + 1 + 1 + 1 + 2 + 1 + 12];
    static uint8_t reading[2048];
    size_t at = 0, needed = 0, written = 0;
    message[at++] = 1;
    message[at++] = 0;
    message[at++] = 1;
    message[at++] = 3;
    memcpy(message + at, ed25519_key, 32);
    at += 32;
    memset(message + at, 0x22, 32);
    at += 32;
    memset(message + at, 0, 32); /* the System program */
    at += 32;
    memset(message + at, 7, 32); /* the blockhash */
    at += 32;
    message[at++] = 1;            /* one instruction */
    message[at++] = 2;            /* the System program */
    message[at++] = 2;
    message[at++] = 0;
    message[at++] = 1;
    message[at++] = 12;
    message[at++] = 2;            /* Transfer */
    at += 3;
    message[at++] = 0x40;         /* 1,000,000 lamports */
    message[at++] = 0x42;
    message[at++] = 0x0f;
    at += 5;
    CHECK(at == sizeof message, "a Solana transfer written");
    CHECK(kc_solana_read_message(message, sizeof message, NULL, 0, &needed) ==
                  KC_ERR_BUFFER &&
              needed > 0 && needed < sizeof reading,
          "the Solana reading's length asked first");
    CHECK(kc_solana_read_message(message, sizeof message, reading,
                                 sizeof reading - 1, &written) == KC_OK &&
              written == needed,
          "the Solana transfer read for a screen");
    reading[written] = 0;
    CHECK(strstr((const char *)reading, "\"systemTransfer\"") &&
              strstr((const char *)reading, "\"lamports\":\"1000000\""),
          "its transfer and its lamports among the facts");
    CHECK(kc_ed25519_sign(handle, solana, solana_len, message, sizeof message,
                          ed25519_signature,
                          sizeof ed25519_signature) == KC_OK &&
              kc_ed25519_sign(handle, solana, solana_len, message,
                              sizeof message, second,
                              sizeof second) == KC_ERR_UNSHOWN,
          "the Solana transfer signed once");
  }
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/1'/2'/3'", 10, digest,
                        sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_OK &&
            kc_ed25519_sign(handle, (const uint8_t *)"m/1'/2'/3'", 10,
                            digest, sizeof digest, second,
                            sizeof second) == KC_OK &&
            memcmp(ed25519_signature, second, sizeof second) == 0,
        "an ed25519 signature at a path no network uses, the same twice");
  /* O58: a Stellar key signs only the hash of a transaction read for a
     screen. */
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/148'/0'", 13, digest,
                        sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a Stellar key refuses a hash no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/397'/0'", 13, digest,
                        sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a NEAR key refuses a hash no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/637'/0'/0'/0'", 19,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "an Aptos key refuses bytes no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/784'/0'/0'/0'", 19,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a Sui key refuses a digest no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/283'/0'/0'/0'", 19,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "an Algorand key refuses bytes no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/1729'/0'/0'", 17,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a Tezos key refuses a digest no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/508'/0'/0'/0'", 19,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a MultiversX key refuses bytes no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/354'/0'/0'/0'", 19,
                        digest, sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a Polkadot key refuses bytes no screen was shown");
  CHECK(kc_ed25519_sign(handle, (const uint8_t *)"m/44'/607'/0'", 13, digest,
                        sizeof digest, ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a TON key refuses a hash no screen was shown");
  CHECK(kc_ed25519_public_key(handle, (const uint8_t *)"m/44'/501'/0'/0", 15,
                              ed25519_key, sizeof ed25519_key) == KC_ERR_PATH,
        "a level that is not hardened");

  CHECK(kc_cardano_public_key(handle, cardano, cardano_len, cardano_key,
                              sizeof cardano_key) == KC_OK,
        "the Cardano public key");
  to_hex(cardano_key, sizeof cardano_key, hex);
  CHECK(strcmp(hex, PINNED_CARDANO_KEY) == 0, "the pinned Cardano key");
  /* O58: a key at m/1852'/1815' signs only the hash of a body read for a
     screen, one signature a reading. */
  CHECK(kc_cardano_sign(handle, cardano, cardano_len, digest, sizeof digest,
                        ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_UNSHOWN,
        "a Cardano key refuses a hash no screen was shown");
  {
    /* The smallest body the module writes: one input, one output of one ADA
       to an enterprise address, a fee of 0.17 ADA, a time to live. */
    uint8_t body[93];
    size_t at = 0;
    static uint8_t reading[1024];
    size_t needed = 0, written = 0;
    uint8_t hash[32];
    const char *found;
    body[at++] = 0xa4;
    body[at++] = 0x00;
    body[at++] = 0xd9;
    body[at++] = 0x01;
    body[at++] = 0x02;
    body[at++] = 0x81;
    body[at++] = 0x82;
    body[at++] = 0x58;
    body[at++] = 0x20;
    memset(body + at, 0x11, 32);
    at += 32;
    body[at++] = 0x00;
    body[at++] = 0x01;
    body[at++] = 0x81;
    body[at++] = 0xa2;
    body[at++] = 0x00;
    body[at++] = 0x58;
    body[at++] = 0x1d;
    memset(body + at, 0x61, 29);
    at += 29;
    body[at++] = 0x01;
    body[at++] = 0x1a; /* 1,000,000 lovelace */
    body[at++] = 0x00;
    body[at++] = 0x0f;
    body[at++] = 0x42;
    body[at++] = 0x40;
    body[at++] = 0x02;
    body[at++] = 0x1a; /* 170,000 */
    body[at++] = 0x00;
    body[at++] = 0x02;
    body[at++] = 0x98;
    body[at++] = 0x10;
    body[at++] = 0x03;
    body[at++] = 0x19; /* 1,000 */
    body[at++] = 0x03;
    body[at++] = 0xe8;
    CHECK(at == sizeof body, "a Cardano body written");
    /* One signer, the module's first key; named twice, refused. */
    uint8_t signers[2 + 2 + sizeof CARDANO_PATH - 1];
    uint8_t twice[2 + 2 * (2 + sizeof CARDANO_PATH - 1)];
    signers[0] = 1;
    signers[1] = 0;
    signers[2] = (uint8_t)cardano_len;
    signers[3] = 0;
    memcpy(signers + 4, cardano, cardano_len);
    twice[0] = 2;
    twice[1] = 0;
    memcpy(twice + 2, signers + 2, 2 + cardano_len);
    memcpy(twice + 4 + cardano_len, signers + 2, 2 + cardano_len);
    CHECK(kc_cardano_read_transaction(handle, body, sizeof body, twice,
                                      sizeof twice, reading,
                                      sizeof reading - 1, &written) ==
              KC_ERR_TRANSACTION,
          "a Cardano key named twice as a signer refused");
    CHECK(kc_cardano_read_transaction(handle, body, sizeof body, signers,
                                      sizeof signers, NULL, 0, &needed) ==
                  KC_ERR_BUFFER &&
              needed > 0 && needed < sizeof reading,
          "the Cardano reading's length asked first");
    CHECK(kc_cardano_read_transaction(handle, body, sizeof body, signers,
                                      sizeof signers, reading,
                                      sizeof reading - 1, &written) == KC_OK &&
              written == needed,
          "the Cardano body read for a screen");
    reading[written] = 0;
    found = strstr((const char *)reading, "\"hash\":\"0x");
    CHECK(found != NULL && from_hex(found + 10, hash, sizeof hash),
          "its hash among the facts");
    CHECK(strstr((const char *)reading, "\"lovelace\":\"1000000\"") != NULL,
          "and its lovelace");
    CHECK(kc_cardano_sign(handle, cardano, cardano_len, hash, sizeof hash,
                          ed25519_signature,
                          sizeof ed25519_signature) == KC_OK &&
              kc_cardano_sign(handle, cardano, cardano_len, hash, sizeof hash,
                              second, sizeof second) == KC_ERR_UNSHOWN,
          "the Cardano body's hash signed once");
  }
  CHECK(kc_cardano_export_private_key(handle, cardano, cardano_len,
                                      cardano_node,
                                      sizeof cardano_node) == KC_OK,
        "the Cardano export");
  memset(cardano_node, 0, sizeof cardano_node);
  CHECK(kc_cardano_icarus_public_key(handle, cardano, cardano_len, cardano_key,
                                     sizeof cardano_key) == KC_OK,
        "the Icarus public key");
  to_hex(cardano_key, sizeof cardano_key, hex);
  CHECK(strcmp(hex, PINNED_ICARUS_KEY) == 0, "the pinned Icarus key");

  uint8_t matches = 7;
  CHECK(kc_matches_phrase(handle, phrase, strlen(PHRASE), &matches) == KC_OK &&
            matches == 1,
        "the open phrase matches");
  matches = 7;
  CHECK(kc_matches_phrase(handle, (const uint8_t *)OTHER_PHRASE,
                          strlen(OTHER_PHRASE), &matches) == KC_OK &&
            matches == 0,
        "another phrase does not");
  matches = 7;
  CHECK(kc_matches_phrase(handle, phrase, strlen(PHRASE) - 1, &matches) ==
                KC_ERR_PHRASE &&
            matches == 0,
        "a phrase cut short refused as a phrase");

  CHECK(kc_starknet_public_key(handle, starknet, starknet_len, stark_key,
                               sizeof stark_key) == KC_OK,
        "the Stark public key");
  to_hex(stark_key, sizeof stark_key, hex);
  CHECK(strcmp(hex, PINNED_STARKNET_KEY) == 0, "the pinned Stark key");
  digest[0] = 0x07; /* below 2^251 */
  CHECK(kc_starknet_sign(handle, starknet, starknet_len, digest, sizeof digest,
                         stark_signature,
                         sizeof stark_signature) == KC_ERR_UNSHOWN,
        "a Starknet key refuses a hash no screen was shown");
  /* The primitive, at a path no module writes. */
  static const char STARK_FREE[] = "m/1'/2'/3'/4/9";
  CHECK(kc_starknet_sign(handle, (const uint8_t *)STARK_FREE,
                         strlen(STARK_FREE), digest, sizeof digest,
                         stark_signature, sizeof stark_signature) == KC_OK &&
            kc_starknet_sign(handle, (const uint8_t *)STARK_FREE,
                             strlen(STARK_FREE), digest, sizeof digest,
                             stark_second, sizeof stark_second) == KC_OK &&
            memcmp(stark_signature, stark_second, sizeof stark_second) == 0,
        "a Stark signature, the same twice");
  digest[0] = 0x08; /* 2^251 and above are not felts it signs */
  CHECK(kc_starknet_sign(handle, (const uint8_t *)STARK_FREE,
                         strlen(STARK_FREE), digest, sizeof digest,
                         stark_signature,
                         sizeof stark_signature) == KC_ERR_DIGEST,
        "a hash at 2^251 refused");
  digest[0] = 7;

  /* An imported key's session (O22): the phrase's key, opened on its own,
     answers at "m" as the phrase's session does at its path, and nowhere else. */
  uint64_t imported = 0;
  uint8_t imported_public[33];
  CHECK(kc_secp256k1_export_private_key(handle, path, path_len, key,
                                        sizeof key) == KC_OK &&
            kc_open_key(KC_CURVE_SECP256K1, key, sizeof key, &imported) ==
                KC_OK &&
            imported != 0,
        "open an imported secp256k1 key");
  memset(key, 0, sizeof key);
  CHECK(kc_secp256k1_public_key(imported, (const uint8_t *)"m", 1,
                                KC_PUBLIC_KEY_COMPRESSED, imported_public,
                                sizeof imported_public) == KC_OK &&
            memcmp(imported_public, public_key, sizeof public_key) == 0,
        "the imported key's public key at m");
  CHECK(kc_secp256k1_public_key(imported, path, path_len,
                                KC_PUBLIC_KEY_COMPRESSED, imported_public,
                                sizeof imported_public) == KC_ERR_PATH,
        "an imported key at another path refused");
  CHECK(kc_ed25519_public_key(imported, (const uint8_t *)"m", 1, ed25519_key,
                              sizeof ed25519_key) == KC_ERR_KIND,
        "an imported secp256k1 key asked for ed25519 refused");
  CHECK(kc_cardano_icarus_public_key(imported, (const uint8_t *)"m", 1,
                                     cardano_key,
                                     sizeof cardano_key) == KC_ERR_KIND,
        "an imported key asked for Icarus refused");
  CHECK(kc_close(imported) == KC_OK, "close the imported key");
  CHECK(kc_ed25519_export_private_key(handle, solana, solana_len, key,
                                      sizeof key) == KC_OK &&
            kc_open_key(KC_CURVE_ED25519, key, sizeof key, &imported) == KC_OK,
        "open an imported ed25519 key");
  memset(key, 0, sizeof key);
  CHECK(kc_ed25519_public_key(imported, (const uint8_t *)"m", 1, ed25519_key,
                              sizeof ed25519_key) == KC_OK,
        "the imported ed25519 key's public key at m");
  to_hex(ed25519_key, sizeof ed25519_key, hex);
  CHECK(strcmp(hex, PINNED_SOLANA_KEY) == 0, "the imported ed25519 key is the pinned one");
  CHECK(kc_close(imported) == KC_OK, "close the imported ed25519 key");

  /* 2c: EIP-155's example, read, held to the app's transaction and signed. */
  uint8_t eip155_key[32], eip155_unsigned[(sizeof EIP155_UNSIGNED - 1) / 2];
  uint8_t eip155_expected[182];
  memset(eip155_key, 0x46, sizeof eip155_key);
  CHECK(from_hex(EIP155_UNSIGNED, eip155_unsigned, sizeof eip155_unsigned),
        "the EIP-155 signing data");
  memset(eip155_expected, 0, sizeof eip155_expected);
  eip155_expected[32] = 1;                 /* chain 1 */
  eip155_expected[33] = 1;                 /* a recipient */
  memset(eip155_expected + 34, 0x35, 20);
  {
    static const uint8_t ether[8] = {0x0d, 0xe0, 0xb6, 0xb3,
                                     0xa7, 0x64, 0x00, 0x00};
    static const uint8_t gwei20[5] = {0x04, 0xa8, 0x17, 0xc8, 0x00};
    memcpy(eip155_expected + 54 + 24, ether, 8); /* value: 10^18 */
    eip155_expected[86 + 30] = 0x52;             /* gas: 21000 */
    eip155_expected[86 + 31] = 0x08;
    memcpy(eip155_expected + 118 + 27, gwei20, 5); /* gas price: 20 gwei */
  }
  CHECK(kc_open_key(KC_CURVE_SECP256K1, eip155_key, sizeof eip155_key,
                    &imported) == KC_OK,
        "open EIP-155's key");
  CHECK(kc_secp256k1_sign_evm_transaction(
            imported, (const uint8_t *)"m", 1, eip155_unsigned,
            sizeof eip155_unsigned, eip155_expected, sizeof eip155_expected,
            signature, sizeof signature) == KC_ERR_UNSHOWN,
        "a transaction no screen was shown refused (O53)");
  {
    size_t needed = 0;
    uint8_t shown_reading[2048];
    CHECK(kc_evm_read_transaction(imported, (const uint8_t *)"m", 1,
                                  eip155_expected, sizeof eip155_expected,
                                  shown_reading, sizeof shown_reading,
                                  &needed) == KC_OK,
          "EIP-155's example read for a screen");
  }
  CHECK(kc_secp256k1_sign_evm_transaction(
            imported, (const uint8_t *)"m", 1, eip155_unsigned,
            sizeof eip155_unsigned, eip155_expected, sizeof eip155_expected,
            signature, sizeof signature) == KC_OK &&
            signature[64] == 0,
        "EIP-155's example signed");
  to_hex(signature, 32, hex);
  CHECK(strcmp(hex, EIP155_R) == 0, "EIP-155's r");
  CHECK(kc_secp256k1_sign_evm_transaction(
            imported, (const uint8_t *)"m", 1, eip155_unsigned,
            sizeof eip155_unsigned, eip155_expected, sizeof eip155_expected,
            signature, sizeof signature) == KC_ERR_UNSHOWN,
        "one reading signs once");
  eip155_expected[34] ^= 1;
  CHECK(kc_secp256k1_sign_evm_transaction(
            imported, (const uint8_t *)"m", 1, eip155_unsigned,
            sizeof eip155_unsigned, eip155_expected, sizeof eip155_expected,
            signature, sizeof signature) == KC_ERR_TRANSACTION,
        "another recipient refused");
  {
    size_t needed = 0, written = 0;
    char reading[2048];
    CHECK(kc_evm_read_transaction(imported, (const uint8_t *)"m", 1,
                                  eip155_expected, sizeof eip155_expected,
                                  NULL, 0, &needed) == KC_ERR_BUFFER &&
              needed > 0 && needed < sizeof reading,
          "the reading's length asked");
    CHECK(kc_evm_read_transaction(imported, (const uint8_t *)"m", 1,
                                  eip155_expected, sizeof eip155_expected,
                                  (uint8_t *)reading, sizeof reading,
                                  &written) == KC_OK &&
              written == needed,
          "EIP-155's example read");
    reading[written] = 0;
    /* The recipient as the check above left it: 0x34, then nineteen 0x35;
       the sender EIP-155 names, the key's own account. */
    CHECK(strstr(reading, "\"to\":\"0x34" "35353535353535353535"
                          "353535353535353535\"") != NULL &&
              strstr(reading, "\"reading\":\"none\"") != NULL &&
              strstr(reading, "\"from\":\"0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f\"") !=
                  NULL,
          "its sender, its recipient and its empty call data among the facts");
  }
  CHECK(kc_close(imported) == KC_OK, "close EIP-155's key");

  /* 2d: BIP-143's second example, read, held to the request and signed. */
  {
    uint8_t key[32], request[(sizeof BIP143_P2SH_P2WPKH_REQUEST - 1) / 2];
    uint8_t signed_input[96];
    size_t probe = 0;
    CHECK(from_hex(BIP143_P2SH_P2WPKH_KEY, key, sizeof key) &&
              from_hex(BIP143_P2SH_P2WPKH_REQUEST, request, sizeof request),
          "BIP-143's second example");
    CHECK(kc_open_key(KC_CURVE_SECP256K1_BITCOIN, key, sizeof key,
                      &imported) == KC_OK,
          "open its key as a Bitcoin key");
    CHECK(kc_secp256k1_sign_digest(imported, (const uint8_t *)"m", 1, digest,
                                   sizeof digest, signature,
                                   sizeof signature) ==
              KC_ERR_TRANSACTION_ONLY,
          "a Bitcoin key signs no bare digest (O37)");
    /* 2f-3: signed only once a screen was given its reading, once. */
    {
      static uint8_t reading[2048];
      size_t needed = 0, written = 0;
      CHECK(kc_bitcoin_sign_transaction(imported, request, sizeof request,
                                        signed_input, sizeof signed_input) ==
                KC_ERR_UNSHOWN,
            "BIP-143's second example refused before its reading");
      CHECK(kc_bitcoin_read_transaction(imported, request, sizeof request,
                                        NULL, 0, &needed) == KC_ERR_BUFFER &&
                needed > 0 && needed < sizeof reading,
            "the Bitcoin reading's length asked first");
      CHECK(kc_bitcoin_read_transaction(imported, request, sizeof request,
                                        reading, sizeof reading - 1,
                                        &written) == KC_OK &&
                written == needed,
            "BIP-143's second example read for a screen");
      reading[written] = 0;
      CHECK(strstr((const char *)reading, "\"flavour\":\"bitcoin\"") &&
                strstr((const char *)reading, "\"kind\":\"p2shP2wpkh\""),
            "its input's kind among the facts");
    }
    CHECK(kc_bitcoin_sign_transaction(imported, request, sizeof request,
                                      signed_input,
                                      sizeof signed_input) == KC_OK,
          "BIP-143's second example signed");
    CHECK(kc_bitcoin_sign_transaction(imported, request, sizeof request,
                                      signature, 0) == KC_ERR_ARGUMENT,
          "an output of the wrong length");
    to_hex(signed_input, 32, hex);
    CHECK(strcmp(hex, BIP143_P2SH_P2WPKH_SIGHASH) == 0, "its sighash");
    CHECK(kc_bitcoin_sign_transaction(imported, request, sizeof request,
                                      signed_input,
                                      sizeof signed_input) == KC_ERR_UNSHOWN,
          "and once");
    request[sizeof request - 8] ^= 1; /* the fee, one satoshi off */
    CHECK(kc_bitcoin_read_transaction(imported, request, sizeof request, NULL,
                                      0, &probe) == KC_ERR_TRANSACTION,
          "another fee refused");
    CHECK(kc_close(imported) == KC_OK, "close its key");
  }

  /* 2e: an EVM personal message and EIP-712 typed data, hashed here. */
  {
    uint8_t key[32], spec_digest[32], typed[65];
    const uint8_t *m = (const uint8_t *)"m";
    CHECK(from_hex(WEB3_KEY, key, sizeof key) &&
              from_hex(EIP712_SPEC_DIGEST, spec_digest, sizeof spec_digest),
          "web3.js's key and EIP-712's digest");
    CHECK(kc_open_key(KC_CURVE_SECP256K1, key, sizeof key, &imported) == KC_OK,
          "open web3.js's key");
    CHECK(kc_evm_sign_personal_message(imported, m, 1,
                                       (const uint8_t *)"Some data", 9,
                                       signature, sizeof signature) == KC_OK &&
              signature[64] == 1,
          "web3.js's message signed");
    to_hex(signature, 32, hex);
    CHECK(strcmp(hex, WEB3_SOME_DATA_R) == 0, "web3.js's r");
    /* 2f-2: signed only once a screen was given its reading (O54), and
       once; the reading what is signed, its digest the EIP's. */
    {
      static uint8_t reading[4096];
      size_t needed = 0, written = 0;
      CHECK(kc_evm_sign_typed_data(imported, m, 1,
                                   (const uint8_t *)EIP712_SPEC_MAIL,
                                   strlen(EIP712_SPEC_MAIL), typed,
                                   sizeof typed) == KC_ERR_UNSHOWN,
            "EIP-712's example refused before its reading");
      CHECK(kc_evm_read_typed_data(imported, m, 1,
                                   (const uint8_t *)EIP712_SPEC_MAIL,
                                   strlen(EIP712_SPEC_MAIL), NULL, 0,
                                   &needed) == KC_ERR_BUFFER &&
                needed > 0 && needed < sizeof reading,
            "the typed reading's length asked first");
      CHECK(kc_evm_read_typed_data(imported, m, 1,
                                   (const uint8_t *)EIP712_SPEC_MAIL,
                                   strlen(EIP712_SPEC_MAIL), reading,
                                   sizeof reading - 1, &written) == KC_OK &&
                written == needed,
            "EIP-712's example read for a screen");
      reading[written] = 0;
      CHECK(strstr((const char *)reading, "\"primaryType\":\"Mail\"") &&
                strstr((const char *)reading,
                       "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826") &&
                strstr((const char *)reading, EIP712_SPEC_DIGEST) &&
                strstr((const char *)reading,
                       "\"signer\":\"0x2c7536e3605d9c16a7a3d7b1898e529396a65c23\""),
            "its sender as hashed, the EIP's digest, and web3.js's account");
    }
    CHECK(kc_evm_sign_typed_data(imported, m, 1,
                                 (const uint8_t *)EIP712_SPEC_MAIL,
                                 strlen(EIP712_SPEC_MAIL), typed,
                                 sizeof typed) == KC_OK,
          "EIP-712's example signed");
    CHECK(kc_evm_sign_typed_data(imported, m, 1,
                                 (const uint8_t *)EIP712_SPEC_MAIL,
                                 strlen(EIP712_SPEC_MAIL), signature,
                                 sizeof signature) == KC_ERR_UNSHOWN,
          "and once");
    CHECK(kc_secp256k1_sign_digest(imported, m, 1, spec_digest,
                                   sizeof spec_digest, signature,
                                   sizeof signature) == KC_OK &&
              memcmp(signature, typed, sizeof typed) == 0,
          "over the digest the EIP publishes");
    CHECK(kc_evm_sign_typed_data(imported, m, 1, (const uint8_t *)"{}", 2,
                                 typed, sizeof typed) == KC_ERR_TYPED_DATA,
          "typed data that does not read refused");
    CHECK(kc_close(imported) == KC_OK, "close web3.js's key");
    /* The same key opened as EVM's: its message signed as before, no
       digest (O43). */
    CHECK(kc_open_key(KC_CURVE_SECP256K1_EVM, key, sizeof key, &imported) ==
              KC_OK,
          "open web3.js's key as EVM's");
    CHECK(kc_evm_sign_personal_message(imported, m, 1,
                                       (const uint8_t *)"Some data", 9,
                                       signature, sizeof signature) == KC_OK,
          "its message signed");
    to_hex(signature, 32, hex);
    CHECK(strcmp(hex, WEB3_SOME_DATA_R) == 0, "web3.js's r again");
    CHECK(kc_secp256k1_sign_digest(imported, m, 1, spec_digest,
                                   sizeof spec_digest, signature,
                                   sizeof signature) ==
              KC_ERR_TRANSACTION_ONLY,
          "a key opened as EVM's signs no bare digest");
    CHECK(kc_close(imported) == KC_OK, "close it");
    memset(key, 0, sizeof key);
  }
  CHECK(kc_open_key(KC_CURVE_SECP256K1, (const uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 32, &imported) ==
                KC_ERR_KEY &&
            imported == 0,
        "a scalar above the order refused");

  CHECK(kc_close(handle) == KC_OK, "close");
  CHECK(kc_secp256k1_sign_digest(handle, path, path_len, digest, sizeof digest,
                                 signature, sizeof signature) == KC_ERR_HANDLE,
        "a closed handle signs nothing");
  CHECK(kc_ed25519_sign(handle, solana, solana_len, digest, sizeof digest,
                        ed25519_signature,
                        sizeof ed25519_signature) == KC_ERR_HANDLE,
        "a closed handle signs nothing on ed25519");
  CHECK(kc_matches_phrase(handle, phrase, strlen(PHRASE), &matches) ==
                KC_ERR_HANDLE &&
            matches == 0,
        "a closed handle matches nothing");

  printf("so_smoke: all checks passed\n");
  return 0;
}
