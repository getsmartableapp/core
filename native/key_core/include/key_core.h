/*
 * Smartable key core, ABI version 10. Written by hand to match src/lib.rs,
 * which is where each function's rules are documented; the Dart binding
 * (dart/lib/key_core.dart) is the other copy of these declarations.
 *
 * Every function returns one of the KC_* codes below, writes its output only
 * on success, and never unwinds into the caller.
 */
#ifndef SMARTABLE_KEY_CORE_H
#define SMARTABLE_KEY_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KC_ABI_VERSION 41

#define KC_OK 0
#define KC_ERR_ARGUMENT 1   /* null pointer, or a buffer of the wrong length */
#define KC_ERR_HANDLE 2     /* closed or never opened */
#define KC_ERR_PHRASE 3     /* not a checksum-valid English phrase as stored */
#define KC_ERR_PATH 4       /* not m/<index>['] ... as the wallet writes it,
                             or, for ed25519, a level not hardened */
#define KC_ERR_DIGEST 5     /* zero, or not below the curve's order; Starknet:
                               a hash at or above 2^251 */
#define KC_ERR_DERIVATION 6 /* a BIP-32 or BIP32-Ed25519 child that does not exist */
#define KC_ERR_INTERNAL 7   /* a caught panic, or a signature failing its check */
#define KC_ERR_KIND 8       /* a call this session's kind does not answer */
#define KC_ERR_KEY 9        /* kc_open_key: not a key on the curve */
#define KC_ERR_SEAL 10      /* kc_open_sealed: a wrong key, a changed byte, or
                               fewer bytes than a nonce and a tag */
#define KC_ERR_TRANSACTION_ONLY 12 /* a bare digest of a key that signs only
                                      what the core reads: a Bitcoin-family
                                      key, a transaction (O37, and no EVM
                                      message); an EVM key, a transaction, a
                                      message or typed data (O43); a TRON
                                      key or a Cosmos zone's, only
                                      kc_secp256k1_sign_digest of what was
                                      read (O58); an XRP key, no
                                      digest, only kc_xrpl_sign_transaction
                                      (O59); a Kaspa key, no digest, only
                                      kc_kaspa_sign_transaction (O58); a
                                      Zcash key, no digest, only
                                      kc_zcash_sign_transaction */
#define KC_ERR_TYPED_DATA 13 /* kc_evm_sign_typed_data: over 512 KiB, or not
                                EIP-712 typed data as the app's validator
                                reads it (O42, O44) */
#define KC_ERR_BUFFER 14 /* kc_evm_read_transaction, kc_evm_read_typed_data,
                            kc_bitcoin_read_transaction,
                            kc_solana_read_message,
                            kc_tron_read_transaction,
                            kc_xrpl_read_transaction,
                            kc_cosmos_read_sign_doc,
                            kc_stellar_read_transaction,
                            kc_near_read_transaction,
                            kc_aptos_read_transaction,
                            kc_sui_read_transaction,
                            kc_algorand_read_transaction,
                            kc_tezos_read_operation,
                            kc_multiversx_read_transaction,
                            kc_polkadot_read_transaction,
                            kc_ton_read_transfer,
                            kc_filecoin_read_message, kc_icp_read_call,
                            kc_kaspa_read_transaction,
                            kc_zcash_read_transaction,
                            kc_starknet_read_transaction,
                            kc_cardano_read_transaction: out shorter than
                            the
                            reading, or null; *out_len holds what it needs */
#define KC_ERR_UNSHOWN 15 /* kc_secp256k1_sign_evm_transaction: no unused
                             reading for this key covers it — the same
                             facts, a fee within the cap shown (O53);
                             kc_evm_sign_typed_data: no unused reading for
                             this key has its digest (O54);
                             kc_bitcoin_sign_transaction: no unused reading
                             was of this request (2f-3); kc_ed25519_sign by a
                             Solana key: none was of this message (O58);
                             kc_secp256k1_sign_digest by a TRON key: the
                             digest is no unused reading's txid (O58);
                             kc_xrpl_sign_transaction: no unused reading was
                             of this payment, its expiry aside (O59);
                             kc_secp256k1_sign_digest by a Cosmos zone's key:
                             no unused reading's SignDoc hash (O58); by a
                             Filecoin key: no unused reading's message
                             digest (O58); by an ICP key: no unused
                             reading's call digest (O58);
                             kc_kaspa_sign_transaction: no unused reading
                             was of this request (O58);
                             kc_zcash_sign_transaction: no unused reading
                             was of this request; kc_starknet_sign by a
                             key at m/44'/9004': no unused reading of
                             kc_starknet_read_transaction, held to this key,
                             was of this hash (O58);
                             kc_ed25519_sign by a Stellar or a NEAR key: no
                             unused reading's transaction hash; by an Aptos
                             or Movement key, none was of this message; by a
                             Sui key, no unused reading's intent digest; by an
                             Algorand key, none was of this message; by a
                             Tezos key, no unused reading's watermarked group
                             digest; by a MultiversX key, none was of this
                             message; by a Polkadot or a TON key, none for
                             this key was of it (O58) */
#define KC_ERR_TRANSACTION 11 /* kc_secp256k1_sign_evm_transaction,
                                 kc_bitcoin_sign_transaction,
                                 kc_kaspa_sign_transaction and
                                 kc_zcash_sign_transaction: not a
                                 transaction the app writes, or not the one it
                                 built */

#define KC_CURVE_SECP256K1 0 /* kc_open_key: a 32-byte scalar */
#define KC_CURVE_ED25519 1   /* kc_open_key: a 32-byte seed */
#define KC_CURVE_SECP256K1_BITCOIN 2 /* kc_open_key: a Bitcoin-family scalar,
                                        which signs no bare digest (O37) */
#define KC_CURVE_SECP256K1_EVM 3 /* kc_open_key: an EVM scalar, which signs no
                                    bare digest and no Bitcoin transaction
                                    (O43) */
#define KC_CURVE_ED25519_SOLANA 4 /* kc_open_key: a Solana seed, which signs
                                     only a message kc_solana_read_message
                                     read, once (O58) */
#define KC_CURVE_SECP256K1_TRON 5 /* kc_open_key: a TRON scalar, which signs
                                     only the SHA-256 of a transaction
                                     kc_tron_read_transaction read, once, and
                                     no Bitcoin or EVM one (O58) */
#define KC_CURVE_SECP256K1_XRP 6 /* kc_open_key: an XRP Ledger scalar, which
                                    signs only a payment
                                    kc_xrpl_read_transaction read, once, and
                                    no digest (O59) */
#define KC_CURVE_SECP256K1_COSMOS 7 /* kc_open_key: a Cosmos zone's scalar,
                                       which signs only the SHA-256 of a
                                       SignDoc kc_cosmos_read_sign_doc read,
                                       once (O58) */
#define KC_CURVE_ED25519_STELLAR 8 /* kc_open_key: a Stellar seed, which
                                      signs only the hash of a transaction
                                      kc_stellar_read_transaction read, once
                                      (O58) */
#define KC_CURVE_ED25519_SUI 9 /* kc_open_key: a Sui seed, which signs only
                                  the BLAKE2b-256 of an intent message
                                  kc_sui_read_transaction read, once (O58) */
#define KC_CURVE_ED25519_ALGORAND 10 /* kc_open_key: an Algorand seed, which
                                        signs only a transaction
                                        kc_algorand_read_transaction read,
                                        once (O58) */
#define KC_CURVE_ED25519_TEZOS 11 /* kc_open_key: a Tezos seed, which signs
                                     only the watermarked BLAKE2b-256 of a
                                     group kc_tezos_read_operation read, once
                                     (O58) */
#define KC_CURVE_SECP256K1_FILECOIN 12 /* kc_open_key: a Filecoin key, which
                                          signs only the digest of a message
                                          kc_filecoin_read_message read, once,
                                          and no Bitcoin or EVM transaction
                                          (O58) */
#define KC_CURVE_SECP256K1_ICP 13 /* kc_open_key: an ICP key, which signs
                                     only the digest of a call
                                     kc_icp_read_call read, once, and no
                                     Bitcoin or EVM transaction (O58) */
#define KC_CURVE_SECP256K1_KASPA 14 /* kc_open_key: a Kaspa key, which signs
                                       only a send kc_kaspa_read_transaction
                                       read, once, through
                                       kc_kaspa_sign_transaction, and no
                                       digest, message, Bitcoin or EVM
                                       transaction (O58) */
#define KC_CURVE_SECP256K1_ZCASH 15 /* kc_open_key: a Zcash transparent key,
                                       which signs only a send
                                       kc_zcash_read_transaction read, once,
                                       through kc_zcash_sign_transaction, and
                                       no digest, message, Bitcoin or EVM
                                       transaction */

#define KC_PUBLIC_KEY_COMPRESSED 0   /* 33 bytes */
#define KC_PUBLIC_KEY_UNCOMPRESSED 1 /* 65 bytes */

uint32_t kc_abi_version(void);

/* On any refusal *out_handle is 0. */
int32_t kc_open(const uint8_t *phrase, size_t phrase_len, uint64_t *out_handle);

/* The phrase sealed as the wallet stores it: AES-256-GCM, nonce (12) ||
   ciphertext || tag (16), no associated data; key: 32 bytes. The phrase is
   opened and written over inside; only the handle comes back. On any refusal
   *out_handle is 0. */
int32_t kc_open_sealed(const uint8_t *sealed, size_t sealed_len,
                       const uint8_t *key, size_t key_len,
                       uint64_t *out_handle);

/* *out_matches: 1 when candidate is the phrase handle was opened on, 0 when
   it is another; compared by the seeds, in constant time, and nothing of the
   candidate kept. A candidate not in the stored form is KC_ERR_PHRASE, before
   the session is looked at. *out_matches is 0 on any refusal. */
int32_t kc_matches_phrase(uint64_t handle, const uint8_t *candidate,
                          size_t candidate_len, uint8_t *out_matches);

/* Phase 7a, the split backup in the core. kc_slip39_backup splits the
   entropy of the phrase handle was opened on into count SLIP-39 shares,
   threshold of which restore it, each sealed under password (NFC UTF-8) as
   SealedShare version 4 writes it: Argon2id with labels' m, t and p, then
   AES-256-GCM, the labels bid and at sealed beside the words. out: a JSON
   list, per share set, g, m, t, salt and ct; only the share at paper_index
   (255: none) also carries its words, under w. *out_len is the JSON's
   length; out_cap short of it is KC_ERR_BUFFER and the shares are gone. */
int32_t kc_slip39_backup(uint64_t handle, uint8_t threshold, uint8_t count,
                         uint8_t paper_index, const uint8_t *password,
                         size_t password_len, const uint8_t *labels,
                         size_t labels_len, uint8_t *out, size_t out_cap,
                         size_t *out_len);

/* *out_restores: 1 when the sealed bodies in shares (a JSON list) and the
   typed paper words (none when paper_len is 0) give back handle's phrase
   from every set of threshold, opened under password; 0 otherwise. Nothing
   opened leaves. *out_restores is 0 on any refusal. */
int32_t kc_slip39_check(uint64_t handle, const uint8_t *shares,
                        size_t shares_len, const uint8_t *paper,
                        size_t paper_len, uint8_t threshold,
                        const uint8_t *password, size_t password_len,
                        uint8_t *out_restores);

/* Phase 7b, the restore in the core. kc_slip39_restore opens the sealed
   bodies in shares (a JSON list, any version) and the typed shares in extra
   (a JSON list of strings) under password, needs the most any opened body
   says (at least min_threshold), tries every set until one recombines to a
   phrase's entropy, and opens a session on it: the phrase is never text.
   *out_needed and *out_read: how many were needed and distinct ones read.
   Too few: KC_ERR_SHARE_PASSWORD when a copy failed its tag, else
   KC_ERR_SHARE_ALTERED when one disagreed with its labels, else KC_ERR_SHARE;
   no set restoring: KC_ERR_SHARE. *out_handle is 0 on any refusal. */
#define KC_ERR_SHARE_PASSWORD 16
#define KC_ERR_SHARE_ALTERED 17
#define KC_ERR_SHARE 18
int32_t kc_slip39_restore(const uint8_t *shares, size_t shares_len,
                          const uint8_t *extra, size_t extra_len,
                          uint8_t min_threshold, const uint8_t *password,
                          size_t password_len, uint64_t *out_handle,
                          uint8_t *out_needed, uint8_t *out_read);

/* *out_matches: 1 when the sessions handle and other hold one phrase, by
   their seeds in constant time; 0 otherwise and on any refusal. */
int32_t kc_matches_session(uint64_t handle, uint64_t other,
                           uint8_t *out_matches);

/* One imported key opened from its sealed record — sealed under key, the
   account key (32 bytes), in kc_open_sealed's layout — and a one-key session
   on it for curve, as kc_open_key opens one: the key's bytes never cross.
   A record this key does not open, a changed byte or a short record is
   KC_ERR_SEAL. *out_handle is 0 on any refusal. */
int32_t kc_open_sealed_key(int32_t curve, const uint8_t *sealed,
                           size_t sealed_len, const uint8_t *key,
                           size_t key_len, uint64_t *out_handle);

/* The phrase handle was opened on, sealed under key (32 bytes) as the vault
   stores it — kc_open_sealed's layout, the phrase in the stored form — the
   record written to out. *out_len: its length (12 + the phrase + 16);
   out_cap short of it is KC_ERR_BUFFER (256 is room for 24 words). */
int32_t kc_seal_phrase(uint64_t handle, const uint8_t *key, size_t key_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* One imported key (O22): every call for its curve reads it at "m" alone.
   On any refusal *out_handle is 0. */
int32_t kc_open_key(int32_t curve, const uint8_t *secret, size_t secret_len,
                    uint64_t *out_handle);

int32_t kc_close(uint64_t handle);

/* Returns how many handles were open. */
uint64_t kc_close_all(void);

int32_t kc_secp256k1_public_key(uint64_t handle, const uint8_t *path,
                                size_t path_len, int32_t format, uint8_t *out,
                                size_t out_len);

/* out: 65 bytes, r || s || recovery id (0 to 3). A TRON key — a phrase's at
 * m/44'/195', or one opened as KC_CURVE_SECP256K1_TRON — signs only the
 * SHA-256 of a transaction an unused reading of kc_tron_read_transaction was
 * of, once; a Cosmos zone's — at m/44'/118' or m/44'/459', or opened as
 * KC_CURVE_SECP256K1_COSMOS — only the SHA-256 of a SignDoc an unused reading
 * of kc_cosmos_read_sign_doc was of, once; a Filecoin key — at m/44'/461', or
 * opened as KC_CURVE_SECP256K1_FILECOIN — only the BLAKE2b-256 of the CID of
 * a message an unused reading of kc_filecoin_read_message was of, once; an
 * ICP key — at m/44'/223', or opened as KC_CURVE_SECP256K1_ICP — only the
 * SHA-256 of ic-request and the request id of a call an unused reading of
 * kc_icp_read_call was of, once (KC_ERR_UNSHOWN, O58). */
int32_t kc_secp256k1_sign_digest(uint64_t handle, const uint8_t *path,
                                 size_t path_len, const uint8_t *digest,
                                 size_t digest_len, uint8_t *out,
                                 size_t out_len);

/* A TRON transaction's raw_data — whose SHA-256 is its id and what its
 * signature is over — read for the review screen as UTF-8 JSON: its id,
 * reference block, expiry, timestamp, fee limit, memo, and its one contract,
 * decoded where it is a TRX transfer or a contract call (a TRC-20 transfer
 * named); and kept. A field no transaction of this wallet carries, one
 * stated twice, or bytes the app's reader refuses: KC_ERR_TRANSACTION.
 * *out_len receives the length; with out null or out_cap shorter,
 * KC_ERR_BUFFER and nothing else written or kept. No session: nothing secret
 * is read. */
int32_t kc_tron_read_transaction(const uint8_t *raw, size_t raw_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/* A Cosmos SDK SignDoc — whose SHA-256 a SIGN_MODE_DIRECT signature is over
 * — read for the review screen as UTF-8 JSON: the chain, account number,
 * every message (a bank MsgSend decoded), memo, timeout height, each
 * signer's key, mode and sequence, and the fee; and kept. An extension
 * option, a tip, a signer of several keys, a field no transaction of this wallet
 * carries or a singular one twice: KC_ERR_TRANSACTION. *out_len receives the
 * length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing else
 * written or kept. No session. */
int32_t kc_cosmos_read_sign_doc(const uint8_t *sign_doc, size_t sign_doc_len,
                                uint8_t *out, size_t out_cap,
                                size_t *out_len);

/* An XRP Ledger payment's signing serialisation — the bytes after "STX\0" —
 * read for the review screen as UTF-8 JSON: the account, destination and
 * tag, amount and fee in drops, sequence, expiry, flags, signing key and
 * memos; and kept, its LastLedgerSequence aside (O59). A field the module
 * does not write, one out of order or twice, or an issued currency's amount:
 * KC_ERR_TRANSACTION. *out_len receives the length; with out null or out_cap
 * shorter, KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_xrpl_read_transaction(const uint8_t *blob, size_t blob_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/* An XRP key's signature of blob — a payment an unused reading was of in
 * every field but LastLedgerSequence, which it must carry, once
 * (KC_ERR_UNSHOWN, O59) — over the SHA-512 half of "STX\0" and blob, which
 * the core takes. Only an XRP key: a phrase's at m/44'/144', or one opened as
 * KC_CURVE_SECP256K1_XRP (KC_ERR_KIND). out: 64 bytes, r || s, low s. */
int32_t kc_xrpl_sign_transaction(uint64_t handle, const uint8_t *path,
                                 size_t path_len, const uint8_t *blob,
                                 size_t blob_len, uint8_t *out,
                                 size_t out_len);

/* Sign what you see (2c): unsigned is a legacy EIP-155 or an EIP-1559
 * transaction's unsigned bytes; expected is the transaction as the app built
 * it — kind (1: 0 legacy, 2 EIP-1559), chain id (32), recipient presence and
 * address (1 + 20), value, gas limit, gas price or priority fee, maximum fee
 * (32 each, big-endian), then the call data. Read and held to expected before
 * Keccak-256 and the signature. out: 65 bytes, r || s || recovery id. */
int32_t kc_secp256k1_sign_evm_transaction(uint64_t handle, const uint8_t *path,
                                          size_t path_len,
                                          const uint8_t *unsigned_tx,
                                          size_t unsigned_len,
                                          const uint8_t *expected,
                                          size_t expected_len, uint8_t *out,
                                          size_t out_len);

/* The screen shows what the core read (2f-1): expected, in
 * kc_secp256k1_sign_evm_transaction's layout, read for the review for the key
 * at path below handle — that key's address as from, the facts, the fee cap
 * and the call data's reading — as UTF-8 JSON, and kept with that address:
 * one signature of a transaction it covers by that key may then be made
 * (2f-1b). A key the signature refuses: KC_ERR_KIND. *out_len receives the
 * length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing else
 * written or kept. */
int32_t kc_evm_read_transaction(uint64_t handle, const uint8_t *path,
                                size_t path_len, const uint8_t *expected,
                                size_t expected_len, uint8_t *out,
                                size_t out_cap, size_t *out_len);

/* Sign what you see (2e): message is the bytes the review showed; the core
 * prefixes "\x19Ethereum Signed Message:\n" and the length in decimal, and
 * takes Keccak-256 itself. out: 65 bytes, r || s || recovery id. */
int32_t kc_evm_sign_personal_message(uint64_t handle, const uint8_t *path,
                                     size_t path_len, const uint8_t *message,
                                     size_t message_len, uint8_t *out,
                                     size_t out_len);

/* Sign what you see (2e): json is the EIP-712 typed data the review read, as
 * UTF-8; the core reads it and computes keccak256(0x19 0x01 || domain
 * separator || hashStruct(message)) — only of a document an unused reading of
 * kc_evm_read_typed_data has the digest of, once (2f-2, O54). out: 65 bytes,
 * r || s || recovery id. */
int32_t kc_evm_sign_typed_data(uint64_t handle, const uint8_t *path,
                               size_t path_len, const uint8_t *json,
                               size_t json_len, uint8_t *out, size_t out_len);

/* The screen shows what the core read (2f-2): json, as kc_evm_sign_typed_data
 * takes it, read for the review for the key at path below handle as UTF-8
 * JSON — that key's address as signer; what is signed, the declared fields of
 * the domain and the message as hashed; the places of the values the page
 * sent that are not; the digest; and the permit, when the document is one of
 * the six standard permits exactly (O55) — and kept with that address: one
 * signature of a document with its digest by that key may then be made. A
 * key the signature refuses, as it would. *out_len receives the length; with
 * out null or out_cap shorter, KC_ERR_BUFFER and nothing else written or
 * kept. */
int32_t kc_evm_read_typed_data(uint64_t handle, const uint8_t *path,
                               size_t path_len, const uint8_t *json,
                               size_t json_len, uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* A Bitcoin-family transaction, every input signed once the core has read it
   and held it to the request (layout: src/lib.rs) — only a request an unused
   reading of kc_bitcoin_read_transaction was of, once (2f-3). out: 96 bytes
   per input, the sighash then r || s or a BIP-340 signature. */
int32_t kc_bitcoin_sign_transaction(uint64_t handle, const uint8_t *request,
                                    size_t request_len, uint8_t *out,
                                    size_t out_len);

/* The screen shows what the core read (2f-3): request, in
   kc_bitcoin_sign_transaction's layout, held as the signature would hold it —
   change the script of the wallet's key at its path — and read for the review
   as UTF-8 JSON: the flavour, the txid, the inputs, the outputs with whether
   each is change, the sum spent and the fee; and kept. *out_len receives the
   length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing else
   written or kept. */
int32_t kc_bitcoin_read_transaction(uint64_t handle, const uint8_t *request,
                                    size_t request_len, uint8_t *out,
                                    size_t out_cap, size_t *out_len);

/* A Kaspa send, every input signed by BIP-340 over the sighash the core
   computed — BIP-143's shape, every hash BLAKE2b-256 keyed by
   TransactionSigningHash — with the key the request names: a phrase's at
   m/44'/111111', or one opened as KC_CURVE_SECP256K1_KASPA at m (layout:
   src/lib.rs). Only a request an unused reading of kc_kaspa_read_transaction
   was of, once (KC_ERR_UNSHOWN, O58). out: 96 bytes per input, the sighash
   then the signature. */
int32_t kc_kaspa_sign_transaction(uint64_t handle, const uint8_t *request,
                                  size_t request_len, uint8_t *out,
                                  size_t out_len);

/* The screen shows what the core read (O58): request, in
   kc_kaspa_sign_transaction's layout — version 0, Schnorr keys' scripts
   alone, the module's sequence, one signature operation, no lock time, the
   native subnetwork, no gas, the fee the difference — every input the
   signing key's own coin, read for the review as UTF-8 JSON: the inputs, the
   outputs with their kaspa: addresses, which the core spells, and whether
   each is change, the sum sent, the sum spent, the fee and the sighashes;
   and kept. *out_len receives the length; with out null or out_cap shorter,
   KC_ERR_BUFFER and nothing else written or kept. */
int32_t kc_kaspa_read_transaction(uint64_t handle, const uint8_t *request,
                                  size_t request_len, uint8_t *out,
                                  size_t out_cap, size_t *out_len);

/* A transparent Zcash send, every input signed by ECDSA (low R, low s)
   over the ZIP-244 signature digest the core computed under SIGHASH_ALL,
   with the key the request names: a phrase's at m/44'/133', or one opened
   as KC_CURVE_SECP256K1_ZCASH at m (layout: src/lib.rs). Only a request an
   unused reading of kc_zcash_read_transaction was of, once (KC_ERR_UNSHOWN).
   out: 96 bytes per input, the digest then r || s. */
int32_t kc_zcash_sign_transaction(uint64_t handle, const uint8_t *request,
                                  size_t request_len, uint8_t *out,
                                  size_t out_len);

/* The screen shows what the core read: request, in
   kc_zcash_sign_transaction's layout — the unsigned version 5 transaction
   (transparent only, no lock time, an expiry, the module's sequence, empty
   scriptSigs), the coin each input spends, how each recipient was written,
   the fee the difference — every input the signing key's own coin, read for
   the review as UTF-8 JSON: the inputs, the outputs with their t1, t3 or
   tex1 addresses, which the core spells, and whether each is change, the sum
   sent, the sum spent, the fee, the expiry height, the transaction id and
   the signature digests; and kept. *out_len receives the length; with out
   null or out_cap shorter, KC_ERR_BUFFER and nothing else written or kept. */
int32_t kc_zcash_read_transaction(uint64_t handle, const uint8_t *request,
                                  size_t request_len, uint8_t *out,
                                  size_t out_cap, size_t *out_len);

/* For the export screens only. out: 32 bytes. */
int32_t kc_secp256k1_export_private_key(uint64_t handle, const uint8_t *path,
                                        size_t path_len, uint8_t *out,
                                        size_t out_len);

/* out: 65 bytes, chain code (32) || compressed public key (33). */
int32_t kc_secp256k1_extended_public_key(uint64_t handle, const uint8_t *path,
                                         size_t path_len, uint8_t *out,
                                         size_t out_len);

/* For a Bitcoin input. out: 64 bytes, r || s, low s, r < 2^255. */
int32_t kc_secp256k1_sign_digest_low_r(uint64_t handle, const uint8_t *path,
                                       size_t path_len, const uint8_t *digest,
                                       size_t digest_len, uint8_t *out,
                                       size_t out_len);

/* BIP-340. tweak_len 32: BIP-341 key-path tweak first; 0: untweaked, and
 * tweak is not read. out: 64 bytes. */
int32_t kc_secp256k1_schnorr_sign(uint64_t handle, const uint8_t *path,
                                  size_t path_len, const uint8_t *digest,
                                  size_t digest_len, const uint8_t *tweak,
                                  size_t tweak_len, uint8_t *out,
                                  size_t out_len);

/* ed25519 by SLIP-10: every level of path hardened. out: 32 bytes. */
int32_t kc_ed25519_public_key(uint64_t handle, const uint8_t *path,
                              size_t path_len, uint8_t *out, size_t out_len);

/* Ed25519 (RFC 8032) over the message itself, any length; message non-null
 * even when message_len is 0. out: 64 bytes. A Solana key — a phrase's at
 * m/44'/501', or one opened as KC_CURVE_ED25519_SOLANA — signs only a
 * message an unused reading of kc_solana_read_message was of, once; a
 * Stellar key — at m/44'/148', or opened as KC_CURVE_ED25519_STELLAR — only
 * the 32-byte hash of a transaction an unused reading of
 * kc_stellar_read_transaction was of, once; a NEAR key — at m/44'/397' —
 * only the 32-byte hash of a transaction an unused reading of
 * kc_near_read_transaction was of, once; an Aptos or Movement key — at
 * m/44'/637' — only a message an unused reading of kc_aptos_read_transaction
 * was of, once; a Sui key — at m/44'/784', or opened as KC_CURVE_ED25519_SUI
 * — only the BLAKE2b-256 of an intent message an unused reading of
 * kc_sui_read_transaction was of, once; an Algorand key — at m/44'/283', or
 * opened as KC_CURVE_ED25519_ALGORAND — only a message an unused reading of
 * kc_algorand_read_transaction was of, once; a Tezos key — at m/44'/1729',
 * or opened as KC_CURVE_ED25519_TEZOS — only the BLAKE2b-256 of 0x03 and a
 * group an unused reading of kc_tezos_read_operation was of, once; a
 * MultiversX key — at m/44'/508' — only a signing JSON an unused reading of
 * kc_multiversx_read_transaction was of, once; a Polkadot key — at
 * m/44'/354' — only an Asset Hub signing payload an unused reading of
 * kc_polkadot_read_transaction for this key was of, once; a TON key — at
 * m/44'/607' — only the 32-byte hash of a signing message an unused reading
 * of kc_ton_read_transfer for this key was of, once (KC_ERR_UNSHOWN, O58). */
int32_t kc_ed25519_sign(uint64_t handle, const uint8_t *path, size_t path_len,
                        const uint8_t *message, size_t message_len,
                        uint8_t *out, size_t out_len);

/* A Solana message — the bytes after the signature table — read for the
 * review screen as UTF-8 JSON: its header, accounts, fee payer, blockhash,
 * every instruction and what it does where its program is one a send of this
 * wallet's uses, and its lookup tables; and kept. *out_len receives the
 * length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing else
 * written or kept. No session: nothing secret is read. */
int32_t kc_solana_read_message(const uint8_t *message, size_t message_len,
                               uint8_t *out, size_t out_cap, size_t *out_len);

/* A Stellar TransactionSignaturePayload — the network id, the envelope type
 * and the transaction in XDR, whose SHA-256 is its id and what its signature
 * is over — read for the review screen as UTF-8 JSON: the network, source,
 * fee, sequence, time window, memo and every operation; and kept. Another
 * envelope, a precondition beyond a time window, an operation the module
 * does not write, a Soroban extension, a padding byte not zero:
 * KC_ERR_TRANSACTION. *out_len receives the length; with out null or out_cap
 * shorter, KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_stellar_read_transaction(const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len);

/* A NEAR Transaction's Borsh bytes, whose SHA-256 is its id and what its
 * signature is over, read for the review screen as UTF-8 JSON: the signer,
 * its key, the nonce, the receiver, the block, every transfer's deposit and
 * the hash; and kept. An account id NEAR would not take, a key not ed25519,
 * no action or one not a transfer, a byte after the last: KC_ERR_TRANSACTION.
 * *out_len receives the length; with out null or out_cap shorter,
 * KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_near_read_transaction(const uint8_t *transaction,
                                 size_t transaction_len, uint8_t *out,
                                 size_t out_cap, size_t *out_len);

/* An Aptos RawTransaction's signing message — SHA3-256 of
 * "APTOS::RawTransaction", then its BCS — which an Aptos or Movement
 * signature is over, read for the review screen as UTF-8 JSON: the sender,
 * sequence number, function, recipient, amount, gas ceiling and price, expiry
 * and chain id; and kept. Another domain, a payload not an entry function, a
 * function not 0x1::aptos_account::transfer with its address and amount, a
 * ULEB128 not in its shortest form, a byte after the chain id:
 * KC_ERR_TRANSACTION. *out_len receives the length; with out null or out_cap
 * shorter, KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_aptos_read_transaction(const uint8_t *message, size_t message_len,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* A Sui intent message — the intent's three bytes, then the TransactionData's
 * BCS — whose BLAKE2b-256 a Sui signature is over, read for the review screen
 * as UTF-8 JSON: the sender, recipient, amount, gas coins, owner, price and
 * budget, and the transaction's digest; and kept. Another intent or kind, a
 * programme other than the module's transfer, an expiry, a ULEB128 not in
 * its shortest form, a byte after the last field: KC_ERR_TRANSACTION.
 * *out_len receives the length; with out null or out_cap shorter,
 * KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_sui_read_transaction(const uint8_t *message, size_t message_len,
                                uint8_t *out, size_t out_cap, size_t *out_len);

/* "TX" and an Algorand transaction's canonical msgpack, which its signature
 * is over, read for the review screen as UTF-8 JSON: the id, whether the
 * genesis is mainnet's, and every field tagged with its kind; and kept. Not
 * canonical as the module writes it, no sender or type, a rekey, a close or
 * an asset close: KC_ERR_TRANSACTION. *out_len receives the length; with out
 * null or out_cap shorter, KC_ERR_BUFFER and nothing else written or kept.
 * No session. */
int32_t kc_algorand_read_transaction(const uint8_t *message,
                                     size_t message_len, uint8_t *out,
                                     size_t out_cap, size_t *out_len);

/* A Tezos operation group as this wallet's forger writes it — the branch,
 * then each operation — whose BLAKE2b-256 after the watermark 0x03 its
 * signature is over, read for the review screen as UTF-8 JSON: the branch and
 * every reveal and transaction with its source, fee, counter, limits, amount,
 * destination, entrypoint and argument; and kept. An operation the forger
 * never writes, a key not ed25519, a zarith not in its shortest form, a
 * Micheline node it does not write, a byte after: KC_ERR_TRANSACTION.
 * *out_len receives the length; with out null or out_cap shorter,
 * KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_tezos_read_operation(const uint8_t *forged, size_t forged_len,
                                uint8_t *out, size_t out_cap,
                                size_t *out_len);

/* A MultiversX transaction's signing JSON, which its signature is over, read
 * for the review screen as UTF-8 JSON: the nonce, value, receiver, sender,
 * gas price and limit, the data and its text, the chain and whether it is
 * mainnet's; and kept. Any spelling but the module's — another key or order,
 * whitespace, an escape, a leading zero, a version other than 1, an address
 * not an erd1 bech32 of 32 bytes, data not canonical base64:
 * KC_ERR_TRANSACTION. *out_len receives the length; with out null or out_cap
 * shorter, KC_ERR_BUFFER and nothing else written or kept. No session. */
int32_t kc_multiversx_read_transaction(const uint8_t *payload,
                                       size_t payload_len, uint8_t *out,
                                       size_t out_cap, size_t *out_len);

/* A Polkadot Asset Hub extrinsic's signing payload, which its signature is
 * over, read for the review screen for the Polkadot key at path below
 * handle's seed as UTF-8 JSON: that key's public half as signer, the call
 * (Balances.transfer_keep_alive), the destination, the amount, the era's
 * period and phase, the nonce, the tip, the spec and transaction versions,
 * the genesis and the era's block, and whether the genesis is Asset Hub's;
 * and kept with that key. Any other call or address kind, an immortal era,
 * an asset paying the fee, a metadata hash, a compact not in its shortest
 * form, a byte after: KC_ERR_TRANSACTION; a path not m/44'/354' or not
 * hardened: KC_ERR_PATH; a one-key session: KC_ERR_KIND. *out_len receives
 * the length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing
 * else written or kept. */
int32_t kc_polkadot_read_transaction(uint64_t handle, const uint8_t *path,
                                     size_t path_len, const uint8_t *payload,
                                     size_t payload_len, uint8_t *out,
                                     size_t out_cap, size_t *out_len);

/* A TON wallet v4R2 signing message as a bag of cells, whose root's hash its
 * signature is over, read for the review screen for the TON key at path below
 * handle's seed as UTF-8 JSON: that key's public half as publicKey, the
 * subwallet, the expiry, the seqno, every message — its mode, bounce flag,
 * destination, value and body (nothing, a comment, or a jetton transfer
 * whose forward payload is nothing, a comment or a STON.fi swap) — and the
 * hash, which the core takes; and kept with that key. Another root count, an
 * exotic cell, a CRC32C wrong, a cell not reached, another wallet's opcode, a
 * state init, an extra currency, another body, a Coins not in its shortest
 * form: KC_ERR_TRANSACTION; a path not m/44'/607' or not hardened:
 * KC_ERR_PATH; a one-key session: KC_ERR_KIND. *out_len receives the length;
 * with out null or out_cap shorter, KC_ERR_BUFFER and nothing else written or
 * kept. */
int32_t kc_ton_read_transfer(uint64_t handle, const uint8_t *path,
                             size_t path_len, const uint8_t *boc,
                             size_t boc_len, uint8_t *out, size_t out_cap,
                             size_t *out_len);

/* For the export screens only. out: 32 bytes, SLIP-10's key. */
int32_t kc_ed25519_export_private_key(uint64_t handle, const uint8_t *path,
                                      size_t path_len, uint8_t *out,
                                      size_t out_len);

/* Cardano: BIP32-Ed25519 from the Ledger scheme's master key; normal levels
 * allowed. out: 32 bytes. */
int32_t kc_cardano_public_key(uint64_t handle, const uint8_t *path,
                              size_t path_len, uint8_t *out, size_t out_len);

/* Cardano by the Icarus scheme (CIP-0003): BIP32-Ed25519 below the master key
 * Yoroi, Eternl and Daedalus build from the phrase's entropy. A public key
 * only; nothing signs under it. out: 32 bytes. */
int32_t kc_cardano_icarus_public_key(uint64_t handle, const uint8_t *path,
                                     size_t path_len, uint8_t *out,
                                     size_t out_len);

/* By the extended key (kL the scalar, kR the nonce prefix), over the message
 * itself. out: 64 bytes. A key at m/1852'/1815' signs only the 32-byte
 * BLAKE2b-256 of a body a reading of kc_cardano_read_transaction was of with
 * this key among its signers, once (KC_ERR_UNSHOWN, O58). */
int32_t kc_cardano_sign(uint64_t handle, const uint8_t *path, size_t path_len,
                        const uint8_t *message, size_t message_len,
                        uint8_t *out, size_t out_len);

/* A Cardano transaction body's CBOR, whose BLAKE2b-256 every witness signs,
 * read for the review screen as UTF-8 JSON with the keys that will sign it:
 * the inputs, the outputs — each address and its lovelace — the fee, the
 * time to live, the hash and the signers' payment key hashes. signers: two
 * bytes of count, then per signer two bytes of length and its path at
 * m/1852'/1815' below handle's phrase (layout: src/lib.rs). One witness per
 * payment key: two signers of one key hash, KC_ERR_TRANSACTION, nothing
 * kept. Kept for each signer named, once each time it is given. Another key
 * than the inputs, outputs, fee and time to live, a native asset, a datum,
 * an input twice, a length indefinite, a number not in its shortest form, a
 * byte after: KC_ERR_TRANSACTION. *out_len receives the length; with out
 * null or out_cap shorter, KC_ERR_BUFFER and nothing else written or kept. */
int32_t kc_cardano_read_transaction(uint64_t handle, const uint8_t *body,
                                    size_t body_len, const uint8_t *signers,
                                    size_t signers_len, uint8_t *out,
                                    size_t out_cap, size_t *out_len);

/* A Filecoin message's CBOR, whose CID's BLAKE2b-256 its signature is over,
 * read for the review screen as UTF-8 JSON: the recipient and the sender as
 * f1 addresses, the nonce, the value, the gas limit, the fee cap, the
 * premium, the CID and the digest, which the core takes; and kept. Another
 * version, a method call, parameters, an address other than f1, a negative
 * amount, a big integer with a leading zero, a CBOR number not in its
 * shortest form, a byte after: KC_ERR_TRANSACTION. *out_len receives the
 * length; with out null or out_cap shorter, KC_ERR_BUFFER and nothing else
 * written or kept. No session. */
int32_t kc_filecoin_read_message(const uint8_t *message, size_t message_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/* An ICP call's content map as CBOR, whose request id's domain-separated
 * SHA-256 its signature is over, read for the review screen as UTF-8 JSON:
 * the ledger's transfer — the recipient's account identifier, the amount,
 * the fee, the memo, the creation time — the sender, the expiry, the request
 * id and the digest, which the core takes; and kept. Another canister or
 * method, a nonce, a subaccount, no creation time, an account identifier
 * whose checksum is wrong, a type table not the module's, a CBOR head not
 * shortest, a byte after: KC_ERR_TRANSACTION. *out_len receives the length;
 * with out null or out_cap shorter, KC_ERR_BUFFER and nothing else written
 * or kept. No session. */
int32_t kc_icp_read_call(const uint8_t *content, size_t content_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/* For the export screens only. out: 96 bytes, kL || kR || chain code. */
int32_t kc_cardano_export_private_key(uint64_t handle, const uint8_t *path,
                                      size_t path_len, uint8_t *out,
                                      size_t out_len);

/* Starknet by Argent's derivation: path is in the second tree
 * (m/44'/9004'/0'/0/i), seeded by the key at m/44'/60'/0'/0/0.
 * out: 32 bytes, x of the public point, big-endian. */
int32_t kc_starknet_public_key(uint64_t handle, const uint8_t *path,
                               size_t path_len, uint8_t *out, size_t out_len);

/* Stark ECDSA over a 32-byte big-endian hash below 2^251, RFC 6979 nonce.
 * out: 64 bytes, r || s, big-endian. A key at m/44'/9004' signs only the hash
 * of a transaction a reading of kc_starknet_read_transaction was of, held to
 * this key, once (KC_ERR_UNSHOWN, O58). */
int32_t kc_starknet_sign(uint64_t handle, const uint8_t *path, size_t path_len,
                         const uint8_t *hash, size_t hash_len, uint8_t *out,
                         size_t out_len);

/* The screen shows what the core read (O58): a v3 Starknet transaction's
 * JSON body as the module sends it, unsigned — an INVOKE of one ERC-20
 * transfer, or a DEPLOY_ACCOUNT of an Argent class, at version 3 or the
 * query version — held to the Stark key at path (m/44'/9004'/...): an
 * invoke's sender its Argent account, a deployment's salt and constructor
 * its own. Read for the review as UTF-8 JSON: the kind, whether a query, the
 * network, the bounds and the most they cost, the sender, nonce, token,
 * recipient and amount or the deployment's address, class and key, and the
 * Poseidon hash, which the core takes; and kept with the key. Any other
 * transaction: KC_ERR_TRANSACTION; another path: KC_ERR_PATH. *out_len
 * receives the length; with out null or out_cap shorter, KC_ERR_BUFFER and
 * nothing else written or kept. */
int32_t kc_starknet_read_transaction(uint64_t handle, const uint8_t *path,
                                     size_t path_len,
                                     const uint8_t *transaction,
                                     size_t transaction_len, uint8_t *out,
                                     size_t out_cap, size_t *out_len);

/* For the export screens only. out: 32 bytes, the ground Stark key. */
int32_t kc_starknet_export_private_key(uint64_t handle, const uint8_t *path,
                                       size_t path_len, uint8_t *out,
                                       size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SMARTABLE_KEY_CORE_H */
