# Conformance vectors

Test data for the MeshCore Local API, protocol 1 ([SPEC.md](../SPEC.md)). Every file is plain
JSON so any implementation can load it in a unit test.

| File | Covers | SPEC.md |
|---|---|---|
| `pairing.json` | the test key pair, its `X\|\|Y` public key and fingerprint, nonces, the signed strings, valid and invalid signatures, invalid public keys, the client's check of the challenge `message`, the nonce shape | 5 |
| `validators.json` | hashtag channel names, hashtag channel keys, region names, `since`, `path` and `pathHashSize`, payload sizes, `dataType`, text length, `hello.client` name and version | 6, 8 |
| `regions.json` | `regions.resolve` on a synthetic catalogue | 8.3 |

## The test key is public

`pairing.json` contains a P-256 private key. It exists so that signatures can be checked byte
for byte. **Use it in tests only.** A server MUST NOT ship with it in an allowlist, and a client
MUST NOT use it as its identity. Anyone who reads this repository can sign with it.

## How to use the files

* **Fingerprint.** Decode `testKey.publicKey`, check that it is 64 bytes and on the curve,
  and compare your fingerprint function with `testKey.fingerprint`.
* **Signatures (server side).** Every entry in `validSignatures` must verify against
  `testKey.publicKey` in all four encodings (`derBase64`, `rawBase64`, `highSDerBase64`,
  `highSRawBase64`) and must fail against `otherKey.publicKey`. Every case in
  `invalidSignatures.cases` must fail for `invalidSignatures.message`.
* **Signatures (client side).** If your library signs with RFC 6979 (for example Rust `p256`
  or Python `cryptography` with `deterministic_signing=True`), signing `message` with
  `testKey.privateScalarHex` must give exactly `rHex` and `sHex`. A library that signs with a
  random `k` (Java and Android `Signature`, Node `crypto`, Web Crypto) will give a different
  signature each time; check that your signature verifies with the server-side code instead.
  `privateKeyPkcs8DerBase64` loads directly into `KeyFactory`/`PKCS8EncodedKeySpec`, Node
  `createPrivateKey({format: 'der', type: 'pkcs8'})` and Python `load_der_private_key`.
* **Challenge check (client side).** For `challengeMessageCheck`, a client given a challenge
  with that `nonce` accepts exactly the strings in `accept` and refuses everything in `reject`.
* **Public keys.** Every entry in `invalidPublicKeys` must be refused (`bad_request`).
* **Validators.** `valid`, `wellFormed`, `result`, `epochMs` and `expect` give the answer a
  conformant server computes; `error` and `expect` values that are not `ok` are API error
  codes. `"expect": "either"` means both acceptance and `bad_request` conform. In `texts`, a
  `textRepeat` case means the text is `unit` repeated `count` times.
* **Regions.** Load `catalogue` as the server's region list and resolve every case; compare
  `distanceKm` with a tolerance of 0.001 km.

## Where the values come from

`gen/generate.py` writes all three files. It is deterministic: the private key is derived from a
fixed label, the nonce from a fixed string, and signatures use RFC 6979. Each signature is made
twice, by OpenSSL through `cryptography` and by a small pure-Python RFC 6979 signer that is first
checked against the P-256 "sample" vector in RFC 6979 appendix A.2.5. The script stops if the two
disagree.

```sh
uv run --with cryptography python vectors/gen/generate.py
```

Cross-checks that were run against the two existing servers:

* `gen/rust/vectors.rs` against meshcored's `localapi` crate (`crypto.rs`, `protocol.rs`,
  `regions.rs`) and `p256` 0.13. All pairing, name, `since` and region vectors pass, and `p256`
  reproduces every `rHex`/`sHex`. Instructions are at the top of the file.
* `gen/dart/check_vectors.dart` against MeshCore Open's `local_api_crypto.dart` and copies of the
  server's name and `since` helpers. All pairing and name vectors pass. Two `since` cases fail
  because that server accepts a date-time without an offset (`2026-10-26T12:00:00`) and a bare
  date (`2026-10-26`) as local time; SPEC.md appendix B lists this as a required change.

Path, payload, `dataType`, text and client identity vectors were checked by reading the two
servers' validation code (`hub.rs` `path_param`, `text_param`, `prepare_send_inner`;
`local_api_server.dart` `_pathParam`, `_textParam`, `_payloadParam`). Known deviations are in
SPEC.md appendix A.
