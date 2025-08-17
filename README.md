# mysteryn-crypto

This crate provides a range of cryptographic functions, including support for digital signatures, public and private keys, identities and hashes. It also includes functionalities for Decentralized Identifiers (DIDs) and encodings.

Targets: Rust, Wasm, Node.js, Web.

## Docs

See the [`mysteryn-crypto` Readme](./mysteryn-crypto/README.md) for the full description.

Types:

- Hash
- Identity
- Multikey
- Multisig
- Did

Encodings:

- Multibase
- Base32precheck (base32 with a Human Readable Prefix and a checksum)
- varint

Classic algorithms:

- Ed25519
- Ed448
- Secp256k1
- P256
- P384
- P521
- BLS12-381G1
- RSA 3072
- RSA 4096
- X25519
- HmacSha256

Post-quantum algorithms:

- Falcon512
- Falcon1024
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- MLKEM512
- FAEST-128f
- SLH-DSA-shake-128f

## Workspace members

- `mysteryn-crypto` - the primary crypto library,
- `mysteryn-core` - the core functions for writing keys implementations,
- `mysteryn-keys` - a collection of classic and post-quantum digital signature and cryptographic keys algorithms.

## License

This software is licensed under the [MIT license](./LICENSE).
