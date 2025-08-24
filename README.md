# Mysteryn Crypto

This repository provides a range of cryptographic functions, including support for digital signatures, public and private keys, identities, and hashes. It also includes features for Decentralized Identifiers (DIDs) and various encoding schemes.

**Targets:** Rust, Wasm, Node.js, Web.

## Documentation

For a full description of the project, see the [`mysteryn-crypto` README](./mysteryn-crypto/README.md).

**Types:**

- Hash
- Identity
- Multikey
- Multisig
- DID

**Encodings:**

- Multibase
- Base32precheck (Base32 with a Human-Readable Prefix and a checksum)
- Varint

**Classic Algorithms:**

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

**Post-Quantum Algorithms:**

- Falcon512
- Falcon1024
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- MLKEM512
- FAEST-128f
- SLH-DSA-shake-128f

## Workspace Members

- `mysteryn-crypto` - The primary crypto library.
- `mysteryn-core` - Core functions for writing key implementations.
- `mysteryn-keys` - (External repo) A collection of classic and post-quantum digital signature and cryptographic key algorithms.

## License

This software is licensed under the [MIT license](./LICENSE).
