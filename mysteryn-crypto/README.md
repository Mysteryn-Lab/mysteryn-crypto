# Mysteryn Crypto

This crate provides a range of cryptographic functions, including support for digital signatures, public and private keys, identities, and hashes. It also includes features for Decentralized Identifiers (DIDs) and various encoding schemes.

**Features:**

- Implements **Multikey** cryptographic keys and **Multisig** digital signature codecs.
- Compatible with **Rust** and **Wasm** targets, including **Node.js** and web browsers.
- Allows the list of supported cryptographic algorithms to be customized or expanded with new custom algorithms.

The following **Classic digital signature** algorithms are included:

| Algorithm                                                                                 | Bits of security | Public key bytes | Signature bytes | Signing time, µs | Verifying time, µs | Memory allocation, bytes |
| ----------------------------------------------------------------------------------------- |:----------------:| ----------------:| ---------------:| ----------------:| ------------------:| ------------------------:|
| [Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)                                  | 128              | 32               | 64              | 28               | 2,555              | 64                       |
| [Ed448](https://datatracker.ietf.org/doc/html/rfc8032)                                    | 224              | 57               | 114             | 16,060           | 16,540             | 2,757                    |
| **Secp256k1**                                                                             | **256**          | 33               | 64              | 123              | 165                | 64                       |
| [P256](https://neuromancer.sk/std/nist/P-256)                                             | 128              | 33               | 90\*            | 577              | 673                | 128                      |
| [P384](https://neuromancer.sk/std/nist/P-384)                                             | 192              | 49               | 133\*           | 1,113            | 1,554              | 192                      |
| **[P521](https://neuromancer.sk/std/nist/P-521)**                                         | **256**          | 66               | 182\*           | 1,543            | 2,015              | 264                      |
| [BLS12-381G1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-00)     | 128              | 96               | 48              | 1,513            | 4,967              | 48                       |
| [~~BLS12-381G2~~](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-00) | 128              | 48               | 96              |                  |                    |                          |
| RSA 3072                                                                                  | 128              | 422              | 384             | 9,388            | 556                | 24,950                   |
| RSA 4096                                                                                  | 140              | 550              | 512             | 17,860           | 896                | 25,210                   |
| X25519                                                                                    | 128              | 32               | 64              | 148              | 2,889              | 326                      |
| ~~X448~~                                                                                  | 224              | 56               |                 |                  |                    |                          |
| **HmacSha256**                                                                            | **256**          | -                | 32              | 2                | 2                  | 32                       |

The following **Post-quantum digital signature** algorithms are included:

| Algorithm                                                                       | Security level | Bits of security | Public key bytes | Signature bytes | Signing time, µs | Verifying time, µs | Memory allocation, bytes |
| ------------------------------------------------------------------------------- |:--------------:|:----------------:| ----------------:| ---------------:| ----------------:| ------------------:| ------------------------:|
| [Falcon512](https://openquantumsafe.org/liboqs/algorithms/sig/falcon.html)      | 1              | 108              | 897              | 666             | 1,841            | 100                | 157,600                  |
| **[Falcon1024](https://openquantumsafe.org/liboqs/algorithms/sig/falcon.html)** | **5**          | 252              | 1,793            | 1,280           | 3,068            | 215                | 315,300                  |
| [ML-DSA-44](https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html)      | 2              | 128\*            | 1,312            | 2,420           | 712              | 187                | 2,420                    |
| [ML-DSA-65](https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html)      | 3              | 192              | 1,952            | 3,309           | 1,318            | 291                | 3,309                    |
| **[ML-DSA-87](https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html)**  | **5**          | 256              | 2,592            | 4,627           | 1,469            | 477                | 4,627                    |
| MLKEM512                                                                        | 1              | 128              | 800              |                 | 247              | 2,987              | 3,239                    |
| FAEST-128f                                                                      | 1              | 128              | 32               | 6,336           | 30,870           | 25,670             | 433,700                  |
| SLH-DSA-shake-128f                                                              | 1              | 128              | 32               | 17,088          | 198,000          | 12,590             | 17,088                   |
| ~~SLH-DSA-shake-192f~~                                                          | 3              | 192              | 48               | 35,664          |                  |                    |                          |
| ~~SLH-DSA-shake-256f~~                                                          | 5              | 256              | 64               | 49,856          |                  |                    |                          |

**Note:**

- Algorithms in **bold** are recommended for their high security and performance.
- Algorithms with a ~~strikethrough~~ are not yet implemented.
- \* The signature size is not fixed.

**Custom digital signature** algorithms can be added by implementing `SecretKeyTrait`, `PublicKeyTrait` and `SignatureTrait`, and including them as a custom key variant. See [`./examples/custom-keys.rs`](./examples/custom-keys.rs) for a demo.

## Examples

### Quick start

Create a file `keys.rs` containing the default implementation of the `SecretKey`, `PublicKey` and `Signature`.

```rust
/// Default implementation of key and signature types.
use mysteryn_crypto::multikey::*;
use mysteryn_keys::DefaultKeyFactory;

/// Multikey secret key.
pub type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
/// Multikey public key.
#[allow(dead_code)]
pub type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
/// Multisig signature.
#[allow(dead_code)]
pub type Signature = Multisig<DefaultKeyFactory>;
```

And use keys (`quick-start.rs`).

```rust
/// Default implementation of key and signature types.
use mysteryn_crypto::multikey::*;
use mysteryn_keys::DefaultKeyFactory;

// keys.rs
////////////////////////////////////////////////////////////////////////////////
/// Multikey secret key.
pub type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
/// Multikey public key.
#[allow(dead_code)]
pub type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
/// Multisig signature.
#[allow(dead_code)]
pub type Signature = Multisig<DefaultKeyFactory>;
////////////////////////////////////////////////////////////////////////////////
// Use this instead.
// mod keys;
// use keys::*;

use mysteryn_crypto::prelude::*;
use mysteryn_crypto::{multicodec::multicodec_prefix, result::Result};

fn main() -> Result<()> {
    let data = "test data";

    println!("--- supported key Secp256k1:");
    // can create
    let secret_key = SecretKey::new(
        multicodec_prefix::SECP256K1_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let public_key = PublicKey::try_from(secret_key.public_key())?;
    let did = public_key.get_did_pkh("mys", "")?;
    println!("secret {secret_key}\npublic {public_key}\nDID {did}");

    // can sign
    let signature = secret_key.sign(data.as_bytes(), None)?;
    println!("signed \"{data}\"\nsignature {signature}");

    // can verify
    public_key.verify(data.as_bytes(), &signature)?;
    println!("Successfully signed and verified data.");

    println!("\n--- not supported key 0x300:");
    assert!(SecretKey::new(0x300, None, None, Some("secret"), Some("pub")).is_err());
    println!("not supported");

    Ok(())
}

/*
    Expected output:
    ```
    --- supported key Secp256k1:
    secret secret_xahgjgzfsxwdjkxun9wspqzgrfx26kvvsz6vjfx27j2lthzsedvylgpy8denujqk8cjcqdq4e0xq8qxur4vfjxhw35e8fpqxg
    public pub_xahgjwwqgrwp6kyqgpyypqz5qkpt7mzxvjqcugmx86l5md6gujt5zxar83mdse558tvsmrsnmsecs6un8u28rq
    DID did:pkh:mys:zgVxC5GqCJFVorUp1d1JLNyuWydwkMWHd8vHUW4T7nyZp5H
    signed "test data"
    signature z5SCDYTvnkBFz5L6tq64PBoypyEJr68eqgD24yWbuWjobxRDVy3tHEWwbz2SQSbQzFhY72R2bNr9rWpmQ9KS4nd91DdRNDECrosem45wBpcHDmLU9dPoi7A
    Successfully signed and verified data.

    --- not supported key 0x300:
    not supported
    ```
*/
```

### Node.js example

```js
import { createSecret, secret2public, public2did, sign, verify, did2public } from "mysteryn-crypto"

const ED25519_SECRET = 0x1300

const secret = createSecret(ED25519_SECRET, null, null, "secret", "pub", null)
console.log("Secret key", secret)

const key = secret2public(secret)
console.log("Public key", key)

const did = public2did(key)
console.log("DID", did)

const obj = {
  a: "test",
  b: 1
}
console.log("Data", obj)

const data = new TextEncoder().encode(
  JSON.stringify(obj)
)

const signature = await sign(data, secret)
console.log("Signature", signature)

// verify with a public key
await verify(data, key, signature)

// verify with the DID
const key2 = did2public(did)
await verify(data, key2, signature)

console.log("Successfully signed and verified data.")

// Expected output:
//
// ```text
// Secret key secret_xa82qzvqqpqyst0kltnd8nxexvv0246g5y4ec3u4v28x9ugv7l4xkdvdzr26hhrgzkmxcza9ey54nq
// Public key pub_xa8tkszqqpqys8hy4d9vwrrz8a0m7jvv56aa0rs63wke4rgdxprvtlr6tj55nflq2q5vjk3nw4623q
// DID did:key:xa8tkszqqpqys8hy4d9vwrrz8a0m7jvv56aa0rs63wke4rgdxprvtlr6tj55nflqdzmuydkftzv3ks
// Data { a: 'test', b: 1 }
// Signature zKEPzYdqYNFuGVUyi97FP7HbKKaT6d4YfkioRLTCbRJkbSrDhifrJDC19teyQbZbdEx3v1XLDTE1nZH9whjEa1ywBUF6GajbwMJyAxSLvrELEbAmNug4E
// Successfully signed and verified data.
// ```
```

## Specification

### Unsigned Varint

This is the encoding scheme for integer numbers, also known as `varuint`.

The encoding rules are as follows:

- Unsigned integers are serialized 7 bits at a time, starting with the least significant bits.
- The most significant bit (MSB) in each output byte indicates if there is a continuation byte (MSB = 1).
- There are no signed integers.
- Integers are minimally encoded.

See the [unsigned-varint specification](https://github.com/multiformats/unsigned-varint) for more details.

Examples:

```text
1 (0x01)        => 00000001 (0x01)
127 (0x7f)      => 01111111 (0x7f)
128 (0x80)      => 10000000 00000001 (0x8001)
255 (0xff)      => 11111111 00000001 (0xff01)
300 (0x012c)    => 10101100 00000010 (0xac02)
16384 (0x4000)  => 10000000 10000000 00000001 (0x808001)
```

### Varbytes

This is the varuint length-prefixed bytes.

```text
<length-varuint><bytes>
```

where

- `length-varuint` - length of bytes encoded as a [multiformats varint](https://github.com/multiformats/unsigned-varint).
- `bytes` - raw bytes.

```text
<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

### Multikey

This is a binary format for encoding secret and public keys.

```text
<multikey-code><codec-code><hrp-varbytes><attributes>
```

where

- `multikey-code` - the value `0x123a` encoded as a [multiformats varint](https://github.com/multiformats/unsigned-varint) (`0xba24`).
- `codec-code` - a varuint-encoded multicode for the key algorithm, as specified in the [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv). Custom algorithms have this value as zero (`0`).
- `hrp-varbytes` - varbytes of the *UTF-8* encoded HRP (Human-Readable Prefix), which can be empty (zero size).
- `attributes` - key attributes encoding.

```text
multikey
sigil           key HRP
|                  |
v                  v
0xba24 <varuint> <hrp> <attributes>
         ^                    ^
         |                    |
    key codec sigil       key attributes


<hrp> ::= <varbytes>

                         variable number of attributes
                                       |
                            ______________________
                           /                      \
<attributes> ::= <varuint> N(<varuint>, <varbytes>)
                     ^           ^          ^
                    /           /           |
            count of      attribute     attribute
          attributes     identifier       value


<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

Key attributes:

**KeyIsEncrypted (0x00)**: A boolean flag indicating if the key data is encrypted.

**KeyData (0x01)**: The key data.

**CipherCodec (0x02)**: The codec sigil specifying the encryption cipher used to encrypt the key data.

**CipherKeyLen (0x03)**: The number of octets in the key encryption key.

**CipherNonce (0x04)**: The nonce value for the key encryption cipher.

**KdfCodec (0x05)**: The codec sigil specifying the key encryption key derivation function.

**KdfSalt (0x06)**: The salt value used in the key encryption key derivation function.

**KdfRounds (0x07)**: The number of rounds used in the key encryption key derivation function.

**Threshold (0x08)**: The number of threshold signature key shares needed to recreate the key.

**Limit (0x09)**: The total number of shares in the split threshold signature key.

**ShareIdentifier (0x0a)**: The identifier for a given threshold key share.

**ThresholdData (0x0b)**: Threshold signing codec-specific data. This is typically used to store the accumulated key shares while gathering enough shares to recreate the key.

**AlgorithmName (0x0c)**: An arbitrary string name for the algorithm. This is optional and is intended to support arbitrary and/or non-standard key types. Used for the custom codec.

**KeyType (0x0d)**: An arbitrary numeric key type attribute. This is optional and is intended to support arbitrary and/or non-standard key types. For the custom codec, `0` or not set means public, and `1` means secret.

**PublicHrp (0x0e)**: The public key's human-readable prefix. This is optional and is used with a secret key only to set the related public key prefix.

See the [Multikey Specification](https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.md) for more details.

### Multisig

This is a binary format for encoding digital signatures.

```text
<multisig-code><codec-code><message-varbytes><attributes>
```

where

- `multisig-code` - the value `0x1239` encoded as a [multiformats varint](https://github.com/multiformats/unsigned-varint) (`0xb924`).
- `codec-code` - a varuint-encoded multicode of the signature algorithm (which is the same as the public key's code), as specified in the [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv). Custom algorithms have this value as zero (`0`).
- `message-varbytes` - the signed data if embedded, or empty with a zero length.
- `attributes` - signature attributes encoding.

```text
signing codec sigil     signature attributes
         |                     |
         v                     v
0x39 <varuint> <message> <attributes>
^                  ^
|                  |
multisig    optional combined
sigil       signature message

<message> ::= <varbytes>

                         variable number of attributes
                                       |
                            ______________________
                           /                      \
<attributes> ::= <varuint> N(<varuint>, <varbytes>)
                     ^           ^          ^
                    /           /           |
            count of      attribute     attribute
          attributes     identifier       value


<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

Signature attributes:

**SigData (0x00)**: The signature data.

**PayloadEncoding (0x01)**: The sigil specifying the encoding of the signed message.

**Scheme (0x02)**: The threshold signing scheme.

**Threshold (0x03)**: The minimum number of signature shares required to reconstruct the signature.

**Limit (0x04)**: The total number of shares for a threshold signature.

**ShareIdentifier (0x05)**: The identifier for the signature share.

**ThresholdData (0x06)**: Codec-specific threshold signature data, which is typically used to accumulate threshold signature shares.

**AlgorithmName (0x07)**: An arbitrary string name for the algorithm. This is optional and is intended to support arbitrary and/or non-standard signature types. It is the signature algorithm name of the custom signature codec.

**Nonce (0x08)**: Nonce bytes (optional). Used for codecs without signature randomization.

**PublicKey (0x09)**: Raw public key bytes (optional). Used for cases when a public key cannot be found otherwise.

See the [Multisig Specification](https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multisig.md) for more details.

### DID

This is the format of the [Decentralized identifier](https://en.wikipedia.org/wiki/Decentralized_identifier).

The **Multidid** binary format:

```txt
<multidid-code><method-name-varbytes><method-code><method-specific-id-varbytes><url-varbytes>
```

where

- `multidid-code` - the value `0x0d1d` encoded as a [multiformats varint](https://github.com/multiformats/unsigned-varint),

- `method-name-varbytes` - the method name string ("key", "pkh", "pkh:mys", ...),

- `method-code` - a varint encoded multicode for the [DID Method identifier](https://www.w3.org/TR/did-core/#a-simple-example) or `0x55` for a general DID, or `0x00` for the Identity,

- `method-specific-id-varbytes` - varbytes, a unique method-specific ID, which may include colons (`:`):
  
  - "did:key": public key bytes.
  - "did:pkh" with the Identity (0x00) codec: identity bytes.
  - "did:pkh" with the Raw (0x55) codec: a string representing `[<network-id>:][<chain-id>:]<account-id>`.
  - "did:*" with the Raw (0x55) codec: a string of the method-specific ID for general DIDs.

- `url-varbytes` - varbytes, an *UTF-8* encoded string representing the [DID URL parameters](https://www.w3.org/TR/did-core/#did-url-syntax).

The DID string format for a general DID:

```txt
did:<method>:<url>
```

The DID string format for the `did:key`:

```txt
did:key:<Multibase(<method-code><public-key-bytes>)>[<url>]
```

The DID string format for the `did:pkh`:

```txt
did:pkh:[<network-id>:][<chain-id>:]<account-id>[<url>]
```

When a HRP is used, the part after "did:pkh:" is an address with "_" replaced by ":".
For example, the address and its DID:

```txt
        mys_xarcs8r9x45wzu9kddgphmkextlkuerv8sdvh64vu380gprhkuhsz9awzs255cgunklu
did:pkh:mys:xarcs8r9x45wzu9kddgphmkextlkuerv8sdvh64vu380gprhkuhsz9awzs255cgunklu
```

See [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) for a detailed description.

Examples:

```text
did:example:123456789abcdefghi
did:key:pub_xa8tkszqmsw43qzqfqsksq2rvlvq8626wvjrcelyjsrd85xlxqzngap0h0jhrfajvgcmwryvztundgd9zw
did:pkh:mys:xarcs8r9x45wzu9kddgphmkextlkuerv8sdvh64vu380gprhkuhsz9awzs255cgunklu
```

### Multihash

This is a binary format for encoding hashes.

```text
<codec-code><hash-data-varbytes>
```

where

- `codec-code` - a varint encoded multicode for the hash algorithm,

- `hash-data-varbytes` - hash bytes.

String format:

```txt
Multibase(<codec-code><hash-data-varbytes>)
```

See the [multihash specification](https://github.com/multiformats/multihash) for more details.

### Identity

This is a format for identities and addresses, which includes a Human-Readable Prefix (HRP) and a hash.

```txt
<hrp-varbytes><codec-code><hash-data-varbytes>
```

where

- `hrp-varbytes` - varbytes of the *UTF-8* encoded HRP (Human-Readable Prefix), which can be empty (zero size).
- `codec-code` - a varint-encoded multicode for the hash algorithm.
- `hash-data-varbytes` - hash bytes.

String format:

```text
<hrp>_<Multibase(<codec-code><hash-data-varbytes>)>
```

### Base32pc

This is a variant of Base32 encoding with the human-readable prefix (`HRP`) and the checksum.

```text
<prefix-string>_xa<Base32(<data><checksum>)>
```

where

- `prefix-string` - a UTF-8 encoded string prefix.
- `_xa` - the underscore delimiter (`_`), the Multibase prefix (`x`), and the encoding version char (`a`)\*.
- `data` - data bytes.
- `checksum` - 8 or more bytes of a Reed-Solomon BCH checksum, which is calculated over the concatenation of the prefix and data (`checksum(<prefix-string>_xa<data>)`).

\* The custom Multibase prefix (`x`) is followed by the encoding character(s). If there are many versions (more than a single character can encode), the Multibase prefix will become (`xx`) to start a new list.

Alternative variant in the Multibase format, without a HRP (uses the prefix `xa`):

```text
xa<Base32(<data><checksum>)>
```

Alternative variant with a constant prefix (is context-dependent):

```text
<prefix-string><Base32(<data><checksum>)>
```

Alphabet:

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

The format is inspired by [Bech32](https://en.bitcoin.it/wiki/Bech32). It uses the same alphabet, but the delimiter is `_` (as it is easier to see than `1`), and it includes a Reed-Solomon BCH checksum and an encoding version. Additionally, this format is not limited by data size.

Examples:

```text
secrettest_xa82qzvqqpqysq4hf8zmg7t5gwn7zahqtg6pg3zmnz5wevvsgpak75ufrlyn0tesny9vkfale342xq
pubtest_xa8tkszqqpqysrhqvweac9lzyhw6ceum9pk2lxaujpv6gqp50uww65ykrqhp83j22gpe8wzx0npm3q
```

## Build and test

### WebAssembly

To build this library to the WebAssembly:

1. Install`wasm-pack`:

   This version does not require your "Cargo.toml" to have `crate-type = ["cdylib", "rlib"]`.

   ```bash
   cargo install --git https://github.com/druide/wasm-pack.git
   ```

2. Build a web package:

   ```bash
   wasm-pack build --target web
   ```

3. Build a npm module:

   ```bash
   wasm-pack build --target nodejs
   ```

Node.js example:

```bash
cd examples/nodejs
npm run reinstall
npm start
```

### Tests and benches

Run tests:

```bash
cargo test
```

Testing with the `WasmEdge` or `wasmtime` (see `.cargo/config.toml` runner):

```bash
cargo test --target wasm32-wasip2 -- --nocapture
```

Testing in a browser with the `wasm-pack`:

```bash
wasm-pack test --chrome
```

Testing in a browser with the `wasm-bindgen-test-runner`:

```bash
NO_HEADLESS=1 cargo test --target wasm32-unknown-unknown -- --nocapture

# Windows version
set NO_HEADLESS=1 && cargo test --target wasm32-unknown-unknown -- --nocapture
```

Coverage.

```bash
RUSTFLAGS="-C instrument-coverage" cargo test --tests
grcov . --binary-path ./target/debug/deps/ -s . -t html --branch --ignore-not-existing --ignore '../*' --ignore "/*" -o target/coverage/html
grcov . -s . --binary-path ./target/debug/ -t lcov --branch --ignore-not-existing -o ./target/debug/
rm -f *.profraw
```

Benchmarks.

Cargo stands benches as tests, so need `--test`. As the memory allocator is
global, need to run in one thread. To distinquish benches, their names start
with "bench":

```bash
cargo bench -- --test --test-threads=1 -q bench
```

or

```bash
cargo b
```

### Run examples

```bash
# run native
cargo run --example quick-start

# run in the WasmEdge or wasmtime
cargo run --target wasm32-wasip2 --example quick-start

# compile and run in the WasmEdge
cargo build --target wasm32-wasip2 --release --example quick-start
wasmedge compile --optimize=z target/wasm32-wasip2/release/examples/quick-start.wasm target/wasm32-wasip2/release/examples/quick-start_aot.wasm
wasmedge run target/wasm32-wasip2/release/examples/quick-start_aot.wasm

# compile and run in the wasmtime
cargo build --target wasm32-wasip2 --release --example quick-start
wasmtime compile target/wasm32-wasip2/release/examples/quick-start.wasm -o target/wasm32-wasip2/release/examples/quick-start.cwasm
wasmtime --allow-precompiled target/wasm32-wasip2/release/examples/quick-start.cwasm
```

```bash
cargo run --example custom-keys
```

## License

Licensed under the [Ethical Use License v1.0](./LICENSE.md).
