mod keys;

use keys::*;
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
    let did = public_key.get_did_pkh("mys", None)?;
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
