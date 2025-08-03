// cargo run --features=bls12381 --example custom_key_set

mod custom_keys;

use custom_keys::*;
use mysteryn_crypto::prelude::*;
use mysteryn_crypto::{
    attributes::SignatureAttributes, multicodec::multicodec_prefix, result::Result,
};
use std::str::FromStr;

const UNSUPPORTED_SECRET: &str = "zCNWdZsMTcGKpkYDX6HUSAzhX6FJJg98fHfCPzyctuLof";

fn main() -> Result<()> {
    println!("--- supported default key Secp256k1:");
    // can create
    let secret_key = SecretKey::new(
        multicodec_prefix::SECP256K1_SECRET,
        None,
        None,
        Some("custom_secret"),
        Some("custom"),
    )?;
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();
    println!("secret {}\npublic {}", secret_key, public_key);
    // can sign
    let data = b"test data";
    let nonce = b"12345678";
    let mut attributes = SignatureAttributes::default();
    attributes.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attributes))?;
    println!("signed \"test data\":\nsignature {}", signature);
    public_key.verify(data, &signature)?;

    println!("--- supported additional key Bls12381G1:");
    // can create
    let secret_key = SecretKey::new(
        multicodec_prefix::BLS12381G1_SECRET,
        None,
        None,
        Some("custom_secret"),
        Some("custom"),
    )?;
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();
    println!("secret {}\npublic {}", secret_key, public_key);
    // can sign
    let data = b"test data";
    let nonce = b"12345678";
    let mut attributes = SignatureAttributes::default();
    attributes.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attributes))?;
    println!("signed \"test data\":\nsignature {}", signature);
    public_key.verify(data, &signature)?;

    println!("--- unsupported key P256:");
    assert!(
        SecretKey::new(
            multicodec_prefix::P256_SECRET,
            None,
            None,
            Some("custom_secret"),
            Some("custom")
        )
        .is_err()
    );
    assert!(SecretKey::from_str(UNSUPPORTED_SECRET).is_err());
    println!("not supported");

    Ok(())
}

/*
Expected output:

```
--- supported default key Secp256k1:
secret custom_secret_xahgjgzfsdvd6hxar0d40hxetrwfjhgqspyql65jeq7hxw8hdky35ark2xzsk8dcznmgyg6kwrc55yfn9j5npczrsxvd6hxar0dk8q8stch8ch2ps
public custom_xahgjwwqgxvd6hxar0d5qszggzyfmertegs520t3vuzjtydl3hmeta70sra8x5zsmhj3knfag9pg30axdxg89nma7x
signed "test data":
signature zgJecdHT1CP1bnwhdzPBgxao9FdFXHXgcJ4kXxmHquBZP6nbYnKEdYnujrwZUeQy16SJvvbwzvz9kvwvWsYS5mr8dysbtMHmydwrxv1D2d5QLmGS3
--- supported additional key Bls12381G1:
secret custom_secret_xahgjgjfsdvd6hxar0d40hxetrwfjhgqspyrphdlctmzwx2exltc4dxzs3d6nlmtmf5va2umktffcrkf9w7klnyrsxvd6hxar0dh3un506w2ad02q
public custom_xahgjw5qgxvd6hxar0d5qszcyjtvsgm4nyxq4lry3fhjttl7axng2kj0pxdmtvqlh8p3sk5aaz9esljrhd6d86xzrgdy6l3wpzlxj3y39gy87enujv4aludw55p8yxq7ju3p7x8qn9c0sut5uc28qajhcwy0gfn4k7dlxcvkjkz8wc0e6uqpc04nv8scn3s
signed "test data":
signature z2qusDfBWovGe6TJWNa7vMJRSHu6BFbWZszbK2qfGJNeuzUf3aek66TanW1qkD7ZtDErtwvMHTZMCVH9QAcVJTtrRNyHRS47
--- unsupported key P256:
not supported
```
*/
