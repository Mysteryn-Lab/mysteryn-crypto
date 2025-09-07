use crate::{
    attributes::{
        KEY_ALGRORITHM_NAME, KEY_DATA, KEY_IS_ENCRYPTED, KEY_PUBLIC_HRP, KEY_TYPE, KeyAttributes,
        SIG_ALGRORITHM_NAME, SIG_DATA, SIG_NONCE, SIG_PAYLOAD_ENCODING, SIG_PUBLIC_KEY, SIG_SCHEME,
        SignatureAttributes,
    },
    multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{read_varbytes, read_varint_u64},
};
use concat_string::concat_string;
use std::fmt::Write as _;

#[inline]
fn read_prefix(buf: &mut &[u8], name: &str) -> Result<u64> {
    let val = read_varint_u64(buf)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError(concat_string!("cannot read ", name, " prefix")))?;
    Ok(val)
}

fn write_str(s: &mut String, fmt: std::fmt::Arguments) {
    s.write_fmt(fmt).unwrap(); // internal errors are impossible here
}

pub(crate) fn key_to_debug_string(key: &[u8], algorithm: &str) -> Result<String> {
    let mut key = key;
    let mut s = String::new();
    // Multisig prefix
    let prefix = read_prefix(&mut key, "key")?;
    if prefix != multicodec_prefix::MULTIKEY {
        return Err(Error::EncodingError(concat_string!(
            "not a Multikey prefix 0x",
            &hex::encode(prefix.to_be_bytes())
        )));
    }
    // key codec
    let key_codec = read_varint_u64(&mut key)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read key codec".to_owned()))?;
    // HRP
    let hrp = read_varbytes(&mut key).map_err(|e| Error::IOError(e.to_string()))?;

    // Attributes
    let attributes = KeyAttributes::from_reader(&mut key)?;
    if let Some(alg) = attributes.get_algorithm_name()? {
        write_str(&mut s, format_args!("algorithm_name: {alg}"));
    } else {
        write_str(&mut s, format_args!("algorithm_name: {algorithm}"));
    }

    write_str(&mut s, format_args!(", codec: 0x{key_codec:02x}"));
    if !hrp.is_empty() {
        write_str(
            &mut s,
            format_args!(
                ", hrp: {}",
                std::str::from_utf8(&hrp).unwrap_or("cannot read hrp")
            ),
        );
    }

    if let Some(t) = attributes.get_key_type()? {
        write_str(
            &mut s,
            format_args!(", key_type: {}", if t == 1 { "secret" } else { "public" }),
        );
    }

    if attributes.get_key_is_encrypted()? {
        s += ", is_encrypted: true";
    }

    if let Some(kd) = attributes.get_key_data() {
        write_str(&mut s, format_args!(", key_size: {}", kd.len()));
    } else {
        s += ", no key data";
    }

    for attr in &attributes.0.0 {
        if ![
            KEY_ALGRORITHM_NAME,
            KEY_TYPE,
            KEY_PUBLIC_HRP,
            KEY_DATA,
            KEY_IS_ENCRYPTED,
        ]
        .contains(attr.0)
        {
            write_str(
                &mut s,
                format_args!(" ,{}: 0x{}", attr.0, hex::encode(attr.1)),
            );
        }
    }
    Ok(s)
}

pub(crate) fn signature_to_debug_string(signature: &[u8], algorithm: &str) -> Result<String> {
    let mut signature = signature;
    let mut s = String::new();
    // Multisig prefix
    let prefix = read_prefix(&mut signature, "signature")?;
    if prefix != multicodec_prefix::MULTISIG {
        return Err(Error::EncodingError(concat_string!(
            "not a Multisig prefix 0x",
            &hex::encode(prefix.to_be_bytes())
        )));
    }
    // signature codec
    let signature_codec = read_varint_u64(&mut signature)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read signature codec".to_owned()))?;
    // A message
    let msg = read_varbytes(&mut signature).map_err(|e| Error::IOError(e.to_string()))?;

    // Attributes
    let attributes = SignatureAttributes::from_reader(&mut signature)?;
    if let Some(alg) = attributes.get_algorithm_name()? {
        write_str(&mut s, format_args!("algorithm_name: {alg}"));
    } else {
        write_str(&mut s, format_args!("#algorithm_name: {algorithm}"));
    }

    write_str(&mut s, format_args!(", codec: 0x{signature_codec:02x}"));
    if !msg.is_empty() {
        write_str(
            &mut s,
            format_args!(
                ", message: {}",
                std::str::from_utf8(&msg).unwrap_or("cannot read a messsage")
            ),
        );
    }

    if let Some(enc) = attributes.get_payload_encoding()? {
        write_str(&mut s, format_args!(", payload_encoding: 0x{enc:02x}"));
    }
    if let Some(pk) = attributes.get_public_key() {
        write_str(
            &mut s,
            format_args!(", public_key: {}", multibase::to_base58(pk)),
        );
    }
    if let Some(scheme) = attributes.get_scheme()? {
        write_str(&mut s, format_args!(", scheme: 0x{scheme:02x}"));
    }
    if let Some(nonce) = attributes.get_nonce() {
        write_str(
            &mut s,
            format_args!(
                ", nonce_size: {}, nonce: {}",
                nonce.len(),
                multibase::to_base58(nonce)
            ),
        );
    }
    if let Some(sd) = attributes.get_signature_data() {
        write_str(&mut s, format_args!(", signature_size: {}", sd.len()));
    } else {
        s += ", no signature data";
    }
    for attr in attributes.raw() {
        if ![
            SIG_DATA,
            SIG_PAYLOAD_ENCODING,
            SIG_SCHEME,
            SIG_ALGRORITHM_NAME,
            SIG_NONCE,
            SIG_PUBLIC_KEY,
        ]
        .contains(attr.0)
        {
            write_str(
                &mut s,
                format_args!(" ,{}: 0x{}", attr.0, hex::encode(attr.1)),
            );
        }
    }
    Ok(s)
}
#[cfg(test)]
mod tests {
    use crate::{
        key_traits::*,
        multikey::util::{key_to_debug_string, signature_to_debug_string},
        multikey::{MultikeyPublicKey, MultikeySecretKey, Multisig},
        result::Result,
    };
    use mysteryn_keys::DefaultKeyFactory;
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;

    const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgy85w6a709xu0qk3hl0unyc7ytc8dmgca22w4ejswdjkgdde6d4r58qxur4v2xmyflkjl4eg";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_key_to_debug_string() -> Result<()> {
        let secret_key = SecretKey::from_str(SECRET1)?;
        let public_key = PublicKey::try_from(secret_key.public_key())?;

        let secret_key_debug =
            key_to_debug_string(&secret_key.to_bytes(), secret_key.algorithm_name())?;
        let public_key_debug =
            key_to_debug_string(&public_key.to_bytes(), public_key.algorithm_name())?;

        assert!(secret_key_debug.contains("algorithm_name: EdDSA"));
        //assert!(secret_key_debug.contains("key_type: secret"));
        assert!(public_key_debug.contains("algorithm_name: EdDSA"));
        //assert!(public_key_debug.contains("key_type: public"));

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_signature_to_debug_string() -> Result<()> {
        let secret_key = SecretKey::from_str(SECRET1)?;
        let data = b"test data";
        let signature = secret_key.sign(data, None)?;
        let multisig = Multisig::<DefaultKeyFactory>::try_from(&signature)?;

        let signature_debug =
            signature_to_debug_string(multisig.as_bytes(), multisig.algorithm_name())?;

        assert!(signature_debug.contains("algorithm_name: EdDSA"));
        assert!(signature_debug.contains("signature_size: 64"));

        Ok(())
    }
}
