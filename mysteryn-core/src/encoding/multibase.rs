use super::base32pc;
use base32ct::{Base32Unpadded, Encoding};
use base64::Engine;

/// Encode to multibase base32pc.
pub fn to_base32pc(data: &[u8]) -> String {
    base32pc::encode_constant("x", data)
}

/// Encode to multibase base32pc with a HRP.
pub fn to_base32pc_with_prefix(data: &[u8], prefix: &str) -> String {
    base32pc::encode_constant(&concat_string!(prefix, "x"), data)
}

/// Encode to multibase base58.
pub fn to_base58(data: &[u8]) -> String {
    // Pre-allocate the output size (len * 138 / 100 + 1)
    concat_string!("z", &bs58::encode(data).into_string())
}

/// Encode to multibase base64.
pub fn to_base64(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    concat_string!("u", encoded)
}

/// Encode to multibase hex.
pub fn to_hex(data: &[u8]) -> String {
    concat_string!("f", &hex::encode(data))
}

/// Encode to multibase base32.
pub fn to_base32(data: &[u8]) -> String {
    concat_string!("b", &Base32Unpadded::encode_string(data))
}

/// Decode a multibase encoded string.
pub fn decode(s: &str) -> crate::result::Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    match s.as_bytes()[0] {
        b'x' => base32pc::decode_constant("x", s),
        b'z' => bs58::decode(&s[1..])
            .into_vec()
            .map_err(|e| crate::result::Error::EncodingError(e.to_string())),
        b'u' => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&s[1..])
            .map_err(|e| crate::result::Error::EncodingError(e.to_string())),
        b'f' => {
            hex::decode(&s[1..]).map_err(|e| crate::result::Error::EncodingError(e.to_string()))
        }
        b'b' => Base32Unpadded::decode_vec(&s[1..])
            .map_err(|e| crate::result::Error::EncodingError(e.to_string())),
        _ => Err(crate::result::Error::EncodingError(format!(
            "not supported encoding: \"{}\"",
            s.chars().next().unwrap_or_default()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_base32pc() {
        let data = b"hello world";
        let encoded = to_base32pc(data);
        assert_eq!(encoded, "xdpjkcmr0ypmk7unvvjl9ff3df3zr6");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_to_base32pc_with_prefix() {
        let data = b"hello world";
        let encoded = to_base32pc_with_prefix(data, "custom");
        assert_eq!(encoded, "customxdpjkcmr0ypmk7unvvjl27276dqlw7");
    }

    #[test]
    fn test_to_base58() {
        let data = b"hello world";
        let encoded = to_base58(data);
        assert_eq!(encoded, "zStV1DL6CwTryKyV");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_to_base64() {
        let data = b"hello world";
        let encoded = to_base64(data);
        assert_eq!(encoded, "uaGVsbG8gd29ybGQ");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_to_hex() {
        let data = b"hello world";
        let encoded = to_hex(data);
        assert_eq!(encoded, "f68656c6c6f20776f726c64");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_to_base32() {
        let data = b"hello world";
        let encoded = to_base32(data);
        assert_eq!(encoded, "bnbswy3dpeb3w64tmmq");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_empty() {
        let decoded = decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_unsupported() {
        let result = decode("a_unsupported");
        assert!(result.is_err());
    }
}
