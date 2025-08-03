use super::base32precheck;
use base32ct::{Base32Unpadded, Encoding};
use base64::Engine;

/// Encode to multibase base32pc.
pub fn to_base32pc(data: &[u8]) -> String {
    base32precheck::encode_constant("x", data)
}

/// Encode to multibase base32pc with a HRP.
pub fn to_base32pc_with_prefix(data: &[u8], prefix: &str) -> String {
    base32precheck::encode_constant(&[prefix, "x"].concat(), data)
}

/// Encode to multibase base58.
pub fn to_base58(data: &[u8]) -> String {
    ["z", &bs58::encode(data).into_string()].concat()
}

/// Encode to multibase base64.
pub fn to_base64(data: &[u8]) -> String {
    [
        "u",
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
    ]
    .concat()
}

/// Encode to multibase hex.
pub fn to_hex(data: &[u8]) -> String {
    ["f", &hex::encode(data)].concat()
}

/// Encode to multibase base32.
pub fn to_base32(data: &[u8]) -> String {
    ["b", &Base32Unpadded::encode_string(data)].concat()
}

/// Decode a multibase encoded string.
pub fn decode(s: &str) -> crate::result::Result<Vec<u8>> {
    if s.is_empty() {
        Ok(vec![])
    } else if s.starts_with('x') {
        base32precheck::decode_constant("x", s)
    } else if let Some(s) = s.strip_prefix('z') {
        bs58::decode(s)
            .into_vec()
            .map_err(|e| crate::result::Error::EncodingError(e.to_string()))
    } else if let Some(s) = s.strip_prefix('u') {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| crate::result::Error::EncodingError(e.to_string()))
    } else if let Some(s) = s.strip_prefix('f') {
        hex::decode(s).map_err(|e| crate::result::Error::EncodingError(e.to_string()))
    } else if let Some(s) = s.strip_prefix('b') {
        Base32Unpadded::decode_vec(s)
            .map_err(|e| crate::result::Error::EncodingError(e.to_string()))
    } else {
        Err(crate::result::Error::EncodingError(format!(
            "not supported encoding: \"{}\"",
            s.chars().next().unwrap_or_default()
        )))
    }
}
