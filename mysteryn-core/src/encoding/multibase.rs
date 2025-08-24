use super::base32precheck;
use base32ct::{Base32Unpadded, Encoding};
use base64::Engine;

/// Encode to multibase base32pc.
pub fn to_base32pc(data: &[u8]) -> String {
    base32precheck::encode_constant("x", data)
}

/// Encode to multibase base32pc with a HRP.
pub fn to_base32pc_with_prefix(data: &[u8], prefix: &str) -> String {
    base32precheck::encode_constant(&concat_string!(prefix, "x"), data)
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
        b'x' => base32precheck::decode_constant("x", s),
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
