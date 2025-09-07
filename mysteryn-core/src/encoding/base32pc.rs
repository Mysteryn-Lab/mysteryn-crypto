use crate::{
    error_correction::checksum,
    result::{Error, Result},
};
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;

const BASE32PC: Encoding = new_encoding! {
    symbols: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
};
pub const DELIMITER: &str = "_";
const MULTIBASE_PREFIX: &str = "xa";
const MULTIBASE_PREFIX_BYTES: &[u8] = b"xa";

/// Encode data to the Base32pc string with a HRP.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    if hrp.is_empty() {
        // No HRP - prepend the multibase prefix and checksum once.
        let mut combined = Vec::with_capacity(MULTIBASE_PREFIX_BYTES.len() + data.len());
        combined.extend_from_slice(MULTIBASE_PREFIX_BYTES);
        combined.extend_from_slice(data);

        let encoded_data = BASE32PC.encode(&checksum::append(&combined));
        concat_string!(MULTIBASE_PREFIX, encoded_data)
    } else {
        // HRP present - build the full string with delimiter and checksum.
        let mut combined = Vec::with_capacity(
            hrp.len() + DELIMITER.len() + MULTIBASE_PREFIX_BYTES.len() + data.len(),
        );
        combined.extend_from_slice(hrp.as_bytes());
        combined.extend_from_slice(DELIMITER.as_bytes());
        combined.extend_from_slice(MULTIBASE_PREFIX_BYTES);
        combined.extend_from_slice(data);

        let data_with_checksum = checksum::append(&combined);

        let encoded_data = BASE32PC.encode(
            &data_with_checksum[hrp.len() + DELIMITER.len() + MULTIBASE_PREFIX_BYTES.len()..],
        );
        concat_string!(hrp, DELIMITER, MULTIBASE_PREFIX, encoded_data)
    }
}

/// Decode a Base32pc-encoded string. Returns the HRP and data bytes.
pub fn decode(text: &str) -> Result<(&str, Vec<u8>)> {
    let (hrp, data_part) = text.rsplit_once(DELIMITER).unwrap_or(("", text));

    let data_part = data_part
        .strip_prefix(MULTIBASE_PREFIX)
        .ok_or_else(|| Error::EncodingError("invalid prefix".to_string()))?;

    let decoded_bytes = BASE32PC
        .decode(data_part.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    if hrp.is_empty() {
        // No HRP - the whole string is just data + checksum.
        let decoded = checksum::decode(&decoded_bytes)?;
        let data = decoded
            .strip_prefix(MULTIBASE_PREFIX_BYTES)
            .ok_or_else(|| Error::EncodingError("invalid prefix".to_string()))?;
        Ok(("", data.to_vec()))
    } else {
        // HRP present - validate that the prefix matches.
        let mut combined = Vec::with_capacity(
            hrp.len() + DELIMITER.len() + MULTIBASE_PREFIX_BYTES.len() + decoded_bytes.len(),
        );
        combined.extend_from_slice(hrp.as_bytes());
        combined.extend_from_slice(DELIMITER.as_bytes());
        combined.extend_from_slice(MULTIBASE_PREFIX_BYTES);
        combined.extend_from_slice(&decoded_bytes);

        let decoded = checksum::decode(&combined)?;
        let prefix_len = hrp.len() + DELIMITER.len() + MULTIBASE_PREFIX.len();
        Ok((hrp, decoded[prefix_len..].to_vec()))
    }
}

/// Encode data to the Base32pc with a constant prefix.
pub fn encode_constant(prefix: &str, data: &[u8]) -> String {
    if prefix.is_empty() {
        BASE32PC.encode(&checksum::append(data))
    } else {
        let mut combined = Vec::with_capacity(prefix.len() + data.len());
        combined.extend_from_slice(prefix.as_bytes());
        combined.extend_from_slice(data);

        let data_with_checksum = checksum::append(&combined);

        let encoded_data = BASE32PC.encode(&data_with_checksum[prefix.len()..]);
        concat_string!(prefix, encoded_data)
    }
}

/// Encode the Base32pc string with a constant prefix.
pub fn decode_constant(prefix: &str, text: &str) -> Result<Vec<u8>> {
    let data_part = text
        .strip_prefix(prefix)
        .ok_or_else(|| Error::EncodingError("invalid prefix".to_string()))?;

    let decoded_bytes = BASE32PC
        .decode(data_part.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    if prefix.is_empty() {
        return Ok(checksum::decode(&decoded_bytes)?.to_vec());
    }

    let mut combined = Vec::with_capacity(prefix.len() + decoded_bytes.len());
    combined.extend_from_slice(prefix.as_bytes());
    combined.extend_from_slice(&decoded_bytes);

    let decoded = checksum::decode(&combined)?;
    let payload = decoded
        .strip_prefix(prefix.as_bytes())
        .ok_or_else(|| Error::EncodingError("invalid prefix".to_string()))?;
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_constant, encode, encode_constant};
    use rand::{RngCore, rng};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode("", &orig);
        assert_eq!(encoded, "xa0psszqhlqszsvpcgqypqxpq9qcrssr68z7dvklvy");
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(orig, decoded.1);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_hrp() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode("test", &orig);
        assert_eq!(encoded, "test_xaqyp07pq9qcrssqgzqvzq2ps8pztr5jgz7nc4j");
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.0, "test");
        assert_eq!(decoded.1, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_constant_prefix() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_constant("did:key:xa", &orig);
        assert_eq!(encoded, "did:key:xaqyp07pq9qcrssqgzqvzq2ps8pr8xdfx2g9mpq");
        let decoded = decode_constant("did:key:xa", &encoded).expect("cannot decode");
        assert_eq!(decoded, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_hrp_big() {
        let mut orig = [0u8; 10000];
        rng().fill_bytes(&mut orig);

        let encoded = encode("test", &orig);
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.1, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure_checksum() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        //println!("encoded {}", encode("test", &orig));
        let encoded = "test_xaqyp07pq9qcrssqgzqvzq2ps8pztr5jgz7nc4j".to_owned();
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.0, "test");
        assert_eq!(decoded.1, orig);

        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            if v.as_bytes()[i] == b'0' {
                continue;
            }
            v.remove(i);
            v.insert(i, '0');
            assert!(decode(&v).is_err());
        }
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure_checksum_constant() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_constant("did:key:xa", &orig);
        let decoded = decode_constant("did:key:xa", &encoded).expect("cannot decode");
        assert_eq!(decoded, orig);

        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            if v.as_bytes()[i] == b'0' {
                continue;
            }
            v.remove(i);
            v.insert(i, '0');
            assert!(decode(&v).is_err());
        }
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss_checksum() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        //println!("encoded {}", encode("test", &orig));
        let encoded = "test_xaqyp07pq9qcrssqgzqvzq2ps8pztr5jgz7nc4j".to_owned();
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.0, "test");
        assert_eq!(decoded.1, orig);

        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v.remove(i);
            assert!(decode(&v).is_err());
        }
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss_checksum_constant() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_constant("did:key:xa", &orig);
        let decoded = decode_constant("did:key:xa", &encoded).expect("cannot decode");
        assert_eq!(decoded, orig);

        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v.remove(i);
            assert!(decode(&v).is_err());
        }
    }
}
