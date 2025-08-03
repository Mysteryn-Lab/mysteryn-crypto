use crate::{
    error_correction::checksum,
    result::{Error, Result},
};
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;

const BASE32PRECHECK: Encoding = new_encoding! {
    symbols: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
};
pub const DELIMITER: &str = "_";
const MULTIBASE_PREFIX: &str = "xa";

/// Encode data to the Base32pc string with a HRP.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    if hrp.is_empty() {
        let combined = [MULTIBASE_PREFIX.as_bytes(), data].concat();
        return [
            MULTIBASE_PREFIX,
            &BASE32PRECHECK.encode(&checksum::append(&combined)),
        ]
        .concat();
    }
    let combined = [
        hrp.as_bytes(),
        DELIMITER.as_bytes(),
        MULTIBASE_PREFIX.as_bytes(),
        data,
    ]
    .concat();
    let checksum = checksum::get_checksum(&combined);
    [
        hrp,
        DELIMITER,
        MULTIBASE_PREFIX,
        &BASE32PRECHECK.encode(&[data, &checksum].concat()),
    ]
    .concat()
}

/// Decode a Base32pc-encoded string. Returns the HRP and data bytes.
pub fn decode(text: &str) -> Result<(&str, Vec<u8>)> {
    let s = text.rsplitn(2, DELIMITER).collect::<Vec<&str>>();

    let Some(data_and_checksum) = s[0].strip_prefix(MULTIBASE_PREFIX) else {
        return Err(Error::EncodingError("invalid prefix".to_owned()));
    };
    let data_and_checksum = BASE32PRECHECK
        .decode(data_and_checksum.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    if s.len() < 2 {
        let decoded = checksum::decode(&data_and_checksum)?;
        if let Some(decoded) = decoded.strip_prefix(MULTIBASE_PREFIX.as_bytes()) {
            return Ok(("", decoded.to_vec()));
        }
        return Err(Error::EncodingError("invalid prefix".to_owned()));
    }
    let text_hrp = s[1];
    let combined = [
        text_hrp.as_bytes(),
        DELIMITER.as_bytes(),
        MULTIBASE_PREFIX.as_bytes(),
        &data_and_checksum,
    ]
    .concat();
    let decoded = checksum::decode(&combined)?;
    let prefix = [
        text_hrp.as_bytes(),
        DELIMITER.as_bytes(),
        MULTIBASE_PREFIX.as_bytes(),
    ]
    .concat();
    if let Some(decoded) = decoded.strip_prefix(prefix.as_slice()) {
        Ok((text_hrp, decoded.to_vec()))
    } else {
        Err(Error::EncodingError("invalid prefix".to_owned()))
    }
}

/// Encode data to the Base32pc with a constant prefix.
pub fn encode_constant(prefix: &str, data: &[u8]) -> String {
    if prefix.is_empty() {
        return BASE32PRECHECK.encode(&checksum::append(data));
    }
    let combined = [prefix.as_bytes(), data].concat();
    let checksum = checksum::get_checksum(&combined);
    [prefix, &BASE32PRECHECK.encode(&[data, &checksum].concat())].concat()
}

/// Encode the Base32pc string with a constant prefix.
pub fn decode_constant(prefix: &str, text: &str) -> Result<Vec<u8>> {
    let s = if prefix.is_empty() {
        text
    } else if let Some(s) = text.strip_prefix(prefix) {
        s
    } else {
        return Err(Error::EncodingError("invalid prefix".to_string()));
    };

    let data_and_checksum = BASE32PRECHECK
        .decode(s.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    if prefix.is_empty() {
        let decoded = checksum::decode(&data_and_checksum)?;
        return Ok(decoded.to_vec());
    }
    let combined = [prefix.as_bytes(), &data_and_checksum].concat();
    let decoded = checksum::decode(&combined)?;
    if let Some(decoded) = decoded.strip_prefix(prefix.as_bytes()) {
        Ok(decoded.to_vec())
    } else {
        Err(Error::EncodingError("invalid prefix".to_owned()))
    }
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
        assert_eq!(encoded, "xa0psszqhlqszsvpcgqypqxpq9qcrss66t7g4j443rcv");
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(orig, decoded.1);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_hrp() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode("test", &orig);
        assert_eq!(encoded, "test_xaqyp07pq9qcrssqgzqvzq2ps8ppm2dynntw05kys");
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.0, "test");
        assert_eq!(decoded.1, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_constant_prefix() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_constant("did:key:xa", &orig);
        assert_eq!(encoded, "did:key:xaqyp07pq9qcrssqgzqvzq2ps8ppt3gyfnmf7dmcg");
        let decoded = decode_constant("did:key:xa", &encoded).expect("cannot decode");
        assert_eq!(decoded, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_hrp_big() {
        let mut orig = [0u8; 1000];
        rng().fill_bytes(&mut orig);

        let encoded = encode("test", &orig);
        let decoded = decode(&encoded).expect("cannot decode");
        assert_eq!(decoded.1, orig);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure_checksum() {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = "test_xaqyp07pq9qcrssqgzqvzq2ps8ppm2dynntw05kys".to_owned();
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
        let encoded = "test_xaqyp07pq9qcrssqgzqvzq2ps8ppm2dynntw05kys".to_owned();
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
