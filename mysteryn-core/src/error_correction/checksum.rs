use crate::result::{Error, Result};
use reed_solomon::{Decoder, Encoder};

const ECC_LEN: usize = 8;
const CHUNK_LEN: usize = 256;

/// Append a checksum to the end of data.
pub fn append(data: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(ECC_LEN);

    let chunks = data.chunks(CHUNK_LEN - ECC_LEN);
    let mut ecc = vec![];
    let out: Vec<Vec<u8>> = chunks
        .map(|chunk| {
            let b = encoder.encode(chunk);
            ecc.push(b.ecc().to_vec());
            b.data().to_vec()
        })
        .collect();
    [out.concat(), ecc.concat()].concat()
}

/// Get a checksum for the provided data.
pub fn get_checksum(data: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(ECC_LEN);

    let chunks = data.chunks(CHUNK_LEN - ECC_LEN);
    let ecc: Vec<Vec<u8>> = chunks
        .map(|chunk| {
            let b = encoder.encode(chunk);
            b.ecc().to_vec()
        })
        .collect();
    ecc.concat()
}

/// Check the provided data by checksum at the end and return the raw data.
#[allow(clippy::integer_division_remainder_used)]
pub fn decode(data: &[u8]) -> Result<&[u8]> {
    let dec = Decoder::new(ECC_LEN);

    let mut count = data.len() / CHUNK_LEN;
    if data.len() % CHUNK_LEN != 0 {
        count += 1;
    }
    let a = data.split_at(data.len() - count * ECC_LEN);
    let chunks: Vec<&[u8]> = a.0.chunks(CHUNK_LEN - ECC_LEN).collect();
    let ecc: Vec<&[u8]> = a.1.chunks(ECC_LEN).collect();
    if chunks.len() != ecc.len() {
        return Err(Error::EncodingError("invalid input length".to_owned()));
    }
    for i in 0..chunks.len() {
        let chunk = [chunks[i], ecc[i]].concat();
        if chunk.len() < ECC_LEN || dec.is_corrupted(&chunk) {
            return Err(Error::EncodingError("byte loss".to_owned()));
        }
    }
    let size = data.len() - count * ECC_LEN;
    Ok(&data[..size])
}

/// Try to correct the provided data by checksum at the end. Returns the raw data.
#[allow(clippy::integer_division_remainder_used)]
pub fn correct(data: &[u8]) -> Result<Vec<u8>> {
    let dec = Decoder::new(ECC_LEN);

    let mut count = data.len() / CHUNK_LEN;
    if data.len() % CHUNK_LEN != 0 {
        count += 1;
    }
    let a = data.split_at(data.len() - count * ECC_LEN);
    let chunks: Vec<&[u8]> = a.0.chunks(CHUNK_LEN - ECC_LEN).collect();
    let ecc: Vec<&[u8]> = a.1.chunks(ECC_LEN).collect();
    if chunks.len() != ecc.len() {
        return Err(Error::EncodingError("invalid input length".to_owned()));
    }
    let mut data2 = vec![];
    for i in 0..chunks.len() {
        let chunk = [chunks[i].to_vec(), ecc[i].to_vec()].concat();
        if chunk.len() < ECC_LEN {
            return Err(Error::EncodingError("byte loss".to_owned()));
        }
        let buf = dec
            .correct(&chunk, None)
            .map_err(|_| Error::EncodingError("failed to decode".to_owned()))?;
        data2.append(&mut buf.data().to_vec());
    }
    Ok(data2)
}

#[cfg(test)]
mod tests {
    use super::{append, correct, decode};
    use crate::result::Result;
    use rand::{RngCore, rng};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        let decoded = decode(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_checksum_big() -> Result<()> {
        let mut orig = [0u8; 10000];
        rng().fill_bytes(&mut orig);
        let encoded = append(&orig);
        let decoded = decode(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_correct_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        let decoded = correct(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v[i] = 0;
            assert!(decode(&v).is_err());
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v.remove(i);
            assert!(decode(&v).is_err());
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure_correction() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v[i] = 0;
            assert_eq!(correct(&v)?, orig);
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    #[ignore]
    fn test_one_byte_loss_correction() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v.remove(i);
            assert_eq!(correct(&v)?, orig);
            println!("OK {i}");
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_erasure_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                let mut v = encoded.clone();
                v[i] = 0;
                v[j] = 0;
                assert!(decode(&v).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_loss_checksum() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                let mut v = encoded.clone();
                v.remove(i);
                if j < v.len() {
                    v.remove(j);
                }
                assert!(decode(&v).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_erasure_correction() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                let mut v = encoded.clone();
                v[i] = 0;
                v[j] = 0;
                assert_eq!(correct(&v).unwrap(), orig);
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_three_bytes_erasure_correction() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = append(&orig);
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                for h in 0..encoded.len() {
                    let mut v = encoded.clone();
                    v[i] = 0;
                    v[j] = 0;
                    v[h] = 0;
                    assert_eq!(correct(&v)?, orig);
                }
            }
        }

        Ok(())
    }
}
