use crate::result::{Error, Result};
use reed_solomon::{Decoder, Encoder};

const ECC_LEN: usize = 7; // ECC bytes
const CHUNK_LEN: usize = 128; // total block length (data + ecc)
const DATA_CHUNK_LEN: usize = CHUNK_LEN - ECC_LEN; // only data part

/// Append a checksum to the end of data.
pub fn append(data: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(ECC_LEN);
    let chunks = data.chunks(DATA_CHUNK_LEN);
    let num_chunks = chunks.len();

    let mut out = vec![0u8; data.len() + num_chunks * ECC_LEN];
    let mut out_data_pos = 0;
    let mut out_ecc_pos = data.len();

    for chunk in chunks {
        let block = encoder.encode(chunk);
        out[out_data_pos..out_data_pos + chunk.len()].copy_from_slice(block.data());
        out_data_pos += block.data().len();

        out[out_ecc_pos..out_ecc_pos + ECC_LEN].copy_from_slice(block.ecc());
        out_ecc_pos += ECC_LEN;
        // XOR the chunk length with the last byte of ECC, as an additional check
        #[allow(clippy::cast_possible_truncation)]
        {
            out[out_ecc_pos - 1] ^= chunk.len() as u8;
        }
    }

    out
}

/// Get a checksum for the provided data.
pub fn get_checksum(data: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(ECC_LEN);
    let chunks = data.chunks(DATA_CHUNK_LEN);
    let num_chunks = chunks.len();
    let mut ecc_buffer = Vec::with_capacity(num_chunks * ECC_LEN);

    for chunk in chunks {
        let block = encoder.encode(chunk);
        let mut tmp_ecc = [0u8; ECC_LEN];
        tmp_ecc.copy_from_slice(block.ecc());
        if let Some(last_byte) = tmp_ecc.last_mut() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *last_byte ^= chunk.len() as u8;
            }
        }
        ecc_buffer.extend(&tmp_ecc);
    }
    ecc_buffer
}

/// Check the provided data by checksum at the end and return the raw data.
pub fn decode(data: &[u8]) -> Result<&[u8]> {
    let decoder = Decoder::new(ECC_LEN);
    let (data_part, _) = split_data_and_get_chunk_count(data);
    let ecc_part = &data[data_part.len()..];

    let chunks = data_part.chunks(DATA_CHUNK_LEN);
    let eccs = ecc_part.chunks(ECC_LEN);

    if chunks.len() != eccs.len() {
        return Err(Error::InvalidInputLength);
    }

    let mut block_buffer = [0u8; CHUNK_LEN];

    for (chunk, ecc) in chunks.zip(eccs) {
        let block = &mut block_buffer[..chunk.len() + ECC_LEN];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()..].copy_from_slice(ecc);
        if let Some(last_byte) = block.last_mut() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *last_byte ^= chunk.len() as u8;
            }
        }

        if block.len() < ECC_LEN || decoder.is_corrupted(block) {
            return Err(Error::EncodingError("byte loss".to_owned()));
        }
    }

    Ok(&data[..data_part.len()])
}

/// Try to correct the provided data by the checksum. Returns the raw data.
/// Correction is probabilistic, so it may produce incorrect results.
/// It can restore up to 3 error bytes with probability 100% in each chunk,
/// or 1 byte of loss in total with probability 99%.
pub fn correct_approximately(data: &[u8]) -> Result<Vec<u8>> {
    if let Ok(corrected) = i_correct(data) {
        return Ok(corrected);
    }

    // If correction fails, try to restore a single missed byte.
    // This is computationally expensive and should be used with caution.
    let mut buffer = Vec::with_capacity(data.len() + 1);
    for i in 0..=data.len() {
        buffer.clear();
        buffer.extend_from_slice(&data[..i]);
        buffer.push(0); // Placeholder for the missed byte
        buffer.extend_from_slice(&data[i..]);
        if let Ok(corrected) = i_correct(&buffer) {
            return Ok(corrected);
        }
    }

    Err(Error::EncodingError("failed to correct data".to_owned()))
}

fn i_correct(data: &[u8]) -> Result<Vec<u8>> {
    let decoder = Decoder::new(ECC_LEN);
    let (data_part, _) = split_data_and_get_chunk_count(data);
    let ecc_part = &data[data_part.len()..];

    let chunks = data_part.chunks(DATA_CHUNK_LEN);
    let eccs = ecc_part.chunks(ECC_LEN);

    if chunks.len() != eccs.len() {
        return Err(Error::InvalidInputLength);
    }

    let mut corrected_data = Vec::with_capacity(data_part.len());
    let mut block_buffer = [0u8; CHUNK_LEN];

    for (chunk, ecc) in chunks.zip(eccs) {
        let mut tmp_ecc = [0u8; ECC_LEN];
        tmp_ecc.copy_from_slice(ecc);

        if let Some(last_byte) = tmp_ecc.last_mut() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *last_byte ^= chunk.len() as u8;
            }
        }

        let block = &mut block_buffer[..chunk.len() + ECC_LEN];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()..].copy_from_slice(&tmp_ecc);

        let corrected_block = decoder
            .correct(block, None)
            .map_err(|_| Error::EncodingError("failed to decode".to_owned()))?;
        corrected_data.extend_from_slice(corrected_block.data());
    }

    Ok(corrected_data)
}

// Calculates the number of chunks and the length of the data part.
fn split_data_and_get_chunk_count(data: &[u8]) -> (&[u8], usize) {
    if data.is_empty() {
        return (data, 0);
    }
    // ceiling division
    let num_chunks = data.len().div_ceil(CHUNK_LEN);

    let (data_part, _) = data.split_at(data.len() - num_chunks * ECC_LEN);
    (data_part, num_chunks)
}

#[cfg(test)]
mod tests {
    use super::{ECC_LEN, append, correct_approximately, decode};
    use crate::{error_correction::checksum::CHUNK_LEN, result::Result};
    use rand::{Rng, RngCore, rng};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    const REPEATS: usize = 100;

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
        let decoded = correct_approximately(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_error_checksum() -> Result<()> {
        for size in 0..CHUNK_LEN * 3 {
            let mut orig = vec![0u8; size];
            rng().fill_bytes(&mut orig);
            let encoded = append(&orig);
            for i in 0..encoded.len() {
                let mut v = encoded.clone();
                let r = rng().random();
                if v[i] == r {
                    continue; // skip similar bytes to avoid false positives
                }
                v[i] = r;
                assert!(decode(&v).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss_checksum() -> Result<()> {
        for size in 1..CHUNK_LEN * 3 {
            let mut orig = vec![0u8; size];
            rng().fill_bytes(&mut orig);
            let encoded = append(&orig);
            for i in 0..encoded.len() {
                let mut v = encoded.clone();
                v.remove(i);
                assert!(decode(&v).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_error_correction() -> Result<()> {
        for size in 0..CHUNK_LEN * 3 {
            let mut orig = vec![0u8; size];
            rng().fill_bytes(&mut orig);
            let encoded = append(&orig);
            for i in 0..encoded.len() {
                let mut v = encoded.clone();
                let r = rng().random();
                v[i] = r;
                assert_eq!(correct_approximately(&v)?, orig);
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss_correction() -> Result<()> {
        let mut count = 0;
        let mut fails = 0;
        for size in 1..CHUNK_LEN - ECC_LEN {
            let mut orig = vec![0u8; size];
            rng().fill_bytes(&mut orig);
            let encoded = append(&orig);
            for i in 0..encoded.len() {
                count += 1;
                let mut v = encoded.clone();
                v.remove(i);
                if correct_approximately(&v)? != orig {
                    fails += 1;
                }
            }
        }
        println!("{} / {} = {}%", fails, count, fails * 100 / count);
        assert!(
            fails * 100 / count < 2,
            "too many failures: {} / {} ({}%)",
            fails,
            count,
            fails * 100 / count
        );

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_error_checksum() -> Result<()> {
        for size in 1..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                let j = rng().random_range(0..encoded.len());
                let r1 = rng().random();
                let r2 = rng().random();
                if encoded[i] == r1 || encoded[j] == r2 {
                    continue; // skip similar bytes to avoid false positives
                }
                encoded[i] = r1;
                encoded[j] = r2;
                assert!(decode(&encoded).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_loss_checksum() -> Result<()> {
        for size in 2..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                encoded.remove(i);
                let j = rng().random_range(0..encoded.len());
                encoded.remove(j);
                assert!(decode(&encoded).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_error_correction() -> Result<()> {
        for size in 1..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                let j = rng().random_range(0..encoded.len());
                encoded[i] = rng().random();
                encoded[j] = rng().random();
                assert_eq!(correct_approximately(&encoded)?, orig);
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_three_bytes_error_correction() -> Result<()> {
        let mut count = 0;
        let mut fails = 0;
        for size in 1..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                count += 1;
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                let j = rng().random_range(0..encoded.len());
                let h = rng().random_range(0..encoded.len());
                encoded[i] = rng().random();
                encoded[j] = rng().random();
                encoded[h] = rng().random();
                if let Ok(corrected) = correct_approximately(&encoded) {
                    if corrected != orig {
                        fails += 1;
                    }
                } else {
                    fails += 1;
                }
            }
        }
        assert!(
            fails == 0,
            "too many failures: {} / {} ({}%)",
            fails,
            count,
            fails * 100 / count
        );

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_four_bytes_error_checksum() -> Result<()> {
        for size in 1..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                let j = rng().random_range(0..encoded.len());
                let k = rng().random_range(0..encoded.len());
                let h = rng().random_range(0..encoded.len());
                let r1 = rng().random();
                let r2 = rng().random();
                let r3 = rng().random();
                let r4 = rng().random();
                if encoded[i] == r1 || encoded[j] == r2 || encoded[k] == r3 || encoded[h] == r4 {
                    continue; // skip similar bytes to avoid false positives
                }
                encoded[i] = r1;
                encoded[j] = r2;
                encoded[k] = r3;
                encoded[h] = r4;
                assert!(decode(&encoded).is_err());
            }
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_five_bytes_error_checksum() -> Result<()> {
        for size in 1..CHUNK_LEN * 3 {
            for _ in 0..REPEATS {
                let mut orig = vec![0u8; size];
                rng().fill_bytes(&mut orig);
                let mut encoded = append(&orig);
                let i = rng().random_range(0..encoded.len());
                let j = rng().random_range(0..encoded.len());
                let k = rng().random_range(0..encoded.len());
                let h = rng().random_range(0..encoded.len());
                let p = rng().random_range(0..encoded.len());
                let r1 = rng().random();
                let r2 = rng().random();
                let r3 = rng().random();
                let r4 = rng().random();
                let r5 = rng().random();
                if encoded[i] == r1
                    || encoded[j] == r2
                    || encoded[k] == r3
                    || encoded[h] == r4
                    || encoded[p] == r5
                {
                    continue; // skip similar bytes to avoid false positives
                }
                encoded[i] = r1;
                encoded[j] = r2;
                encoded[k] = r3;
                encoded[h] = r4;
                encoded[p] = r5;
                assert!(decode(&encoded).is_err());
            }
        }

        Ok(())
    }
}
