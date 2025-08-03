use crate::result::{Error, Result};
use reed_solomon_rs::fec::fec::{FEC, Share};

const CHUNK_DELIMITER: u8 = 255;
const REQUIRED: usize = 2;
const TOTAL: usize = 6;

/// The Reed-Solomon encoding of bytes.
#[allow(clippy::integer_division_remainder_used)]
pub fn encode(data: &[u8]) -> Vec<u8> {
    #[allow(clippy::missing_panics_doc, reason = "cannot panic with these args")]
    let f = FEC::new(REQUIRED, TOTAL).unwrap();
    let mut shares: Vec<Share> = vec![
        Share {
            number: 0,
            data: vec![]
        };
        TOTAL
    ];

    let mut data = data.to_vec();
    #[allow(clippy::cast_possible_truncation)]
    data.insert(0, (data.len() % 256) as u8);
    #[allow(clippy::cast_possible_truncation)]
    data.insert(0, (data.len() / 256) as u8);
    if data.len() % REQUIRED != 0 {
        let mut padding = vec![0_u8; REQUIRED - data.len() % REQUIRED];
        data.append(&mut padding);
    }

    let output = |s: Share| {
        shares[s.number] = s.clone(); // Deep copy
    };
    #[allow(clippy::missing_panics_doc, reason = "checked to have enough pieces")]
    f.encode(&data, output).unwrap();

    let chunk_size = shares[0].data.len();
    encode_chunks(
        &shares
            .into_iter()
            .map(|s| s.data)
            .collect::<Vec<Vec<u8>>>()
            .concat(),
        chunk_size,
    )
}

/// Decode bytes from the Reed-Solomon encoding.
#[allow(clippy::integer_division_remainder_used)]
pub fn decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut chunk_size = data.len() / TOTAL - 1;
    if chunk_size < 2 || data.len() % chunk_size != 0 {
        chunk_size += 1;
    }

    let f = FEC::new(REQUIRED, TOTAL).map_err(|e| Error::EncodingError(e.to_string()))?;
    let mut shares: Vec<Share> = vec![
        Share {
            number: 0,
            data: vec![]
        };
        TOTAL
    ];

    let chunks = decode_chunks(data, chunk_size);
    for (i, share) in shares.iter_mut().enumerate().take(TOTAL) {
        *share = Share {
            number: i,
            data: vec![0_u8; chunk_size],
        };
    }
    for i in 0..TOTAL.min(chunks.len()) {
        if chunks[i].len() != chunk_size {
            continue;
        }
        shares[i] = Share {
            number: i,
            data: chunks[i].clone(),
        };
    }

    let out = f
        .decode([].to_vec(), shares)
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let size = out[0] as usize * 256 + out[1] as usize;
    let max_len = out.len().min(size + 2);
    Ok(out[2..max_len].to_vec())
}

/// The chunked encoding of bytes. Data is splat to chunks, delimited by `0xFF`.
pub fn encode_chunks(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut x = data
        .chunks(chunk_size)
        .map(|b| [b, &[CHUNK_DELIMITER]].concat())
        .collect::<Vec<Vec<u8>>>()
        .concat();
    x.pop();
    x
}

/// Decode bytes from the chunked encoding. A very simple heuristic is used to
/// restore malformed bytes.
pub fn decode_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let mut chunks = data
        .split(|b| *b == CHUNK_DELIMITER)
        .map(|v| (v.to_vec(), v.len() == chunk_size))
        .collect::<Vec<(Vec<u8>, bool)>>();
    let mut has_bad_chunks = true;
    while has_bad_chunks {
        has_bad_chunks = false;
        for i in 0..chunks.len() {
            let chunk = chunks[i].clone();
            if chunk.1 {
                continue;
            }
            if chunk.0.len() == chunk_size {
                chunks[i] = (chunk.0, true);
                continue;
            }
            if chunk.0.len() == chunk_size * 2 + 1 {
                let a = chunk.0.split_at(chunk_size);
                chunks[i] = (a.0.to_vec(), true);
                let mut b = a.1.to_vec();
                b.remove(0);
                chunks.insert(i + 1, (b, true));
                has_bad_chunks = true;
                break;
            }
            if chunk.0.len() > chunk_size {
                let a = chunk.0.split_at(chunk_size);
                chunks[i] = (a.0.to_vec(), true);
                chunks.insert(i + 1, (a.1.to_vec(), false));
                has_bad_chunks = true;
                break;
            }
            if chunk.0.len() < chunk_size && i < chunks.len() - 1 {
                if chunks[i + 1].1 || chunks[i + 1].0.len() == chunk_size {
                    let mut a = chunk.0;
                    let mut b = vec![0_u8; chunk_size - a.len()];
                    a.append(&mut b);
                    chunks[i] = (a, true);
                    continue;
                } else if chunks[i + 1].0.len() == chunk_size + 1 {
                    let mut a = chunk.0;
                    a.push(CHUNK_DELIMITER);
                    chunks[i] = (a, false);
                    let mut b = chunks[i + 1].0.clone();
                    b.remove(0);
                    chunks[i + 1] = (b, true);
                    has_bad_chunks = true;
                    break;
                }
                let mut a = chunk.0;
                a.push(CHUNK_DELIMITER);
                let b = chunks[i + 1].0.clone();
                let mut c = a;
                c.append(&mut b.clone());
                chunks[i] = (c, false);
                chunks.remove(i + 1);
                has_bad_chunks = true;
                break;
            }
        }
    }
    chunks
        .into_iter()
        .map(|chunk| chunk.0)
        .collect::<Vec<Vec<u8>>>()
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_chunks, encode, encode_chunks};
    use crate::result::Result;
    use rand::{RngCore, rng};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode_chunks() -> Result<()> {
        let chunk_size = 3;

        let orig = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_chunks(&orig, chunk_size);
        let decoded = decode_chunks(&encoded, chunk_size).concat();

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_encode_decode() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode(&orig);
        let decoded = decode(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_empty() -> Result<()> {
        let orig = vec![];
        let encoded = encode(&orig);
        let decoded = decode(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_small() -> Result<()> {
        let orig = vec![1, 2];
        let encoded = encode(&orig);
        print!("encoded: {encoded:?}");
        let decoded = decode(&encoded)?;

        assert_eq!(orig, decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_big() -> Result<()> {
        let mut orig = [0u8; 2000];
        rng().fill_bytes(&mut orig);
        let encoded = encode(&orig);
        print!("encoded: {}", encoded.len());
        let decoded = decode(&encoded)?;

        assert_eq!(orig.to_vec(), decoded);

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_erasure() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v[i] = 0;
            let decoded = decode(&v)?;
            assert_eq!(orig, decoded);
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_one_byte_loss() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode(&orig);
        for i in 0..encoded.len() {
            let mut v = encoded.clone();
            v.remove(i);
            let decoded = decode(&v)?;
            assert_eq!(orig, decoded);
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_erasure() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode(&orig);
        let mut failed = 0;
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                let mut v = encoded.clone();
                v[i] = 0;
                v[j] = 0;
                let Ok(decoded) = decode(&v) else {
                    failed += 1;
                    continue;
                };
                if orig != decoded {
                    failed += 1;
                    println!("failed: {orig:?} != {decoded:?}");
                }
            }
        }

        if failed > 0 {
            println!("failed {failed} times");
        }
        if failed > 10 {
            assert_eq!(failed, 0);
        }

        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_two_bytes_loss() -> Result<()> {
        let orig = vec![1, 2, 255, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode(&orig);
        let mut failed = 0;
        for i in 0..encoded.len() {
            for j in 0..encoded.len() {
                let mut v = encoded.clone();
                v.remove(i);
                if j < v.len() {
                    v.remove(j);
                }
                let Ok(decoded) = decode(&v) else {
                    failed += 1;
                    continue;
                };
                if orig != decoded {
                    failed += 1;
                    println!("failed: {orig:?} != {decoded:?}");
                }
            }
        }

        if failed > 0 {
            println!("failed {failed} times");
        }
        if failed > 10 {
            assert_eq!(failed, 0);
        }

        Ok(())
    }
}
