use crate::{
    multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{encode_varint_u64, encode_varint_usize},
};
use concat_string::concat_string;
use multihash_codetable::{Code, MultihashDigest};
use multihash_derive::Hasher;
use rand::{Rng, RngCore, rngs::ThreadRng};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

pub const MAX_DISTANCE: f64 = 1e100;

// Helper for building a multihash byte vector.
fn build_multihash(codec: u64, data: &[u8]) -> Vec<u8> {
    let varint_codec = encode_varint_u64(codec);
    let varint_len = encode_varint_usize(data.len());
    let mut out = Vec::with_capacity(varint_codec.len() + varint_len.len() + data.len());
    out.extend_from_slice(&varint_codec);
    out.extend_from_slice(&varint_len);
    out.extend_from_slice(data);
    out
}

fn unsupported_error(code: Code) -> Error {
    Error::EncodingError(concat_string!(
        "hash code ",
        &format!("{code:?}"),
        " is not supported"
    ))
}

/// The hash in multihash format.
/// See https://github.com/multiformats/multihash.
#[derive(PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(Vec<u8>);

impl Hash {
    /// Get bytes of the hash (including multicodec prefix).
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the codec of the hash.
    pub fn codec(&self) -> u64 {
        #[expect(clippy::missing_panics_doc, reason = "checked on creation")]
        unsigned_varint::decode::u64(&self.0).unwrap().0
    }

    /// Get raw bytes of the hash, without a multicodec prefix.
    pub fn raw(&self) -> &[u8] {
        #[expect(clippy::missing_panics_doc, reason = "checked on creation")]
        let (_, rest) = unsigned_varint::decode::u64(&self.0).unwrap();
        #[expect(clippy::missing_panics_doc, reason = "checked on creation")]
        let (_, data) = unsigned_varint::decode::usize(rest).unwrap();
        data
    }

    /// Calculate a hash from bytes.
    pub fn hash_bytes(b: &[u8]) -> Self {
        #[expect(clippy::missing_panics_doc, reason = "hash is known")]
        Self::hash_bytes_with_code(b, Code::Blake3_256).unwrap()
    }

    /// Calculate a hash from bytes with a specific codec.
    pub fn hash_bytes_with_code(b: &[u8], code: Code) -> Result<Self> {
        let codec = match code {
            Code::Sha2_256 => multicodec_prefix::SHA2_256,
            Code::Sha2_512 => multicodec_prefix::SHA2_512,
            Code::Blake3_256 => multicodec_prefix::BLAKE3,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(unsupported_error(code));
            }
        };
        let h = code.digest(b);
        Ok(Self(build_multihash(codec, h.digest())))
    }

    /// Calculate a hash from multiple byte slices.
    pub fn hash_multi(b: &[&[u8]]) -> Self {
        #[expect(clippy::missing_panics_doc, reason = "the hash is known")]
        Self::hash_multi_with_code(b, Code::Blake3_256).unwrap()
    }

    /// Calculate a hash from multiple byte slices with a specific codec.
    pub fn hash_multi_with_code(b: &[&[u8]], code: Code) -> Result<Self> {
        match code {
            Code::Sha2_256 => {
                let mut hasher = multihash_codetable::Sha2_256::default();
                for item in b {
                    hasher.update(item);
                }
                Ok(Self(build_multihash(
                    multicodec_prefix::SHA2_256,
                    hasher.finalize(),
                )))
            }
            Code::Sha2_512 => {
                let mut hasher = multihash_codetable::Sha2_512::default();
                for item in b {
                    hasher.update(item);
                }
                Ok(Self(build_multihash(
                    multicodec_prefix::SHA2_512,
                    hasher.finalize(),
                )))
            }
            Code::Blake3_256 => {
                let mut hasher = multihash_codetable::Blake3_256::default();
                for item in b {
                    hasher.update(item);
                }
                Ok(Self(build_multihash(
                    multicodec_prefix::BLAKE3,
                    hasher.finalize(),
                )))
            }
            #[allow(unreachable_patterns)]
            _ => Err(unsupported_error(code)),
        }
    }

    /// Create a random hash.
    pub fn random() -> Self {
        let mut csprng = ThreadRng::default();
        let mut result = vec![0; 32];
        csprng.fill_bytes(&mut result);
        Self(build_multihash(multicodec_prefix::BLAKE3, &result))
    }

    /// Create a random hash with the provided random number generator.
    pub fn random_rng<T: Rng>(rng: &mut T) -> Self {
        let mut buf = [0; 32];
        rng.fill_bytes(&mut buf);
        Self(build_multihash(multicodec_prefix::BLAKE3, &buf))
    }

    /// Create a random hash with the provided codec.
    pub fn random_with_code(code: Code) -> Result<Self> {
        let (codec, size) = match code {
            Code::Sha2_256 => (multicodec_prefix::SHA2_256, 32),
            Code::Sha2_512 => (multicodec_prefix::SHA2_512, 64),
            Code::Blake3_256 => (multicodec_prefix::BLAKE3, 32),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(unsupported_error(code));
            }
        };
        let mut buf = vec![0; size];
        ThreadRng::default().fill_bytes(&mut buf);
        Ok(Self(build_multihash(codec, &buf)))
    }

    /// Create an empty hash (zero-filled).
    pub fn empty() -> Self {
        Self(build_multihash(multicodec_prefix::BLAKE3, &[0u8; 32]))
    }

    /// Calculate distance between hashes.
    pub fn distance(&self, other: &Hash) -> f64 {
        hash_distance(self.raw(), other.raw())
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::to_base32(&self.0))
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash(\"{}\")", multibase::to_base32(&self.0))
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let (codec, rest) = unsigned_varint::decode::u64(value)
            .map_err(|_| Error::EncodingError("invalid hash bytes".to_owned()))?;

        let expected_len = match codec {
            multicodec_prefix::BLAKE3 | multicodec_prefix::SHA2_256 => 32,
            multicodec_prefix::SHA2_512 => 64,
            _ => {
                return Err(Error::EncodingError(concat_string!(
                    "unsupported hash algorithm 0x",
                    &hex::encode(codec.to_be_bytes())
                )));
            }
        };

        let (data_len, data) = unsigned_varint::decode::usize(rest)
            .map_err(|_| Error::EncodingError("invalid hash bytes".into()))?;
        // length check
        if data_len != expected_len || data.len() < data_len {
            return Err(Error::EncodingError("invalid hash bytes length".into()));
        }
        Ok(Self(build_multihash(codec, data)))
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CustomVisitor::<Hash>(std::marker::PhantomData))
        } else {
            deserializer.deserialize_bytes(CustomVisitor::<Hash>(std::marker::PhantomData))
        }
    }
}

pub(crate) struct CustomVisitor<T>(pub(crate) std::marker::PhantomData<T>);

impl<'de, T> serde::de::Visitor<'de> for CustomVisitor<T>
where
    T: for<'a> TryFrom<&'a [u8], Error = Error> + FromStr<Err = Error>,
    T: serde::de::Deserialize<'de>,
    T: 'de,
{
    type Value = T;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::try_from(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Calculate hash distance between bytes.
/// It is a value in range 0..1, where 0 means the same and 1 means completely different.
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::integer_division_remainder_used)]
pub fn hash_distance(hash1: &[u8], hash2: &[u8]) -> f64 {
    let (short, long) = if hash1.len() <= hash2.len() {
        (hash1, hash2)
    } else {
        (hash2, hash1)
    };
    if short.is_empty() || long.is_empty() {
        return MAX_DISTANCE;
    }
    let short_len = short.len();

    // One pass to accumulate sums for each position in the shorter slice
    let mut sums = vec![0.0_f64; short_len];
    let mut counts = vec![0_u32; short_len];

    for (i, &byte) in long.iter().enumerate() {
        let idx = i % short_len;
        sums[idx] += f64::from(byte) / 255.0;
        counts[idx] += 1;
    }

    // Compute the mean per position and accumulate absolute differences
    let mut diff_sum = 0.0_f64;
    for (i, &byte) in short.iter().enumerate() {
        let mean = sums[i] / f64::from(counts[i]);
        let val = f64::from(byte) / 255.0;
        diff_sum += (val - mean).abs();
    }

    diff_sum / short_len as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_equal() {
        let hash1 = [0, 0, 0];
        let hash2 = [0, 0, 0];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 0.0);

        let hash1 = [1, 1, 0];
        let hash2 = [1, 1, 0];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 0.0);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_equal_dif_length() {
        let hash1 = [0, 0, 0];
        let hash2 = [0, 0, 0, 0, 0];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 0.0);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_different() {
        let hash1 = [0, 0, 0];
        let hash2 = [255, 255, 255];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 1.0);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_different_dif_length() {
        let hash1 = [0, 0, 0];
        let hash2 = [255, 255, 255, 255, 255];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 1.0);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_mean() {
        let hash1 = [0, 0, 0];
        let hash2 = [255, 255, 255, 0, 0, 0];

        let d = hash_distance(&hash1, &hash2);
        assert_eq!(d, 0.5);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_hash_distance() {
        let hash1 = Hash::from_str("bdyqjkxi6ap6s2ip2o4iuhax2tmljplgh3ocu2zo76oo3b74vu2yzoda")
            .expect("can decode");
        let hash2 = Hash::from_str("bdyqhszenfyunxc7duhqjawrjrvjny42sdtujj3ngaj7syfqiqgwuf6q")
            .expect("can decode");

        let d = hash1.distance(&hash2);
        assert_eq!(d, 0.4034313725490196);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_hash_distance_of_different_algorithms() {
        // blake3
        let hash1 = Hash::from_str("bdyqg3je7mxlfzxfmd3glerw5xmibvyryahelk22paujnimkxrjzrefa")
            .expect("can decode");
        // sha512
        let hash2 = Hash::from_str("bcnaf27c67jqvyjsfgwf7kgjqeljsbcmasffpisj3gb2oaug4cumf2rbsht6tdatm5wwojnedndd4pzamvep7ublnpo3sgn6s2hbhxzi4vm").expect("can decode");

        let d = hash1.distance(&hash2);
        assert_eq!(d, 0.2468137254901961);
    }
}
