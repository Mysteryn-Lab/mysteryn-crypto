use crate::{
    base32precheck,
    key_traits::{KeyFactory, PublicKeyTrait},
    multibase,
    multicodec::multicodec_prefix,
    multikey::MultikeyPublicKey,
    result::{Error, Result},
    varint::{
        encode_varbytes, encode_varint_u64, encode_varint_usize, read_varbytes,
        write_varbytes_unsafe, write_varint_u64_unsafe,
    },
};
use multihash_codetable::{Code, MultihashDigest};
use multihash_derive::Hasher;
use rand::{Rng, RngCore, rngs::ThreadRng};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

pub const MAX_DISTANCE: f64 = 1e100;

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
        let (codec, _) = unsigned_varint::decode::u64(&self.0).unwrap();
        codec
    }

    /// Get raw bytes of the hash, without a multicodec prefix.
    pub fn raw(&self) -> &[u8] {
        let reader = &self.0;
        #[expect(clippy::missing_panics_doc, reason = "checked on creation")]
        let (_, data) = unsigned_varint::decode::u64(reader).unwrap();
        #[expect(clippy::missing_panics_doc, reason = "checked on creation")]
        let (_, data) = unsigned_varint::decode::usize(data).unwrap();
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
                return Err(Error::EncodingError(format!(
                    "hash code {code:?} is not supported"
                )));
            }
        };
        let h = code.digest(b);

        let data = h.digest().to_vec();

        Ok(Self(
            [
                encode_varint_u64(codec),
                encode_varint_usize(data.len()),
                data,
            ]
            .concat(),
        ))
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
                let result = hasher.finalize().to_vec();
                Ok(Self(
                    [
                        encode_varint_u64(multicodec_prefix::SHA2_256),
                        encode_varint_usize(result.len()),
                        result,
                    ]
                    .concat(),
                ))
            }
            Code::Sha2_512 => {
                let mut hasher = multihash_codetable::Sha2_512::default();
                for item in b {
                    hasher.update(item);
                }
                let result = hasher.finalize().to_vec();
                Ok(Self(
                    [
                        encode_varint_u64(multicodec_prefix::SHA2_512),
                        encode_varint_usize(result.len()),
                        result,
                    ]
                    .concat(),
                ))
            }
            Code::Blake3_256 => {
                let mut hasher = multihash_codetable::Blake3_256::default();
                for item in b {
                    hasher.update(item);
                }
                let result = hasher.finalize().to_vec();
                Ok(Self(
                    [
                        encode_varint_u64(multicodec_prefix::BLAKE3),
                        encode_varint_usize(result.len()),
                        result,
                    ]
                    .concat(),
                ))
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::EncodingError(format!(
                "hash code {code:?} is not supported"
            ))),
        }
    }

    /// Create a random hash.
    pub fn random() -> Self {
        let mut csprng = ThreadRng::default();
        let mut result = vec![0; 32];

        csprng.fill_bytes(&mut result);
        let prefix = encode_varint_u64(multicodec_prefix::BLAKE3);
        Self([prefix, encode_varint_usize(result.len()), result].concat())
    }

    /// Create a random hash with the provided random number generator.
    pub fn random_rng<T: Rng>(rng: &mut T) -> Self {
        let mut result = vec![0; 32];

        rng.fill_bytes(&mut result);
        let prefix = encode_varint_u64(multicodec_prefix::BLAKE3);
        Self([prefix, encode_varint_usize(result.len()), result].concat())
    }

    /// Create a random hash with the provided codec.
    pub fn random_with_code(code: Code) -> Result<Self> {
        let (codec, size) = match code {
            Code::Sha2_256 => (multicodec_prefix::SHA2_256, 32),
            Code::Sha2_512 => (multicodec_prefix::SHA2_512, 64),
            Code::Blake3_256 => (multicodec_prefix::BLAKE3, 32),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::EncodingError(format!(
                    "hash code {code:?} is not supported"
                )));
            }
        };
        let mut csprng = ThreadRng::default();
        let mut result = vec![0; size];

        csprng.fill_bytes(&mut result);
        let prefix = encode_varint_u64(codec);
        Ok(Self(
            [prefix, encode_varint_usize(result.len()), result].concat(),
        ))
    }

    /// Create an empty hash (zero-filled).
    pub fn empty() -> Self {
        let result = vec![0; 32];
        let prefix = encode_varint_u64(multicodec_prefix::BLAKE3);
        Self([prefix, encode_varint_usize(result.len()), result].concat())
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
        let reader = value;
        let (codec, mut data) = unsigned_varint::decode::u64(reader)
            .map_err(|_| Error::EncodingError("invalid hash bytes".to_owned()))?;
        if codec != multicodec_prefix::SHA2_256
            && codec != multicodec_prefix::SHA2_512
            && codec != multicodec_prefix::BLAKE3
        {
            return Err(Error::EncodingError(format!(
                "unsupported hash algorithm {codec:#02x?}"
            )));
        }
        let data = read_varbytes(&mut data)
            .map_err(|_| Error::EncodingError("invalid hash bytes".to_owned()))?;
        let size = match codec {
            multicodec_prefix::BLAKE3 | multicodec_prefix::SHA2_256 => 32,
            multicodec_prefix::SHA2_512 => 64,
            _ => 0,
        };
        if data.len() != size {
            return Err(Error::EncodingError("invalid hash bytes length".to_owned()));
        }
        Ok(Self(
            [encode_varint_u64(codec), encode_varbytes(&data)].concat(),
        ))
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
            deserializer.deserialize_str(CustomVisitor)
        } else {
            deserializer.deserialize_bytes(CustomVisitor)
        }
    }
}
struct CustomVisitor;
impl serde::de::Visitor<'_> for CustomVisitor {
    type Value = Hash;

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

struct CustomVisitor2;
impl serde::de::Visitor<'_> for CustomVisitor2 {
    type Value = Identity;

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

/// The Identity. Includes the Human Readable Prefix and a hash.
#[derive(PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct Identity(pub(crate) Option<String>, pub(crate) Hash);

impl Identity {
    /// Create new Identity.
    pub fn new(hrp: Option<String>, hash: Hash) -> Self {
        Self(hrp, hash)
    }

    /// Get the Identity HRP.
    pub fn hrp(&self) -> &str {
        if let Some(s) = self.0.as_ref() { s } else { "" }
    }

    /// Get the Identity hash.
    pub fn hash(&self) -> &Hash {
        &self.1
    }

    /// Get the Identity bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        write_varbytes_unsafe(self.hrp().as_bytes(), &mut buf);
        write_varint_u64_unsafe(self.1.codec(), &mut buf);
        write_varbytes_unsafe(self.1.raw(), &mut buf);
        buf
    }

    /// Get an Identity from the public key.
    pub fn from_public_key<PK: PublicKeyTrait>(key: &PK, hrp: &str) -> Self {
        Self(
            if hrp.is_empty() {
                None
            } else {
                Some(hrp.to_string())
            },
            Hash::hash_bytes(&key.to_bytes()),
        )
    }
}

impl<KF: KeyFactory> From<&MultikeyPublicKey<KF>> for Identity {
    fn from(key: &MultikeyPublicKey<KF>) -> Self {
        let hrp = key.hrp();
        Self(
            if hrp.is_empty() {
                None
            } else {
                Some(hrp.to_string())
            },
            Hash::hash_bytes(&key.to_bytes()),
        )
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base32precheck::encode(self.hrp(), self.1.bytes()))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Identity(\"{}\")",
            base32precheck::encode(self.hrp(), self.1.bytes())
        )
    }
}

impl FromStr for Identity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (hrp, data) =
            base32precheck::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(Self(
            if hrp.is_empty() {
                None
            } else {
                Some(hrp.to_string())
            },
            Hash::try_from(data.as_slice())?,
        ))
    }
}

impl TryFrom<&[u8]> for Identity {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let mut reader = value;
        let hrp = read_varbytes(&mut reader)
            .map_err(|_| Error::EncodingError("invalid ID bytes".to_owned()))?;
        let hrp = if hrp.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(&hrp)
                    .map_err(|_| Error::EncodingError("invalid ID prefix".to_owned()))?
                    .to_string(),
            )
        };
        let hash = Hash::try_from(reader)?;
        Ok(Self(hrp, hash))
    }
}

impl Serialize for Identity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        if deserializer.is_human_readable() {
            deserializer
                .deserialize_string(CustomVisitor2)
                .map_err(|_err| Error::custom("failed to deserialize id string"))
        } else {
            deserializer
                .deserialize_bytes(CustomVisitor2)
                .map_err(|err| Error::custom(format!("failed to deserialize id bytes: {err}")))
        }
    }
}

/// Calculate hash distance between bytes.
/// It is a value in range 0..1, where 0 means the same and 1 means completely different.
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::integer_division_remainder_used)]
pub fn hash_distance(hash1: &[u8], hash2: &[u8]) -> f64 {
    let len1 = hash1.len();
    let len2 = hash2.len();
    if len1 == 0 || len2 == 0 {
        return MAX_DISTANCE;
    }
    let t = if len1 < len2 {
        let mut t = vec![(0_f64, 0_f64); len1];
        let mut pos = 0;
        for hash_item in hash2.iter().take(len2) {
            t[pos].0 += f64::from(*hash_item) / 255.0;
            t[pos].1 += 1.0;
            pos = (pos + 1) % len1;
        }
        t
    } else {
        let mut t = vec![(0_f64, 0_f64); len2];
        let mut pos = 0;
        for item in hash1.iter().take(len1) {
            t[pos].0 += f64::from(*item) / 255.0;
            t[pos].1 += 1.0;
            pos = (pos + 1) % len2;
        }
        t
    };
    let mut sum: f64 = 0.0;
    if len1 < len2 {
        for i in 0..len1 {
            let v = f64::from(hash1[i]) / 255.0 - t[i].0 / t[i].1;
            sum += v.abs();
        }
    } else {
        for i in 0..len2 {
            let v = f64::from(hash2[i]) / 255.0 - t[i].0 / t[i].1;
            sum += v.abs();
        }
    }
    sum / t.len() as f64
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

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_identity() {
        let id_str = "mys_xarcs00f95fymgxx90fd9fkttm7zmj3zjrmr4expfrcp0f8ay6338ncmmzp7fy0rljzdaq";
        let id = Identity::from_str(id_str).expect("cannot parse");
        assert_eq!(id.to_string(), id_str);
    }
}
