use super::hash_impl::{CustomVisitor, Hash};
use crate::{
    base32pc,
    key_traits::{KeyFactory, PublicKeyTrait},
    multikey::MultikeyPublicKey,
    result::{Error, Result},
    varint::{decode_varbytes, write_varbytes_unsafe, write_varint_u64_unsafe},
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt::Display, str::FromStr};

/// The Identity. Includes the Human Readable Prefix and a hash.
#[derive(PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct Identity(pub(crate) Cow<'static, str>, pub(crate) Hash);

impl Identity {
    /// Create new Identity.
    pub fn new(hrp: &str, hash: Hash) -> Self {
        // Leak only if needed; otherwise keep it owned
        let hrp = if hrp.is_empty() {
            Cow::Borrowed("")
        } else {
            Cow::Owned(hrp.to_owned())
        };
        Self(hrp, hash)
    }

    /// Get the Identity HRP.
    pub fn hrp(&self) -> &str {
        &self.0
    }

    /// Get the Identity hash.
    pub fn hash(&self) -> &Hash {
        &self.1
    }

    /// Get the Identity bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.hrp().len() + 8 + self.1.raw().len());
        // Write the HRP.
        write_varbytes_unsafe(self.hrp().as_ref(), &mut buf);
        // Write the codec.
        write_varint_u64_unsafe(self.1.codec(), &mut buf);
        // Write the hash.
        write_varbytes_unsafe(self.1.raw(), &mut buf);
        buf
    }

    /// Get an Identity from the public key.
    pub fn from_public_key<PK: PublicKeyTrait>(key: &PK, hrp: &str) -> Self {
        Self::new(hrp, Hash::hash_bytes(&key.to_bytes()))
    }
}

impl<KF: KeyFactory> From<&MultikeyPublicKey<KF>> for Identity {
    fn from(key: &MultikeyPublicKey<KF>) -> Self {
        Self::new(key.hrp(), Hash::hash_bytes(&key.to_bytes()))
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base32pc::encode(self.hrp(), self.1.bytes()))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Identity(\"{}\")",
            base32pc::encode(self.hrp(), self.1.bytes())
        )
    }
}

impl FromStr for Identity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (hrp, data) = base32pc::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(Self::new(hrp, Hash::try_from(data.as_slice())?))
    }
}

impl TryFrom<&[u8]> for Identity {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let (hrp_bytes, rest) =
            decode_varbytes(value).map_err(|_| Error::EncodingError("invalid ID bytes".into()))?;
        let hrp = if hrp_bytes.is_empty() {
            ""
        } else {
            std::str::from_utf8(hrp_bytes)
                .map_err(|_| Error::EncodingError("invalid ID prefix".into()))?
        };
        let hash = Hash::try_from(rest)?;
        Ok(Self::new(hrp, hash))
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
                .deserialize_string(CustomVisitor::<Identity>(std::marker::PhantomData))
                .map_err(|_err| Error::custom("failed to deserialize id string"))
        } else {
            deserializer
                .deserialize_bytes(CustomVisitor::<Identity>(std::marker::PhantomData))
                .map_err(|err| Error::custom(format!("failed to deserialize id bytes: {err}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_identity() {
        //println!("{}", Identity::new("mys", Hash::hash_bytes(&[1, 2, 3, 4])));
        let id_str = "mys_xarcsxx7qazu2ztgmrztaqtrv8zt2aq5f44xg7cgp4rn5avhxmrxs9gv3qn2qj9wcjfy";
        let id = Identity::from_str(id_str).expect("cannot parse");
        assert_eq!(id.to_string(), id_str);
        let bytes = id.to_bytes();
        let id2 = Identity::try_from(bytes.as_slice()).expect("cannot parse from bytes");
        assert_eq!(id, id2);
        assert_eq!(id2.to_string(), id_str);
        assert_eq!(id2.hrp(), "mys");
        assert_eq!(id2.hash().codec(), 30);
    }
}
