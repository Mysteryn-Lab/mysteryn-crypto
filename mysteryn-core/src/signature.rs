use crate::{
    multibase,
    result::{Error, Result},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// A signature in the binary form.
#[derive(PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct RawSignature(Bytes);

impl RawSignature {
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn to_base58(&self) -> String {
        multibase::to_base58(self.as_slice())
    }
}

impl Display for RawSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl Debug for RawSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl From<&[u8]> for RawSignature {
    fn from(bytes: &[u8]) -> Self {
        Self(Bytes::copy_from_slice(bytes))
    }
}

impl FromStr for RawSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = multibase::decode(s)
            .map_err(|_| Error::InvalidSignature("failed to parse signature".to_owned()))?;
        Ok(RawSignature::from(b.as_slice()))
    }
}

impl Serialize for RawSignature {
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

impl<'de> Deserialize<'de> for RawSignature {
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
    type Value = RawSignature;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RawSignature(Bytes::copy_from_slice(v)))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        RawSignature::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_signature_from_bytes() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let signature = RawSignature::from(bytes);
        assert_eq!(signature.as_slice(), bytes);
    }

    #[test]
    fn test_raw_signature_display_and_from_str() {
        let bytes: &[u8] = &[0, 1, 2, 3, 255, 254, 253, 252];
        let signature = RawSignature::from(bytes);
        let base58_str = "z13DV616t9R";
        assert_eq!(signature.to_string(), base58_str);

        let parsed_signature = RawSignature::from_str(base58_str).unwrap();
        assert_eq!(parsed_signature, signature);

        assert!(RawSignature::from_str("invalid base58").is_err());
    }

    #[test]
    fn test_raw_signature_serde_human_readable() {
        let bytes: &[u8] = &[10, 20, 30, 40, 50];
        let signature = RawSignature::from(bytes);

        let json_str = serde_json::to_string(&signature).unwrap();
        let expected_str = format!("\"{}\"", signature.to_base58());
        assert_eq!(json_str, expected_str);

        let deserialized_signature: RawSignature = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized_signature, signature);
    }

    #[test]
    fn test_raw_signature_serde_binary() {
        let bytes: &[u8] = &[100, 110, 120, 130, 140];
        let signature = RawSignature::from(bytes);

        let cbor_bytes = serde_ipld_dagcbor::to_vec(&signature).unwrap();
        let expected_bytes = [69, 100, 110, 120, 130, 140];
        assert_eq!(cbor_bytes, &expected_bytes[..]);

        let deserialized_signature: RawSignature =
            serde_ipld_dagcbor::from_slice(&cbor_bytes).unwrap();
        assert_eq!(deserialized_signature, signature);
    }
}
