use super::util::signature_to_debug_string;
use crate::{
    RawSignature,
    attributes::SignatureAttributes,
    key_traits::{KeyFactory, SignatureTrait},
    multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{read_varbytes, read_varint_u64},
};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    fmt::{Debug, Display},
    marker::PhantomData,
    str::FromStr,
};

/// The Multisig.
/// The inner signature contains raw bytes already converted to the Multisig format.
#[derive(Clone)]
pub struct Multisig<KF: KeyFactory>(Box<dyn SignatureTrait>, PhantomData<KF>);

impl<KF: KeyFactory> Multisig<KF> {
    pub fn attributes(&self) -> SignatureAttributes {
        let mut signature = self.as_bytes();
        // Multisig prefix
        let Ok(Some(prefix)) = read_varint_u64(&mut signature) else {
            return SignatureAttributes::new();
        };
        if prefix != multicodec_prefix::MULTISIG {
            return SignatureAttributes::new();
        }
        // signature codec
        if read_varint_u64(&mut signature).is_err() {
            return SignatureAttributes::new();
        }
        // A message
        if read_varbytes(&mut signature).is_err() {
            return SignatureAttributes::new();
        }
        // Attributes
        let Ok(attributes) = SignatureAttributes::from_reader(&mut signature) else {
            return SignatureAttributes::new();
        };
        attributes
    }
}

impl<KF: KeyFactory> SignatureTrait for Multisig<KF> {
    fn codec(&self) -> u64 {
        self.0.codec()
    }

    fn signature_nonce_size(&self) -> usize {
        self.0.signature_nonce_size()
    }

    fn algorithm_name(&self) -> &'static str {
        self.0.algorithm_name()
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Inner signature bytes are in Multisig format.
    fn raw(&self) -> &RawSignature {
        self.0.raw()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<KF: KeyFactory> TryFrom<&[u8]> for Multisig<KF> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let buf = bytes.to_vec();
        let mut buf: &[u8] = &buf;
        // Multisig prefix
        let prefix = read_varint_u64(&mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read signature prefix".to_owned()))?;
        if prefix != multicodec_prefix::MULTISIG {
            return Err(Error::EncodingError(format!(
                "not a Multisig prefix 0x{prefix:02x}"
            )));
        }
        // signature codec
        let signature_codec = read_varint_u64(&mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read signature codec".to_owned()))?;

        // An empty message
        let msg = read_varbytes(&mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        if !msg.is_empty() {
            return Err(Error::InvalidSignature(
                "embedded signature message is not supported".to_owned(),
            ));
        }
        // Attributes
        let attributes = SignatureAttributes::from_reader(&mut buf)?;

        // We keep Multisig raw bytes as-is, without decoding.
        // It differs in format from the inner algorithm signature, but is used
        // by Multisig only.
        Ok(Self(
            KF::signature_from_bytes(signature_codec, bytes, &attributes)?,
            PhantomData::<KF>,
        ))
    }
}

impl<KF: KeyFactory> TryFrom<&RawSignature> for Multisig<KF> {
    type Error = Error;
    fn try_from(raw_signature: &RawSignature) -> Result<Self> {
        Self::try_from(raw_signature.as_slice())
    }
}

impl<KF: KeyFactory> Display for Multisig<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", multibase::to_base58(self.as_bytes()))
    }
}

impl<KF: KeyFactory> FromStr for Multisig<KF> {
    type Err = Error;

    fn from_str(sig: &str) -> Result<Self> {
        let b = multibase::decode(sig).map_err(|e| Error::EncodingError(e.to_string()))?;
        Self::try_from(b.as_slice())
    }
}

impl<KF: KeyFactory> Serialize for Multisig<KF> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de, KF: KeyFactory> Deserialize<'de> for Multisig<KF> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let v: Vec<u8> = deserializer.deserialize_str(CustomVisitor)?;
            Self::from_str(
                std::str::from_utf8(v.as_slice())
                    .map_err(|e| serde::de::Error::custom(e.to_string()))?,
            )
            .map_err(|e| serde::de::Error::custom(e.to_string()))
        } else {
            let v: Vec<u8> = deserializer.deserialize_bytes(CustomVisitor)?;
            Self::try_from(v.as_slice()).map_err(|e| serde::de::Error::custom(e.to_string()))
        }
    }
}
struct CustomVisitor;
impl serde::de::Visitor<'_> for CustomVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.to_vec())
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.as_bytes().to_vec())
    }
}

impl<KF: KeyFactory> Debug for Multisig<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let signature = self.as_bytes();
        let info = match signature_to_debug_string(signature, self.algorithm_name()) {
            Ok(info) => info,
            Err(e) => e.to_string(),
        };

        write!(f, "Multisig({}, signature: {:?})", info, self.0)
    }
}

impl<KF: KeyFactory> TryFrom<Box<dyn SignatureTrait>> for Multisig<KF> {
    type Error = Error;
    fn try_from(key: Box<dyn SignatureTrait>) -> Result<Self> {
        let Some(k) = key.as_any().downcast_ref::<Multisig<KF>>() else {
            return Err(Error::InvalidKey("not a multisig".to_string()));
        };
        Ok(k.clone())
    }
}

impl<KF: KeyFactory> PartialEq for Multisig<KF> {
    fn eq(&self, other: &Self) -> bool {
        // Compare by raw signatures.
        self.0.raw().as_slice() == other.0.raw().as_slice()
    }
}

impl<KF: KeyFactory> Eq for Multisig<KF> {}

impl<KF: KeyFactory> PartialOrd for Multisig<KF> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<KF: KeyFactory> Ord for Multisig<KF> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by raw signatures.
        self.0.raw().as_slice().cmp(other.0.raw().as_slice())
    }
}
