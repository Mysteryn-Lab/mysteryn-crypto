use super::{Multisig, util::key_to_debug_string};
use crate::{
    RawSignature,
    attributes::{KeyAttributes, SignatureAttributes},
    base32precheck,
    did::Did,
    key_traits::{KeyFactory, PublicKeyTrait, SignatureTrait},
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{
        read_varbytes, read_varint_u64, write_varbytes_unsafe, write_varint_u64_unsafe,
        write_varint_usize_unsafe,
    },
};
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    fmt::{Debug, Display},
    marker::PhantomData,
    str::FromStr,
};

/// The Multikey public key.
/// Internal format: `(key, attributes, hrp, hash)`.
/// The attribute `KEY_DATA` is not set to save a memory - it is automaticaly
/// inserted on serialization.
#[derive(Clone)]
pub struct MultikeyPublicKey<KF: KeyFactory>(
    // Inner public key.
    Box<dyn PublicKeyTrait>,
    // Key attributes, excluding `KEY_DATA`.
    KeyAttributes,
    // HRP.
    Option<String>,
    // Key hash.
    Vec<u8>,
    PhantomData<KF>,
);

impl<KF: KeyFactory> AsRef<MultikeyPublicKey<KF>> for MultikeyPublicKey<KF> {
    fn as_ref(&self) -> &MultikeyPublicKey<KF> {
        self
    }
}

impl<KF: KeyFactory> MultikeyPublicKey<KF> {
    pub(crate) fn from_key_attributes(
        key: Box<dyn PublicKeyTrait>,
        mut attributes: KeyAttributes,
        hrp: Option<String>,
    ) -> Self {
        // Remove key data, as we have the key instance.
        attributes.set_key_data(None);
        let mut k = Self(key, attributes, hrp, vec![], PhantomData::<KF>);
        let h = Code::Blake3_256.digest(&k.to_bytes());
        k.3 = h.digest().to_vec();
        k
    }

    /// Return bytes of the inner key
    pub fn to_inner_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn hrp(&self) -> &str {
        self.2.as_ref().map_or("", |s| s)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut data: &[u8] = data;

        // Multikey prefix
        let prefix = read_varint_u64(&mut data)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read multikey prefix".to_owned()))?;
        if prefix != multicodec_prefix::MULTIKEY {
            return Err(Error::InvalidKey(format!(
                "not a multikey prefix: 0x{prefix:02x}",
            )));
        }
        // Key codec
        let key_codec = read_varint_u64(&mut data)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read key codec".to_owned()))?;
        // HRP
        let hrp = read_varbytes(&mut data).map_err(|e| Error::IOError(e.to_string()))?;
        let hrp = if hrp.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(&hrp)
                    .map_err(|e| Error::IOError(e.to_string()))?
                    .to_owned(),
            )
        };
        // Key attributes
        let attributes = KeyAttributes::from_reader(&mut data)?;
        if key_codec == multicodec_prefix::CUSTOM && attributes.get_algorithm_name()?.is_none() {
            return Err(Error::InvalidKey("no algorithm name".to_string()));
        }
        let key_data = if let Some(v) = attributes.get_key_data() {
            v.clone()
        } else {
            return Err(Error::InvalidKey("no key data".to_owned()));
        };
        let key = KF::public_from_bytes(key_codec, &key_data, &attributes)?;
        Ok(Self::from_key_attributes(key, attributes, hrp))
    }
}

impl<KF: KeyFactory + Clone> PublicKeyTrait for MultikeyPublicKey<KF> {
    fn codec(&self) -> u64 {
        multicodec_prefix::MULTIKEY
    }

    fn signature_codec(&self) -> u64 {
        multicodec_prefix::MULTISIG
    }

    fn signature_nonce_size(&self) -> usize {
        self.0.signature_nonce_size()
    }

    fn algorithm_name(&self) -> &'static str {
        self.0.algorithm_name()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let key_codec = self.0.codec();

        // Multikey prefix
        write_varint_u64_unsafe(multicodec_prefix::MULTIKEY, &mut buf);
        // Key codec
        write_varint_u64_unsafe(key_codec, &mut buf);
        // HRP
        if let Some(hrp) = self.2.as_ref() {
            if hrp.is_empty() {
                write_varint_usize_unsafe(0, &mut buf);
            } else {
                write_varbytes_unsafe(hrp.as_bytes(), &mut buf);
            }
        } else {
            write_varint_usize_unsafe(0, &mut buf);
        }
        // Key attributes
        let mut attr = self.1.clone();
        attr.set_key_data(Some(&self.0.to_bytes()));
        // custom algorithm name
        if key_codec == multicodec_prefix::CUSTOM {
            attr.set_algorithm_name(Some(self.algorithm_name()));
        }
        attr.to_writer(&mut buf).expect("unchecked write");

        buf
    }

    fn get_ciphertext(&self, nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        self.0.get_ciphertext(nonce)
    }

    fn can_verify(&self) -> bool {
        self.0.can_verify()
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        let mut signature = signature.as_slice();

        // Multisig prefix
        let prefix = read_varint_u64(&mut signature)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read signature prefix".to_owned()))?;
        if prefix != multicodec_prefix::MULTISIG {
            return Err(Error::InvalidSignature(format!(
                "invalid signature prefix 0x{prefix:02x}",
            )));
        }
        // signature codec
        let signature_codec = read_varint_u64(&mut signature)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::IOError("cannot read signature codec".to_owned()))?;
        if signature_codec != self.0.signature_codec() {
            return Err(Error::InvalidSignature(format!(
                "invalid signature codec 0x{signature_codec:02x}",
            )));
        }
        // An empty message
        let msg = read_varbytes(&mut signature).map_err(|e| Error::IOError(e.to_string()))?;
        if !msg.is_empty() {
            return Err(Error::InvalidSignature(
                "embedded signature message is not supported".to_owned(),
            ));
        }
        // Attributes
        let attributes = SignatureAttributes::from_reader(&mut signature)?;
        if let Some(algorithm_name) = attributes.get_algorithm_name()? {
            if algorithm_name != self.algorithm_name() {
                return Err(Error::InvalidSignature(format!(
                    "invalid signature algorithm {algorithm_name}"
                )));
            }
        } else if signature_codec == multicodec_prefix::CUSTOM {
            return Err(Error::InvalidSignature(
                "no signature algorithm".to_string(),
            ));
        }
        let Some(signature_data) = attributes.get_signature_data() else {
            return Err(Error::InvalidSignature("no signature data".to_owned()));
        };

        if self.0.signature_nonce_size() > 0 {
            // the algorithm signature has a nonce
            self.0
                .verify(data, &RawSignature::from(signature_data.as_slice()))?;
        } else if let Some(nonce) = attributes.get_nonce() {
            // append the nonce to data
            self.0.verify(
                &[data, nonce].concat(),
                &RawSignature::from(signature_data.as_slice()),
            )?;
        } else {
            // no nonce
            self.0
                .verify(data, &RawSignature::from(signature_data.as_slice()))?;
        }

        Ok(())
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        Ok(Box::new(Multisig::<KF>::try_from(signature)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<KF: KeyFactory> Display for MultikeyPublicKey<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base32precheck::encode(self.hrp(), &self.to_bytes());
        write!(f, "{s}")
    }
}

impl<KF: KeyFactory> Debug for MultikeyPublicKey<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let key = self.to_bytes();
        let info = match key_to_debug_string(&key, self.algorithm_name()) {
            Ok(info) => info,
            Err(e) => e.to_string(),
        };

        write!(f, "MultikeyPublicKey({}, key: {:?})", info, self.0)
    }
}

impl<KF: KeyFactory> TryFrom<&[u8]> for MultikeyPublicKey<KF> {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data)
    }
}

impl<KF: KeyFactory> TryFrom<Box<dyn PublicKeyTrait>> for MultikeyPublicKey<KF> {
    type Error = Error;
    fn try_from(key: Box<dyn PublicKeyTrait>) -> Result<Self> {
        let Some(k) = key.as_any().downcast_ref::<MultikeyPublicKey<KF>>() else {
            return Err(Error::InvalidKey("not a multikey".to_string()));
        };
        Ok(k.clone())
    }
}

impl<KF: KeyFactory> FromStr for MultikeyPublicKey<KF> {
    type Err = Error;

    fn from_str(key: &str) -> Result<Self> {
        let (hrp, data) =
            base32precheck::decode(key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let s = Self::from_bytes(&data)?;
        if hrp != s.hrp() {
            return Err(Error::InvalidKey("invalid prefix".to_string()));
        }
        Ok(s)
    }
}

impl<KF: KeyFactory> TryFrom<&Did> for MultikeyPublicKey<KF> {
    type Error = Error;
    fn try_from(did: &Did) -> Result<Self> {
        Self::try_from(did.get_public_key_bytes()?.as_slice())
    }
}

impl<KF: KeyFactory> PartialEq for MultikeyPublicKey<KF> {
    fn eq(&self, other: &Self) -> bool {
        // Compare by key hashes.
        self.3 == other.3
    }
}

impl<KF: KeyFactory> Eq for MultikeyPublicKey<KF> {}

impl<KF: KeyFactory> PartialOrd for MultikeyPublicKey<KF> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<KF: KeyFactory> Ord for MultikeyPublicKey<KF> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by key hashes.
        self.3.cmp(&other.3)
    }
}

impl<KF: KeyFactory> Serialize for MultikeyPublicKey<KF> {
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

impl<'de, KF: KeyFactory> Deserialize<'de> for MultikeyPublicKey<KF> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(MultikeyPublicKeyVisitor(PhantomData))
        } else {
            deserializer.deserialize_bytes(MultikeyPublicKeyVisitor(PhantomData))
        }
    }
}
struct MultikeyPublicKeyVisitor<KF: KeyFactory>(PhantomData<KF>);
impl<KF: KeyFactory> serde::de::Visitor<'_> for MultikeyPublicKeyVisitor<KF> {
    type Value = MultikeyPublicKey<KF>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::try_from(v).map_err(|e| E::custom(e.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::from_str(v).map_err(|e| E::custom(e.to_string()))
    }
}
