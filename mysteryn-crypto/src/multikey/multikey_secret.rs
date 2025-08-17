use super::{MultikeyPublicKey, Multisig, util::key_to_debug_string};
use crate::{
    RawSignature,
    attributes::{HASH_ATTR_ID, KeyAttributes, SignatureAttributes},
    base32precheck,
    key_traits::{KeyFactory, PublicKeyTrait, SecretKeyTrait, SignatureTrait},
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{
        read_varbytes, read_varint_u64, write_varbytes_unsafe, write_varint_u64,
        write_varint_u64_unsafe, write_varint_usize, write_varint_usize_unsafe,
    },
};
use multihash_codetable::{Code, MultihashDigest};
use rand::{RngCore, rng};
use std::{
    any::Any,
    fmt::{Debug, Display},
    marker::PhantomData,
    str::FromStr,
};

pub const DEFAULT_NONCE_LENGTH: usize = 12;
pub const MIN_NONCE_LENGTH: usize = 8;

/// The Multikey secret key.
/// Internal format: `(key, attributes, hrp, hash)`.
/// The attribute `KEY_DATA` is not set to save a memory - it is automaticaly
/// inserted on serialization.
#[derive(Clone)]
pub struct MultikeySecretKey<KF: KeyFactory>(
    // Inner secret key.
    Box<dyn SecretKeyTrait>,
    // Key attributes, excluding `KEY_DATA`.
    KeyAttributes,
    // HRP.
    Option<String>,
    // Key hash.
    Vec<u8>,
    PhantomData<KF>,
);

impl<KF: KeyFactory> AsRef<MultikeySecretKey<KF>> for MultikeySecretKey<KF> {
    fn as_ref(&self) -> &MultikeySecretKey<KF> {
        self
    }
}

impl<KF: KeyFactory> MultikeySecretKey<KF> {
    pub fn new(
        algorithm: u64,
        algorithm_name: Option<&str>,
        hash_algorithm: Option<u64>,
        hrp: Option<&str>,
        public_hrp: Option<&str>,
    ) -> Result<Self> {
        let mut attributes = KeyAttributes::new();
        if algorithm == multicodec_prefix::CUSTOM {
            if algorithm_name.is_none() {
                return Err(Error::InvalidKey("no algorithm name".to_owned()));
            }
            attributes.set_key_type(Some(1)); // secret key marker
            attributes.set_algorithm_name(algorithm_name);
        }
        if let Some(hash_algorithm) = hash_algorithm {
            attributes.set_varint(HASH_ATTR_ID, Some(hash_algorithm));
        }
        if let Some(public_hrp) = public_hrp {
            attributes.set_public_hrp(Some(public_hrp));
        }
        let key = KF::new_secret(algorithm, &attributes)?;
        Ok(Self::from_key_attributes(
            key,
            attributes,
            hrp.map(std::string::ToString::to_string),
        ))
    }

    pub(crate) fn from_key_attributes(
        key: Box<dyn SecretKeyTrait>,
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

    pub fn hrp(&self) -> &str {
        self.2.as_ref().map_or("", |s| s)
    }

    fn public_hrp(&self) -> &str {
        self.1.get_public_hrp().unwrap_or(None).unwrap_or_default()
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut data: &[u8] = data;

        // Multikey prefix
        let prefix = read_varint_u64(&mut data)
            .map_err(|e| Error::InvalidKey(e.to_string()))?
            .ok_or_else(|| Error::InvalidKey("cannot read multikey prefix".to_owned()))?;
        if prefix != multicodec_prefix::MULTIKEY {
            return Err(Error::InvalidKey(format!(
                "not a multikey prefix: 0x{prefix:02x}",
            )));
        }
        // Key codec
        let key_codec = read_varint_u64(&mut data)
            .map_err(|e| Error::InvalidKey(e.to_string()))?
            .ok_or_else(|| Error::InvalidKey("cannot read key codec".to_owned()))?;
        // HRP
        let hrp = read_varbytes(&mut data).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let hrp = if hrp.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(&hrp)
                    .map_err(|e| Error::InvalidKey(e.to_string()))?
                    .to_owned(),
            )
        };
        // Key attributes
        let attributes = KeyAttributes::from_reader(&mut data)?;
        if key_codec == multicodec_prefix::CUSTOM {
            if attributes.get_algorithm_name()?.is_none() {
                return Err(Error::InvalidKey("no algorithm name".to_string()));
            }
            if attributes.get_key_type()? != Some(1) {
                return Err(Error::InvalidKey("not a secret key".to_string()));
            }
        }
        if attributes.get_key_is_encrypted()? {
            return Err(Error::InvalidKey(
                "encrypted keys are not supported".to_owned(),
            ));
        }

        let Some(key_data) = attributes.get_key_data() else {
            return Err(Error::InvalidKey("no key data".to_owned()));
        };
        let key = KF::secret_from_bytes(key_codec, key_data, &attributes)?;
        Ok(Self::from_key_attributes(key, attributes, hrp))
    }

    /// Get public Multikey from this secret key.
    pub fn public_multikey(&self) -> MultikeyPublicKey<KF> {
        let public_key = self.0.public_key();
        let mut attributes = KeyAttributes::new();
        // TODO
        attributes.set_varint(
            HASH_ATTR_ID,
            self.1.get_varint(HASH_ATTR_ID).unwrap_or(None),
        );
        if self.codec() == multicodec_prefix::CUSTOM {
            attributes.set_algorithm_name(Some(self.algorithm_name()));
        }
        let hrp = self.public_hrp();
        MultikeyPublicKey::<KF>::from_key_attributes(
            public_key,
            attributes,
            if hrp.is_empty() {
                None
            } else {
                Some(hrp.to_string())
            },
        )
    }
}

impl<KF: KeyFactory> SecretKeyTrait for MultikeySecretKey<KF> {
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

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        let public_key = self.0.public_key();
        let mut attributes = KeyAttributes::new();
        // TODO
        attributes.set_varint(
            HASH_ATTR_ID,
            self.1.get_varint(HASH_ATTR_ID).unwrap_or(None),
        );
        if self.codec() == multicodec_prefix::CUSTOM {
            attributes.set_algorithm_name(Some(self.algorithm_name()));
        }
        let hrp = self.public_hrp();
        Box::new(MultikeyPublicKey::<KF>::from_key_attributes(
            public_key,
            attributes,
            if hrp.is_empty() {
                None
            } else {
                Some(hrp.to_string())
            },
        ))
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
        // Attributes
        let mut attr = self.1.clone();
        attr.set_key_data(Some(&self.0.to_bytes()));
        if key_codec == multicodec_prefix::CUSTOM {
            attr.set_key_type(Some(1)); // secret key marker
            attr.set_algorithm_name(Some(self.algorithm_name()));
        }
        attr.to_writer(&mut buf).expect("unchecked write");

        buf
    }

    fn get_shared_secret(&self, ciphertext: Option<Vec<u8>>) -> Option<Vec<u8>> {
        self.0.get_shared_secret(ciphertext)
    }

    fn sign(
        &self,
        data: &[u8],
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.sign_exchange(data, None, attributes)
    }

    fn sign_exchange(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let mut buf = Vec::new();
        let signature_codec = self.0.signature_codec();

        // Multisig prefix
        write_varint_u64(multicodec_prefix::MULTISIG, &mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // Signature codec
        write_varint_u64(signature_codec, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // An empty message
        write_varint_usize(0, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // Attributes
        let mut temp_attributes = SignatureAttributes::default();
        let attributes: &mut SignatureAttributes = if let Some(attributes) = attributes {
            attributes
        } else {
            &mut temp_attributes
        };
        // custom algorithm name
        if signature_codec == multicodec_prefix::CUSTOM {
            attributes.set_algorithm_name(Some(self.algorithm_name()));
        }

        let raw_signature = if self.0.signature_nonce_size() > 0 {
            // the algorithm signature has a nonce
            attributes.set_nonce(None);
            self.0
                .sign_exchange(data, other_public_key_raw_bytes, Some(attributes))?
        } else {
            // algorithm without a nonce, add nonce to data
            let mut csprng = rng();
            let mut nonce: [u8; DEFAULT_NONCE_LENGTH] = [0; DEFAULT_NONCE_LENGTH];
            csprng.fill_bytes(&mut nonce);
            attributes.set_nonce(Some(&nonce));
            self.0.sign_exchange(
                &[data, &nonce].concat(),
                other_public_key_raw_bytes,
                Some(attributes),
            )?
        };
        attributes.set_signature_data(Some(raw_signature.as_bytes()));
        attributes.to_writer(&mut buf)?;

        Ok(RawSignature::from(buf.as_slice()))
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        let mut buf = Vec::new();
        let signature_codec = self.0.signature_codec();

        // Multisig prefix
        write_varint_u64(multicodec_prefix::MULTISIG, &mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // Signature codec
        write_varint_u64(signature_codec, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // An empty message
        write_varint_usize(0, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // Attributes
        let mut temp_attributes = SignatureAttributes::default();
        let attributes: &mut SignatureAttributes = if let Some(attributes) = attributes {
            attributes
        } else {
            &mut temp_attributes
        };
        // custom algorithm name
        if signature_codec == multicodec_prefix::CUSTOM {
            attributes.set_algorithm_name(Some(self.algorithm_name()));
        }

        let nonce_length = attributes.get_nonce().unwrap_or(&vec![]).len();
        if nonce_length < MIN_NONCE_LENGTH {
            return Err(Error::ValidationError("Too small nonce length".to_owned()));
        }

        let raw_signature = if self.0.signature_nonce_size() > 0 {
            // the algorithm signature has a nonce, but for deterministics keep a nonce for SKV
            let s =
                self.0
                    .sign_deterministic(data, other_public_key_raw_bytes, Some(attributes))?;
            // then remove
            attributes.set_nonce(None);
            s
        } else {
            // algorithm without a nonce, add nonce to data
            let Some(nonce) = attributes.get_nonce() else {
                return Err(Error::ValidationError("cannot read nonce".to_owned()));
            };
            self.0.sign_deterministic(
                &[data, nonce].concat(),
                other_public_key_raw_bytes,
                Some(attributes),
            )?
        };
        attributes.set_signature_data(Some(raw_signature.as_bytes()));
        attributes.to_writer(&mut buf)?;

        Ok(RawSignature::from(buf.as_slice()))
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
                "invalid signature alrorithm 0x{signature_codec:02x}"
            )));
        }
        // message should be empty
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

impl<KF: KeyFactory> Display for MultikeySecretKey<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base32precheck::encode(self.hrp(), &self.to_bytes());
        write!(f, "{s}")
    }
}

impl<KF: KeyFactory> Debug for MultikeySecretKey<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let key = self.to_bytes();
        let info = match key_to_debug_string(&key, self.algorithm_name()) {
            Ok(info) => info,
            Err(e) => e.to_string(),
        };

        write!(f, "MultikeySecretKey({}, key: {:?})", info, self.0)
    }
}

impl<KF: KeyFactory> TryFrom<&[u8]> for MultikeySecretKey<KF> {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data)
    }
}

impl<KF: KeyFactory> FromStr for MultikeySecretKey<KF> {
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

impl<KF: KeyFactory> TryFrom<Box<dyn SecretKeyTrait>> for MultikeySecretKey<KF> {
    type Error = Error;
    fn try_from(key: Box<dyn SecretKeyTrait>) -> Result<Self> {
        let Some(k) = key.as_any().downcast_ref::<MultikeySecretKey<KF>>() else {
            return Err(Error::InvalidKey("not a multikey".to_string()));
        };
        Ok(k.clone())
    }
}

impl<KF: KeyFactory> PartialEq for MultikeySecretKey<KF> {
    fn eq(&self, other: &Self) -> bool {
        // Compare by key hashes.
        self.3 == other.3
    }
}

impl<KF: KeyFactory> Eq for MultikeySecretKey<KF> {}

impl<KF: KeyFactory> PartialOrd for MultikeySecretKey<KF> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<KF: KeyFactory> Ord for MultikeySecretKey<KF> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by key hashes.
        self.3.cmp(&other.3)
    }
}
