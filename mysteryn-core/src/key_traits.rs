use crate::{
    attributes::{KeyAttributes, SignatureAttributes},
    result::Result,
    signature::RawSignature,
};
use ambassador::delegatable_trait;
use dyn_clone::{DynClone, clone_trait_object};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    fmt::{Debug, Display},
};

#[cfg(not(target_arch = "wasm32"))]
pub trait KeyMaterialConditionalSendSync: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<K> KeyMaterialConditionalSendSync for K where K: Send + Sync {}

#[cfg(target_arch = "wasm32")]
pub trait KeyMaterialConditionalSendSync {}

#[cfg(target_arch = "wasm32")]
impl<K> KeyMaterialConditionalSendSync for K {}

/// This trait must be implemented by a struct that encapsulates cryptographic
/// secret key data. The trait represent the minimum required API for
/// producing a digital signature from a cryptographic secret key, and verifying
/// such a signature.
#[delegatable_trait]
pub trait SecretKeyTrait: KeyMaterialConditionalSendSync + Debug + Display + DynClone {
    /// Key codec
    fn codec(&self) -> u64;

    /// Signature codec
    fn signature_codec(&self) -> u64;

    /// Returns the number of nonce bytes the algorithm is using in signatures.
    /// If 0, nonce has to be added to data.
    fn signature_nonce_size(&self) -> usize;

    /// The algorithm name of signature
    fn algorithm_name(&self) -> &'static str;

    /// Public key
    fn public_key(&self) -> Box<dyn PublicKeyTrait>;

    /// Get binary view of the key
    fn to_bytes(&self) -> Vec<u8>;

    /// Get a shared secret if algorithm supports it.
    fn get_shared_secret(&self, ciphertext: Option<Vec<u8>>) -> Option<Vec<u8>>;

    /// Sign some data with this key. If algorithm supports nonce, it is automatically generated.
    fn sign(
        &self,
        data: &[u8],
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature>;

    /// Sign some data with this key and other side public key.
    /// If algorithm supports nonce, it is automatically generated.
    fn sign_exchange(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature>;

    /// Deterministic signing for test. Provide enough randomness in the nonce.
    /// For key exchange algorithms, other side public key must be provided
    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature>;

    /// Verify the alleged signature of some data against this key
    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()>;

    /// Get signature from `RawSignature`
    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>>;

    /// Convert to Any
    fn as_any(&self) -> &dyn Any;
}

clone_trait_object!(SecretKeyTrait);

impl SecretKeyTrait for Box<dyn SecretKeyTrait> {
    fn codec(&self) -> u64 {
        self.as_ref().codec()
    }

    fn signature_codec(&self) -> u64 {
        self.as_ref().signature_codec()
    }

    fn signature_nonce_size(&self) -> usize {
        self.as_ref().signature_nonce_size()
    }

    fn algorithm_name(&self) -> &'static str {
        self.as_ref().algorithm_name()
    }

    fn public_key(&self) -> Box<dyn PublicKeyTrait> {
        self.as_ref().public_key()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_bytes()
    }

    fn get_shared_secret(&self, ciphertext: Option<Vec<u8>>) -> Option<Vec<u8>> {
        self.as_ref().get_shared_secret(ciphertext)
    }

    fn sign(
        &self,
        data: &[u8],
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.as_ref().sign(data, attributes)
    }

    fn sign_exchange(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.as_ref()
            .sign_exchange(data, other_public_key_raw_bytes, attributes)
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<Vec<u8>>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.as_ref()
            .sign_deterministic(data, other_public_key_raw_bytes, attributes)
    }

    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()> {
        self.as_ref().verify(data, signature)
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        self.as_ref().signature(signature)
    }

    /// Convert to Any
    fn as_any(&self) -> &dyn Any {
        self.as_ref().as_any()
    }
}

/// This trait must be implemented by a struct that encapsulates cryptographic
/// public key data. The trait represent the minimum required API for verifying
/// a digital signature.
#[delegatable_trait]
pub trait PublicKeyTrait: KeyMaterialConditionalSendSync + Debug + Display + DynClone {
    /// Key codec
    fn codec(&self) -> u64;

    /// Signature codec
    fn signature_codec(&self) -> u64;

    /// Returns the number of nonce bytes the algorithm is using in signatures.
    /// If 0, nonce has to be added to data.
    fn signature_nonce_size(&self) -> usize;

    /// The algorithm name of signature
    fn algorithm_name(&self) -> &'static str;

    /// Get binary view of the key
    fn to_bytes(&self) -> Vec<u8>;

    /// Get ciphertext and shared secret, if algorithm supports it
    fn get_ciphertext(&self, nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)>;

    /// Returns true if public key can verify signatures
    fn can_verify(&self) -> bool;

    /// Verify the alleged signature of some data against this key
    fn verify(&self, payload: &[u8], signature: &RawSignature) -> Result<()>;

    /// Get signature from `RawSignature`
    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>>;

    /// Convert to Any
    fn as_any(&self) -> &dyn Any;
}

clone_trait_object!(PublicKeyTrait);

impl PublicKeyTrait for Box<dyn PublicKeyTrait> {
    fn codec(&self) -> u64 {
        self.as_ref().codec()
    }

    fn signature_codec(&self) -> u64 {
        self.as_ref().signature_codec()
    }
    fn signature_nonce_size(&self) -> usize {
        self.as_ref().signature_nonce_size()
    }

    fn algorithm_name(&self) -> &'static str {
        self.as_ref().algorithm_name()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_bytes()
    }

    fn get_ciphertext(&self, nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        self.as_ref().get_ciphertext(nonce)
    }

    fn can_verify(&self) -> bool {
        self.as_ref().can_verify()
    }

    fn verify(&self, payload: &[u8], signature: &RawSignature) -> Result<()> {
        self.as_ref().verify(payload, signature)
    }

    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
        self.as_ref().signature(signature)
    }

    fn as_any(&self) -> &dyn Any {
        self.as_ref().as_any()
    }
}

/// This trait must be implemented by a struct that encapsulates cryptographic
/// signature data. The trait represent the minimum required API for working
/// with a digital signature.
#[delegatable_trait]
pub trait SignatureTrait: KeyMaterialConditionalSendSync + Debug + Display + DynClone {
    /// Signature codec
    fn codec(&self) -> u64;

    /// Returns the number of nonce bytes the algorithm is using in signatures.
    /// If 0, nonce has to be added to data.
    fn signature_nonce_size(&self) -> usize;

    /// The algorithm name of signature
    fn algorithm_name(&self) -> &'static str;

    /// Get binary view of the signature
    fn as_bytes(&self) -> &[u8];

    /// Get as raw signature
    fn raw(&self) -> &RawSignature;

    /// Convert to Any
    fn as_any(&self) -> &dyn Any;
}

impl SignatureTrait for Box<dyn SignatureTrait> {
    fn codec(&self) -> u64 {
        self.as_ref().codec()
    }

    fn signature_nonce_size(&self) -> usize {
        self.as_ref().signature_nonce_size()
    }

    fn algorithm_name(&self) -> &'static str {
        self.as_ref().algorithm_name()
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }

    fn raw(&self) -> &RawSignature {
        self.as_ref().raw()
    }

    /// Convert to Any
    fn as_any(&self) -> &dyn Any {
        self.as_ref().as_any()
    }
}

clone_trait_object!(SignatureTrait);

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A supported digital signature algorithm.
pub struct SupportedAlgorithm {
    /// Algorithm name.
    pub algorithm_name: String,
    /// Secret key multicodec prefix. `0` for custom codecs.
    pub secret_codec: u64,
    /// Public key and signature multicodec prefix. `0` for custom codecs.
    pub codec: u64,
    /// If this algorithm uses key exchange (need other party public key to sign).
    pub key_exchange: bool,
    /// If a public key can verify the signature.
    pub public_verify: bool,
}

/// Implement this trait to support key types.
pub trait KeyFactory:
    KeyMaterialConditionalSendSync + std::marker::Send + Debug + Eq + Clone + 'static
{
    /// Create new secret key.
    fn new_secret(algorithm: u64, attributes: &KeyAttributes) -> Result<Box<dyn SecretKeyTrait>>;
    /// Read a secret key from bytes.
    fn secret_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &KeyAttributes,
    ) -> Result<Box<dyn SecretKeyTrait>>;
    /// Read a public key from bytes.
    fn public_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &KeyAttributes,
    ) -> Result<Box<dyn PublicKeyTrait>>;
    /// Read a signature from bytes.
    fn signature_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        attributes: &SignatureAttributes,
    ) -> Result<Box<dyn SignatureTrait>>;
    /// List supported algorithms. Returns a vector of `SupportedAlgorithm`.
    fn list_supported() -> Vec<SupportedAlgorithm>;
}
