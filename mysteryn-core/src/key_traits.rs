use crate::{
    attributes::{KeyAttributes, SignatureAttributes},
    concat_vec,
    multicodec::multicodec_prefix::MULTIKEY,
    result::Result,
    signature::RawSignature,
    varint::encode_varint_u64,
};
use ambassador::delegatable_trait;
use dyn_clone::{DynClone, clone_trait_object};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    borrow::Cow,
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
    fn to_bytes(&'_ self) -> Cow<'_, [u8]>;

    /// Get a shared secret if algorithm supports it.
    fn get_shared_secret(&self, ciphertext: Option<&[u8]>) -> Option<Vec<u8>>;

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
        other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature>;

    /// Deterministic signing for test. Provide enough randomness in the nonce.
    /// For key exchange algorithms, other side public key must be provided
    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature>;

    /// Verify the alleged signature of some data against this key
    fn verify(&self, data: &[u8], signature: &RawSignature) -> Result<()>;

    /// Get signature from `RawSignature`
    fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>>;

    /// Convert to Any
    fn as_any(&self) -> &dyn Any;

    /// Export a key to the ssh format.
    fn to_ssh_key(&self) -> Result<String>;

    /// Get multiformat prefixed bytes of the key.
    fn to_prefixed(&self) -> Cow<'_, [u8]> {
        if self.codec() == MULTIKEY {
            // Multikey bytes are already prefixed.
            self.to_bytes()
        } else {
            Cow::Owned(concat_vec!(
                encode_varint_u64(self.codec()),
                self.to_bytes()
            ))
        }
    }
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

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        self.as_ref().to_bytes()
    }

    fn get_shared_secret(&self, ciphertext: Option<&[u8]>) -> Option<Vec<u8>> {
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
        other_public_key_raw_bytes: Option<&[u8]>,
        attributes: Option<&mut SignatureAttributes>,
    ) -> Result<RawSignature> {
        self.as_ref()
            .sign_exchange(data, other_public_key_raw_bytes, attributes)
    }

    fn sign_deterministic(
        &self,
        data: &[u8],
        other_public_key_raw_bytes: Option<&[u8]>,
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

    fn to_ssh_key(&self) -> Result<String> {
        self.as_ref().to_ssh_key()
    }

    fn to_prefixed(&self) -> Cow<'_, [u8]> {
        self.as_ref().to_prefixed()
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
    fn to_bytes(&'_ self) -> Cow<'_, [u8]>;

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

    /// Export a key to the ssh format.
    fn to_ssh_key(&self) -> Result<String>;

    /// Get multiformat prefixed bytes of the key.
    fn to_prefixed(&self) -> Cow<'_, [u8]> {
        if self.codec() == MULTIKEY {
            // Multikey bytes are already prefixed.
            self.to_bytes()
        } else {
            Cow::Owned(concat_vec!(
                encode_varint_u64(self.codec()),
                self.to_bytes()
            ))
        }
    }
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

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
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

    fn to_ssh_key(&self) -> Result<String> {
        self.as_ref().to_ssh_key()
    }

    fn to_prefixed(&self) -> Cow<'_, [u8]> {
        self.as_ref().to_prefixed()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::RawSignature;
    use std::fmt;

    // --- Mocks ---

    #[derive(Debug, Clone)]
    struct MockSecretKey;

    impl Display for MockSecretKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockSecretKey")
        }
    }

    impl SecretKeyTrait for MockSecretKey {
        fn codec(&self) -> u64 {
            1
        }
        fn signature_codec(&self) -> u64 {
            2
        }
        fn signature_nonce_size(&self) -> usize {
            3
        }
        fn algorithm_name(&self) -> &'static str {
            "mock"
        }
        fn public_key(&self) -> Box<dyn PublicKeyTrait> {
            Box::new(MockPublicKey)
        }
        fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
            Cow::Borrowed(&[4, 5, 6])
        }
        fn get_shared_secret(&self, _ciphertext: Option<&[u8]>) -> Option<Vec<u8>> {
            Some(vec![7, 8, 9])
        }
        fn sign(
            &self,
            _data: &[u8],
            _attributes: Option<&mut SignatureAttributes>,
        ) -> Result<RawSignature> {
            Ok(RawSignature::from(&[10, 11, 12][..]))
        }
        fn sign_exchange(
            &self,
            _data: &[u8],
            _other_public_key_raw_bytes: Option<&[u8]>,
            _attributes: Option<&mut SignatureAttributes>,
        ) -> Result<RawSignature> {
            Ok(RawSignature::from(&[10, 11, 12][..]))
        }
        fn sign_deterministic(
            &self,
            _data: &[u8],
            _other_public_key_raw_bytes: Option<&[u8]>,
            _attributes: Option<&mut SignatureAttributes>,
        ) -> Result<RawSignature> {
            Ok(RawSignature::from(&[10, 11, 12][..]))
        }
        fn verify(&self, _data: &[u8], _signature: &RawSignature) -> Result<()> {
            Ok(())
        }
        fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
            Ok(Box::new(MockSignature(signature.clone())))
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn to_ssh_key(&self) -> Result<String> {
            Ok("ssh_key_mock".to_string())
        }
    }

    #[derive(Debug, Clone)]
    struct MockPublicKey;

    impl Display for MockPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockPublicKey")
        }
    }

    impl PublicKeyTrait for MockPublicKey {
        fn codec(&self) -> u64 {
            10
        }
        fn signature_codec(&self) -> u64 {
            11
        }
        fn signature_nonce_size(&self) -> usize {
            12
        }
        fn algorithm_name(&self) -> &'static str {
            "mock_pub"
        }
        fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
            Cow::Borrowed(&[13, 14, 15])
        }
        fn get_ciphertext(&self, _nonce: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
            Some((vec![16], vec![17]))
        }
        fn can_verify(&self) -> bool {
            true
        }
        fn verify(&self, _payload: &[u8], _signature: &RawSignature) -> Result<()> {
            Ok(())
        }
        fn signature(&self, signature: &RawSignature) -> Result<Box<dyn SignatureTrait>> {
            Ok(Box::new(MockSignature(signature.clone())))
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn to_ssh_key(&self) -> Result<String> {
            Ok("ssh_key_mock".to_string())
        }
    }

    #[derive(Debug, Clone)]
    struct MockSignature(RawSignature);

    impl Display for MockSignature {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockSignature")
        }
    }

    impl SignatureTrait for MockSignature {
        fn codec(&self) -> u64 {
            20
        }
        fn signature_nonce_size(&self) -> usize {
            21
        }
        fn algorithm_name(&self) -> &'static str {
            "mock_sig"
        }
        fn as_bytes(&self) -> &[u8] {
            self.0.as_slice()
        }
        fn raw(&self) -> &RawSignature {
            &self.0
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // --- Tests ---

    #[test]
    fn test_boxed_secret_key_trait_delegation() {
        let mock_key = MockSecretKey;
        let boxed_key: Box<dyn SecretKeyTrait> = Box::new(mock_key.clone());

        assert_eq!(boxed_key.codec(), mock_key.codec());
        assert_eq!(boxed_key.signature_codec(), mock_key.signature_codec());
        assert_eq!(
            boxed_key.signature_nonce_size(),
            mock_key.signature_nonce_size()
        );
        assert_eq!(boxed_key.algorithm_name(), mock_key.algorithm_name());
        assert_eq!(boxed_key.to_bytes(), mock_key.to_bytes());
        assert_eq!(
            boxed_key.get_shared_secret(None),
            mock_key.get_shared_secret(None)
        );
        assert!(boxed_key.sign(&[], None).is_ok());
        assert!(boxed_key.verify(&[], &RawSignature::from(&[][..])).is_ok());
        assert!(boxed_key.public_key().codec() == 10);
    }

    #[test]
    fn test_boxed_public_key_trait_delegation() {
        let mock_key = MockPublicKey;
        let boxed_key: Box<dyn PublicKeyTrait> = Box::new(mock_key.clone());

        assert_eq!(boxed_key.codec(), mock_key.codec());
        assert_eq!(boxed_key.signature_codec(), mock_key.signature_codec());
        assert_eq!(
            boxed_key.signature_nonce_size(),
            mock_key.signature_nonce_size()
        );
        assert_eq!(boxed_key.algorithm_name(), mock_key.algorithm_name());
        assert_eq!(boxed_key.to_bytes(), mock_key.to_bytes());
        assert_eq!(
            boxed_key.get_ciphertext(None),
            mock_key.get_ciphertext(None)
        );
        assert_eq!(boxed_key.can_verify(), mock_key.can_verify());
        assert!(boxed_key.verify(&[], &RawSignature::from(&[][..])).is_ok());
    }

    #[test]
    fn test_boxed_signature_trait_delegation() {
        let raw_sig = RawSignature::from(&[1, 2, 3][..]);
        let mock_sig = MockSignature(raw_sig);
        let boxed_sig: Box<dyn SignatureTrait> = Box::new(mock_sig.clone());

        assert_eq!(boxed_sig.codec(), mock_sig.codec());
        assert_eq!(
            boxed_sig.signature_nonce_size(),
            mock_sig.signature_nonce_size()
        );
        assert_eq!(boxed_sig.algorithm_name(), mock_sig.algorithm_name());
        assert_eq!(boxed_sig.as_bytes(), mock_sig.as_bytes());
        assert_eq!(boxed_sig.raw().as_slice(), mock_sig.raw().as_slice());
    }
}
