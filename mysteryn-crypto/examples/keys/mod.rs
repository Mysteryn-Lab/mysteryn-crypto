/// Default implementation of key and signature types.
use mysteryn_crypto::multikey::*;
use mysteryn_keys::DefaultKeyFactory;

/// Multikey secret key.
pub type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
/// Multikey public key.
#[allow(dead_code)]
pub type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
/// Multisig signature.
#[allow(dead_code)]
pub type Signature = Multisig<DefaultKeyFactory>;
