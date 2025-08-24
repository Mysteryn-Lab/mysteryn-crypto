use super::did_entity::Did;
use crate::{
    Hash, Identity,
    key_traits::{PublicKeyTrait, SecretKeyTrait},
    result::Result,
};

pub trait SecretDidTrait: SecretKeyTrait {
    /// Provides a DID that can be used to solve the public key
    fn get_did(&self) -> Result<Did> {
        let pk = self.public_key();
        Did::from_public_key_bytes(pk.codec(), Some(self.algorithm_name()), &pk.to_bytes())
    }

    /// Provides a "did:pkh" DID
    fn get_did_pkh(&self, method_name: &str, hrp: &str) -> Result<Did> {
        let pk = self.public_key();
        let id = Identity::new(hrp, Hash::hash_bytes(&pk.to_bytes()));
        Did::from_identity(&id, method_name)
    }
}

impl<T> SecretDidTrait for T where T: SecretKeyTrait {}

pub trait PublicDidTrait: PublicKeyTrait {
    /// Provides a "did:key" DID that can be used to solve the key
    fn get_did(&self) -> Result<Did> {
        Did::from_public_key_bytes(self.codec(), Some(self.algorithm_name()), &self.to_bytes())
    }

    /// Provides a "did:pkh" DID
    fn get_did_pkh(&self, method_name: &str, hrp: &str) -> Result<Did> {
        let id = Identity::new(hrp, Hash::hash_bytes(&self.to_bytes()));
        Did::from_identity(&id, method_name)
    }
}

impl<T> PublicDidTrait for T where T: PublicKeyTrait {}
