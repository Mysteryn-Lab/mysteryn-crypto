use crate::{
    Identity,
    did::Did,
    did::{PublicDidTrait, SecretDidTrait},
    key_traits::*,
    multikey::{MultikeyPublicKey, MultikeySecretKey, Multisig},
    result::Error,
};
use core::fmt;
use mysteryn_keys::DefaultKeyFactory;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

// Decrare key and signature types

/// Multikey secret key
pub type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
/// Multikey public key
pub type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
/// Multisig signature
pub type Signature = Multisig<DefaultKeyFactory>;

#[derive(Debug, Clone)]
pub struct MysJsError(String);
impl std::error::Error for MysJsError {}

impl MysJsError {
    fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl fmt::Display for MysJsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Error> for MysJsError {
    fn from(e: Error) -> Self {
        MysJsError::new(&e.to_string())
    }
}

/// Generate a new secret key
/// @throws
#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn createSecret(
    algorithm: u32,
    algorithm_name: Option<String>,
    hash_algorithm: Option<u32>,
    hrp: &str,
    public_key_hrp: &str,
) -> Result<String, JsError> {
    let secret_key = SecretKey::new(
        algorithm as u64,
        algorithm_name.as_deref(),
        hash_algorithm.map(|x| x as u64),
        if hrp.is_empty() { None } else { Some(hrp) },
        if public_key_hrp.is_empty() {
            None
        } else {
            Some(public_key_hrp)
        },
    )?;
    Ok(secret_key.to_string())
}

/// Convert a secret key to bytes.
/// @throws
#[wasm_bindgen]
pub fn secret2bytes(secret_string: &str) -> Result<Vec<u8>, JsError> {
    Ok(SecretKey::from_str(secret_string)?.to_bytes().to_vec())
}

/// Get a public key from the secret key.
/// @throws
#[wasm_bindgen]
pub fn secret2public(secret_string: &str) -> Result<String, JsError> {
    Ok(SecretKey::from_str(secret_string)?.public_key().to_string())
}

/// Get a "did:key" DID from the secret key
/// @throws
#[wasm_bindgen]
pub fn secret2did(secret_string: &str) -> Result<String, JsError> {
    let key = SecretKey::from_str(secret_string)?;
    Ok(key.get_did()?.to_string())
}

/// Get a "did:pkh" DID from the secret key
/// @throws
#[wasm_bindgen]
pub fn secret2did_pkh(
    secret_string: &str,
    method_name: &str,
    hrp: Option<String>,
) -> Result<String, JsError> {
    let key = SecretKey::from_str(secret_string)?;
    Ok(key
        .get_did_pkh(method_name, hrp.as_deref().unwrap_or(""))?
        .to_string())
}

/// Get an Identity from the secret key
/// @throws
#[wasm_bindgen]
pub fn secret2id(secret_string: &str, hrp: Option<String>) -> Result<String, JsError> {
    let key = SecretKey::from_str(secret_string)?;
    let id = Identity::from_public_key(&key.public_key(), &hrp.unwrap_or(String::new()));
    Ok(id.to_string())
}

/// Convert the public key to bytes.
/// @throws
#[wasm_bindgen]
pub fn public2bytes(key_string: &str) -> Result<Vec<u8>, JsError> {
    Ok(PublicKey::from_str(key_string)?.to_bytes().to_vec())
}

/// Get an Identity from the public key.
/// @throws
#[wasm_bindgen]
pub fn public2id(key_string: &str, hrp: Option<String>) -> Result<String, JsError> {
    let key = PublicKey::from_str(key_string)?;
    Ok(Identity::from_public_key(&key, &hrp.unwrap_or(String::new())).to_string())
}

/// Get a "did:key" DID from the public key
/// @throws
#[wasm_bindgen]
pub fn public2did(key_string: &str) -> Result<String, JsError> {
    let key = PublicKey::from_str(key_string)?;
    Ok(key.get_did()?.to_string())
}

/// Get a "did:pkh" DID from the public key
/// @throws
#[wasm_bindgen]
pub fn public2did_pkh(
    key_string: &str,
    method_name: &str,
    hrp: Option<String>,
) -> Result<String, JsError> {
    let key = PublicKey::from_str(key_string)?;
    Ok(key
        .get_did_pkh(method_name, hrp.as_deref().unwrap_or(""))?
        .to_string())
}

/// Get a DID from the Identity
/// @throws
#[wasm_bindgen]
pub fn id2did(id_string: &str, method_name: &str) -> Result<String, JsError> {
    let id = Identity::from_str(&id_string)?;
    let did = Did::from_identity(&id, method_name)?;
    Ok(did.to_string())
}

/// Get a public key from the DID
/// @throws
#[wasm_bindgen]
pub fn did2public(did_string: &str) -> Result<String, JsError> {
    let did = Did::from_str(did_string)?;
    let bytes = did.get_public_key_bytes()?;
    let key = PublicKey::try_from(bytes.as_slice())?;
    Ok(key.to_string())
}

/// Convert a DID to bytes
/// @throws
#[wasm_bindgen]
pub fn did2bytes(did_string: &str) -> Result<Vec<u8>, JsError> {
    let did = Did::from_str(did_string)?;
    Ok(did.as_bytes().to_vec())
}

/// Get an Identity from the Did.
/// @throws
#[wasm_bindgen]
pub fn did2id(did_string: &str) -> Result<String, JsError> {
    let did = Did::from_str(did_string)?;
    Ok(did.get_identity()?.to_string())
}

/// Sign a data with the secret key and optionally other public key
/// @throws
#[wasm_bindgen]
pub fn sign(
    data: &[u8],
    secret_string: &str,
    other_public_key: Option<String>,
) -> Result<String, JsError> {
    let key = SecretKey::from_str(secret_string)?;
    let other_public_key_raw_bytes = if let Some(s) = other_public_key {
        Some(PublicKey::from_str(&s)?.to_bytes().to_vec())
    } else {
        None
    };
    let sig = key.sign_exchange(data, other_public_key_raw_bytes.as_deref(), None)?;
    let signature = Signature::try_from(&sig)?;
    Ok(signature.to_string())
}

/// Verify the signature
/// @throws
#[wasm_bindgen]
pub fn verify(data: &[u8], key_string: &str, signature: &str) -> Result<(), JsError> {
    let key = PublicKey::from_str(key_string)?;
    let sig = Signature::from_str(signature)?;
    Ok(key.verify(data, sig.raw())?)
}

/// Debug secret key
/// @throws
#[wasm_bindgen]
pub fn secret2debug(secret_string: &str) -> Result<String, JsError> {
    let key = SecretKey::from_str(secret_string)?;
    Ok(format!("{key:#?}"))
}

/// Debug public key
/// @throws
#[wasm_bindgen]
pub fn public2debug(key_string: &str) -> Result<String, JsError> {
    let key = PublicKey::from_str(key_string)?;
    Ok(format!("{key:#?}"))
}

/// Debug signature
/// @throws
#[wasm_bindgen]
pub fn signature2debug(signature_string: &str) -> Result<String, JsError> {
    let sig = Signature::from_str(signature_string)?;
    Ok(format!("{sig:#?}"))
}

/// Debug DID
/// @throws
#[wasm_bindgen]
pub fn did2debug(did_string: &str) -> Result<String, JsError> {
    let did = Did::from_str(did_string)?;
    Ok(format!("{did:#?}"))
}

/// Create DID document
/// @throws
#[wasm_bindgen]
pub fn did2document(
    did_string: &str,
    key_string: Option<String>,
    secret_string: Option<String>,
) -> Result<JsValue, JsError> {
    let did = Did::from_str(did_string)?;
    let doc = did.get_document(key_string, secret_string)?;
    Ok(serde_wasm_bindgen::to_value(&doc)?)
}

/// List supported algorithms.
/// @throws
#[wasm_bindgen]
pub fn list_supported() -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &DefaultKeyFactory::list_supported(),
    )?)
}
