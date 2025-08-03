use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<String>>,
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(alias = "publicKeyBase58")]
    #[serde(alias = "publicKeyMultibase")]
    #[serde(alias = "publicKeyJwk")]
    pub public_key: Option<KeyFormat>,
    #[serde(alias = "privateKeyBase58")]
    #[serde(alias = "privateKeyMultibase")]
    #[serde(alias = "privateKeyJwk")]
    pub private_key: Option<KeyFormat>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum KeyFormat {
    Base58(String),
    Multibase(String),
    JWK(JWK),
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct JWK {
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl Serialize for VerificationMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("type", &self.key_type)?;
        map.serialize_entry("controller", &self.controller)?;

        if let Some(pk) = &self.public_key {
            match pk {
                KeyFormat::Base58(pk) => map.serialize_entry("publicKeyBase58", &pk)?,
                KeyFormat::Multibase(pk) => map.serialize_entry("publicKeyMultibase", &pk)?,
                KeyFormat::JWK(pk) => map.serialize_entry("publicKeyJwk", &pk)?,
            }
        }
        if let Some(pk) = &self.private_key {
            match pk {
                KeyFormat::Base58(pk) => map.serialize_entry("privateKeyBase58", &pk)?,
                KeyFormat::Multibase(pk) => map.serialize_entry("privateKeyMultibase", &pk)?,
                KeyFormat::JWK(pk) => map.serialize_entry("privateKeyJwk", &pk)?,
            }
        }

        map.end()
    }
}
