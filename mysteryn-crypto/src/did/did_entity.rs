use super::did_document::{Document, KeyFormat, VerificationMethod};
use crate::{
    Hash, Identity, base32pc, multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{
        read_varbytes, read_varint_u64, write_varbytes, write_varint_u64, write_varint_usize,
    },
};
use concat_string::concat_string;
use mysteryn_core::concat_vec;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

pub const DID_PREFIX: &str = "did:";
pub const DID_KEY_PREFIX: &str = "did:key:";
pub const DID_PKH_PREFIX: &str = "did:pkh:";
pub const DID_BASE58_PREFIX: &str = "did:key:z";

#[derive(PartialEq, Eq)]
pub enum DidEncoding {
    Base58btc,
    Base32pc,
}

// Note: varint encoding of multicodec 0x0d1d.
pub const DID_IPLD_PREFIX: &[u8] = &[0x9d, 0x1a];

/// The DID, binary-encoded as Multidid.
///
/// The Multidid format:
///
/// ```txt
/// <multidid-code><method-name-varbytes><method-code><method-specific-id-varbytes><url-varbytes>
/// ```
///
/// where
///   - `multidid-code` - the value `0x0d1d` encoded as a [multiformats varint](https://github.com/multiformats/unsigned-varint),
///   - `method-name-varbytes` - the method name string ("key", "pkh", "pkh:mys", ...),
///   - `method-code` - a varint encoded multicode for the [DID Method identifier](https://www.w3.org/TR/did-core/#a-simple-example) or `0x55` for a general DID,
///   - `method-specific-id-varbytes` - varbytes, unique method specific id, which may include colons (":"):
///       - "did:key": public key bytes,
///       - "did:pkh" with the Identity (0x00) codec: identity bytes
///       - "did:pkh" with the Raw (0x55) codec: a string representing `[<network-id>:][<chain-id>:]<account-id>`,
///       - "did:*" with the Raw (0x55) codec: a string of method specific id for general DIDs;
///   - `url-varbytes` - varbytes, an *UTF-8* encoded string representing the [DID URL parameters](https://www.w3.org/TR/did-core/#did-url-syntax).
///
/// The DID string format for a general DID:
///
/// ```txt
/// did:<method>:<url>
/// ```
///
/// The DID string format for the `did:key`:
///
/// ```txt
/// did:key:<Multibase(<method-code><public-key-bytes>)>[<url>]
/// ```
///
/// The DID string format for the `did:pkh`:
///
/// ```txt
/// did:pkh:[<network-id>:][<chain-id>:]<account-id>[<url>]
/// ```
#[derive(PartialEq, Eq, Clone)]
pub struct Did(Vec<u8>);

impl Did {
    /// Get DID as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// DID method name
    pub fn method(&self) -> String {
        let mut buf = &self.0[2..];
        // method-name
        let Ok(method_name) =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))
        else {
            return String::new();
        };
        let Ok(method_name) =
            std::str::from_utf8(&method_name).map_err(|e| Error::EncodingError(e.to_string()))
        else {
            return String::new();
        };
        method_name.to_owned()
    }

    /// DID method specific id:
    /// - public key for "did:key"
    /// - identity (address) for "did:pkh"
    pub fn method_specific_id(&self) -> Option<Vec<u8>> {
        let mut buf = &self.0[2..];
        // method-name
        if read_varbytes(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))
            .is_err()
        {
            return None;
        }
        // method-code
        let Ok(mc) = read_varint_u64(&mut buf) else {
            return None;
        };
        mc?;
        // method-specific-id
        let Ok(data) = read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))
        else {
            return None;
        };
        if data.is_empty() { None } else { Some(data) }
    }

    /// DID URL part
    pub fn url(&self) -> Result<String> {
        let s = self.to_string();
        let method = self.method();
        if let Some(s) = s.strip_prefix(&(method + ":")) {
            return Ok(s.to_string());
        }
        let mut buf = &self.0[2..];
        // method-name
        read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        // method-code
        read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;
        // method-specific-id
        read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let url_bytes = read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let url = std::str::from_utf8(&url_bytes)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .to_owned();
        Ok(url)
    }

    /// DID codec
    pub fn codec(&self) -> Result<u64> {
        let mut buf = &self.0[2..];
        read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let codec = read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;
        Ok(codec)
    }

    /// Create the DID from a public key bytes
    pub fn from_public_key_bytes(
        codec: u64,
        algorithm_name: Option<&str>,
        raw_bytes: &[u8],
    ) -> Result<Did> {
        // multidid-code
        let mut buf = DID_IPLD_PREFIX.to_vec();
        // method-name
        write_varbytes("key".as_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // method-code
        write_varint_u64(codec, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // method-specific-id
        write_varbytes(raw_bytes, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // url-varbytes
        if codec == multicodec_prefix::CUSTOM {
            let url = if let Some(algorithm_name) = algorithm_name {
                concat_string!("?alg=", &urlencoding::encode(algorithm_name))
            } else {
                String::new()
            };
            write_varbytes(url.as_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        } else {
            write_varint_usize(0, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        }
        Ok(Did(buf))
    }

    /// Get public key bytes
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = &self.0[2..];
        // method-name
        let method_name =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let method_name =
            std::str::from_utf8(&method_name).map_err(|e| Error::EncodingError(e.to_string()))?;
        if method_name != "key" && !method_name.starts_with("key:") {
            return Err(Error::ValidationError("not a did:key".to_string()));
        }
        // method-code
        read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;
        read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Create the DID from an identity
    pub fn from_identity(id: &Identity, method_name: &str) -> Result<Did> {
        // multidid-code
        let mut buf = DID_IPLD_PREFIX.to_vec();
        let hrp = id.hrp();
        let method_name = if method_name.is_empty() {
            if hrp.is_empty() {
                "pkh".to_owned()
            } else {
                concat_string!("pkh:", hrp)
            }
        } else {
            if !hrp.is_empty() && hrp != method_name {
                return Err(Error::ValidationError(
                    "method name doesn't match id prefix".to_string(),
                ));
            }
            concat_string!("pkh:", method_name)
        };
        // method-name
        write_varbytes(method_name.as_bytes(), &mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // method-code
        write_varint_u64(multicodec_prefix::IDENTITY, &mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?;
        // method-specific-id
        write_varbytes(&id.to_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        // url-varbytes
        write_varint_usize(0, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        Ok(Did(buf))
    }

    pub fn get_identity(&self) -> Result<Identity> {
        let mut buf = &self.0[2..];
        // method-name
        let method_name =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let method_name =
            std::str::from_utf8(&method_name).map_err(|e| Error::EncodingError(e.to_string()))?;
        if method_name != "pkh" && !method_name.starts_with("pkh:") {
            return Err(Error::ValidationError("not a did:pkh".to_string()));
        }
        let codec = read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::ValidationError("invalid codec".to_string()))?;
        let method_specific_id =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        if codec == multicodec_prefix::IDENTITY {
            Identity::try_from(method_specific_id.as_slice())
                .map_err(|e| Error::EncodingError(e.to_string()))
        } else if let Ok(hash) = Hash::try_from(method_specific_id.as_slice()) {
            Ok(Identity::new("", hash))
        } else {
            Err(Error::ValidationError(
                "does not contain identity".to_string(),
            ))
        }
    }

    pub fn hrp(&self) -> String {
        let mut buf = &self.0[2..];
        let Ok(method_name) = read_varbytes(&mut buf) else {
            return String::new();
        };
        let Ok(method_name) = std::str::from_utf8(&method_name) else {
            return String::new();
        };
        let Ok(codec) = read_varint_u64(&mut buf) else {
            return String::new();
        };
        let Some(codec) = codec else {
            return String::new();
        };
        let Ok(method_specific_id) = read_varbytes(&mut buf) else {
            return String::new();
        };

        if codec == multicodec_prefix::RAW {
            return String::new();
        }

        if method_name == "key" || method_name.starts_with("key:") {
            let mut hrp = String::new();

            if codec == multicodec_prefix::MULTIKEY {
                let mut key_buf = method_specific_id.as_slice();
                // Multikey prefix
                if read_varint_u64(&mut key_buf).is_err() {
                    return String::new();
                }
                // Key codec
                if read_varint_u64(&mut key_buf).is_err() {
                    return String::new();
                }
                // HRP
                let Ok(hrp_bytes) = read_varbytes(&mut key_buf) else {
                    return String::new();
                };
                std::str::from_utf8(&hrp_bytes)
                    .unwrap_or_default()
                    .clone_into(&mut hrp);
            }
            return hrp;
        }

        if method_name == "pkh" || method_name.starts_with("pkh:") {
            let mut hrp = String::new();

            if codec == multicodec_prefix::IDENTITY {
                let mut id_buf = method_specific_id.as_slice();
                // HRP
                let Ok(hrp_bytes) = read_varbytes(&mut id_buf) else {
                    return String::new();
                };
                std::str::from_utf8(&hrp_bytes)
                    .unwrap_or_default()
                    .clone_into(&mut hrp);
            }
            return hrp;
        }

        String::new()
    }

    /// Encode the Did to a string
    pub fn encode(&self, encoding: &DidEncoding) -> Result<String> {
        let mut buf = &self.0[2..];
        let method_name =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let method_name =
            std::str::from_utf8(&method_name).map_err(|e| Error::EncodingError(e.to_string()))?;
        let codec = read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;
        let method_specific_id =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let url = read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let url = std::str::from_utf8(&url).map_err(|e| Error::EncodingError(e.to_string()))?;

        if codec == multicodec_prefix::RAW {
            let id_str = std::str::from_utf8(&method_specific_id)
                .map_err(|e| Error::EncodingError(e.to_string()))?;
            return Ok(concat_string!(DID_PREFIX, method_name, ":", id_str, url));
        }

        if method_name == "key" || method_name.starts_with("key:") {
            let mut hrp = String::new();

            let mut buf = vec![];
            if codec == multicodec_prefix::MULTIKEY {
                let mut key_buf = method_specific_id.as_slice();
                // Multikey prefix
                read_varint_u64(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                // Key codec
                read_varint_u64(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                // HRP
                let hrp_bytes =
                    read_varbytes(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                std::str::from_utf8(&hrp_bytes)
                    .map_err(|e| Error::IOError(e.to_string()))?
                    .clone_into(&mut hrp);
            } else {
                write_varint_u64(codec, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
            }
            let key = &concat_vec!(buf, method_specific_id);

            if *encoding == DidEncoding::Base32pc {
                return Ok(concat_string!(
                    DID_PREFIX,
                    method_name,
                    ":",
                    &base32pc::encode(&hrp, key),
                    url
                ));
            }
            return Ok([
                DID_PREFIX,
                method_name,
                ":",
                &multibase::to_base58(key),
                url,
            ]
            .concat());
        }

        if method_name == "pkh" || method_name.starts_with("pkh:") {
            let (hrp, bytes) = if codec == multicodec_prefix::IDENTITY {
                // identity
                let id = Identity::try_from(method_specific_id.as_slice())
                    .map_err(|e| Error::IOError(e.to_string()))?;
                (id.hrp().to_owned(), id.hash().bytes().to_vec())
            } else if let Ok(hash) = Hash::try_from(method_specific_id.as_slice()) {
                // some hash
                (String::new(), hash.bytes().to_vec())
            } else {
                let id_str = std::str::from_utf8(&method_specific_id)
                    .map_err(|e| Error::EncodingError(e.to_string()))?;
                return Ok(concat_string!(DID_PREFIX, method_name, ":", id_str, url));
            };
            if *encoding == DidEncoding::Base32pc {
                let id = base32pc::encode(&hrp, &bytes);
                let id = id.rsplit_once('_').map_or(id.as_str(), |s| s.1);
                return Ok([DID_PREFIX, method_name, ":", id, url].concat());
            }
            return Ok([
                DID_PREFIX,
                method_name,
                ":",
                &multibase::to_base58(&bytes),
                url,
            ]
            .concat());
        }

        let id_str = std::str::from_utf8(&method_specific_id)
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(concat_string!(DID_PREFIX, method_name, ":", id_str, url))
    }

    /// Encode the Did to a public key string
    pub fn get_public_key_string(&self) -> Result<String> {
        let mut buf = &self.0[2..];
        let method_name =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        let method_name =
            std::str::from_utf8(&method_name).map_err(|e| Error::EncodingError(e.to_string()))?;
        let codec = read_varint_u64(&mut buf)
            .map_err(|e| Error::EncodingError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;

        if codec == multicodec_prefix::RAW {
            return Err(Error::ValidationError("not supported".to_string()));
        }

        if method_name == "key" || method_name.starts_with("key:") {
            let method_specific_id =
                read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
            let mut hrp = String::new();

            if codec == multicodec_prefix::MULTIKEY {
                let mut key_buf = method_specific_id.as_slice();
                // Multikey prefix
                read_varint_u64(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                // Key codec
                read_varint_u64(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                // HRP
                let hrp_bytes =
                    read_varbytes(&mut key_buf).map_err(|e| Error::IOError(e.to_string()))?;
                std::str::from_utf8(&hrp_bytes)
                    .map_err(|e| Error::IOError(e.to_string()))?
                    .clone_into(&mut hrp);
            }

            if !hrp.is_empty() {
                return Ok(base32pc::encode(&hrp, &method_specific_id));
            }
            return Ok(multibase::to_base58(&method_specific_id));
        }

        Err(Error::ValidationError("not supported".to_string()))
    }

    fn get_key_verification_methods(
        &self,
        controller: &str,
        secret_key: Option<String>,
    ) -> Result<Vec<VerificationMethod>> {
        let key = self.get_public_key_string()?;
        Ok(vec![VerificationMethod {
            id: "#key-1".to_owned(),
            key_type: "publicKeyMultibase".into(),
            controller: controller.to_owned(),
            public_key: Some(KeyFormat::Multibase(key)),
            private_key: secret_key.map(KeyFormat::Multibase),
        }])
    }

    fn get_pkh_verification_methods(
        controller: &str,
        public_key: Option<String>,
        secret_key: Option<String>,
    ) -> Result<Vec<VerificationMethod>> {
        let Some(public_key) = public_key else {
            return Err(Error::ValidationError(
                "Public key was not provided".to_owned(),
            ));
        };
        Ok(vec![VerificationMethod {
            id: "#key-1".to_owned(),
            key_type: "publicKeyMultibase".into(),
            controller: controller.to_owned(),
            public_key: Some(KeyFormat::Multibase(public_key)),
            private_key: secret_key.map(KeyFormat::Multibase),
        }])
    }

    pub fn get_document(
        &self,
        public_key: Option<String>,
        secret_key: Option<String>,
    ) -> Result<Document> {
        let controller = self.to_string();
        let method = self.method();
        if method == "key" || method.starts_with("key:") {
            let vm = &self.get_key_verification_methods(&controller, secret_key)?;
            let vm_ids: Vec<String> = vm
                .iter()
                .map(|x| {
                    let Some((_, id)) = x.id.split_once('#') else {
                        return x.id.clone();
                    };
                    concat_string!("#", id)
                })
                .collect();
            Ok(Document {
                context: "https://www.w3.org/ns/did/v1".to_owned(),
                id: controller,
                key_agreement: None,
                authentication: Some(vm_ids.clone()),
                assertion_method: Some(vm_ids.clone()),
                capability_delegation: Some(vm_ids.clone()),
                capability_invocation: Some(vm_ids.clone()),
                verification_method: vm.clone(),
            })
        } else if method == "pkh" || method.starts_with("pkh:") {
            let vm = &Self::get_pkh_verification_methods(&controller, public_key, secret_key)?;
            let vm_ids: Vec<String> = vm
                .iter()
                .map(|x| {
                    let Some((_, id)) = x.id.split_once('#') else {
                        return x.id.clone();
                    };
                    concat_string!("#", id)
                })
                .collect();
            Ok(Document {
                context: "https://www.w3.org/ns/did/v1".to_owned(),
                id: controller,
                key_agreement: None,
                authentication: Some(vm_ids.clone()),
                assertion_method: Some(vm_ids.clone()),
                capability_delegation: Some(vm_ids.clone()),
                capability_invocation: Some(vm_ids.clone()),
                verification_method: vm.clone(),
            })
        } else {
            Err(Error::EncodingError(concat_string!(
                "method ",
                method,
                " is not supported"
            )))
        }
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.encode(if self.hrp().is_empty() {
                &DidEncoding::Base58btc
            } else {
                &DidEncoding::Base32pc
            }) {
                Ok(did_str) => did_str,
                Err(e) => concat_string!("<", e.to_string(), ">"),
            }
        )
    }
}

impl Debug for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let method = self.method();
        let url = self.url().map_err(|_| std::fmt::Error)?;
        if method == "key" || method.starts_with("key:") {
            let algorithm = self.codec().unwrap_or_default();
            let key =
                multibase::to_base58(&self.get_public_key_bytes().map_err(|_| std::fmt::Error)?);
            write!(
                f,
                "Did(did: {self}, method: {method}, algorithm: 0x{algorithm:02x}, key: {key}, url: {url})"
            )
        } else if method == "pkh" || method.starts_with("pkh:") {
            if self.codec().map_err(|_| std::fmt::Error)? == multicodec_prefix::IDENTITY {
                let id = self.get_identity().map_err(|_| std::fmt::Error)?;
                write!(
                    f,
                    "Did(did: {self}, method: {method}, id: {id}, url: {url})"
                )
            } else if self.codec().map_err(|_| std::fmt::Error)? == multicodec_prefix::RAW {
                let id = self.method_specific_id().unwrap_or_default();
                let id = std::str::from_utf8(&id).map_err(|_| std::fmt::Error)?;
                write!(
                    f,
                    "Did(did: {self}, method: {method}, id: {id}, url: {url})"
                )
            } else {
                let hash = self.method_specific_id().unwrap_or_default();
                let hash: Hash = Hash::try_from(hash.as_slice()).map_err(|_| std::fmt::Error)?;
                write!(
                    f,
                    "Did(did: {self}, method: {method}, id: {hash}, url: {url})"
                )
            }
        } else {
            let id = self.method_specific_id().unwrap_or_default();
            let id = std::str::from_utf8(&id).map_err(|_| std::fmt::Error)?;
            write!(
                f,
                "Did(did: {self}, method: {method}, id: {id}, url: {url})"
            )
        }
    }
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let Some(s) = s.strip_prefix(DID_PREFIX) else {
            return Err(Error::EncodingError("not a did".to_owned()));
        };
        let Some((method_name1, tail)) = s.split_once(':') else {
            return Err(Error::EncodingError("invalid did".to_owned()));
        };
        let (method_name, tail) = if let Some((method_name2, tail)) = tail.split_once(':') {
            (concat_string!(method_name1, ":", method_name2), tail)
        } else {
            (method_name1.to_owned(), tail)
        };

        // multidid-code
        let mut buf = DID_IPLD_PREFIX.to_vec();
        // method-name
        write_varbytes(method_name.as_bytes(), &mut buf)
            .map_err(|e| Error::IOError(e.to_string()))?;

        if method_name == "key" || method_name.starts_with("key:") {
            let pos = tail.find(|c: char| ['/', '?', '#'].contains(&c));
            let (key, url) = if let Some(pos) = pos {
                tail.split_at(pos)
            } else {
                (tail, "")
            };

            let key = if key.contains(base32pc::DELIMITER) {
                let (_, key) = base32pc::decode(key)?;
                key
            } else {
                multibase::decode(key)?
            };

            let mut reader = key.as_slice();

            let codec = read_varint_u64(&mut reader)
                .map_err(|e| Error::EncodingError(e.to_string()))?
                .ok_or_else(|| Error::EncodingError("cannot read codec".to_owned()))?;
            let key_data = if codec == multicodec_prefix::MULTIKEY {
                &key
            } else {
                reader
            };

            // method-code
            write_varint_u64(codec, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
            // method-specific-id
            write_varbytes(key_data, &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
            // url-varbytes
            write_varbytes(url.as_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        } else if method_name == "pkh" || method_name.starts_with("pkh:") {
            let pos = tail.find(|c: char| ['/', '?', '#'].contains(&c));
            let (hash, url) = if let Some(pos) = pos {
                tail.split_at(pos)
            } else {
                (tail, "")
            };

            let id_candidate = concat_string!(
                method_name.strip_prefix("pkh:").unwrap_or(&method_name),
                "_",
                hash
            );
            if let Ok(id) = Identity::from_str(&id_candidate) {
                // method-code
                write_varint_u64(multicodec_prefix::IDENTITY, &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // method-specific-id
                write_varbytes(&id.to_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // url-varbytes
                write_varbytes(url.as_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
            } else if let Ok(id) = Hash::from_str(hash) {
                // method-code
                write_varint_u64(id.codec(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // method-specific-id
                write_varbytes(id.bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
                // url-varbytes
                write_varbytes(url.as_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
            } else {
                // other "did:pkh" methods
                // method-code
                write_varint_u64(multicodec_prefix::RAW, &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // method-specific_id
                write_varbytes(hash.as_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // url-varbytes
                write_varbytes(url.as_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
            }
        } else {
            let pos = tail.find(|c: char| ['/', '?', '#'].contains(&c));
            let (id, url) = if let Some(pos) = pos {
                tail.split_at(pos)
            } else {
                (tail, "")
            };
            // method-code
            write_varint_u64(multicodec_prefix::RAW, &mut buf)
                .map_err(|e| Error::IOError(e.to_string()))?;
            // method-specific-id
            write_varbytes(id.as_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
            // url-varbytes
            write_varbytes(url.as_bytes(), &mut buf).map_err(|e| Error::IOError(e.to_string()))?;
        }

        Ok(Self(buf))
    }
}

impl Serialize for Did {
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

impl<'de> Deserialize<'de> for Did {
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
    type Value = Did;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "bytes or string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Did(v.to_vec()))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Did::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Did, DidEncoding};
    use crate::{
        Identity,
        did::PublicDidTrait,
        multikey::{MultikeyPublicKey, MultikeySecretKey},
    };
    use crate::{
        key_traits::*,
        result::Result,
        varint::{read_varbytes, read_varint_u64},
    };
    use crate::{multicodec::multicodec_prefix, test::dag_cbor_roundtrip};
    use mysteryn_core::multibase;
    use mysteryn_keys::{DefaultKeyFactory, ed25519::*, falcon512::*};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;

    const PUBLIC: &str = "z7codm6KnRVquT4fy4zNMXgemx4k3bmZixUqvixHtM7SC";
    //const PUBLIC_PREFIXED: &str = "z6Mkm54gMLaDm3LNZZWfkZLCNnCmme1u1ep5eVkrZEFuGLDa";
    const DID_STR: &str = "did:key:z6Mkm54gMLaDm3LNZZWfkZLCNnCmme1u1ep5eVkrZEFuGLDa";
    const DID_URL_STR: &str =
        "did:key:z6Mkm54gMLaDm3LNZZWfkZLCNnCmme1u1ep5eVkrZEFuGLDa?example=123&test=true";
    const MULTIKEY_PUBLIC: &str =
        "mys_xahgjw6qgrd4uhxqgpyzzhny3ylpyklhcrlv63hcty26k3jrkxu9nhrpgc0us8r9y8zalh7xqzpptetumh";
    const MULTIKEY_DID_STR: &str = "did:key:mys_xahgjw6qgrd4uhxqgpyzzhny3ylpyklhcrlv63hcty26k3jrkxu9nhrpgc0us8r9y8zalh7xqzpptetumh";
    const FALCON_PUBLIC: &str = "z3822NDFsrmnHuBXvrM3n8RUY5ZjmsJtJyDdLvr6mbG6vt6Qn2pG8KYYfpYpjBLi1Lz3yWvqPma648GK9eBUVvdKQDAJKZijEZFNnk8gKvZkEUN7Vnkbr2CrDA2Ma7HJVgoJ6GjoGbCebEuMykxdKUCRtgmCo833tri318LG6fvXqKjMFM1MVoKdEiZPPjXvHw91cu1Luz9ZkNae3543CCNQJ3JdTuw4TtdX7v7ypWnQ6giQsw6q684oETyfo919asvLPg4LvT6fg5ttWPenXM5YXrLs5ospoCVP3Ci25uWWzoC48Hp4KTusLBf2GhahHFK8dQBZWn3DoysJGvktcx68uozrPekMmdjKuWnPegXnrpZjNVT2rg6AVBMxB6FeqJ8jGSFX6L1BQhRo93KyVFhsmCU1JJvqfyC7nmmiHL3KHcPsgrRcDWQBYcX8yZcXM9rf3ScYjphaLZLQd22gdy1G4hbZje31z6ZCquYU3xcMqbG7txmTj4t7uY9HCE14f3yWkVc1wDmAaGNvPTiFyTxjPUjKRdkMSuAVZcJUHbSWVb1MXFc7TRpJRBUhYEsQt9uZ1MudMXEe5yxarZn4GbsrTrrhk8HaYW7Yez9VYC1x9pigNuxAKmB3DesUiL1se9ppSa2LJkAFB5rWE6xPKgfu2xEaQQYWWGY7qGMe14hzyuVQquLC1rTLMjPPhchLqsWzXbgr5angbsLx8Q5yGSafepeQGtrKDmwc4Yvv7121B1wJEzrobd2cgUNkZCLqSzzsh6x6Ly7BGErgGCh8FwGS25CNYQEUwFxcbU4ppjYS2W6AqQqNn3ESb5Dauf1UytYQoeM2VrtCAmyvitnAuidUeV5pJmS96Z5C34V8nVFKktgRaScT8y7anmfWjVismWazaHhKqnSXWsRHAzrFaRFsmo1difMN5mq8rnGydVjttFWa1zE5sqLsh8vLEHSNyuqQQ9aNHwwesf9XBmPRoUvezG1xTsCdecviRjZxYmLYjKJNNx27GK6XkbB3D1rf5vabtw3F5VfBsTiGzveRCL9JNiwfo4Qg59ot9gnPnwpFtMBjgy8PX5cZjR5zWmdTNQZrSuSc9YRfyKMSwA4LRTiGT4xvBWbug2Kr5bRXZ5uQyCqcN2HtN9Ex1LGjgYadP9ZSaS9TwBn5kxSuCubZQJx1YzuojLSUFEprGy4hPAechL2ojUcHZoPprV3WTFVFkPMnNGGGqR";
    const FALCON_DID_STR: &str = "did:key:z13822NDFsrmnHuBXvrM3n8RUY5ZjmsJtJyDdLvr6mbG6vt6Qn2pG8KYYfpYpjBLi1Lz3yWvqPma648GK9eBUVvdKQDAJKZijEZFNnk8gKvZkEUN7Vnkbr2CrDA2Ma7HJVgoJ6GjoGbCebEuMykxdKUCRtgmCo833tri318LG6fvXqKjMFM1MVoKdEiZPPjXvHw91cu1Luz9ZkNae3543CCNQJ3JdTuw4TtdX7v7ypWnQ6giQsw6q684oETyfo919asvLPg4LvT6fg5ttWPenXM5YXrLs5ospoCVP3Ci25uWWzoC48Hp4KTusLBf2GhahHFK8dQBZWn3DoysJGvktcx68uozrPekMmdjKuWnPegXnrpZjNVT2rg6AVBMxB6FeqJ8jGSFX6L1BQhRo93KyVFhsmCU1JJvqfyC7nmmiHL3KHcPsgrRcDWQBYcX8yZcXM9rf3ScYjphaLZLQd22gdy1G4hbZje31z6ZCquYU3xcMqbG7txmTj4t7uY9HCE14f3yWkVc1wDmAaGNvPTiFyTxjPUjKRdkMSuAVZcJUHbSWVb1MXFc7TRpJRBUhYEsQt9uZ1MudMXEe5yxarZn4GbsrTrrhk8HaYW7Yez9VYC1x9pigNuxAKmB3DesUiL1se9ppSa2LJkAFB5rWE6xPKgfu2xEaQQYWWGY7qGMe14hzyuVQquLC1rTLMjPPhchLqsWzXbgr5angbsLx8Q5yGSafepeQGtrKDmwc4Yvv7121B1wJEzrobd2cgUNkZCLqSzzsh6x6Ly7BGErgGCh8FwGS25CNYQEUwFxcbU4ppjYS2W6AqQqNn3ESb5Dauf1UytYQoeM2VrtCAmyvitnAuidUeV5pJmS96Z5C34V8nVFKktgRaScT8y7anmfWjVismWazaHhKqnSXWsRHAzrFaRFsmo1difMN5mq8rnGydVjttFWa1zE5sqLsh8vLEHSNyuqQQ9aNHwwesf9XBmPRoUvezG1xTsCdecviRjZxYmLYjKJNNx27GK6XkbB3D1rf5vabtw3F5VfBsTiGzveRCL9JNiwfo4Qg59ot9gnPnwpFtMBjgy8PX5cZjR5zWmdTNQZrSuSc9YRfyKMSwA4LRTiGT4xvBWbug2Kr5bRXZ5uQyCqcN2HtN9Ex1LGjgYadP9ZSaS9TwBn5kxSuCubZQJx1YzuojLSUFEprGy4hPAechL2ojUcHZoPprV3WTFVFkPMnNGGGqR?alg=Falcon-512";
    //const IDENTITY: &str = "xa0ps3ugy8y8p36qk9js2jj4qgafkv2dhl6zl032kwglu2zqvtdm5rsd5jz77q98dqzxsfk";
    //const IDENTITY_BASE58: &str = "z1gW6mAB3Nhk7z2ckCizjMfdPJukb2UvJRhp6PkrxL81izTg";
    const DID_PKH_STR: &str = "did:pkh:mys:zgW6mAB3Nhk7z2ckCizjMfdPJukb2UvJRhp6PkrxL81izTg";
    //const IDENTITY_HRP: &str = "mys_xarcsgwgwrr5pvt9q4992q36nvc5m0l597lz4vu3lc5yqckmhg8qmfy960jzczm9cstq";
    const DID_PKH_HRP_STR: &str =
        "did:pkh:mys:xarcsgwgwrr5pvt9q4992q36nvc5m0l597lz4vu3lc5yqckmhg8qmfy960jzczm9cstq";
    const DID_PKH_MULTIKEY_STR: &str =
        "did:pkh:mys:xarcs8r9x45wzu9kddgphmkextlkuerv8sdvh64vu380gprhkuhsz9awzs255cgunklu";

    // Generate the above keys.
    #[test]
    #[ignore]
    fn generate_keys() -> Result<()> {
        let secret1 = Ed25519SecretKey::new();
        let public1 = secret1.public_key();
        println!("const PUBLIC: &str = \"{public1}\";");
        println!(
            "//const PUBLIC_PREFIXED: &str = \"{}\";",
            multibase::to_base58(public1.to_prefixed().as_ref())
        );
        println!("const DID_STR: &str = \"{}\";", public1.get_did()?);
        println!(
            "const DID_URL_STR: &str = \"{}?example=123&test=true\";",
            public1.get_did()?
        );
        let secret2 = SecretKey::new(
            multicodec_prefix::ED25519_SECRET,
            None,
            None,
            Some("secret"),
            Some("mys"),
        )?;
        let public2 = secret2.public_key();
        println!("const MULTIKEY_PUBLIC: &str = \"{public2}\";");
        println!("const MULTIKEY_DID_STR: &str = \"{}\";", public2.get_did()?);
        let secret3 = Falcon512SecretKey::new();
        let public3 = secret3.public_key();
        println!("const FALCON_PUBLIC: &str = \"{public3}\";");
        println!("const FALCON_DID_STR: &str = \"{}\";", public3.get_did()?);
        let id1 = Identity::from_public_key(&public1, "");
        println!("//const IDENTITY: &str = \"{id1}\";");
        println!(
            "//const IDENTITY_BASE58: &str = \"{}\";",
            multibase::to_base58(&id1.to_bytes())
        );
        println!(
            "const DID_PKH_STR: &str = \"{}\";",
            Did::from_identity(&id1, "mys")?
        );
        let id2 = Identity::from_public_key(&public1, "mys");
        println!("//const IDENTITY_HRP: &str = \"{id2}\";");
        println!(
            "const DID_PKH_HRP_STR: &str = \"{}\";",
            Did::from_identity(&id2, "mys")?
        );
        let id3 = Identity::from_public_key(&public2, "mys");
        println!(
            "const DID_PKH_MULTIKEY_STR: &str = \"{}\";",
            Did::from_identity(&id3, "mys")?
        );
        Ok(())
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_did_string() {
        let did = Did::from_str(DID_STR).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_public_key() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let did = key.get_did().expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_did_pkh() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let did = key.get_did_pkh("mys", "").expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_extract_public_key() {
        let did = Did::from_str(DID_STR).expect("cannot get did");
        let bytes = did
            .get_public_key_bytes()
            .expect("cannot get public key bytes");
        let key = Ed25519PublicKey::try_from(bytes.as_slice()).expect("cannot create public key");
        assert_eq!(key.to_string(), PUBLIC);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_extract_public_key_string() {
        let did = Did::from_str(DID_STR).expect("cannot get did");
        let key = did
            .get_public_key_string()
            .expect("cannot get public key string");
        assert_eq!(key.to_string(), PUBLIC);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_extract_custom_public_key_string() {
        let did = Did::from_str(FALCON_DID_STR).expect("cannot get did");
        let key = did
            .get_public_key_string()
            .expect("cannot get public key string");
        assert_eq!(key.to_string(), FALCON_PUBLIC);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_did_key_binary_format() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let did = key.get_did().expect("cannot get did");

        let mut buf = did.as_bytes();
        // Multidid prefix
        let prefix = read_varint_u64(&mut buf)
            .expect("cannot get prefix")
            .unwrap();
        assert_eq!(prefix, 0x0d1d);

        // method-prefix
        let method_prefix = read_varbytes(&mut buf).expect("cannot get method prefix");
        let method_prefix =
            std::str::from_utf8(&method_prefix).expect("cannot parse method prefix");
        assert_eq!(method_prefix, "key");

        // method-code
        let codec = read_varint_u64(&mut buf)
            .expect("cannot get prefix")
            .unwrap();
        assert_eq!(codec, 0xed);

        // method-data
        let method_data = read_varbytes(&mut buf).expect("cannot read method data");
        assert_eq!(
            method_data,
            vec![
                98, 82, 45, 202, 237, 72, 108, 82, 0, 121, 35, 128, 181, 142, 149, 229, 218, 229,
                229, 42, 219, 92, 95, 2, 138, 51, 214, 42, 67, 186, 227, 29
            ]
        );

        // url
        let url = read_varbytes(&mut buf).expect("cannot read url");
        assert!(url.is_empty());
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_encode_decode() {
        let did = Did::from_str(DID_STR).expect("cannot get did");

        assert_eq!(did.to_string(), DID_STR);
        assert_eq!(
            did.encode(&DidEncoding::Base58btc).expect("cannot encode"),
            DID_STR
        );
        assert_eq!(
            did.encode(&DidEncoding::Base32pc).expect("cannot encode"),
            "did:key:xa0ps76qtz2gku4m2gd3fqq7frsz6ca909mtj722kmt30s9z3n6c4y8whrr5yr8r09thttc"
        );

        let did2 = Did::from_str(DID_STR).expect("cannot get did");
        assert_eq!(did2.to_string(), DID_STR);
        assert_eq!(
            did2.encode(&DidEncoding::Base58btc).expect("cannot encode"),
            DID_STR
        );
        assert_eq!(
            did2.encode(&DidEncoding::Base32pc).expect("cannot encode"),
            "did:key:xa0ps76qtz2gku4m2gd3fqq7frsz6ca909mtj722kmt30s9z3n6c4y8whrr5yr8r09thttc"
        );
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_url() {
        let did = Did::from_str(DID_URL_STR).expect("cannot parse did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_URL_STR);
        assert_eq!(
            did.url().expect("cannot get method/url"),
            "?example=123&test=true"
        );
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_multikey_public_key() {
        let key = PublicKey::from_str(MULTIKEY_PUBLIC).expect("cannot decode key string");
        let did = key.get_did().expect("cannot get did");
        println!("{did:#?}");

        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), MULTIKEY_DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_did_pkh_from_multikey() {
        let key = PublicKey::from_str(MULTIKEY_PUBLIC).expect("cannot decode key string");
        let did = key.get_did_pkh("mys", key.hrp()).expect("cannot get did");

        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_MULTIKEY_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_multikey_did_string() {
        let did = Did::from_str(MULTIKEY_DID_STR).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), MULTIKEY_DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_extract_multikey_public_key() {
        let did = Did::from_str(MULTIKEY_DID_STR).expect("cannot get did");
        let bytes = did
            .get_public_key_bytes()
            .expect("cannot get public key bytes");
        let key = PublicKey::try_from(bytes.as_slice()).expect("cannot create public key");
        assert_eq!(key.to_string(), MULTIKEY_PUBLIC);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn it_round_trips_a_did() {
        let did_string = DID_STR;
        let did = dag_cbor_roundtrip(&Did::from_str(&did_string).unwrap()).unwrap();
        assert_eq!(did_string, did.to_string());

        let did_string = "did:web:example.com";
        let did = dag_cbor_roundtrip(&Did::from_str(&did_string).unwrap()).unwrap();
        assert_eq!(did_string, did.to_string());
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_custom_public_key() {
        let key = Falcon512PublicKey::from_str(FALCON_PUBLIC).expect("cannot decode key string");
        let did = key.get_did().expect("cannot get did");

        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), FALCON_DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_custom_key_did_string() {
        let did = Did::from_str(FALCON_DID_STR).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), FALCON_DID_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_extract_custom_public_key() {
        let did = Did::from_str(FALCON_DID_STR).expect("cannot get did");
        let bytes = did
            .get_public_key_bytes()
            .expect("cannot get public key bytes");
        let key = Falcon512PublicKey::try_from(bytes.as_slice()).expect("cannot create public key");
        assert_eq!(key.to_string(), FALCON_PUBLIC);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_did_pkh_string() {
        let did = Did::from_str(DID_PKH_STR).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_STR);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_did_pkh_hrp_string() {
        let did = Did::from_str(DID_PKH_HRP_STR).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_HRP_STR);
        println!("{did:#?}")
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_parse_bitcoin_pkh_string() {
        let btc_str =
            "did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6";
        let did = Did::from_str(btc_str).expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), btc_str);
        println!("{did:#?}")
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_identity() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let id = Identity::from_public_key(&key, "");
        let did = Did::from_identity(&id, "mys").expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_STR);
        assert_eq!(did.get_identity().unwrap(), id);

        assert_eq!(
            Did::from_str(DID_PKH_STR).unwrap().get_identity().unwrap(),
            id
        );
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_hrp_identity() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let id = Identity::from_public_key(&key, "mys");
        let did = Did::from_identity(&id, "mys").expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_HRP_STR);

        assert_eq!(
            Did::from_str(DID_PKH_HRP_STR)
                .unwrap()
                .get_identity()
                .unwrap(),
            id
        );
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_did_key_document() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let did = key.get_did().unwrap();
        let doc = did.get_document(None, None).unwrap();
        println!("Doc: {doc:#?}");
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_did_pkh_document() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let id = Identity::from_public_key(&key, "");
        let did = Did::from_identity(&id, "mys").unwrap();
        println!("Did: {did}");
        let doc = did.get_document(Some(key.to_string()), None).unwrap();
        println!("Doc: {doc:#?}");
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_did_pkh_document_from_multikey() {
        let key = PublicKey::from_str(MULTIKEY_PUBLIC).expect("cannot decode key string");
        let id = Identity::from_public_key(&key, "mys");
        let did = Did::from_identity(&id, "mys").unwrap();
        println!("Did: {did}");
        let doc = did.get_document(Some(key.to_string()), None).unwrap();
        println!("Doc: {doc:#?}");
    }
}
