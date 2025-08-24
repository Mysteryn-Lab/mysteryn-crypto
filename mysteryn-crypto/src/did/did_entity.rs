use super::did_document::{Document, KeyFormat, VerificationMethod};
use crate::{
    Hash, Identity, base32precheck, multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{
        encode_varbytes, encode_varint_u64, read_varbytes, read_varint_u64, write_varbytes,
        write_varint_u64, write_varint_usize,
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
    Base32precheck,
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
        if codec != multicodec_prefix::IDENTITY {
            return Err(Error::ValidationError(
                "does not contain identity".to_string(),
            ));
        }
        let method_specific_id =
            read_varbytes(&mut buf).map_err(|e| Error::EncodingError(e.to_string()))?;
        Identity::try_from(method_specific_id.as_slice())
            .map_err(|e| Error::EncodingError(e.to_string()))
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

            if *encoding == DidEncoding::Base32precheck {
                return Ok(concat_string!(
                    DID_PREFIX,
                    method_name,
                    ":",
                    &base32precheck::encode(&hrp, key),
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
            } else {
                // some hash
                let hash = Hash::try_from(
                    [
                        encode_varint_u64(codec),
                        encode_varbytes(&method_specific_id),
                    ]
                    .concat()
                    .as_slice(),
                )?;
                (String::new(), hash.bytes().to_vec())
            };
            if *encoding == DidEncoding::Base32precheck {
                return Ok([
                    DID_PREFIX,
                    method_name,
                    ":",
                    &base32precheck::encode(&hrp, &bytes),
                    url,
                ]
                .concat());
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
                return Ok(base32precheck::encode(&hrp, &method_specific_id));
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
                &DidEncoding::Base32precheck
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

            let key = if key.contains(base32precheck::DELIMITER) {
                let (_, key) = base32precheck::decode(key)?;
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

            if let Ok(id) = Identity::from_str(hash) {
                // method-code
                write_varint_u64(multicodec_prefix::IDENTITY, &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
                // method-specific-id
                write_varbytes(&id.to_bytes(), &mut buf)
                    .map_err(|e| Error::IOError(e.to_string()))?;
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
    use mysteryn_keys::{DefaultKeyFactory, ed25519::*, falcon512::*};
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;

    const PUBLIC: &str = "z46jJo6Ah1hEcZHgHUNPedH9aU5YgcXfKarmuKtm5V6Ug";
    const DID_STR: &str = "did:key:z6MkhYzMPLR8MEj5fnWz9wMVUNhaHepY2QugGsgqAAj6QKG4";
    const DID_URL_STR: &str =
        "did:key:z46jJo6Ah1hEcZHgHUNPedH9aU5YgcXfKarmuKtm5V6Ug?example=123&test=true";
    const MULTIKEY_PUBLIC: &str =
        "pub_xahgjw6qgrwp6kyqgpyr6m6pzcm2apgpy9qn2w0dyaawq8nnmqy7w6pnl93nxx26ga8wvk7ng8k54etmr9";
    const MULTIKEY_DID_STR: &str = "did:key:pub_xahgjw6qgrwp6kyqgpyr6m6pzcm2apgpy9qn2w0dyaawq8nnmqy7w6pnl93nxx26ga8wvk7ng8k54etmr9";
    const FALCON_PUBLIC: &str = "z33F6fAkYB9t5RxszqufuwFtQeMC5ayfWWVvEP2cAYJvcCsDUqDNv3ZnebJRaH2Z6xKnzRV1Wepue6k5VzwmQJVi1rxXTG8MqQfevBxAUF4fy5GC9rzWXSSdYNbGPd94up5oixTgFKg9nGqLLjPB9iqzQB5PcKu4w5CfG2jTQSvbLaGD1GTjtQPxMzinodDnp3otvyxGbULkXRjVrXXnwZMNA5ZjgJQogitUdj8RzumQTMDGk3Syb9DnYsdDEGkHELvJj3cE3K1NkJtjJ8MVeexPN9wD1SLhydUw97mVmeGsS42fguk3nkTTUtppYvyjaB2kviBRbccZFJZPAqwKaX4BEp5obWoMg12c38h82sQbtHGZAoHjH47qjUuDe6gjHSzJqrH5ctQ6Ge9UW8bjWkzTxmLDk3xTv94n5GwJvsqxvuxQmyDai1oWDxMF3jwhYzseRbUyHxGNMboWEzWJ7L9uwJ2JFiCnZMH7ukA9tf6RBCL2STqytr4EXFryK9zYVedQhB6MqYNQec7TUPBwChEhe3XVDrUeTr88pMFnGcwXPJdXYadCwHjDXEEUBmFvb9WYyJcSurHq2QkrpPXvmSKUsk4idpwezrV8LRNSRL2sBb1kDkGtbaD9LBNiqRABPJnz4xycHxRbd62GUH54kX36LZ1FK4BZqk426y6WRxpm38udEXECQfv1FhM5DqFp6TjjYm2eSRsYeAqrAaozrobW8wrTywavVgDCrpgrXN2PFtu2jRNs78svih37f4MVUVpYCMu1BdZVJWTeg8w4xhNSBvRauyGcwAgCkuVG3svUnG3WmZEggVhnbuuLRPgv2i93kfhriCn8oUr4DMeigPetpuRmnbryVKbRzd3aAfandZjDA512hAN9MMCS8wD1PLDrv5mmAhMj1CizXm7QJXvek6NDCPfpCpnqFgbavo4EKf7aCURyuKgZRKPtZSe99RWkGv3tXeTTenEiv7sHNzt3j9Vg84CBcKickPD9zEPd6GkLHBgkRRgSi1NmT4yrsqpPkKbS7BFTuQ3PVSwq8mcXFuqRmZsCn1xVLTwYiXxQXf9bRvCbKzePC4ebCzvor2vbhCG8HujjfNfGCwgX7CgLKWbjDscxNsKxsgHVGK1ch5RyAi7qcakX46rJZjypH8cQL3YXznTvh7ynfV8BJcQ6wrTa6MJXbTKCZUaRDqQCxAo5aCD46ARnUhvZf8UWh1vKPbqSAf";
    const FALCON_DID_STR: &str = "did:key:z133F6fAkYB9t5RxszqufuwFtQeMC5ayfWWVvEP2cAYJvcCsDUqDNv3ZnebJRaH2Z6xKnzRV1Wepue6k5VzwmQJVi1rxXTG8MqQfevBxAUF4fy5GC9rzWXSSdYNbGPd94up5oixTgFKg9nGqLLjPB9iqzQB5PcKu4w5CfG2jTQSvbLaGD1GTjtQPxMzinodDnp3otvyxGbULkXRjVrXXnwZMNA5ZjgJQogitUdj8RzumQTMDGk3Syb9DnYsdDEGkHELvJj3cE3K1NkJtjJ8MVeexPN9wD1SLhydUw97mVmeGsS42fguk3nkTTUtppYvyjaB2kviBRbccZFJZPAqwKaX4BEp5obWoMg12c38h82sQbtHGZAoHjH47qjUuDe6gjHSzJqrH5ctQ6Ge9UW8bjWkzTxmLDk3xTv94n5GwJvsqxvuxQmyDai1oWDxMF3jwhYzseRbUyHxGNMboWEzWJ7L9uwJ2JFiCnZMH7ukA9tf6RBCL2STqytr4EXFryK9zYVedQhB6MqYNQec7TUPBwChEhe3XVDrUeTr88pMFnGcwXPJdXYadCwHjDXEEUBmFvb9WYyJcSurHq2QkrpPXvmSKUsk4idpwezrV8LRNSRL2sBb1kDkGtbaD9LBNiqRABPJnz4xycHxRbd62GUH54kX36LZ1FK4BZqk426y6WRxpm38udEXECQfv1FhM5DqFp6TjjYm2eSRsYeAqrAaozrobW8wrTywavVgDCrpgrXN2PFtu2jRNs78svih37f4MVUVpYCMu1BdZVJWTeg8w4xhNSBvRauyGcwAgCkuVG3svUnG3WmZEggVhnbuuLRPgv2i93kfhriCn8oUr4DMeigPetpuRmnbryVKbRzd3aAfandZjDA512hAN9MMCS8wD1PLDrv5mmAhMj1CizXm7QJXvek6NDCPfpCpnqFgbavo4EKf7aCURyuKgZRKPtZSe99RWkGv3tXeTTenEiv7sHNzt3j9Vg84CBcKickPD9zEPd6GkLHBgkRRgSi1NmT4yrsqpPkKbS7BFTuQ3PVSwq8mcXFuqRmZsCn1xVLTwYiXxQXf9bRvCbKzePC4ebCzvor2vbhCG8HujjfNfGCwgX7CgLKWbjDscxNsKxsgHVGK1ch5RyAi7qcakX46rJZjypH8cQL3YXznTvh7ynfV8BJcQ6wrTa6MJXbTKCZUaRDqQCxAo5aCD46ARnUhvZf8UWh1vKPbqSAf?alg=Falcon-512";
    const DID_PKH_STR: &str = "did:pkh:mys:zgW2mgt3C1zSi9KYKGjm4WMXfHXjkmcHnqH3avFmCCFKNM2";
    const DID_PKH_HRP_STR: &str =
        "did:pkh:mys:id_xarcsyh4durd0lefdg43d77fjsr755vpfn2h433tdf9ykxz8l8a3sz4nwrky72wzezlq";
    const DID_PKH_MULTIKEY_STR: &str =
        "did:pkh:mys:id_xarcsvmunqp4ezcvnsgrzdfe0knm36j0rerpcylrj0yaesza8dpgaltlx0wkgwd4vets";

    // Generate the above keys.
    #[test]
    #[ignore]
    fn generate_keys() -> Result<()> {
        let secret1 = Ed25519SecretKey::new();
        let public1 = secret1.public_key();
        println!("const PUBLIC: &str = \"{public1}\";");
        println!("const DID_STR: &str = \"{}\";", public1.get_did()?);
        println!("const DID_URL_STR: &str = \"did:key:{public1}?example=123&test=true\";");
        let secret2 = SecretKey::new(
            multicodec_prefix::ED25519_SECRET,
            None,
            None,
            Some("secret"),
            Some("pub"),
        )?;
        let public2 = secret2.public_key();
        println!("const MULTIKEY_PUBLIC: &str = \"{public2}\";");
        println!("const MULTIKEY_DID_STR: &str = \"{}\";", public2.get_did()?);
        let secret3 = Falcon512SecretKey::new();
        let public3 = secret3.public_key();
        println!("const FALCON_PUBLIC: &str = \"{public3}\";");
        println!("const FALCON_DID_STR: &str = \"{}\";", public3.get_did()?);
        let id1 = Identity::from_public_key(&public1, "");
        println!(
            "const DID_PKH_STR: &str = \"{}\";",
            Did::from_identity(&id1, "mys")?
        );
        let id2 = Identity::from_public_key(&public1, "id");
        println!(
            "const DID_PKH_HRP_STR: &str = \"{}\";",
            Did::from_identity(&id2, "mys")?
        );
        let id3 = Identity::from_public_key(&public2, "id");
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
                46, 10, 205, 32, 181, 195, 157, 135, 240, 140, 38, 24, 154, 11, 236, 141, 238, 180,
                224, 137, 46, 39, 84, 226, 125, 36, 39, 55, 116, 130, 67, 217
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
            did.encode(&DidEncoding::Base32precheck)
                .expect("cannot encode"),
            "did:key:xa0ps76qfwptxjpdwrnkrlprpxrzdqhmyda66wpzfwya2wylfyyumhfqjrm9f07wl6eyj77"
        );

        let did2 = Did::from_str(DID_STR).expect("cannot get did");
        assert_eq!(did2.to_string(), DID_STR);
        assert_eq!(
            did2.encode(&DidEncoding::Base58btc).expect("cannot encode"),
            DID_STR
        );
        assert_eq!(
            did2.encode(&DidEncoding::Base32precheck)
                .expect("cannot encode"),
            "did:key:xa0ps76qfwptxjpdwrnkrlprpxrzdqhmyda66wpzfwya2wylfyyumhfqjrm9f07wl6eyj77"
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
        let did = key.get_did_pkh("mys", "id").expect("cannot get did");

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
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn can_create_from_hrp_identity() {
        let key = Ed25519PublicKey::from_str(PUBLIC).expect("cannot decode key string");
        let id = Identity::from_public_key(&key, "id");
        let did = Did::from_identity(&id, "mys").expect("cannot get did");
        assert_eq!(&did.0[0..2], super::DID_IPLD_PREFIX);
        assert_eq!(did.to_string(), DID_PKH_HRP_STR);
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
        let id = Identity::from_public_key(&key, "id");
        let did = Did::from_identity(&id, "mys").unwrap();
        println!("Did: {did}");
        let doc = did.get_document(Some(key.to_string()), None).unwrap();
        println!("Doc: {doc:#?}");
    }
}
