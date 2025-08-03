use crate::{
    attributes::{
        KEY_ALGRORITHM_NAME, KEY_DATA, KEY_IS_ENCRYPTED, KEY_PUBLIC_HRP, KEY_TYPE, KeyAttributes,
        SIG_ALGRORITHM_NAME, SIG_DATA, SIG_NONCE, SIG_PAYLOAD_ENCODING, SIG_PUBLIC_KEY, SIG_SCHEME,
        SignatureAttributes,
    },
    multibase,
    multicodec::multicodec_prefix,
    result::{Error, Result},
    varint::{read_varbytes, read_varint_u64},
};
use std::fmt::Write as _;

pub(crate) fn key_to_debug_string(key: &[u8], algorithm: &str) -> Result<String> {
    let mut key = key;
    let mut s = String::new();
    // Multisig prefix
    let prefix = read_varint_u64(&mut key)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read key prefix".to_owned()))?;
    if prefix != multicodec_prefix::MULTIKEY {
        return Err(Error::EncodingError(format!(
            "not a Multikey prefix 0x{prefix:02x}"
        )));
    }
    // key codec
    let key_codec = read_varint_u64(&mut key)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read key codec".to_owned()))?;
    // HRP
    let hrp = read_varbytes(&mut key).map_err(|e| Error::IOError(e.to_string()))?;

    // Attributes
    let attributes = KeyAttributes::from_reader(&mut key)?;
    if let Some(alg) = attributes.get_algorithm_name()? {
        let _ = write!(s, "algorithm_name: {alg}");
    } else {
        let _ = write!(s, "algorithm_name: {algorithm}");
    }

    let _ = write!(s, ", codec: 0x{key_codec:02x}");
    if !hrp.is_empty() {
        let _ = write!(
            s,
            ", hrp: {}",
            std::str::from_utf8(&hrp).unwrap_or("cannot read hrp")
        );
    }

    if let Some(t) = attributes.get_key_type()? {
        let _ = write!(
            s,
            ", key_type: {}",
            if t == 1 { "secret" } else { "public" }
        );
    }

    if attributes.get_key_is_encrypted()? {
        s += ", is_encrypted: true";
    }

    if let Some(kd) = attributes.get_key_data() {
        let _ = write!(s, ", key_size: {}", kd.len());
    } else {
        s += ", no key data";
    }

    for attr in attributes.0 {
        if ![
            KEY_ALGRORITHM_NAME,
            KEY_TYPE,
            KEY_PUBLIC_HRP,
            KEY_DATA,
            KEY_IS_ENCRYPTED,
        ]
        .contains(&attr.0)
        {
            let _ = write!(s, ", {}: 0x{}", attr.0, hex::encode(attr.1));
        }
    }
    Ok(s)
}

pub(crate) fn signature_to_debug_string(signature: &[u8], algorithm: &str) -> Result<String> {
    let mut signature = signature;
    let mut s = String::new();
    // Multisig prefix
    let prefix = read_varint_u64(&mut signature)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read signature prefix".to_owned()))?;
    if prefix != multicodec_prefix::MULTISIG {
        return Err(Error::EncodingError(format!(
            "not a Multisig prefix 0x{prefix:02x}"
        )));
    }
    // signature codec
    let signature_codec = read_varint_u64(&mut signature)
        .map_err(|e| Error::IOError(e.to_string()))?
        .ok_or_else(|| Error::IOError("cannot read signature codec".to_owned()))?;
    // A message
    let msg = read_varbytes(&mut signature).map_err(|e| Error::IOError(e.to_string()))?;

    // Attributes
    let attributes = SignatureAttributes::from_reader(&mut signature)?;
    if let Some(alg) = attributes.get_algorithm_name()? {
        let _ = write!(s, "algorithm_name: {alg}");
    } else {
        let _ = write!(s, "#algorithm_name: {algorithm}");
    }

    let _ = write!(s, ", codec: 0x{signature_codec:02x}");
    if !msg.is_empty() {
        let _ = write!(
            s,
            ", message: {}",
            std::str::from_utf8(&msg).unwrap_or("cannot read a messsage")
        );
    }

    if let Some(enc) = attributes.get_payload_encoding()? {
        let _ = write!(s, ", payload_encoding: 0x{enc:02x}");
    }
    if let Some(pk) = attributes.get_public_key() {
        let _ = write!(s, ", public_key: {}", multibase::to_base58(pk));
    }
    if let Some(scheme) = attributes.get_scheme()? {
        let _ = write!(s, ", scheme: 0x{scheme:02x}");
    }
    if let Some(nonce) = attributes.get_nonce() {
        let _ = write!(
            s,
            ", nonce_size: {}, nonce: {}",
            nonce.len(),
            multibase::to_base58(nonce)
        );
    }
    if let Some(sd) = attributes.get_signature_data() {
        let _ = write!(s, ", signature_size: {}", sd.len());
    } else {
        s += ", no signature data";
    }
    for attr in attributes.raw() {
        if ![
            SIG_DATA,
            SIG_PAYLOAD_ENCODING,
            SIG_SCHEME,
            SIG_ALGRORITHM_NAME,
            SIG_NONCE,
            SIG_PUBLIC_KEY,
        ]
        .contains(attr.0)
        {
            let _ = write!(s, ", {}: 0x{}", attr.0, hex::encode(attr.1));
        }
    }
    Ok(s)
}
