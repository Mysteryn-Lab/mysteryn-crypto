use crate::{
    encoding::varint::{
        read_varbytes, read_varint_u64, read_varint_usize, write_varbytes, write_varint_u64,
        write_varint_usize,
    },
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

pub const KEY_IS_ENCRYPTED: u64 = 0x00;
pub const KEY_DATA: u64 = 0x01;
pub const KEY_ALGRORITHM_NAME: u64 = 0x0c;
pub const KEY_TYPE: u64 = 0x0d;
pub const KEY_PUBLIC_HRP: u64 = 0x0e;
/**
 * Key attributes:
 *
 * `KeyIsEncrypted (0x00)` : The value is a single boolean byte flag; true if the key data is encrypted.
 * `KeyData (0x01)` : The value is the key data.
 * `CipherCodec (0x02)` : The codec sigil specifying the encryption cipher used to encrypt the key data.
 * `CipherKeyLen (0x03)` : The number of octets in the key encryption key.
 * `CipherNonce (0x04)` : The nonce value for the key encryption cipher.
 * `KdfCodec (0x05)` : The codec sigil specifying the key encryption key derivation function.
 * `KdfSalt (0x06)` : The salt value used in the key encryption key derivation function.
 * `KdfRounds (0x07)` : The number of rounds used in the key encryption key derivation function.
 * `Threshold (0x08)` : The number of threshold signature key shares needed to recreate the key.
 * `Limit (0x09)` : The total number of shares in the split threshold singature key.
 * `ShareIdentifier (0x0a)` : The identifer for a given threshold key share.
 * `ThresholdData (0x0b)` : Threshold signing codec-specific data. This is typically use to
 *      store the accumulated key shares while gathring enough shares to recreate the key.
 * `AlgorithmName (0x0c)` : The key algorithm name of the custom key codec.
 * `KeyType (0x0d)` : The key type of the custom codec (0 or not set - public, 1 - secret).
 * `PublicHrp` (0x0e) : Public key human-readable prefix (used for a secret key).
 */
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct Attributes(pub BTreeMap<u64, Vec<u8>>);

impl Attributes {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn from_reader<R: Read + Unpin>(reader: &mut R) -> Result<Self> {
        let count = read_varint_usize(reader)
            .map_err(|e| Error::IOError(e.to_string()))?
            .ok_or_else(|| Error::EncodingError("cannot read attribute count".to_owned()))?;
        let mut attributes = Self::new();
        for _ in 0..count {
            let attr_id = read_varint_u64(reader)
                .map_err(|e| Error::IOError(e.to_string()))?
                .ok_or_else(|| Error::EncodingError("cannot read attribute id".to_owned()))?;
            let value = read_varbytes(reader).map_err(|e| Error::IOError(e.to_string()))?;
            attributes.0.insert(attr_id, value);
        }
        Ok(attributes)
    }

    pub fn to_writer<W: Write + Unpin>(&self, writer: &mut W) -> Result<()> {
        write_varint_usize(self.0.len(), writer).map_err(|e| Error::IOError(e.to_string()))?;
        for (attr_id, attr_data) in &self.0 {
            write_varint_u64(*attr_id, writer).map_err(|e| Error::IOError(e.to_string()))?;
            write_varbytes(attr_data, writer).map_err(|e| Error::IOError(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_varint(&self, key: u64) -> Result<Option<u64>> {
        self.0
            .get(&key)
            .map(|bytes| {
                let mut buf = bytes.as_slice();
                read_varint_u64(&mut buf).map_err(|e| Error::IOError(e.to_string()))
            })
            .transpose()
            .map(std::option::Option::flatten)
    }

    pub fn set_varint(&mut self, key: u64, value: Option<u64>) {
        if let Some(value) = value {
            let mut buffer = unsigned_varint::encode::u64_buffer();
            let encoded = unsigned_varint::encode::u64(value, &mut buffer);
            self.0.insert(key, encoded.to_vec());
        } else {
            self.0.remove(&key);
        }
    }

    pub fn get_bytes(&self, key: u64) -> Option<&[u8]> {
        self.0.get(&key).map(Vec::as_slice)
    }

    pub fn set_bytes(&mut self, key: u64, bytes: Option<&[u8]>) {
        if let Some(bytes) = bytes {
            self.0.insert(key, bytes.to_vec());
        } else {
            self.0.remove(&key);
        }
    }
}

impl Default for Attributes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct KeyAttributes(pub Attributes);

impl KeyAttributes {
    pub fn new() -> Self {
        Self(Attributes::new())
    }

    pub fn from_reader<R: Read + Unpin>(reader: &mut R) -> Result<Self> {
        Ok(Self(Attributes::from_reader(reader)?))
    }

    pub fn to_writer<W: Write + Unpin>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer(writer)
    }

    pub fn get_varint(&self, key: u64) -> Result<Option<u64>> {
        self.0.get_varint(key)
    }

    pub fn set_varint(&mut self, key: u64, value: Option<u64>) {
        self.0.set_varint(key, value);
    }

    pub fn get_bytes(&self, key: u64) -> Option<&[u8]> {
        self.0.get_bytes(key)
    }

    pub fn set_bytes(&mut self, key: u64, bytes: Option<&[u8]>) {
        self.0.set_bytes(key, bytes);
    }

    pub fn get_key_is_encrypted(&self) -> Result<bool> {
        Ok(self.0.get_varint(KEY_IS_ENCRYPTED)?.unwrap_or(0) != 0)
    }

    pub fn set_key_is_encrypted(&mut self, key_is_encrypted: bool) {
        self.0.set_varint(
            KEY_IS_ENCRYPTED,
            if key_is_encrypted { Some(1) } else { None },
        );
    }

    pub fn get_key_data(&self) -> Option<&[u8]> {
        self.0.get_bytes(KEY_DATA)
    }

    pub fn set_key_data(&mut self, key_data: Option<&[u8]>) {
        self.0.set_bytes(KEY_DATA, key_data);
    }

    pub fn get_algorithm_name(&self) -> Result<Option<&str>> {
        self.0
            .get_bytes(KEY_ALGRORITHM_NAME)
            .map(|bytes| std::str::from_utf8(bytes).map_err(|e| Error::IOError(e.to_string())))
            .transpose()
    }

    pub fn set_algorithm_name(&mut self, name: Option<&str>) {
        self.0
            .set_bytes(KEY_ALGRORITHM_NAME, name.map(str::as_bytes));
    }

    pub fn get_key_type(&self) -> Result<Option<u64>> {
        self.0.get_varint(KEY_TYPE)
    }

    pub fn set_key_type(&mut self, key_type: Option<u64>) {
        self.0.set_varint(KEY_TYPE, key_type);
    }

    pub fn get_public_hrp(&self) -> Result<Option<&str>> {
        self.0
            .get_bytes(KEY_PUBLIC_HRP)
            .map(|bytes| std::str::from_utf8(bytes).map_err(|e| Error::IOError(e.to_string())))
            .transpose()
    }

    pub fn set_public_hrp(&mut self, name: Option<&str>) {
        self.0.set_bytes(KEY_PUBLIC_HRP, name.map(str::as_bytes));
    }
}

impl Default for KeyAttributes {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<KeyAttributes> for Attributes {
    type Error = Error;
    fn try_from(attrs: KeyAttributes) -> Result<Self> {
        Ok(attrs.0)
    }
}

pub const SIG_DATA: u64 = 0x00;
pub const SIG_PAYLOAD_ENCODING: u64 = 0x01;
pub const SIG_SCHEME: u64 = 0x02;
pub const SIG_ALGRORITHM_NAME: u64 = 0x07;
pub const SIG_NONCE: u64 = 0x08;
pub const SIG_PUBLIC_KEY: u64 = 0x09;

pub const BLS12381_BASIC_SCHEME: u64 = 0x00;

/**
 * Signature attributes:
 *
 * `SigData (0x00)` : The signature data.
 * `PayloadEncoding (0x01)` : The sigil specifying the encoding of the signed message.
 * `Scheme (0x02)` : The threshold signing scheme.
 * `Threshold (0x03)` : The minumum number of signature shares required to reconstruct the signature.
 * `Limit (0x04)` : The total number of shares for a threshold signature.
 * `ShareIdentifier (0x05)` : The identifier for the signature share.
 * `ThresholdData (0x06)` : Codec-speicific threshold signature data. This is typically used to accumulate threshold signature shares.
 * `AlgorithmName (0x07)` : The signature algorithm name of the custom signature codec.
 * `Nonce (0x08)` : Nonce bytes, for codecs without signature randomization.
 * `PublicKey(0x09)` : Public key bytes
 */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignatureAttributes(pub Attributes);

impl SignatureAttributes {
    pub fn new() -> Self {
        Self(Attributes::new())
    }

    pub fn raw(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.0.0
    }

    pub fn from_reader<R: Read + Unpin>(reader: &mut R) -> Result<Self> {
        Ok(Self(Attributes::from_reader(reader)?))
    }

    pub fn to_writer<W: Write + Unpin>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer(writer)
    }

    pub fn get_varint(&self, key: u64) -> Result<Option<u64>> {
        self.0.get_varint(key)
    }

    pub fn set_varint(&mut self, key: u64, value: Option<u64>) {
        self.0.set_varint(key, value);
    }

    pub fn get_bytes(&self, key: u64) -> Option<&[u8]> {
        self.0.get_bytes(key)
    }

    pub fn set_bytes(&mut self, key: u64, bytes: Option<&[u8]>) {
        self.0.set_bytes(key, bytes);
    }

    pub fn get_signature_data(&self) -> Option<&[u8]> {
        self.0.get_bytes(SIG_DATA)
    }

    pub fn set_signature_data(&mut self, key_data: Option<&[u8]>) {
        self.0.set_bytes(SIG_DATA, key_data);
    }

    pub fn get_payload_encoding(&self) -> Result<Option<u64>> {
        self.0.get_varint(SIG_PAYLOAD_ENCODING)
    }

    pub fn set_payload_encoding(&mut self, encoding: Option<u64>) {
        self.0.set_varint(SIG_PAYLOAD_ENCODING, encoding);
    }

    pub fn get_scheme(&self) -> Result<Option<u64>> {
        self.0.get_varint(SIG_SCHEME)
    }

    pub fn set_scheme(&mut self, hash_algorithm: Option<u64>) {
        self.0.set_varint(SIG_SCHEME, hash_algorithm);
    }

    pub fn get_algorithm_name(&self) -> Result<Option<&str>> {
        self.0
            .get_bytes(SIG_ALGRORITHM_NAME)
            .map(|bytes| std::str::from_utf8(bytes).map_err(|e| Error::IOError(e.to_string())))
            .transpose()
    }

    pub fn set_algorithm_name(&mut self, name: Option<&str>) {
        self.0
            .set_bytes(SIG_ALGRORITHM_NAME, name.map(str::as_bytes));
    }

    pub fn get_nonce(&self) -> Option<&[u8]> {
        self.0.get_bytes(SIG_NONCE)
    }

    pub fn set_nonce(&mut self, nonce: Option<&[u8]>) {
        self.0.set_bytes(SIG_NONCE, nonce);
    }

    pub fn get_public_key(&self) -> Option<&[u8]> {
        self.0.get_bytes(SIG_PUBLIC_KEY)
    }

    pub fn set_public_key(&mut self, public_key: Option<&[u8]>) {
        self.0.set_bytes(SIG_PUBLIC_KEY, public_key);
    }
}

impl Default for SignatureAttributes {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<SignatureAttributes> for Attributes {
    type Error = Error;
    fn try_from(attrs: SignatureAttributes) -> Result<Self> {
        Ok(attrs.0)
    }
}

// Custom attributes
pub const HASH_ATTR_ID: u64 = 40;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_key_attributes_new() {
        let attributes = KeyAttributes::new();
        assert!(attributes.0.0.is_empty());
    }

    #[test]
    fn test_key_attributes_rw() {
        let mut attributes = KeyAttributes::new();
        attributes.set_key_is_encrypted(true);
        attributes.set_key_data(Some(&[1, 2, 3]));
        attributes.set_algorithm_name(Some("test-algo"));
        attributes.set_key_type(Some(1));
        attributes.set_public_hrp(Some("hrp"));

        let mut buffer = Vec::new();
        attributes.to_writer(&mut buffer).unwrap();

        let mut reader = Cursor::new(buffer);
        let read_attributes = KeyAttributes::from_reader(&mut reader).unwrap();

        assert_eq!(attributes, read_attributes);
        assert!(read_attributes.get_key_is_encrypted().unwrap());
        assert_eq!(read_attributes.get_key_data().unwrap(), &[1, 2, 3]);
        assert_eq!(
            read_attributes.get_algorithm_name().unwrap().unwrap(),
            "test-algo"
        );
        assert_eq!(read_attributes.get_key_type().unwrap().unwrap(), 1);
        assert_eq!(read_attributes.get_public_hrp().unwrap().unwrap(), "hrp");
    }

    #[test]
    fn test_key_attributes_varint() {
        let mut attributes = KeyAttributes::new();
        attributes.set_varint(100, Some(12345));
        assert_eq!(attributes.get_varint(100).unwrap(), Some(12345));
        attributes.set_varint(100, None);
        assert_eq!(attributes.get_varint(100).unwrap(), None);
    }

    #[test]
    fn test_key_attributes_bytes() {
        let mut attributes = KeyAttributes::new();
        attributes.set_bytes(101, Some(&[4, 5, 6]));
        assert_eq!(attributes.get_bytes(101).unwrap(), &[4, 5, 6]);
        attributes.set_bytes(101, None);
        assert_eq!(attributes.get_bytes(101), None);
    }

    #[test]
    fn test_signature_attributes_new() {
        let attributes = SignatureAttributes::new();
        assert!(attributes.0.0.is_empty());
    }

    #[test]
    fn test_signature_attributes_rw() {
        let mut attributes = SignatureAttributes::new();
        attributes.set_signature_data(Some(&[1, 2, 3]));
        attributes.set_payload_encoding(Some(123));
        attributes.set_scheme(Some(456));
        attributes.set_algorithm_name(Some("test-sig-algo"));
        attributes.set_nonce(Some(&[7, 8, 9]));
        attributes.set_public_key(Some(&[10, 11, 12]));

        let mut buffer = Vec::new();
        attributes.to_writer(&mut buffer).unwrap();

        let mut reader = Cursor::new(buffer);
        let read_attributes = SignatureAttributes::from_reader(&mut reader).unwrap();

        assert_eq!(attributes, read_attributes);
        assert_eq!(read_attributes.get_signature_data().unwrap(), &[1, 2, 3]);
        assert_eq!(
            read_attributes.get_payload_encoding().unwrap().unwrap(),
            123
        );
        assert_eq!(read_attributes.get_scheme().unwrap().unwrap(), 456);
        assert_eq!(
            read_attributes.get_algorithm_name().unwrap().unwrap(),
            "test-sig-algo"
        );
        assert_eq!(read_attributes.get_nonce().unwrap(), &[7, 8, 9]);
        assert_eq!(read_attributes.get_public_key().unwrap(), &[10, 11, 12]);
    }

    #[test]
    fn test_signature_attributes_varint() {
        let mut attributes = SignatureAttributes::new();
        attributes.set_varint(200, Some(54321));
        assert_eq!(attributes.get_varint(200).unwrap(), Some(54321));
        attributes.set_varint(200, None);
        assert_eq!(attributes.get_varint(200).unwrap(), None);
    }

    #[test]
    fn test_signature_attributes_bytes() {
        let mut attributes = SignatureAttributes::new();
        attributes.set_bytes(201, Some(&[1, 2, 3]));
        assert_eq!(attributes.get_bytes(201).unwrap(), &[1, 2, 3]);
        attributes.set_bytes(201, None);
        assert_eq!(attributes.get_bytes(201), None);
    }
}
