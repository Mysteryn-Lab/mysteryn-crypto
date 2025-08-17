// See: https://www.rfc-editor.org/rfc/rfc7518
// See: https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.4
// See: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

use super::multicodec_prefix;
use phf::phf_map;

#[allow(non_upper_case_globals)]
pub const EdDSA: &str = "EdDSA";
#[allow(non_upper_case_globals)]
pub const Ed448: &str = "Ed448";
pub const RS256: &str = "RS256";
pub const RS512: &str = "RS512";
pub const ES256: &str = "ES256";
pub const ES384: &str = "ES384";
pub const ES512: &str = "ES512";
pub const ES256K: &str = "ES256K";
#[allow(non_upper_case_globals)]
pub const Bls12381G1: &str = "Bls12381G1";
#[allow(non_upper_case_globals)]
pub const Bls12381G2: &str = "Bls12381G2";
pub const X25519: &str = "X25519";
pub const MLKEM512: &str = "ML-KEM-512";
#[allow(non_upper_case_globals)]
pub const SLHDSASHAKE128f: &str = "SLH-DSA-SHAKE-128f";
#[allow(non_upper_case_globals)]
pub const FAEST128f: &str = "FAEST-128f";
#[allow(non_upper_case_globals)]
pub const Falcon512: &str = "Falcon-512";
#[allow(non_upper_case_globals)]
pub const Falcon1024: &str = "Falcon-1024";
pub const MLDSA44: &str = "ML-DSA-44";
pub const MLDSA65: &str = "ML-DSA-65";
pub const MLDSA87: &str = "ML-DSA-87";
pub const HMAC_SHA256: &str = "HMAC-SHA-256";

pub static ALGORITHM_NAME_TO_SECRET_CODE: phf::Map<&'static str, u64> = phf_map! {
  "EdDSA" => multicodec_prefix::ED25519_SECRET,
  "Ed448"=> multicodec_prefix::ED448_SECRET,
  "RS256" => multicodec_prefix::RSA_SECRET,
  "RS512" => multicodec_prefix::RSA_SECRET,
  "ES256" => multicodec_prefix::P256_SECRET,
  "ES384" => multicodec_prefix::P384_SECRET,
  "ES512" => multicodec_prefix::P521_SECRET,
  "ES256K" => multicodec_prefix::SECP256K1_SECRET,
  "Bls12381G1" => multicodec_prefix::BLS12381G1_SECRET,
  "Bls12381G2" => multicodec_prefix::BLS12381G2_SECRET,
  "X25519" => multicodec_prefix::X25519_SECRET,
  "ML-KEM-512" => multicodec_prefix::MLKEM512_SECRET,
};

pub static ALGORITHM_NAME_TO_PUBLIC_CODE: phf::Map<&'static str, u64> = phf_map! {
  "EdDSA" => multicodec_prefix::ED25519,
  "Ed448"=> multicodec_prefix::ED448,
  "RS256" => multicodec_prefix::RSA,
  "RS512" => multicodec_prefix::RSA,
  "ES256" => multicodec_prefix::P256,
  "ES384" => multicodec_prefix::P384,
  "ES512" => multicodec_prefix::P521,
  "ES256K" => multicodec_prefix::SECP256K1,
  "Bls12381G1" => multicodec_prefix::BLS12381G1,
  "Bls12381G2" => multicodec_prefix::BLS12381G2,
  "X25519" => multicodec_prefix::X25519,
  "ML-KEM-512" => multicodec_prefix::MLKEM512,
};
