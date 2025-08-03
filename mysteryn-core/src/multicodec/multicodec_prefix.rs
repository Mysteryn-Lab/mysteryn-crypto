// Multicodec
pub const MULTIKEY: u64 = 0x123a;
pub const MULTISIG: u64 = 0x1239;
pub const MULTIDID: u64 = 0x0d1d;

// IPLD
pub const RAW: u64 = 0x55;
pub const DAG_CBOR: u64 = 0x71;
pub const DAG_COSE: u64 = 0x86;

// Custom
pub const NONCE: u64 = 0x3b;
pub const IDENTITY: u64 = 0x00;
pub const CUSTOM: u64 = 0x00;

// Public keys
pub const ED25519: u64 = 0xED;
pub const ED448: u64 = 0x1203;
pub const P256: u64 = 0x1200;
pub const P384: u64 = 0x1201;
pub const P521: u64 = 0x1202;
pub const RSA: u64 = 0x1205;
pub const SECP256K1: u64 = 0xe7;
pub const BLS12381G1: u64 = 0xea;
pub const BLS12381G2: u64 = 0xeb;
pub const BLS12381G1G2: u64 = 0xee;
pub const X25519: u64 = 0xec;
pub const MLKEM512: u64 = 0x120b;

// Secret keys
pub const ED25519_SECRET: u64 = 0x1300;
pub const ED448_SECRET: u64 = 0x1311;
pub const P256_SECRET: u64 = 0x1306;
pub const P384_SECRET: u64 = 0x1307;
pub const P521_SECRET: u64 = 0x1308;
pub const RSA_SECRET: u64 = 0x1305;
pub const SECP256K1_SECRET: u64 = 0x1301;
pub const BLS12381G1_SECRET: u64 = 0x1309;
pub const BLS12381G2_SECRET: u64 = 0x130a;
pub const BLS12381G1G2_SECRET: u64 = 0x130b;
pub const X25519_SECRET: u64 = 0x1302;
pub const MLKEM512_SECRET: u64 = 0x121b;

// Hashes
pub const SHA2_256: u64 = 0x12;
pub const SHA2_512: u64 = 0x13;
pub const BLAKE3: u64 = 0x1e;
