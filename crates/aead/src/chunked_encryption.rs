//! C2SP chunked encryption tests

use wycheproof_ng_core::*;

define_test_set!(
    "C2SP chunked encryption",
    "c2sp_chunked_encryption_schema.json"
);

define_test_set_names!(
    Aes128Gcm => "c2sp_chunked_encryption_aes_128_gcm",
    Aes256Gcm => "c2sp_chunked_encryption_aes_256_gcm",
);

define_algorithm_map!(
    "Cobblestone-128" => Cobblestone128,
    "Cobblestone-256" => Cobblestone256,
);

define_test_flags!(
    ChunkReordering,
    CounterRollover,
    HeaderFailure,
    InvalidKeySize,
    ModifiedCiphertext,
    PartialPlaintext,
    TrailingData,
    Truncation,
    ValidFinalChunk,
    WrongContext,
    WrongKey,
);

define_test_group_type_id!(
    "ChunkedEncryption" => ChunkedEncryption,
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
pub enum Aead {
    #[serde(rename = "AEAD_AES_128_GCM")]
    Aes128Gcm,
    #[serde(rename = "AEAD_AES_256_GCM")]
    Aes256Gcm,
}

define_test_group!(
    aead: Aead,
    sha: HashFunction,
);

define_test!(
    key: ByteString,
    "ctx" => context: ByteString,
    ct: ByteString,
    "aeadKey" => aead_key: Option<ByteString>,
    "baseNonce" => base_nonce: Option<ByteString>,
    "msgLength" => message_length: Option<usize>,
    "msgSha512" => message_sha512: Option<ByteString>,
);
