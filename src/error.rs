use std::io;
use uuid;

use regex::Error as ReError;

/// The error types.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Db Key is not found")]
    DbKeyNotFound,

    #[error("{0}")]
    NotFound(String),

    #[error("{0} : {1}")]
    DbFileIoError(String, io::Error),

    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("The database file is not a valid one")]
    InvalidKeePassFile,

    /// Unknown database cipher UUID.
    /// Only `ChaCha20` and `AES256` are supported.
    #[error("Invalid Cipher ID. Only `ChaCha20` and `AES256` are supported")]
    UnsupportedCipher(Vec<u8>),
    #[error("Decryption failed")]
    Decryption,
    #[error("Encryption failed")]
    Encryption,
    #[error("Only `ChaCha20` is supported for decrypting/encrypting protected content")]
    UnsupportedStreamCipher(String),

    #[error("Header corrupted")] //#[error("Header Hash Check Failed")]
    HeaderHashCheckFailed,
    #[error("Please enter valid password")]
    HeaderHmacHashCheckFailed,
    #[error("BlockHashCheckFailed")]
    BlockHashCheckFailed,

    /// Unknown key derivation function UUID.
    #[error("Invalid KDF ID.Only `Argon2` and `AES` are supported")]
    UnsupportedKdf(Vec<u8>),
    #[error("{0}")]
    UnsupportedKdfAlgorithm(String),
    #[error("Only Argon 2d kdf algorithm is supported")]
    SupportedOnlyArgon2dKdfAlgorithm,

    #[error("{0}")]
    Argon2Error(String),
    #[error("{0}")]
    DataError(&'static str),
    #[error("{0}")]
    XmlParsingFailed(#[from] quick_xml::Error),
    #[error("{0}")]
    XmlReadingFailed(String),
    #[error("{0}")]
    UuidCoversionFailed(#[from] uuid::Error),

    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("{0}")]
    RegexError(#[from] ReError),

    #[error("{0}")]
    RmpEncodeError(#[from] rmp_serde::encode::Error),

    #[error("{0}")]
    RmpDecodeError(#[from] rmp_serde::decode::Error),

    #[error("{0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("CustomEntryTypeInUse")]
    CustomEntryTypeInUse,

    #[error("{0}")]
    Other(String),
}

// Tauri main converts App error such as above as "hooks::InvokeError" using serde call and then returns to to the UI
// See https://github.com/tauri-apps/tauri/blob/71ea86a443f2585fa98edd79f2361bd85b380f0c/core/tauri/src/hooks.rs
//
// If we want to custom messaging, we need to provide our string message using either "From" trait or custom serde here
// or using Result<T,String> as return type in commands
impl From<Error> for String {
    fn from(error: Error) -> Self {
        format!("{}", error)
    }
}

impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Error::Other(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
