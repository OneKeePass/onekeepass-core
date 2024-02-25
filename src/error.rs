use std::io;
use uuid;

use regex::Error as ReError;

/// The error types.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Db Key is not found")]
    DbKeyNotFound,

    #[error("DbFileContentChangeDetected")]
    DbFileContentChangeDetected,

    #[error("{0}")]
    NotFound(String),

    #[error("{0} : {1}")]
    DbFileIoError(String, io::Error),

    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("The database file is not a valid Keepass file")]
    InvalidKeePassFile,
    #[error("The database file is a Keepass 1 database. This is not supported by OneKeePass. Only Keepass 2 database with KDBX format version 4.x is supported")]
    OldUnsupportedKeePass1,
    #[error("The database file is an older version Kdbx 2 or Kdbx 3 formatted file. This is not supported by OneKeePass. Only Keepass 2 database with KDBX format version 4.x is supported")]
    OldUnsupportedKdbxFormat,

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
    #[error("Invalid credentials were provided, please try again")]
    HeaderHmacHashCheckFailed,
    #[error("BlockHashCheckFailed")]
    BlockHashCheckFailed,

    #[error("Valid password or key file name or both are required")]
    InSufficientCredentials,

    /// Unknown key derivation function UUID.
    // #[error("Invalid KDF ID.Only `Argon2` and `AES` are supported")]
    // UnsupportedKdf(Vec<u8>),
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
    XmlEscapeFailed(#[from] quick_xml::escape::EscapeError),
    #[error("{0}")]
    XmlParsingFailed023(#[from] quick_xml_023::Error),

    #[error("{0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    #[error("{0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("{0}")]
    OtpUrlParseError(String),
    
    #[cfg(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "ios",
        all(target_os = "android", target_arch = "aarch64")
    ))]
    #[error("{0}")]
    CryptoError(#[from] botan::Error),

    #[error("{0}")]
    XmlReadingFailed(String),
    #[error("{0}")]
    UuidCoversionFailed(#[from] uuid::Error),

    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("{0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    RegexError(#[from] ReError),

    #[error("{0}")]
    RmpEncodeError(#[from] rmp_serde::encode::Error),

    #[error("{0}")]
    RmpDecodeError(#[from] rmp_serde::decode::Error),

    // To be removed
    #[error("{0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("{0}")]
    DataEncodingDecodeError(#[from] data_encoding::DecodeError),

    #[error("CustomEntryTypeInUse")]
    CustomEntryTypeInUse,

    #[error("{0}")]
    JsonConversionError(#[from] serde_json::Error),

    #[error("HexDecodeError:{0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("Key file is not an xml file")]
    NotXmlKeyFile,

    #[error("Key file xml file with version 1 is not supported")]
    UnsupportedXmlKeyFileVersion,

    #[error("SecureKeyOperationError {0}")]
    SecureKeyOperationError(String),

    #[error("DuplicateKeyFileName:{0}")]
    DuplicateKeyFileName(String),

    // See DataError where we can use str
    // Other is used where we can use format!
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
