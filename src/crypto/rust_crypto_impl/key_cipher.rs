
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};

use crate::error::{Error, Result};

use sha2::digest::generic_array::GenericArray;

pub struct KeyCipher {
    // key is 256 bits - 32 bytes
    pub(crate) key: Vec<u8>,
    // nonce is 96 bits - 12 bytes
    pub(crate) nonce: Vec<u8>,
}

impl KeyCipher {
    pub fn new() -> Self {
        Self {
            key: Aes256Gcm::generate_key(OsRng).to_vec(),
            nonce: Aes256Gcm::generate_nonce(&mut OsRng).to_vec(),
        }
    }

    pub fn from(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
        }
    }

    #[inline]
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_decrypt(data, true)
    }

    #[inline]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_decrypt(data, false)
    }

    fn encrypt_decrypt(&self, data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(&key);
        let final_data = if encrypt {
            cipher.encrypt(&GenericArray::from_slice(&self.nonce), data)
        } else {
            cipher.decrypt(&GenericArray::from_slice(&self.nonce), data)
        };
        match final_data {
            Ok(v) => Ok(v),
            Err(e) => Err(Error::Other(format!("AES GCM failed {}", e))),
        }
    }
}
