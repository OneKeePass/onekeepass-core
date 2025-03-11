
use crate::crypto;
use crate::error::Result;

pub struct KeyCipher {
    // key is 256 bits - 32 bytes
    pub(crate) key: Vec<u8>,
    // nonce is 96 bits - 12 bytes
    pub(crate) nonce: Vec<u8>,
}

impl KeyCipher {
    pub fn new() -> Self {
        Self {
            // key is 256 bits - 32 bytes
            key: crypto::get_random_bytes::<32>(),
            // nonce is 96 bits - 12 bytes
            // Note nonce 16 bytes also work though "aes_gcm.default_nonce_length()" returns 12
            // XC uses 16 bytes iv
            nonce: crypto::get_random_bytes::<12>(),
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
        let direction = if encrypt {
            botan::CipherDirection::Encrypt
        } else {
            botan::CipherDirection::Decrypt
        };

        let mut aes_gcm = botan::Cipher::new("AES-256/GCM", direction)?;
        aes_gcm.set_key(&self.key)?;

        Ok(aes_gcm.process(&self.nonce, data)?)
    }
}


/* 
pub struct AeadKeyCipher {
    pub salt:Vec<u8>,
    
}

impl AeadKeyCipher {

    fn derive_key_material(&mut self,output_length:usize) {

    }

    pub fn encrypt(&mut self, password:&str, data: &[u8]) {}

    pub fn decrypt() {}
}
*/