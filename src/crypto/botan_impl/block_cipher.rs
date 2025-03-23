use crate::crypto::ContentCipher;
use crate::error::{Error, Result};
use log::debug;

impl ContentCipher {
    pub fn try_from(cipher_id: &[u8], enc_iv: &[u8]) -> Result<Self> {
        use crate::constants::uuid::{AES256, CHACHA20};

        match cipher_id {
            CHACHA20 => {
                let mut buf = [0; 12];
                buf.copy_from_slice(enc_iv);
                Ok(ContentCipher::ChaCha20(buf))
            }
            AES256 => {
                let mut buf = [0; 16];
                buf.copy_from_slice(enc_iv);
                Ok(ContentCipher::Aes256(buf))
            }
            _ => Err(Error::UnsupportedCipher(cipher_id.to_vec())),
        }
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            ContentCipher::ChaCha20(iv) => {
                debug!("decrypting ChaCha20");
                //rust_crypto::decrypt_chacha20(encrypted, key, iv)
                //botan_crypto::decrypt_chacha20(encrypted, key, iv)
                decrypt_chacha20(encrypted, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("decrypting Aes256");
                //rust_crypto::decrypt_aes256(encrypted, key, iv)
                //botan_crypto::decrypt_aes256(encrypted, key, iv)
                decrypt_aes256(encrypted, key, iv)
            }
        }
    }

    pub fn encrypt(&self, plain_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            ContentCipher::ChaCha20(iv) => {
                debug!("enrypting using ChaCha20");
                //rust_crypto::encrypt_chacha20(plain_data, key, iv)
                //botan_crypto::encrypt_chacha20(plain_data, key, iv)
                encrypt_chacha20(plain_data, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("encrypting using Aes256");
                //rust_crypto::encrypt_aes256(plain_data, key, iv)
                //botan_crypto::encrypt_aes256(plain_data, key, iv)
                encrypt_aes256(plain_data, key, iv)
            }
        }
    }
}

pub fn encrypt_aes256(plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Enrypting using botan_crypto AES-256");
    // https://botan.randombit.net/handbook/api_ref/cipher_modes.html#code-example
    encrypt("AES-256/CBC/PKCS7", plain_data, key, enc_iv)
}

pub fn decrypt_aes256(encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Derypting using botan_crypto AES-256");
    decrypt("AES-256/CBC/PKCS7", encrypted, key, enc_iv)
}

pub fn encrypt_chacha20(plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Enrypting using botan_crypto ChaCha20");
    // https://botan.randombit.net/handbook/api_ref/cipher_modes.html#code-example
    encrypt("ChaCha20", plain_data, key, enc_iv)
}

pub fn decrypt_chacha20(encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Derypting using botan_crypto ChaCha20");
    decrypt("ChaCha20", encrypted, key, enc_iv)
}

fn encrypt(alg_name: &str, plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    //TODO: Convert botan::utils::Error to crate::error::Error

    let mut cipher = botan::Cipher::new(alg_name, botan::CipherDirection::Encrypt)
        .map_err(|_| Error::Encryption)?;
    cipher
        .set_key(&key)
        .map_err(|e| Error::UnexpectedError(format!("Encryption failed due to {:?}", e)))?;
    let encrypted = cipher
        .process(&enc_iv, plain_data)
        .map_err(|e| Error::UnexpectedError(format!("Encryption failed due to {:?}", e)))?;

    Ok(encrypted)
}

pub fn decrypt(alg_name: &str, encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    //TODO: Convert botan::utils::Error to crate::error::Error

    let mut cipher = botan::Cipher::new(alg_name, botan::CipherDirection::Decrypt)
        .map_err(|_| Error::Decryption)?;
    cipher
        .set_key(&key)
        .map_err(|e| Error::UnexpectedError(format!("Encryption failed due to {:?}", e)))?;
    let plain_data = cipher
        .process(&enc_iv, encrypted)
        .map_err(|e| Error::UnexpectedError(format!("Encryption failed due to {:?}", e)))?;

    Ok(plain_data)
}
