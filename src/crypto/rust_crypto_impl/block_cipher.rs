use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use log::debug;

use crate::crypto::ContentCipher;
use crate::error::{Error, Result};
use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;

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

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt_aes256(plain_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Enrypting using rust_crypto AES-256");
    let cipher = Aes256Cbc::new_from_slices(&key, &iv[..]).map_err(|_| Error::Encryption)?;
    Ok(cipher.encrypt_vec(plain_data))
}

pub fn decrypt_aes256(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Derypting using rust_crypto AES-256");
    let cipher = Aes256Cbc::new_from_slices(&key, &iv[..]).map_err(|_| Error::Decryption)?;
    cipher.decrypt_vec(encrypted).map_err(|_| Error::Decryption)
}

pub fn encrypt_chacha20(plain_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Enrypting using rust_crypto ChaCha20");
    let mut res = Vec::new();
    res.extend_from_slice(plain_data);
    let mut cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::Encryption)?;
    cipher.apply_keystream(&mut res);
    Ok(res)
}

pub fn decrypt_chacha20(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Derypting using rust_crypto ChaCha20");
    let mut res = Vec::new();
    res.extend_from_slice(encrypted);
    let mut cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::Decryption)?;
    cipher.apply_keystream(&mut res);
    Ok(res)
}
