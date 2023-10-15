use log::*;

use crate::error::{Error, Result};

use super::ContentCipher;

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
                botan_crypto::decrypt_chacha20(encrypted, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("decrypting Aes256");
                //rust_crypto::decrypt_aes256(encrypted, key, iv)
                botan_crypto::decrypt_aes256(encrypted, key, iv)
            }
        }
    }

    pub fn encrypt(&self, plain_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            ContentCipher::ChaCha20(iv) => {
                debug!("enrypting using ChaCha20");
                //rust_crypto::encrypt_chacha20(plain_data, key, iv)
                botan_crypto::encrypt_chacha20(plain_data, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("encrypting using Aes256");
                //rust_crypto::encrypt_aes256(plain_data, key, iv)
                botan_crypto::encrypt_aes256(plain_data, key, iv)
            }
        }
    }
}

mod botan_crypto {
    use crate::error::{Error, Result};

    pub fn encrypt_aes256(plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        // https://botan.randombit.net/handbook/api_ref/cipher_modes.html#code-example
        encrypt("AES-256/CBC/PKCS7", plain_data, key, enc_iv)
    }

    pub fn decrypt_aes256(encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        decrypt("AES-256/CBC/PKCS7", encrypted,key,enc_iv)
    }

    pub fn encrypt_chacha20(plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        // https://botan.randombit.net/handbook/api_ref/cipher_modes.html#code-example
        encrypt("ChaCha20", plain_data, key, enc_iv)
    }

    pub fn decrypt_chacha20(encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        decrypt("ChaCha20", encrypted,key,enc_iv)
    }

    fn encrypt(alg_name:&str,plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        
        //TODO: Convert botan::utils::Error to crate::error::Error

        let mut cipher = botan::Cipher::new(alg_name, botan::CipherDirection::Encrypt)
            .map_err(|_| Error::Encryption)?;
        cipher
            .set_key(&key)
            .map_err(|e| Error::Other(format!("Encryption failed due to {:?}", e)))?;
        let encrypted = cipher
            .process(&enc_iv, plain_data)
            .map_err(|e| Error::Other(format!("Encryption failed due to {:?}", e)))?;

        Ok(encrypted)
    }

    pub fn decrypt(alg_name:&str,encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
        
        //TODO: Convert botan::utils::Error to crate::error::Error

        let mut cipher = botan::Cipher::new(alg_name, botan::CipherDirection::Decrypt)
            .map_err(|_| Error::Decryption)?;
        cipher
            .set_key(&key)
            .map_err(|e| Error::Other(format!("Encryption failed due to {:?}", e)))?;
        let plain_data = cipher
            .process(&enc_iv, encrypted)
            .map_err(|e| Error::Other(format!("Encryption failed due to {:?}", e)))?;

        Ok(plain_data)
    }

}

#[allow(dead_code)]
mod rust_crypto {
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};

    use crate::error::{Error, Result};
    use chacha20::cipher::{NewCipher, StreamCipher};
    use chacha20::ChaCha20;

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    pub fn encrypt_aes256(plain_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Cbc::new_from_slices(&key, &iv[..]).map_err(|_| Error::Encryption)?;
        Ok(cipher.encrypt_vec(plain_data))
    }

    pub fn decrypt_aes256(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Cbc::new_from_slices(&key, &iv[..]).map_err(|_| Error::Decryption)?;
        cipher.decrypt_vec(encrypted).map_err(|_| Error::Decryption)
    }

    pub fn encrypt_chacha20(plain_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        res.extend_from_slice(plain_data);
        let mut cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::Encryption)?;
        cipher.apply_keystream(&mut res);
        Ok(res)
    }

    pub fn decrypt_chacha20(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        res.extend_from_slice(encrypted);
        let mut cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::Decryption)?;
        cipher.apply_keystream(&mut res);
        Ok(res)
    }
}
