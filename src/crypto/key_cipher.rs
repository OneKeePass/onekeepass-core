//#[cfg(not(target_os = "android"))]
#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    target_os = "ios",
    all(target_os = "android", target_arch = "aarch64")
))]
pub(crate) mod botan_crypto {
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
}

#[allow(dead_code)]
pub(crate) mod rust_crypto {
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
}

mod test {

    #[test]
    fn veriy_aes_gcm() {
        use super::botan_crypto::*;

        let kc = KeyCipher::new();

        assert_eq!(kc.key.len(), 32);
        assert_eq!(kc.nonce.len(), 12);

        let plain_text = b"Hello world";
        let enc_result = kc.encrypt(plain_text).unwrap();
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(), &dec_result);

        // key and nonce moved from kc simulating stored somewhere
        let key = kc.key;
        let nonce = kc.nonce;
        // Recreate a new cipher from the previous key and nonce
        let kc = KeyCipher::from(&key, &nonce);
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(), &dec_result);

        let aes_gcm = botan::Cipher::new("AES-256/GCM", botan::CipherDirection::Encrypt).unwrap();
        assert_eq!(aes_gcm.default_nonce_length(), 12);
    }
}
