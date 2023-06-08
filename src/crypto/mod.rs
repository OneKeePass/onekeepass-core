mod block_cipher;
pub mod kdf;
mod stream_cipher;

pub use self::block_cipher::ContentCipher;
pub use self::stream_cipher::ProtectedContentStreamCipher;

//use hex_literal::hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn verify_hmac_sha256(key: &[u8], data: &[&[u8]], test_hash: &[u8]) -> Result<bool> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    //mac.update(data);
    for v in data {
        mac.update(v);
    }
    let r = mac.verify(test_hash).map_err(|_| Error::DataError).is_ok();
    Ok(r)
}

pub fn do_hmac_sha256(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    for v in data {
        mac.update(v);
    }
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn do_sha256_hash(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    //32 bytes hash output
    Ok(result.to_vec())
}

//pub fn do_sha512_hash(data:&[&[u8]] ) -> Result<Vec<u8>> {
pub fn do_sha512_hash(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    //64 bytes hash output
    Ok(result.to_vec())
}

#[allow(dead_code)]
pub fn calculate_hash(data: &Vec<Vec<u8>>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result)
}

#[allow(dead_code)]
pub fn do_vec_sha256_hash(data: Vec<u8>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize())
}
//32 bytes hash output
#[allow(dead_code)]
pub fn do_vecs_sha256_hash(data: &Vec<&Vec<u8>>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result)
}

pub fn do_slice_sha256_hash(data: &[u8]) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize())
}


use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key 
};

pub(crate) struct KeyCipher {
    // key is 256 bits - 32 bytes
    pub(crate) key: Vec<u8>,
    // nonce is 96 bits - 12 bytes
    pub(crate) nonce: Vec<u8>,
}

impl KeyCipher {
    pub fn new() -> Self {
        Self {
            key: Aes256Gcm::generate_key(OsRng).to_vec(),
            nonce: Aes256Gcm::generate_nonce(&mut OsRng).to_vec()
        }
    }

    pub fn from(key:&[u8],nonce:&[u8]) -> Self {
        Self {
            key:key.to_vec(),
            nonce:nonce.to_vec()
        }
    }

    #[inline]
    pub fn encrypt(&self,data:&[u8]) -> Result<Vec<u8>> {
        self.encrypt_decrypt(data, true)
    }

    #[inline]
    pub fn decrypt(&self,data:&[u8]) -> Result<Vec<u8>> {
        self.encrypt_decrypt(data, false)
    }

    fn encrypt_decrypt(&self,data:&[u8],encrypt:bool) -> Result<Vec<u8>>  {
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(&key);
        let final_data = if encrypt {
            cipher.encrypt(&GenericArray::from_slice(&self.nonce), data)
        } else {
            cipher.decrypt(&GenericArray::from_slice(&self.nonce), data)
        };
        match final_data {
            Ok(v) => Ok(v),
            Err(e) => Err(Error::Other(format!("AES GCM failed {}",e)))
        }
    }
}

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

#[allow(dead_code)]
pub struct SecureRandom {
    rng: ChaCha20Rng,
}

#[allow(dead_code)]
impl SecureRandom {
    pub fn new() -> Self {
        SecureRandom {
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    pub fn get_bytes<const N: usize>(&mut self) -> Vec<u8> {
        let mut buf = [0u8; N];
        self.rng.fill_bytes(&mut buf);
        buf.to_vec()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn veriy_aes_gcm() {
        let kc = KeyCipher::new();
        
        assert_eq!(kc.key.len(),32);
        assert_eq!(kc.nonce.len(),12);

        let plain_text = b"Hello world";
        let enc_result = kc.encrypt(plain_text).unwrap();
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(),&dec_result);

        // key and nonce moved from kc simulating stored somewhere
        let key = kc.key;
        let nonce = kc.nonce;
        // Recreate a new cipher from the previous key and nonce
        let kc = KeyCipher::from(&key,&nonce);
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(),&dec_result);
    }
}

