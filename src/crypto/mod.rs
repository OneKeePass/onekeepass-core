mod block_cipher;
pub mod kdf;
mod stream_cipher;

pub use self::block_cipher::ContentCipher;
pub use self::stream_cipher::ProtectedContentStreamCipher;

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
pub fn calculate_hash(data: &Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result.to_vec())
}

// #[allow(dead_code)]
// pub fn do_vec_sha256_hash(data: Vec<u8>) -> Result<GenericArray<u8, U32>> {
//     let mut hasher = Sha256::new();
//     hasher.update(data);
//     Ok(hasher.finalize())
// }

//32 bytes hash output
pub fn do_vecs_sha256_hash(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result.to_vec())
}

pub fn do_slice_sha256_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
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

pub fn get_random_bytes<const N: usize>() ->  Vec<u8> {
    SecureRandom::new().get_bytes::<N>()
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    use super::*;

    #[test]
    fn veriy_aes_gcm() {
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
    }

    #[test]
    fn verify_hash256_1() {
        use sha2::{Digest, Sha256};
        use std::time::{Duration, Instant};
        use std::{fs, io};
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let mut file = fs::File::open(&path).unwrap();
        let mut hasher = Sha256::new();
        println!("Started hashing ...");
        let start = Instant::now();
        let n = io::copy(&mut file, &mut hasher).unwrap();
        let digest = hasher.finalize().to_vec();
        let duration = start.elapsed();
        println!("Completed hashing ...duration {:?}", duration);
        assert!(hex::encode(&digest) == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a")
    }

    #[test]
    fn verify_hash256_2() {
        use sha2::{Digest, Sha256};
        use std::time::{Duration, Instant};
        use std::{fs, io};
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);

        let start = Instant::now();
        let digest = {
            let mut hasher = Sha256::new();
            println!("Started hashing ...");
            let mut buffer = [0; 1024];
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            hasher.finalize().to_vec()
        };

        let duration = start.elapsed();
        println!("Completed hashing ...duration {:?}", duration);
        //println!("Digest hex is {}", hex::encode(&digest));

        assert!(hex::encode(&digest) == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a")
    }

    #[test]
    fn verify_hash256_3() {
        use std::time::{Duration, Instant};
        use std::{fs, io};
        // hex d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);

        // assert!(botan::HashFunction::new("SHA-256").is_ok());

        let start = Instant::now();
        let digest = {
            let mut hasher = botan::HashFunction::new("SHA-256").unwrap();
            println!("Started hashing ...");

            // Reads the complete file in one go
            // let mut buf = vec![];
            // reader.read_to_end(&mut buf).unwrap();
            // hasher.update(&buf).unwrap();
            // hasher.finish().unwrap()

            let mut buffer = [0; 1024];
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]).unwrap();
            }
            hasher.finish().unwrap()
        };

        let duration = start.elapsed();
        println!("Completed hashing ...duration {:?}", duration);

        //println!("Digest hex is {}", hex::encode(&digest));
        assert!(hex::encode(&digest) == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a")
    }
}
