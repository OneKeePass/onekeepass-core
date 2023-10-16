mod block_cipher;
mod hash_functions;
mod random;
mod key_cipher;
mod stream_cipher;
pub mod kdf;

use serde::{Serialize, Deserialize};
use crate::{error::{Error, Result}, constants};

// Re-exports
pub use stream_cipher::botan_crypto::ProtectedContentStreamCipher;
pub use key_cipher::botan_crypto::*;
pub use hash_functions::botan_crypto::*;
pub use random::botan_crypto::*;

// Provides the encryption and decryption 
#[derive(Debug)]
pub enum ContentCipher {
    ChaCha20([u8; 12]),
    Aes256([u8; 16]),
}

// Moved from db module
// TODO: Combine ContentCipher and ContentCipherId ?
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ContentCipherId {
    ChaCha20,
    Aes256,
    UnKnownCipher,
}

impl ContentCipherId {

    // Gets the UUID and Encryption IV of the supported algorithm  
    pub fn uuid_with_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rn16,rn12) = get_random_bytes_2::<16,12>();
        match self {
            ContentCipherId::Aes256 => {
                Ok((constants::uuid::AES256.to_vec(),rn16))
            }
            ContentCipherId::ChaCha20 => {
                Ok((constants::uuid::CHACHA20.to_vec(), rn12))
            }
            _ => return Err(Error::UnsupportedCipher(vec![])),
        }
    }

    // Generates the random master seed and iv for the selected algorithm
    pub fn generate_master_seed_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rn32,rn16,rn12) = get_random_bytes_3::<32,16,12>();
        match self {
            ContentCipherId::Aes256 => Ok((rn32, rn16)),
            ContentCipherId::ChaCha20 => Ok((rn32,rn12)),
            _ => return Err(Error::UnsupportedCipher(vec![])),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::{io::{BufReader, Read}, fs, time::Instant};

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
    fn verify_aes256_encrypt_decrypt() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        let text = "Hello World!";
        let key = get_random_bytes::<32>();

        let encrypted = cipher.encrypt(text.as_bytes(), &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(text.as_bytes(),decrypted);
    }

    fn read_file_data() -> Vec<u8> {
        // File size is 1.06 GB
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);
        
        let mut data:Vec<u8> = vec![];
        reader.read_to_end(&mut data).unwrap();
        println!("File data reading is done and returning all data bytes ; size {}",data.len());
        data
    }

    #[test]
    fn verify_aes256_file_data_encrypt_decrypt() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        let data:Vec<u8> = read_file_data();
        let key = get_random_bytes::<32>();

        let timing = Instant::now();
        let encrypted = cipher.encrypt(&data, &key).unwrap();
        println!("Encryption elapsed time {} seconds",timing.elapsed().as_secs());

        let timing = Instant::now();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        println!("Decryption elapsed time {} seconds",timing.elapsed().as_secs());
        
        assert_eq!(data,decrypted);
    }

    #[test]
    fn verify_aes256_encrypt_decrypt_botan() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let key = get_random_bytes::<32>();
        
        let text = "Hello World!";

        let mut cipher = botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(&key).unwrap();
        //cipher.start(&enc_iv).unwrap();

        let encrypted = cipher.process(&enc_iv, text.as_bytes()).unwrap();

        let mut cipher = botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(&key).unwrap();
        let decrypted = cipher.process(&enc_iv, &encrypted).unwrap();

        assert_eq!(text.as_bytes(),decrypted);

        // let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();
        // let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        // assert_eq!(text.as_bytes(),decrypted);
    }

    #[test]
    fn verify_aes256_file_data_encrypt_decrypt_botan() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let key = get_random_bytes::<32>();
        
        let data:Vec<u8> = read_file_data();

        let mut cipher = botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(&key).unwrap();
        
        let timing = Instant::now();
        let encrypted = cipher.process(&enc_iv, &data).unwrap();
        println!("Encryption elapsed time {} seconds",timing.elapsed().as_secs());

        let mut cipher = botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(&key).unwrap();

        let timing = Instant::now();
        let decrypted = cipher.process(&enc_iv, &encrypted).unwrap();
        println!("Decryption elapsed time {} seconds",timing.elapsed().as_secs());

        assert_eq!(data,decrypted);

        
        // let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();
        // let timing = Instant::now();
        // let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        // println!("Decryption elapsed time {} seconds",timing.elapsed().as_secs());
        // assert_eq!(data,decrypted);
    }


    #[test]
    fn verify_chacha20_encrypt_decrypt_botan() {
        let (uuid, enc_iv) = ContentCipherId::ChaCha20.uuid_with_iv().unwrap();
        let key = get_random_bytes::<32>();
        
        let text = "Hello World!";

        let mut cipher = botan::Cipher::new("ChaCha20", botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(&key).unwrap();
        
        let encrypted = cipher.process(&enc_iv, text.as_bytes()).unwrap();

        let mut cipher = botan::Cipher::new("ChaCha20", botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(&key).unwrap();
        let decrypted = cipher.process(&enc_iv, &encrypted).unwrap();

        assert_eq!(text.as_bytes(),decrypted);

        // let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();
        // let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        // assert_eq!(text.as_bytes(),decrypted);
    }

    #[test]
    fn verify_hash256_1() {
        use sha2::{Digest, Sha256};
        use std::time::Instant;
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
        assert!(
            hex::encode(&digest)
                == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a"
        )
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

        assert!(
            hex::encode(&digest)
                == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a"
        )
    }

    #[test]
    fn verify_hash256_3() {
        use std::time::Instant;
        use std::fs;
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
        assert!(
            hex::encode(&digest)
                == "d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a"
        )
    }

    // Need to add to Cargo.toml to test this
    // alkali = { version = "0.3.0", features = ["aes","hazmat"] }
    /* 
    #[test]
    fn verify_hash256_4() {
        use std::time::{Duration, Instant};
        use std::{fs, io};
        // hex d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);

        let start = Instant::now();

        let digest = {
            let mut hasher = alkali::hash::sha2::sha256::Multipart::new().unwrap();
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
                hasher.update(&buffer[..count]);
            }
            hasher.calculate()
        };

        let duration = start.elapsed();
        println!("Completed hashing ...duration {:?}", duration);

        println!("Digest hex is {}", hex::encode(&digest.0));

        // use alkali::hash::sha2;
        // let message = b"Here's some message we wish to hash :)";
        // let hash = sha2::hash(message).unwrap();
        // assert_eq!(
        //     hash,
        //     sha2::Digest([
        //         0xb7, 0xee, 0x33, 0x80, 0x83, 0xf0, 0x41, 0x65, 0xc1, 0xff, 0xfb, 0xb2, 0x14, 0x6f,
        //         0x18, 0x8b, 0x9c, 0x01, 0x31, 0xd3, 0x0e, 0x7c, 0x45, 0x36, 0xbe, 0xb3, 0x4a, 0x1d,
        //         0xb0, 0x2d, 0x86, 0x9d, 0x87, 0x1a, 0x1c, 0x84, 0xd7, 0x9b, 0x9d, 0xe3, 0x15, 0xc3,
        //         0xb4, 0x2d, 0x9a, 0xb9, 0x54, 0x25, 0x7a, 0xf9, 0x06, 0x28, 0x66, 0x8d, 0x9a, 0xa5,
        //         0x31, 0x45, 0x19, 0xbc, 0x4c, 0x2f, 0xcb, 0xa4
        //     ])
        // );
    }
    */

}
