pub mod kdf;
use crate::{
    constants,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};

#[path = "botan_impl/mod.rs"]
mod crypto_impl;
pub use crypto_impl::*;

/*
// botan crypto is used for all platforms except for android armv7 platform
// as botan lib compilation for 'android armv7' platform could not be done

// To use 'rust_crypto_impl/mod.rs' instead of "botan_impl/mod.rs"
// just remove target_os = "macos" so that the "else" part is enabled

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "macos",
                target_os = "windows",
                target_os = "linux",
                target_os = "ios",
                all(target_os = "android", target_arch = "aarch64")))] {

        #[path = "botan_impl/mod.rs"]
        mod crypto_impl;
        pub use crypto_impl::*;

    } else {
        #[path = "rust_crypto_impl/mod.rs"]
        mod crypto_impl;
        pub use crypto_impl::*;
    }
}

*/

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
        let (rn16, rn12) = get_random_bytes_2::<16, 12>();
        match self {
            ContentCipherId::Aes256 => Ok((constants::uuid::AES256.to_vec(), rn16)),
            ContentCipherId::ChaCha20 => Ok((constants::uuid::CHACHA20.to_vec(), rn12)),
            _ => return Err(Error::UnsupportedCipher(vec![])),
        }
    }

    // Generates the random master seed and iv for the selected algorithm
    pub fn generate_master_seed_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rn32, rn16, rn12) = get_random_bytes_3::<32, 16, 12>();
        match self {
            ContentCipherId::Aes256 => Ok((rn32, rn16)),
            ContentCipherId::ChaCha20 => Ok((rn32, rn12)),
            _ => return Err(Error::UnsupportedCipher(vec![])),
        }
    }
}

#[test]
pub fn init_log_lib_info() {
    crate::util::init_test_logging();
    print_crypto_lib_info();
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use std::{
        fs::{self, File},
        io::{BufReader, Read},
        time::Instant,
    };

    use super::*;
    use crate::util::init_test_logging;

    #[ignore]
    #[test]
    fn check_hmac_sha256() {
        init_log_lib_info();
        use super::*;
        let key = "my secret and secure key of bytes with any size".as_bytes();
        let data1 = "input message".as_bytes();
        let h1 = hmac_sha256_from_slices(&key, &[&data1]).unwrap();

        let r = verify_hmac_sha256(&key, &[&data1], &h1).unwrap();
        println!("r is {}", r);
        assert!(r);
    }

    #[ignore]
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

    #[ignore]
    #[test]
    fn verify_aes256_encrypt_decrypt() {
        init_test_logging();
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        let text = "Hello World!";
        let key = get_random_bytes::<32>();

        let encrypted = cipher.encrypt(text.as_bytes(), &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(text.as_bytes(), decrypted);
    }

    fn read_file_data() -> Vec<u8> {
        // File size is 1.06 GB
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);

        let mut data: Vec<u8> = vec![];
        reader.read_to_end(&mut data).unwrap();
        println!(
            "File data reading is done and returning all data bytes ; size {}",
            data.len()
        );
        data
    }

    fn data_file() -> File {
        // File size is 1.06 GB
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let file = fs::File::open(&path).unwrap();
        file
    }

    #[ignore]
    #[test]
    fn verify_aes256_file_data_encrypt_decrypt() {
        init_log_lib_info();
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        let data: Vec<u8> = read_file_data();
        let key = get_random_bytes::<32>();

        let timing = Instant::now();
        let encrypted = cipher.encrypt(&data, &key).unwrap();
        println!(
            "Encryption elapsed time {} seconds",
            timing.elapsed().as_secs()
        );

        let timing = Instant::now();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        println!(
            "Decryption elapsed time {} seconds",
            timing.elapsed().as_secs()
        );

        assert_eq!(data, decrypted);
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
