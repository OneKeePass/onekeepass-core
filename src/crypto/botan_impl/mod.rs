mod block_cipher;
mod hash_functions;
mod key_cipher;
mod random;
mod stream_cipher;

pub use hash_functions::*;
pub use key_cipher::*;
pub use random::*;
pub use stream_cipher::ProtectedContentStreamCipher;

pub fn print_crypto_lib_info() {
    log::info!("The botan crypto impl module is used for all encryptions and decryptions");
}

#[cfg(test)]
mod tests {
    use std::{fs, io::{BufReader, Read}, time::Instant};
    use crate::{crypto::get_random_bytes, db::ContentCipherId};

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

    #[test]
    fn verify_aes256_encrypt_decrypt_botan() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let key = get_random_bytes::<32>();

        let text = "Hello World!";

        let mut cipher =
            botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(&key).unwrap();
        //cipher.start(&enc_iv).unwrap();

        let encrypted = cipher.process(&enc_iv, text.as_bytes()).unwrap();

        let mut cipher =
            botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(&key).unwrap();
        let decrypted = cipher.process(&enc_iv, &encrypted).unwrap();

        assert_eq!(text.as_bytes(), decrypted);

        // let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();
        // let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        // assert_eq!(text.as_bytes(),decrypted);
    }

    #[test]
    fn verify_aes256_file_data_encrypt_decrypt_botan() {
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let key = get_random_bytes::<32>();

        let data: Vec<u8> = read_file_data();

        let mut cipher =
            botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Encrypt).unwrap();
        cipher.set_key(&key).unwrap();

        let timing = Instant::now();
        let encrypted = cipher.process(&enc_iv, &data).unwrap();
        println!(
            "Encryption elapsed time {} seconds",
            timing.elapsed().as_secs()
        );

        let mut cipher =
            botan::Cipher::new("AES-256/CBC/PKCS7", botan::CipherDirection::Decrypt).unwrap();
        cipher.set_key(&key).unwrap();

        let timing = Instant::now();
        let decrypted = cipher.process(&enc_iv, &encrypted).unwrap();
        println!(
            "Decryption elapsed time {} seconds",
            timing.elapsed().as_secs()
        );

        assert_eq!(data, decrypted);

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

        assert_eq!(text.as_bytes(), decrypted);

        // let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();
        // let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        // assert_eq!(text.as_bytes(),decrypted);
    }
}