use log::error;

use crate::error::{Error, Result};

use crate::constants::inner_header_type::CHACHA20_STREAM;

#[derive(Debug)]
pub struct ProtectedContentStreamCipher {
    cipher: botan::Cipher,
}

impl ProtectedContentStreamCipher {
    pub fn try_from(cipher_id: u32, inner_stream_key: &Vec<u8>) -> Result<Self> {
        let h = crate::crypto::sha512_hash_from_slice_vecs(&[inner_stream_key])?;
        let key = &h[..32]; // first 32 byes
        let iv = &h[32..44]; // next  12 bytes
        if CHACHA20_STREAM == cipher_id {
            let mut cipher = botan::Cipher::new("ChaCha20", botan::CipherDirection::Encrypt)?;
            cipher.set_key(&key)?;

            cipher.start(&iv)?;

            Ok(ProtectedContentStreamCipher { cipher })
        } else {
            Err(Error::UnsupportedStreamCipher(format!("Only CHACHA20 cipher scheme is supported for encrypting/decrypting for in memory protection of Projected string and binary values")))
        }
    }

    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cipher.update(&data)?)
    }

    pub fn process_basic64_str(&mut self, b64_str: &str) -> Result<String> {
        //let decoded = base64::decode(b64_str).ok()?; //TODO: handle  DecodeError
        if !b64_str.is_empty() {
            //let decoded = base64::decode(b64_str).unwrap();

            let decoded = botan::base64_decode(b64_str)?;

            let e = self.process(&decoded)?;

            if let Ok(s) = std::str::from_utf8(&e) {
                Ok(String::from(s))
            } else {
                // Log the error as we are going to use the usafe from_utf8_unchecked method
                error!("The standard from_utf8 conversion of decrypted bytes data failed ...");
                let s = unsafe { std::str::from_utf8_unchecked(&e) };
                Ok(String::from(s))
            }
        } else {
            Ok(String::new())
        }
    }

    // The content string data is encrypted and the base 64 of the encrypted bytes data is returned
    // This fn should be called with non empty string;Otherwise 'process' will return an error
    pub fn process_content_b64_str(&mut self, content: &str) -> Result<String> {
        if content.is_empty() {
            return Err(Error::DataError("Protected data content cannot be an empty string"));
        }
        let b = self.process(content.as_bytes())?;
        let s = botan::base64_encode(&b)?;
        Ok(s)
    }
}
