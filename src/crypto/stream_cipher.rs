use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use log::error;

use crate::error::{Error, Result};

use crate::constants::inner_header_type::CHACHA20_STREAM;

#[derive(Debug)]
pub struct ProtectedContentStreamCipher {
    cipher: ChaCha20,
}

impl ProtectedContentStreamCipher {
    pub fn try_from(cipher_id: u32, inner_stream_key: &Vec<u8>) -> Result<Self> {
        // The inner-stream-key is a 64 bytes sequence from which the key and nounce to be used
        // in ChaCha20 cipher are derived after taking SHA512 hash
        let h = crate::crypto::do_sha512_hash(&[inner_stream_key])?;
        let key = &h[..32]; // first 32 byes
        let iv = &h[32..44]; // next  12 bytes
        if CHACHA20_STREAM == cipher_id {
            let cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::Decryption)?;
            Ok(ProtectedContentStreamCipher { cipher })
        } else {
            Err(Error::UnsupportedStreamCipher(format!("Only CHACHA20 cipher scheme is supported for encrypting/decrypting for in memory protection of Projected string and binary values")))
        }
    }

    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        res.extend_from_slice(data);
        self.cipher.apply_keystream(&mut res);
        Ok(res)
    }

    pub fn process_basic64_str(&mut self, b64_str: &str) -> Result<String> {
        //let decoded = base64::decode(b64_str).ok()?; //TODO: handle  DecodeError
        if !b64_str.is_empty() {
            let decoded = base64::decode(b64_str).unwrap();

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

    /// The content string data is encrypted and the base 64 of the encrypted bytes data is returned
    pub fn process_content_b64_str(&mut self, content: &str) -> Result<String> {
        let b = self.process(content.as_bytes())?;
        let s = base64::encode(&b);
        Ok(s)
    }
}
