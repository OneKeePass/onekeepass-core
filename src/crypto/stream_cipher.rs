//#[cfg(not(target_os = "android"))]
#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    target_os = "ios",
    all(target_os = "android", target_arch = "aarch64")
))]
pub(crate) mod botan_crypto {

    use log::error;

    use crate::error::{Error, Result};

    use crate::constants::inner_header_type::CHACHA20_STREAM;

    #[derive(Debug)]
    pub struct ProtectedContentStreamCipher {
        cipher: botan::Cipher,
    }

    impl ProtectedContentStreamCipher {
        pub fn try_from(cipher_id: u32, inner_stream_key: &Vec<u8>) -> Result<Self> {
            let h = crate::crypto::do_sha512_hash(&[inner_stream_key])?;
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
        pub fn process_content_b64_str(&mut self, content: &str) -> Result<String> {
            let b = self.process(content.as_bytes())?;
            let s = botan::base64_encode(&b)?;
            Ok(s)
        }
    }
}

#[allow(dead_code)]
pub(crate) mod rust_crypto {
    use chacha20::cipher::{NewCipher, StreamCipher};
    use chacha20::ChaCha20;
    use log::error;

    use crate::error::{Error, Result};

    use crate::constants::inner_header_type::CHACHA20_STREAM;
    use crate::util;

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
                //let decoded = base64::decode(b64_str).unwrap();

                let decoded = util::base64_decode(b64_str)?;

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
            let s = util::base64_encode(&b);
            Ok(s)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        constants::inner_header_type::CHACHA20_STREAM,
        crypto::{self, stream_cipher::botan_crypto},
    };

    use super::rust_crypto;

    #[test]
    fn check_stream_cipher_operation() {
        let test_msg = "Test message";
        let inner_stream_key = &crypto::get_random_bytes::<64>();
        let mut stream_cipher =
            rust_crypto::ProtectedContentStreamCipher::try_from(CHACHA20_STREAM, inner_stream_key)
                .unwrap();
        let base64_str1 = stream_cipher.process_content_b64_str(test_msg).unwrap();

        println!("base64_str1 is  {}", &base64_str1);

        let mut stream_cipher =
            botan_crypto::ProtectedContentStreamCipher::try_from(CHACHA20_STREAM, inner_stream_key)
                .unwrap();
        let base64_str2 = stream_cipher.process_content_b64_str(test_msg).unwrap();
        println!("base64_str2 is  {}", &base64_str2);

        assert_eq!(base64_str1, base64_str2);

        let mut stream_cipher =
            botan_crypto::ProtectedContentStreamCipher::try_from(CHACHA20_STREAM, inner_stream_key)
                .unwrap();
        let processed_msg = stream_cipher.process_basic64_str(&base64_str1).unwrap();
        println!("processed_msg is  {}", &processed_msg);
        assert_eq!(test_msg, &processed_msg);
    }
}
