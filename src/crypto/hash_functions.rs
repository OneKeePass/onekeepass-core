pub(crate) mod botan_crypto {

    use crate::error::Result;

    pub fn verify_hmac_sha256(key: &[u8], data: &[&[u8]], test_hash: &[u8]) -> Result<bool> {
        let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)")?;
        hmac.set_key(key)?;
        for v in data {
            hmac.update(v)?;
        }
        let calculated = hmac.finish()?;
        let r = calculated == test_hash;
        Ok(r)
    }

    pub fn do_hmac_sha256(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
        let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)")?;
        hmac.set_key(key)?;
        for v in data {
            hmac.update(v)?;
        }
        let result = hmac.finish()?;
        Ok(result)
    }

    // Returns 32 bytes (256 bits) hash of input data
    pub fn do_sha256_hash(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
        let mut hasher = botan::HashFunction::new("SHA-256")?;
        for v in data {
            hasher.update(v)?;
        }
        let result = hasher.finish()?;
        //32 bytes hash output
        Ok(result)
    }

    // Returns 64 bytes (512 bits) hash of input data
    pub fn do_sha512_hash(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
        let mut hasher = botan::HashFunction::new("SHA-512")?;
        for v in data {
            hasher.update(v)?;
        }
        let result = hasher.finish()?;
        //64 bytes hash output
        Ok(result)
    }

    //32 bytes hash output
    pub fn do_vecs_sha256_hash(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
        let mut hasher = botan::HashFunction::new("SHA-256")?;
        for v in data {
            hasher.update(v)?;
        }
        let result = hasher.finish()?;
        //32 bytes hash output
        Ok(result)
    }

    pub fn do_slice_sha256_hash(data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = botan::HashFunction::new("SHA-256")?;
        hasher.update(data)?;
        Ok(hasher.finish()?)
    }
}

#[allow(dead_code)]
mod rust_crypto {
    use hmac::{Hmac, Mac, NewMac};

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
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn check_hmac_sha256() {
        use botan_crypto::*;
        let key = "my secret and secure key of bytes with any size".as_bytes();
        let data1 = "input message".as_bytes();

        let h1 = do_hmac_sha256(&key, &[&data1]).unwrap();

        let r = verify_hmac_sha256(&key, &[&data1], &h1).unwrap();
        println!("r is {}", r);
        assert!(r);
    }

    #[test]
    fn check_sha256_hash() {
        let data = "input message".as_bytes().to_vec();
        let h1 = rust_crypto::do_sha256_hash(&[&data]).unwrap();
        let h2 = botan_crypto::do_sha256_hash(&[&data]).unwrap();
        assert_eq!(h1, h2);

        let h1 = rust_crypto::do_sha512_hash(&[&data]).unwrap();

        let h2 = botan_crypto::do_sha512_hash(&[&data]).unwrap();
        println!("Size is {}", h1.len());
        assert_eq!(h1, h2);
    }
}
