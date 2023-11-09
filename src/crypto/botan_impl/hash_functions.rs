
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

#[cfg(test)]
mod tests {

    #[test]
    fn check_hmac_sha256() {
        use super::*;
        let key = "my secret and secure key of bytes with any size".as_bytes();
        let data1 = "input message".as_bytes();

        let h1 = do_hmac_sha256(&key, &[&data1]).unwrap();

        let r = verify_hmac_sha256(&key, &[&data1], &h1).unwrap();
        println!("r is {}", r);
        assert!(r);
    }

}
