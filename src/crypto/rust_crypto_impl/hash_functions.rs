
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
