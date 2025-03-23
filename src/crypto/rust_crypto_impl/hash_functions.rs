use hmac::{Hmac, Mac};

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
    let r = mac
        .verify_slice(test_hash)
        .map_err(|_| Error::DataError)
        .is_ok();

    Ok(r)
}

pub fn hmac_sha256_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    for v in data {
        mac.update(v);
    }
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn hmac_sha256_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_sha256_from_slices(key, &[data])
}

pub fn hmac_sha512_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher: Hmac<Sha512> =
        Mac::new_from_slice(key).map_err(|_| Error::DataError("Hmac Sha1 failed"))?;
    hasher.update(data);
    let result = hasher.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn hmac_sha1_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let mut hasher =
        HmacSha1::new_from_slice(key).map_err(|_| Error::DataError("Hmac Sha1 failed"))?;

    // let mut hasher: Hmac<Sha1> = Mac::new_from_slice(key).map_err(|_| Error::DataError("Hmac Sha1 failed"))?;

    hasher.update(data);
    let result = hasher.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn sha256_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    //32 bytes hash output
    Ok(result.to_vec())
}

//pub fn do_sha512_hash(data:&[&[u8]] ) -> Result<Vec<u8>> {
pub fn sha512_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
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

//32 bytes hash output
pub fn sha256_hash_vec_vecs(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result.to_vec())
}

pub fn sha256_hash_from_slice(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

mod tests {
    #[allow(unused_imports)]
    use std::{
        fs::{self, File},
        io::{BufReader, Read},
    };

    #[allow(dead_code)]
    fn data_file() -> File {
        // File size is 1.06 GB
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let file = fs::File::open(&path).unwrap();
        file
    }
    #[test]
    fn verify_large_file_hash256_1() {
        use sha2::{Digest, Sha256};
        use std::io;
        use std::time::Instant;
        let mut file = data_file();
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
    fn verify_large_file_hash256_2() {
        use sha2::{Digest, Sha256};
        use std::time::Instant;
        let file = data_file();
        let mut reader = BufReader::new(file);

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
}
