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

fn hmac_from_slices(hash_algorithm: &str, key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut hmac = botan::MsgAuthCode::new(hash_algorithm)?;
    hmac.set_key(key)?;
    for v in data {
        hmac.update(v)?;
    }
    let result = hmac.finish()?;
    Ok(result)
}

// Creates HMAC hash of data coming in slices
pub fn hmac_sha256_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-256)", key, data)
}

pub fn hmac_sha256_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-256)", key, &[data])
}

pub fn _hmac_sha512_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, data)
}

pub fn hmac_sha512_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, &[data])
}

pub fn _hmac_sha1_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, data)
}

pub fn hmac_sha1_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, &[data])
}

fn hash_from_slice_vecs(hash_algorithm: &str, data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new(hash_algorithm)?;
    for v in data {
        hasher.update(v)?;
    }
    let result = hasher.finish()?;
    //32 bytes hash output
    Ok(result)
}

// Returns 32 bytes (256 bits) hash of input data 'a slice of vecs'
pub fn sha256_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    hash_from_slice_vecs("SHA-256", data)
}

// Returns 64 bytes (512 bits) hash of input data 'a slice of vecs'
pub fn sha512_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    hash_from_slice_vecs("SHA-512", data)
}

//32 bytes hash output of input data 'a vec of vecs'
pub fn sha256_hash_vec_vecs(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new("SHA-256")?;
    for v in data {
        hasher.update(v)?;
    }
    let result = hasher.finish()?;
    //32 bytes hash output
    Ok(result)
}

pub fn sha256_hash_from_slice(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new("SHA-256")?;
    hasher.update(data)?;
    Ok(hasher.finish()?)
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    #[test]
    fn verify_large_file_hash256() {
        use std::fs;
        use std::time::Instant;
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

    #[test]
    fn check_hmac_sha256() {
        use super::*;
        let key = "my secret and secure key of bytes with any size".as_bytes();
        let data1 = "input message".as_bytes();

        let h1 = hmac_sha256_from_slices(&key, &[&data1]).unwrap();

        let r = verify_hmac_sha256(&key, &[&data1], &h1).unwrap();
        println!("r is {}", r);
        assert!(r);
    }
}
