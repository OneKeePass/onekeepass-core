use crate::error::Result;

pub fn verify_hmac_sha256(key: &[u8], data: &[&[u8]], test_hash: &[u8]) -> Result<bool> {
    let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)")?;
    hmac.set_key(key)?;
    for v in data {
        hmac.update(v)?;
    }
    let calculated = hmac.finish()?;
    // println!("Key is {:?}",key);
    // println!("data {:?}", data);
    // println!(
    //     "Test hash {:?} and calculated hash {:?}",
    //     test_hash, calculated
    // );

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

pub fn hmac_sha512_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, data)
}

pub fn hmac_sha512_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, &[data])
}

pub fn hmac_sha1_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, data)
}

pub fn hmac_sha1_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, &[data])
    // let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-1)")?;
    // hmac.set_key(key)?;
    // hmac.update(data)?;
    // let result = hmac.finish()?;
    // Ok(result)
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

    // let mut hasher = botan::HashFunction::new("SHA-256")?;
    // for v in data {
    //     hasher.update(v)?;
    // }
    // let result = hasher.finish()?;
    // //32 bytes hash output
    // Ok(result)
}

// Returns 64 bytes (512 bits) hash of input data 'a slice of vecs'
pub fn sha512_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    hash_from_slice_vecs("SHA-512", data)
    // let mut hasher = botan::HashFunction::new("SHA-512")?;
    // for v in data {
    //     hasher.update(v)?;
    // }
    // let result = hasher.finish()?;
    // //64 bytes hash output
    // Ok(result)
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

    use super::sha256_hash_from_slice;

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

    #[test]
    fn verify1() {
        //let key = 
        let data: [u8; 253] = [
            3, 217, 162, 154, 103, 251, 75, 181, 1, 0, 4, 0, 2, 16, 0, 0, 0, 49, 193, 242, 230,
            191, 113, 67, 80, 190, 88, 5, 33, 106, 252, 90, 255, 3, 4, 0, 0, 0, 1, 0, 0, 0, 4, 32,
            0, 0, 0, 247, 193, 139, 87, 227, 83, 254, 103, 216, 212, 190, 204, 14, 160, 2, 246,
            111, 98, 25, 228, 1, 199, 180, 189, 229, 172, 157, 81, 128, 221, 251, 42, 11, 139, 0,
            0, 0, 0, 1, 66, 5, 0, 0, 0, 36, 85, 85, 73, 68, 16, 0, 0, 0, 239, 99, 109, 223, 140,
            41, 68, 75, 145, 247, 169, 164, 3, 227, 10, 12, 5, 1, 0, 0, 0, 73, 8, 0, 0, 0, 10, 0,
            0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 77, 8, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4, 1, 0, 0, 0,
            80, 4, 0, 0, 0, 2, 0, 0, 0, 66, 1, 0, 0, 0, 83, 32, 0, 0, 0, 21, 129, 62, 55, 66, 148,
            14, 91, 188, 48, 7, 246, 154, 184, 225, 73, 230, 198, 254, 79, 227, 14, 230, 148, 208,
            60, 145, 204, 57, 25, 179, 242, 4, 1, 0, 0, 0, 86, 4, 0, 0, 0, 19, 0, 0, 0, 0, 7, 16,
            0, 0, 0, 214, 17, 240, 154, 26, 195, 180, 177, 209, 115, 161, 231, 76, 122, 13, 86, 0,
            4, 0, 0, 0, 13, 10, 13, 10,
        ];

        let test_hash: [u8; 32] = [
            208, 243, 223, 215, 42, 250, 252, 63, 2, 249, 103, 138, 170, 201, 38, 80, 194, 95, 181,
            193, 158, 172, 164, 243, 87, 203, 69, 131, 154, 156, 57, 65,
        ];

        //let h1 = hmac_sha256_from_slices(key, data)

        //let data1 = [3, 217, 162, 154, 103, 251, 75, 181, 1, 0, 4, 0, 2, 16, 0, 0, 0, 49, 193, 242, 230, 191, 113, 67, 80, 190, 88, 5, 33, 106, 252, 90, 255, 3, 4, 0, 0, 0, 1, 0, 0, 0, 4, 32, 0, 0, 0, 247, 193, 139, 87, 227, 83, 254, 103, 216, 212, 190, 204, 14, 160, 2, 246, 111, 98, 25, 228, 1, 199, 180, 189, 229, 172, 157, 81, 128, 221, 251, 42, 11, 139, 0, 0, 0, 0, 1, 66, 5, 0, 0, 0, 36, 85, 85, 73, 68, 16, 0, 0, 0, 239, 99, 109, 223, 140, 41, 68, 75, 145, 247, 169, 164, 3, 227, 10, 12, 5, 1, 0, 0, 0, 73, 8, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 77, 8, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4, 1, 0, 0, 0, 80, 4, 0, 0, 0, 2, 0, 0, 0, 66, 1, 0, 0, 0, 83, 32, 0, 0, 0, 21, 129, 62, 55, 66, 148, 14, 91, 188, 48, 7, 246, 154, 184, 225, 73, 230, 198, 254, 79, 227, 14, 230, 148, 208, 60, 145, 204, 57, 25, 179, 242, 4, 1, 0, 0, 0, 86, 4, 0, 0, 0, 19, 0, 0, 0, 0, 7, 16, 0, 0, 0, 214, 17, 240, 154, 26, 195, 180, 177, 209, 115, 161, 231, 76, 122, 13, 86, 0, 4, 0, 0, 0, 13, 10, 13, 10];
    }
}
