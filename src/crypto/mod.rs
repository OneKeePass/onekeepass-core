mod block_cipher;
pub mod kdf;
mod stream_cipher;

pub use self::block_cipher::ContentCipher;
pub use self::stream_cipher::ProtectedContentStreamCipher;

//use hex_literal::hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::digest::generic_array::{typenum::U32, GenericArray};
use sha2::{Digest, Sha256, Sha512};

//use crate::result::{Result,Error};
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
pub fn calculate_hash(data: &Vec<Vec<u8>>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result)
}

#[allow(dead_code)]
pub fn do_vec_sha256_hash(data: Vec<u8>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize())
}
//32 bytes hash output
#[allow(dead_code)]
pub fn do_vecs_sha256_hash(data: &Vec<&Vec<u8>>) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    for v in data {
        hasher.update(v);
    }
    let result = hasher.finalize();
    Ok(result)
}

pub fn do_slice_sha256_hash(data: &[u8]) -> Result<GenericArray<u8, U32>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize())
}

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

#[allow(dead_code)]
pub struct SecureRandom {
    rng: ChaCha20Rng,
}

#[allow(dead_code)]
impl SecureRandom {
    pub fn new() -> Self {
        SecureRandom {
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    pub fn get_bytes<const N: usize>(&mut self) -> Vec<u8> {
        let mut buf = [0u8; N];
        self.rng.fill_bytes(&mut buf);
        buf.to_vec()
    }
}

/*
pub trait Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version:u32,
}

impl Argon2Kdf {
    fn to_argon_version(&self) -> argon2::Version {
        if self.version == 19 {
            argon2::Version::Version13
        } else {
            argon2::Version::Version13
        }
    }
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            thread_mode: argon2::ThreadMode::default(),
            time_cost: self.iterations as u32,
            variant: argon2::Variant::Argon2d,
            version: self.to_argon_version(),
        };

        let key = argon2::hash_raw(&composite_key[..], &self.salt, &config)?;


        Ok(key)
    }
}

//Should this be moved to "result" module
impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Self {
        Error::Argon2Error(err.to_string())
    }
}
*/
//Not working
// pub fn hash<D: Digest + Default>(data: Vec<u8>) -> Output<D>  {
//     let mut hasher = D::default();
//     hasher.update(data);
//     let a = hasher.finalize();
//     //Ok(hasher.finalize())
// }

/*
Copied from https://github.com/RustCrypto/hashes/blob/master/sha2/examples/sha256sum.rs
/// Compute digest value for given `Reader` and print it
/// On any error simply return without doing anything
fn process<D: Digest + Default, R: Read>(reader: &mut R, name: &str) {
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => return,
        };
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    print_result(&sh.finalize(), name);
}

fn main() {
    let args = env::args();
    // Process files listed in command line arguments one by one
    // If no files provided process input from stdin
    if args.len() > 1 {
        for path in args.skip(1) {
            if let Ok(mut file) = fs::File::open(&path) {
                process::<Sha256, _>(&mut file, &path);
            }
        }
    } else {
        process::<Sha256, _>(&mut io::stdin(), "-");
    }
}

*/
