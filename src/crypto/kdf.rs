extern crate argon2_sys;
use argon2_sys::{
    argon2_ctx, argon2_error_message, argon2_type, Argon2_Context, ARGON2_OK, ARGON2_VERSION_13,
};
use std::ffi::CStr;

use crate::{
    constants,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};

pub trait Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>>;
}

// Argon2 variants are identified by these constants
// https://docs.rs/argon2-sys/0.1.0/argon2_sys/constant.Argon2_d.html
const VARIANT_ARGON2_D: u32 = 0;
const VARIANT_ARGON2_ID: u32 = 2;

// This variant is not used in KeePass
// const VARIANT_ARGON2_I: u32 = 1;

#[derive(Clone, Deserialize, Serialize, Debug)]
// While deserializing, any missing fields are formed from the struct's implementation of Default
#[serde(default)]
pub struct Argon2Kdf {
    #[serde(skip_serializing)]
    pub(crate) salt: Vec<u8>,

    pub(crate) memory: u64,
    pub(crate) iterations: u64,
    pub(crate) parallelism: u32,
    pub(crate) version: u32,

    variant: u32,
}

impl Default for Argon2Kdf {
    fn default() -> Self {
        // super module is crypto
        Self {
            memory: 67_108_864, // = 64 MB,
            salt: super::get_random_bytes::<32>(),
            iterations: 10,
            parallelism: 2,
            // hard code use of the default for now
            version: 19,
            variant: VARIANT_ARGON2_D,
        }
    }
}

impl Argon2Kdf {
    pub(crate) fn variant_2d() -> Self {
        Self::default()
    }

    pub(crate) fn variant_2id() -> Self {
        let mut argon_kdf = Self::default();
        argon_kdf.variant = VARIANT_ARGON2_ID;
        argon_kdf
    }

    // The uuids used by KeePass KDBX 4
    pub(crate) fn uuid_bytes(&self) -> &[u8] {
        if self.variant == VARIANT_ARGON2_D {
            constants::uuid::ARGON2_D_KDF
        } else {
            constants::uuid::ARGON2_ID_KDF
        }
    }

    // Creates argon2kdf with specific parameters values
    // The arg 'memory' size is in bytes
    pub(crate) fn from(memory: u64, iterations: u64, parallelism: u32) -> Self {
        Self {
            memory,
            salt: super::get_random_bytes::<32>(),
            iterations,
            parallelism,
            // hard code use of the default for now
            version: 19,
            variant: VARIANT_ARGON2_D,
        }
    }
}

impl Kdf for Argon2Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>> {
        let (pwd, pwdlen) = (composite_key.as_ptr() as *mut u8, 32);
        let (salt, saltlen) = (self.salt.as_ptr() as *mut u8, 32);

        let mut buffer = vec![0u8; 32]; //output
        let (ad, adlen) = (::std::ptr::null_mut(), 0);
        let (secret, secretlen) = (::std::ptr::null_mut(), 0);

        let memory_cost = self.memory / 1024; //in Kb

        let mut context = Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd,
            pwdlen,
            salt,
            saltlen,
            secret,
            secretlen,
            ad,
            adlen,
            t_cost: self.iterations as u32,
            m_cost: memory_cost as u32,
            lanes: self.parallelism,
            threads: self.parallelism,
            version: ARGON2_VERSION_13,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let context_ptr = &mut context as *mut Argon2_Context;
        let variant = self.variant as argon2_type;
        let return_code = unsafe { argon2_ctx(context_ptr, variant) };

        match check_return_code(return_code) {
            Ok(_) => {
                //println!("Hashed output: {:?}", u8_arr_to_i8_arr(&buffer[..]));
                Ok(buffer)
            }
            Err(m) => Err(Error::UnexpectedError(m)),
        }
    }
}

// TODO:: Need to redo this ??
fn check_return_code(
    return_code: argon2_sys::Argon2_ErrorCodes,
) -> std::result::Result<(), String> {
    match return_code {
        ARGON2_OK => Ok(()),

        argon2_sys::ARGON2_MEMORY_ALLOCATION_ERROR => Err("MemoryAllocationError".to_string()),

        argon2_sys::ARGON2_THREAD_FAIL => Err("ThreadError".to_string()),

        _ => {
            let err_msg_ptr = unsafe { argon2_error_message(return_code) };
            if err_msg_ptr.is_null() {
                return Err(format!(
                    "Unhandled error from argon2 api c lib call. Error code: {}",
                    return_code,
                ));
            }
            let err_msg_cstr = unsafe { CStr::from_ptr(err_msg_ptr) };
            let err_msg = err_msg_cstr.to_str().unwrap(); // Safe; see argon2_error_message
            Err(format!(
                "Unhandled error from argon2 api c lib call. Error code: {}. Error {}",
                return_code, err_msg
            ))
        }
    }
}
