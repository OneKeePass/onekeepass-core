use crate::{
    constants,
    error::Result,
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


// Botan is the default Argon2 backend. The 'argon2-sys-kdf' feature switches back to the
// argon2-sys reference C implementation. Both must produce identical output for the same
// parameters; see the comparison tests below
impl Kdf for Argon2Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>> {
        #[cfg(feature = "argon2-sys-kdf")]
        {
            debug!("argon2_sys_backend for argon2 transform_key is used...");
            argon2_sys_backend::transform_key(self, &composite_key)
        }

        #[cfg(not(feature = "argon2-sys-kdf"))]
        {
            use log::debug;

            debug!("BOTAN backend for argon2 transform_key is used...");
            botan_backend::transform_key(self, &composite_key)
        }
    }
}

// Only the comparison tests call this when argon2-sys is the selected backend
#[cfg_attr(feature = "argon2-sys-kdf", allow(dead_code))]
mod botan_backend {
    use std::ffi::{c_char, CStr};

    use super::{Argon2Kdf, VARIANT_ARGON2_D};
    use crate::error::{Error, Result};

    pub(super) fn transform_key(kdf: &Argon2Kdf, composite_key: &[u8]) -> Result<Vec<u8>> {
        // botan_pwdhash treats a zero passphrase length as a NUL-terminated C string and
        // calls strlen on it. The composite key is binary, so its length must be non zero
        if composite_key.is_empty() {
            return Err(Error::UnexpectedError(
                "Argon2 key derivation called with an empty composite key".to_string(),
            ));
        }

        // Botan supports only Argon2 version 0x13, which is what KDBX 4 uses
        let algo = if kdf.variant == VARIANT_ARGON2_D {
            c"Argon2d"
        } else {
            c"Argon2id"
        };

        let mut buffer = vec![0u8; 32]; //output

        // For Argon2, Botan's param1 is memory in KiB, param2 is iterations and param3 is
        // parallelism (lanes). Botan runs the lanes on its global thread pool
        let memory_cost = kdf.memory / 1024; //in Kb

        let return_code = unsafe {
            botan_sys::botan_pwdhash(
                algo.as_ptr(),
                memory_cost as usize,
                kdf.iterations as usize,
                kdf.parallelism as usize,
                buffer.as_mut_ptr(),
                buffer.len(),
                composite_key.as_ptr() as *const c_char,
                composite_key.len(),
                kdf.salt.as_ptr(),
                kdf.salt.len(),
            )
        };

        if return_code == botan_sys::BOTAN_FFI_SUCCESS {
            Ok(buffer)
        } else {
            Err(Error::UnexpectedError(error_message(return_code)))
        }
    }

    fn error_message(return_code: botan_sys::BOTAN_FFI_ERROR) -> String {
        let err_msg_ptr = unsafe { botan_sys::botan_error_description(return_code) };
        if err_msg_ptr.is_null() {
            return format!(
                "Unhandled error from botan argon2 api call. Error code: {}",
                return_code
            );
        }
        // Botan returns a pointer to a static string
        let err_msg = unsafe { CStr::from_ptr(err_msg_ptr) }.to_string_lossy();
        format!(
            "Unhandled error from botan argon2 api call. Error code: {}. Error {}",
            return_code, err_msg
        )
    }
}

#[cfg(feature = "argon2-sys-kdf")]
mod argon2_sys_backend {
    use argon2_sys::{
        argon2_ctx, argon2_error_message, argon2_type, Argon2_Context, ARGON2_OK,
        ARGON2_VERSION_13,
    };
    use std::ffi::CStr;

    use super::Argon2Kdf;
    use crate::error::{Error, Result};

    pub(super) fn transform_key(kdf: &Argon2Kdf, composite_key: &[u8]) -> Result<Vec<u8>> {
        let (pwd, pwdlen) = (composite_key.as_ptr() as *mut u8, 32);
        let (salt, saltlen) = (kdf.salt.as_ptr() as *mut u8, 32);

        let mut buffer = vec![0u8; 32]; //output
        let (ad, adlen) = (::std::ptr::null_mut(), 0);
        let (secret, secretlen) = (::std::ptr::null_mut(), 0);

        let memory_cost = kdf.memory / 1024; //in Kb

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
            t_cost: kdf.iterations as u32,
            m_cost: memory_cost as u32,
            lanes: kdf.parallelism,
            threads: kdf.parallelism,
            version: ARGON2_VERSION_13,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let context_ptr = &mut context as *mut Argon2_Context;
        let variant = kdf.variant as argon2_type;
        let return_code = unsafe { argon2_ctx(context_ptr, variant) };

        match check_return_code(return_code) {
            Ok(_) => {
                //println!("Hashed output: {:?}", u8_arr_to_i8_arr(&buffer[..]));
                Ok(buffer)
            }
            Err(m) => Err(Error::UnexpectedError(m)),
        }
    }

    // TODO:: Need to redo this ??
    fn check_return_code(
        return_code: argon2_sys::Argon2_ErrorCodes,
    ) -> std::result::Result<(), String> {
        match return_code {
            ARGON2_OK => Ok(()),

            argon2_sys::ARGON2_MEMORY_ALLOCATION_ERROR => {
                Err("MemoryAllocationError".to_string())
            }

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
}

// Run with: cargo test --lib --features argon2-sys-kdf crypto::kdf
#[cfg(all(test, feature = "argon2-sys-kdf"))]
mod comparison_tests {
    use super::*;

    // Includes 0x00 bytes and bytes that are not valid UTF-8, as a SHA-256 composite key can
    fn binary_composite_key() -> Vec<u8> {
        let mut key = crate::crypto::get_random_bytes::<32>().to_vec();
        key[0] = 0x00;
        key[7] = 0xff;
        key[16] = 0x00;
        key[31] = 0xc3;
        key
    }

    fn assert_same_output(kdf: &Argon2Kdf, composite_key: &[u8]) {
        let from_botan = botan_backend::transform_key(kdf, composite_key).unwrap();
        let from_argon2_sys = argon2_sys_backend::transform_key(kdf, composite_key).unwrap();
        assert_eq!(
            from_botan, from_argon2_sys,
            "Botan and argon2-sys outputs differ for variant {} memory {} iterations {} parallelism {}",
            kdf.variant, kdf.memory, kdf.iterations, kdf.parallelism
        );
    }

    fn with_params(mut kdf: Argon2Kdf, memory: u64, iterations: u64, parallelism: u32) -> Argon2Kdf {
        kdf.memory = memory;
        kdf.iterations = iterations;
        kdf.parallelism = parallelism;
        kdf
    }

    #[test]
    fn botan_matches_argon2_sys_for_small_params() {
        // (memory in bytes, iterations, parallelism)
        let params = [
            (1024 * 1024, 1, 1),
            (1024 * 1024, 2, 2),
            (4 * 1024 * 1024, 3, 4),
            (8 * 1024 * 1024, 2, 8),
        ];
        for (memory, iterations, parallelism) in params {
            for kdf in [Argon2Kdf::variant_2d(), Argon2Kdf::variant_2id()] {
                let kdf = with_params(kdf, memory, iterations, parallelism);
                assert_same_output(&kdf, &binary_composite_key());
            }
        }
    }

    #[test]
    fn botan_matches_argon2_sys_for_default_params() {
        // 64 MB, 10 iterations, parallelism 2 - what new databases use
        assert_same_output(&Argon2Kdf::variant_2d(), &binary_composite_key());
        assert_same_output(&Argon2Kdf::variant_2id(), &binary_composite_key());
    }

    #[test]
    fn transform_key_uses_selected_backend() {
        let kdf = with_params(Argon2Kdf::variant_2d(), 1024 * 1024, 1, 2);
        let key = binary_composite_key();
        assert_eq!(
            kdf.transform_key(key.clone()).unwrap(),
            argon2_sys_backend::transform_key(&kdf, &key).unwrap()
        );
    }
}

// Expected outputs were produced by argon2-sys. These run against whichever backend is selected,
// so they keep guarding KDBX compatibility once argon2-sys is removed
#[cfg(test)]
mod known_answer_tests {
    use super::*;

    // Not valid UTF-8 (starts with 0xc0)
    fn fixed_composite_key() -> Vec<u8> {
        (0u8..32)
            .map(|i| i.wrapping_mul(37).wrapping_add(0xc0))
            .collect()
    }

    fn fixed_kdf(kdf: Argon2Kdf) -> Argon2Kdf {
        let mut kdf = kdf;
        kdf.salt = (0u8..32).map(|i| i.wrapping_mul(11)).collect();
        kdf.memory = 1024 * 1024;
        kdf.iterations = 2;
        kdf.parallelism = 2;
        kdf
    }

    #[test]
    fn argon2d_known_answer() {
        let expected: [u8; 32] = [
            67, 107, 141, 8, 118, 168, 214, 48, 8, 58, 157, 128, 254, 24, 78, 143, 72, 23, 140,
            173, 158, 130, 111, 57, 26, 249, 255, 224, 61, 128, 197, 30,
        ];
        let kdf = fixed_kdf(Argon2Kdf::variant_2d());
        assert_eq!(kdf.transform_key(fixed_composite_key()).unwrap(), expected);
    }

    #[test]
    fn argon2id_known_answer() {
        let expected: [u8; 32] = [
            238, 93, 154, 136, 30, 7, 56, 175, 22, 199, 230, 60, 176, 205, 23, 119, 1, 2, 104, 35,
            149, 70, 105, 179, 3, 34, 235, 123, 104, 132, 24, 235,
        ];
        let kdf = fixed_kdf(Argon2Kdf::variant_2id());
        assert_eq!(kdf.transform_key(fixed_composite_key()).unwrap(), expected);
    }
}
