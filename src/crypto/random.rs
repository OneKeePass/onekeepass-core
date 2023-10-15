
pub use botan_crypto::*;

//pub use rust_crypto::*;

mod botan_crypto {
    use log::error;

    #[allow(dead_code)]
    pub struct SecureRandom {
        rng:botan::RandomNumberGenerator,
    }

    #[allow(dead_code)]
    impl SecureRandom {
        pub fn new() -> Self {
            let r = botan::RandomNumberGenerator::new_system();
            if r.is_err() {
                error!("botan::RandomNumberGenerator::new_system() creation failed !!!!!");
            }
            SecureRandom {
                //TODO: Need to remove the use of .unwrap()
                rng:r.unwrap(),
            }
        }

        pub fn get_bytes<const N: usize>(&mut self) -> Vec<u8> {
            let mut buf = [0u8; N];
            let r = self.rng.fill(&mut buf);
            if r.is_err() {
                error!("Fix this: botan::RandomNumberGenerator::fill() call failed !!!!!");
            }
            buf.to_vec()
        }
    }

    pub fn get_random_bytes<const N: usize>() -> Vec<u8> {
        SecureRandom::new().get_bytes::<N>()
    }
}

#[allow(dead_code)]
mod rust_crypto {
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

    pub fn get_random_bytes<const N: usize>() -> Vec<u8> {
        SecureRandom::new().get_bytes::<N>()
    }
}