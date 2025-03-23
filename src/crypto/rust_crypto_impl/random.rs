use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

struct SecureRandom {
    rng: ChaCha20Rng,
}

impl SecureRandom {
    fn new() -> Self {
        SecureRandom {
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    fn get_bytes<const N: usize>(&mut self) -> Vec<u8> {
        let mut buf = [0u8; N];
        self.rng.fill_bytes(&mut buf);
        buf.to_vec()
    }
}

pub fn get_random_bytes<const N: usize>() -> Vec<u8> {
    SecureRandom::new().get_bytes::<N>()
}

pub fn get_random_bytes_2<const N1: usize, const N2: usize>() -> (Vec<u8>, Vec<u8>) {
    let mut rng = SecureRandom::new();
    (rng.get_bytes::<N1>(), rng.get_bytes::<N2>())
}

pub fn get_random_bytes_3<const N1: usize, const N2: usize, const N3: usize>(
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = SecureRandom::new();
    (
        rng.get_bytes::<N1>(),
        rng.get_bytes::<N2>(),
        rng.get_bytes::<N3>(),
    )
}
