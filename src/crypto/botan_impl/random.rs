use log::error;

#[allow(dead_code)]
struct SecureRandom {
    rng: botan::RandomNumberGenerator,
}

#[allow(dead_code)]
impl SecureRandom {
    fn new() -> Self {
        let r = botan::RandomNumberGenerator::new_system();
        if r.is_err() {
            error!("botan::RandomNumberGenerator::new_system() creation failed !!!!!");
        }
        SecureRandom {
            // IMPORTANT TODO: Need to remove the use of .unwrap()
            rng: r.unwrap(),
        }
    }

    fn get_bytes<const N: usize>(&mut self) -> Vec<u8> {
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
