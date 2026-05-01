use rand::Rng;

pub fn get_rand_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..length).map(|_| rng.random()).collect()
}
