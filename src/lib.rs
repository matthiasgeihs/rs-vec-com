pub mod cf13;

pub trait VectorCommitment {
    type Parameters;
    fn generate_parameters() -> Self::Parameters;
    fn commit(parameters: &Self::Parameters, vector: &[Vec<u8>]) -> Vec<u8>;
    fn open(parameters: &Self::Parameters, vector: &[Vec<u8>], index: usize) -> Vec<u8>;
}

#[cfg(test)]
mod test_util {
    use ark_std::rand::Rng;
    use rand_chacha::rand_core::SeedableRng;

    pub fn test_rng() -> impl Rng {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();
        println!("test_rng seed: {}", seed);

        rand_chacha::ChaChaRng::seed_from_u64(seed)
    }
}
