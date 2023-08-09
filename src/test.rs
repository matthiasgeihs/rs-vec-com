use std::marker::PhantomData;

use ark_std::rand::Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::VectorCommitment;

pub fn test_rng() -> impl Rng {
    let mut rng = rand::thread_rng();
    let seed = rng.gen::<u64>();
    println!("test_rng seed: {}", seed);

    rand_chacha::ChaChaRng::seed_from_u64(seed)
}

pub trait MessageGenerator<VC: VectorCommitment> {
    fn generate<R: Rng>(rng: &mut R) -> VC::Message;
}

struct BytesMessageGenerator<VC: VectorCommitment> {
    _vc: PhantomData<VC>,
}

impl<VC> MessageGenerator<VC> for BytesMessageGenerator<VC>
where
    VC: VectorCommitment<Message = Vec<u8>>,
{
    fn generate<R: Rng>(rng: &mut R) -> VC::Message {
        let len = rng.gen_range(1..=32);
        let mut msg = vec![0u8; len];
        rng.fill_bytes(&mut msg);
        msg
    }
}

pub fn test_vec_com<R: Rng, VC: VectorCommitment, MG: MessageGenerator<VC>>(rng: &mut R) {
    // Sample vector length.
    let q = rng.gen_range(8..=16);
    println!("q = {}", q);

    // Sample message vector.
    let msgs = (0..q).map(|_| MG::generate(rng)).collect::<Vec<_>>();

    // Generate parameters.
    let params = VC::generate_parameters(rng, q).unwrap();

    // Generate commitment.
    let (c, aux) = VC::commit(&params, &msgs).unwrap();

    // Open commitment at random index.
    let i: usize = rng.gen_range(0..q);
    let p = VC::open(&params, &aux, i).unwrap();

    // Verify opening proof.
    let msg = &msgs[i];
    let result = VC::verify(&params, &c, msg, i, &p).unwrap();
    assert!(result);

    // Verify opening proof against different message.
    let msg = &msgs[(i + 1) % q];
    let result = VC::verify(&params, &c, msg, i, &p).unwrap();
    assert!(!result);
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    use super::*;

    #[test]
    fn test_cf13() {
        let mut rng = test_rng();

        type Cf13Bn254 = crate::cf13::Scheme<Bn254>;
        test_vec_com::<_, Cf13Bn254, BytesMessageGenerator<Cf13Bn254>>(&mut rng);

        type Cf13Bls12_381 = crate::cf13::Scheme<Bls12_381>;
        test_vec_com::<_, Cf13Bls12_381, BytesMessageGenerator<Cf13Bls12_381>>(&mut rng);
    }
}
