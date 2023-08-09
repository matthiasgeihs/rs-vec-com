use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::Rng;
use ark_std::{UniformRand, Zero};
use sha2::Sha256;

type Error = String;
type Commitment = G1Projective;
type Proof = G1Projective;

pub struct Parameters {
    pub g_g2: G2Projective,
    pub h_g1: Vec<G1Projective>,
    pub h_g2: Vec<G2Projective>,
    pub hh_g1: Vec<Vec<G1Projective>>,
    pub hh_g2: Vec<Vec<G2Projective>>,
}
pub struct AuxData {
    msg_hashes: Vec<Fr>,
}

fn new_hasher() -> DefaultFieldHasher<Sha256> {
    let domain = &[];
    <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(domain)
}

pub fn generate_parameters<R: Rng>(rng: &mut R, q: usize) -> Result<Parameters, Error> {
    let g_g1 = G1Projective::rand(rng);
    let g_g2 = G2Projective::rand(rng);
    let z = (0..q).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let h_g1 = z.iter().map(|zi| g_g1 * zi).collect::<Vec<_>>();
    let h_g2 = z.iter().map(|zi| g_g2 * zi).collect::<Vec<_>>();
    let hh_g1 = h_g1
        .iter()
        .map(|&hi| z.iter().map(|zi| hi * zi).collect::<Vec<_>>())
        .collect::<Vec<Vec<_>>>();
    let hh_g2 = h_g2
        .iter()
        .map(|&hi| z.iter().map(|zi| hi * zi).collect::<Vec<_>>())
        .collect::<Vec<Vec<_>>>();

    Ok(Parameters {
        g_g2,
        h_g1,
        h_g2,
        hh_g1,
        hh_g2,
    })
}

pub fn commit(parameters: &Parameters, vector: &[Vec<u8>]) -> Result<(Commitment, AuxData), Error> {
    if parameters.h_g1.len() != vector.len() {
        return Err("vector has invalid length".to_string());
    }

    let hasher = new_hasher();
    let msg_hashes = vector
        .iter()
        .map(|mi| {
            let hash_mi: Vec<Fr> = hasher.hash_to_field(mi, 1);
            hash_mi[0]
        })
        .collect::<Vec<_>>();

    let identity = G1Projective::zero();
    let c = parameters
        .h_g1
        .iter()
        .zip(&msg_hashes)
        .fold(identity, |acc, (hi, hash_mi)| acc + *hi * hash_mi);
    let aux = AuxData { msg_hashes };
    Ok((c, aux))
}

pub fn open(parameters: &Parameters, i: usize, aux: AuxData) -> Result<Proof, Error> {
    if i >= parameters.hh_g1.len() {
        return Err("invalid index".to_string());
    }

    let identity = G1Projective::zero();
    let p = parameters.hh_g1[i]
        .iter()
        .enumerate()
        .fold(identity, |acc, (j, hhij)| match j == i {
            true => acc,
            false => acc + *hhij * aux.msg_hashes[j],
        });
    Ok(p)
}

pub fn verify(
    parameters: &Parameters,
    c: Commitment,
    msg: &[u8],
    i: usize,
    p: Proof,
) -> Result<bool, Error> {
    let hasher = new_hasher();
    let msg_hash: Fr = hasher.hash_to_field(msg, 1)[0];
    let hi_g1 = parameters.h_g1[i];
    let a = c - hi_g1 * msg_hash;
    let hi_g2 = parameters.h_g2[i];
    let g_g2 = parameters.g_g2;
    let t1 = Bn254::pairing(a, hi_g2);
    let t2 = Bn254::pairing(p, g_g2);
    Ok(t1.eq(&t2))
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    #[test]
    fn gen_commit_verify() {
        // Create RNG.
        let mut rng = crate::test_util::test_rng();

        // Sample vector length.
        let q = rng.gen_range(8..=16);
        println!("q = {}", q);

        // Sample message vector.
        let msgs = (0..q)
            .map(|_| {
                let l: usize = rng.gen_range(8..256);
                let mut msg = vec![0u8; l];
                rng.fill_bytes(&mut msg);
                msg
            })
            .collect::<Vec<_>>();

        // Generate parameters.
        let params = generate_parameters(&mut rng, q).unwrap();

        // Generate commitment.
        let (c, aux) = commit(&params, &msgs).unwrap();

        // Open commitment at random index.
        let i: usize = rng.gen_range(0..q);
        let p = open(&params, i, aux).unwrap();

        // Verify opening proof.
        let msg = &msgs[i];
        let result = verify(&params, c, msg, i, p).unwrap();
        assert!(result);

        // Verify opening proof against different message.
        let msg = &msgs[(i + 1) % q];
        let result = verify(&params, c, msg, i, p).unwrap();
        assert!(!result);
    }
}
