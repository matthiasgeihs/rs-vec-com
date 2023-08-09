use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::Rng;
use ark_std::{UniformRand, Zero};
use sha2::Sha256;

type Error = String;
type Commitment<P> = <P as Pairing>::G1;
type Proof<P> = <P as Pairing>::G1;

pub struct Parameters<P: Pairing> {
    pub g_g2: P::G2,
    pub h_g1: Vec<P::G1>,
    pub h_g2: Vec<P::G2>,
    pub hh_g1: Vec<Vec<P::G1>>,
    pub hh_g2: Vec<Vec<P::G2>>,
    pub hasher: DefaultFieldHasher<Sha256>,
}
pub struct AuxData<P: Pairing> {
    msg_hashes: Vec<P::ScalarField>,
}

fn new_hasher<P: Pairing>() -> DefaultFieldHasher<Sha256> {
    let domain = &[];
    <DefaultFieldHasher<Sha256> as HashToField<P::ScalarField>>::new(domain)
}

pub fn generate_parameters<R: Rng, P: Pairing>(
    rng: &mut R,
    q: usize,
) -> Result<Parameters<P>, Error> {
    let g_g1 = P::G1::rand(rng);
    let g_g2 = P::G2::rand(rng);
    let z = (0..q)
        .map(|_| P::ScalarField::rand(rng))
        .collect::<Vec<_>>();
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

    let hasher = new_hasher::<P>();

    Ok(Parameters {
        g_g2,
        h_g1,
        h_g2,
        hh_g1,
        hh_g2,
        hasher,
    })
}

pub fn commit<P: Pairing>(
    parameters: &Parameters<P>,
    vector: &[Vec<u8>],
) -> Result<(Commitment<P>, AuxData<P>), Error> {
    if parameters.h_g1.len() != vector.len() {
        return Err("vector has invalid length".to_string());
    }

    let hasher = &parameters.hasher;
    let msg_hashes = vector
        .iter()
        .map(|mi| {
            let hash_mi: Vec<P::ScalarField> = hasher.hash_to_field(mi, 1);
            hash_mi[0]
        })
        .collect::<Vec<_>>();

    let identity = P::G1::zero();
    let c = parameters
        .h_g1
        .iter()
        .zip(&msg_hashes)
        .fold(identity, |acc, (hi, hash_mi)| acc + *hi * hash_mi);
    let aux = AuxData { msg_hashes };
    Ok((c, aux))
}

pub fn open<P: Pairing>(
    parameters: &Parameters<P>,
    i: usize,
    aux: AuxData<P>,
) -> Result<Proof<P>, Error> {
    if i >= parameters.hh_g1.len() {
        return Err("invalid index".to_string());
    }

    let identity = P::G1::zero();
    let p = parameters.hh_g1[i]
        .iter()
        .enumerate()
        .fold(identity, |acc, (j, hhij)| match j == i {
            true => acc,
            false => acc + *hhij * aux.msg_hashes[j],
        });
    Ok(p)
}

pub fn verify<P: Pairing>(
    parameters: &Parameters<P>,
    c: Commitment<P>,
    msg: &[u8],
    i: usize,
    p: Proof<P>,
) -> Result<bool, Error> {
    let hasher = &parameters.hasher;
    let msg_hash: P::ScalarField = hasher.hash_to_field(msg, 1)[0];
    let hi_g1 = parameters.h_g1[i];
    let a = c - hi_g1 * msg_hash;
    let hi_g2 = parameters.h_g2[i];
    let g_g2 = parameters.g_g2;
    let t1 = P::pairing(a, hi_g2);
    let t2 = P::pairing(p, g_g2);
    Ok(t1.eq(&t2))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
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
        let params = generate_parameters::<_, Bn254>(&mut rng, q).unwrap();

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
