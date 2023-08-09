use ark_std::rand::Rng;

pub mod cf13;
#[cfg(test)]
mod test;

type Error = String;

pub trait VectorCommitment {
    type Parameters;
    type Message;
    type Commitment;
    type AuxData;
    type Proof;
    fn generate_parameters<R: Rng>(rng: &mut R, l: usize) -> Result<Self::Parameters, Error>;
    fn commit(
        parameters: &Self::Parameters,
        vector: &[Self::Message],
    ) -> Result<(Self::Commitment, Self::AuxData), Error>;
    fn open(
        parameters: &Self::Parameters,
        aux: &Self::AuxData,
        index: usize,
    ) -> Result<Self::Proof, Error>;
    fn verify(
        parameters: &Self::Parameters,
        commitment: &Self::Commitment,
        msg: &Self::Message,
        index: usize,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}
