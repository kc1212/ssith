mod consts;
mod errors;
mod primitives;
pub mod prover;
pub mod verifier;

use consts::*;
use errors::*;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Copy, Clone, Serialize)]
/// Parameter for the subset sum MPCitH protocol.
pub struct Param {
    /// Dimension of the SSP (n)
    ssp_dimension: usize,
    /// Number of parties (N)
    party_count: usize,
    /// Parameter for cut and choose (M)
    cnc_param: usize,
    /// Parameter for abort in bits, i.e., log A
    abort_param: usize,
    /// The number of reps (tau)
    rep_param: usize,
}

impl Default for Param {
    fn default() -> Self {
        Param {
            ssp_dimension: 128,
            party_count: 4,
            cnc_param: 100,
            abort_param: 14,
            rep_param: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
// TODO impl deref
/// The witness (solution) to the subset sum problem.
pub struct Witness(Vec<u8>);

impl Witness {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Serialize)]
/// The instance of the subset sum problem.
pub struct Instance {
    weights: Vec<u64>,
    t: u64,
}

fn sanity_check(witness: &Witness, instance: &Instance, param: Param) -> Result<(), InternalError> {
    if witness.len() != param.ssp_dimension {
        return Err(InternalError::BadWitnessLength);
    }
    if instance.weights.len() != param.ssp_dimension {
        return Err(InternalError::BadInstanceLength);
    }
    if param.abort_param >= 64 {
        return Err(InternalError::BadAbortParam);
    }

    // recompute the inner product
    let t: u64 = witness
        .0
        .iter()
        .zip(&instance.weights)
        .map(|(witness, weight)| (*witness as u64) * weight)
        .fold(0u64, |acc, s| acc.wrapping_add(s));
    if t != instance.t {
        return Err(InternalError::BadWitnessOrInstance);
    }
    Ok(())
}

fn new_witness_instance<R: RngCore + CryptoRng>(rng: &mut R, param: Param) -> (Witness, Instance) {
    // TODO: this is a bit redundant since we only need one bit from a byte
    let mut w_vec = vec![0u8; param.ssp_dimension];
    rng.fill_bytes(&mut w_vec);
    w_vec.iter_mut().for_each(|w| {
        *w = *w % 2;
    });

    let mut weights = vec![0u64; param.ssp_dimension];
    for x in &mut weights {
        *x = rng.next_u64();
    }

    let t: u64 = weights
        .iter()
        .zip(&w_vec)
        .map(|(weight, witness)| weight * (*witness as u64))
        .fold(0u64, |acc, s| acc.wrapping_add(s));

    (Witness(w_vec), Instance { weights, t })
}

fn hash_witness_instance(witness: &Witness, instance: &Instance) -> [u8; BLOCK_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_WITNESS);
    hasher.update(&witness.len().to_le_bytes());
    hasher.update(&witness.0);

    hasher.update(PREFIX_INSTANCE);
    hasher.update(&instance.weights.len().to_le_bytes());
    for weight in &instance.weights {
        hasher.update(&weight.to_le_bytes());
    }
    hasher.update(&instance.t.to_le_bytes());

    let result = hasher.finalize();
    result.as_slice()[..BLOCK_SIZE].try_into().unwrap()
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProverMsg {
    Step1([u8; DIGEST_SIZE]),
    Step2(([u8; DIGEST_SIZE], Vec<[u8; BLOCK_SIZE]>)),
}

#[derive(Clone, PartialEq, Eq)]
pub enum VerifierMsg {
    Step1(Vec<usize>),
    Step2(Vec<usize>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_sanity_check() {
        let mut rng = ChaChaRng::from_entropy();
        let param = Param::default();
        let (witness, instance) = new_witness_instance(&mut rng, param);
        assert_eq!(sanity_check(&witness, &instance, param), Ok(()));

        let short_param = Param {
            ssp_dimension: 9,
            ..param
        };
        let (short_witness, short_instance) = new_witness_instance(&mut rng, short_param);
        assert_eq!(
            sanity_check(&short_witness, &short_instance, short_param),
            Ok(())
        );
        assert_eq!(
            sanity_check(&witness, &short_instance, short_param),
            Err(InternalError::BadWitnessLength)
        );
        assert_eq!(
            sanity_check(&witness, &instance, short_param),
            Err(InternalError::BadWitnessLength)
        );

        let bad_param = Param {
            abort_param: 64,
            ..param
        };
        assert_eq!(
            sanity_check(&witness, &instance, bad_param),
            Err(InternalError::BadAbortParam)
        );
    }
}
