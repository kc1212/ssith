mod consts;
mod errors;
mod primitives;

use consts::*;
use consts::{BLOCK_SIZE, DIGEST_SIZE};
use errors::*;
use primitives::*;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Param {
    /// Dimension of the SSP (n)
    ssp_dimension: usize,
    /// Number of parties (N)
    party_count: usize,
    /// Parameter for cut and choose (M)
    cnc_param: usize,
    /// Parameter for abort in bits, i.e., log A
    abort_param: usize,
}

impl Param {
    pub fn default() -> Self {
        Param {
            ssp_dimension: 128,
            party_count: 4,
            cnc_param: 100,
            abort_param: 14,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness(Vec<u8>);

impl Witness {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Prover {
    witness: Witness,
    instance: Instance,
    #[serde(with = "hex::serde")]
    mseed: [u8; BLOCK_SIZE],
    #[serde(with = "hex::serde")]
    iv: [u8; BLOCK_SIZE],
    param: Param,
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

/// For each C&C parameter
#[derive(Debug, Serialize, Deserialize)]
pub struct ProverStateInner {
    #[serde(with = "hex::serde")]
    mseed_inner: [u8; BLOCK_SIZE],
    #[serde(with = "hex::serde")]
    rs: Vec<u8>,
    seeds: Vec<WrapperArray>, // Vec<[u8; BLOCK_SIZE]>,
    rhos: Vec<Opening>,
    r_shares: Vec<Vec<u64>>,
    coms: Vec<Commitment>,
    r_shares_sum: Vec<u64>,
    delta_rs: Vec<u64>,
    #[serde(with = "hex::serde")]
    h1: [u8; DIGEST_SIZE],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
/// WrapperArray is created so that serde knows how to
/// (de)serialize a vector of arrays using hex.
struct WrapperArray {
    #[serde(with = "hex::serde")]
    inner: [u8; BLOCK_SIZE],
}

impl WrapperArray {
    fn new(a: [u8; BLOCK_SIZE]) -> Self {
        Self { inner: a }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverState {
    step1_state: Vec<ProverStateInner>,
    h: [u8; DIGEST_SIZE],
}

impl ProverState {
    fn new() -> Self {
        Self {
            step1_state: vec![],
            h: [0u8; DIGEST_SIZE],
        }
    }

    fn set_h(&mut self, h: [u8; DIGEST_SIZE]) {
        self.h = h
    }

    fn push_inner(&mut self, inner: ProverStateInner) {
        self.step1_state.push(inner)
    }
}

impl Prover {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, param: Param) -> Self {
        let (witness, instance) = new_witness_instance(rng, param);
        let mut mseed = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut mseed);
        Self::from_witness_instance_unchecked(witness, instance, mseed, param)
    }

    pub fn from_witness_instance(
        witness: Witness,
        instance: Instance,
        mseed: [u8; BLOCK_SIZE],
        param: Param,
    ) -> Result<Self, InternalError> {
        sanity_check(&witness, &instance, param)?;
        Ok(Self::from_witness_instance_unchecked(
            witness, instance, mseed, param,
        ))
    }

    fn from_witness_instance_unchecked(
        witness: Witness,
        instance: Instance,
        mseed: [u8; BLOCK_SIZE],
        param: Param,
    ) -> Self {
        let iv = hash_witness_instance(&witness, &instance);
        Prover {
            witness,
            instance,
            mseed,
            iv,
            param,
        }
    }

    pub fn step1(&self) -> ProverState {
        let mut h1s = Vec::with_capacity(self.param.cnc_param);
        let mut state = ProverState::new();

        let mseeds_inner = prg_tree(&self.mseed, &self.iv, self.param.cnc_param);
        debug_assert_eq!(mseeds_inner.len(), self.param.cnc_param);
        for mseed_inner in mseeds_inner {
            let rs = prg_bin(&mseed_inner, &self.iv, self.param.ssp_dimension);
            let seeds_rhos = prg_tree(&mseed_inner, &self.iv, self.param.party_count * 2);
            let (seeds, rhos): (Vec<_>, Vec<_>) = seeds_rhos
                .chunks_exact(2)
                .map(|arr| (arr[0], Opening::new(arr[1])))
                .unzip();
            debug_assert_eq!(seeds.len(), self.param.party_count);
            debug_assert_eq!(rhos.len(), self.param.party_count);

            let r_shares: Vec<Vec<u64>> = seeds
                .iter()
                .map(|seed| {
                    prg_u64(seed, &self.iv, self.param.ssp_dimension)
                        .iter()
                        .map(|x| x % (1 << self.param.abort_param as u64))
                        .collect()
                })
                .collect();

            let coms: Vec<_> = seeds
                .iter()
                .zip(rhos.iter())
                .map(|(seed, rho)| commit(seed, &rho))
                .collect();

            // sum over the N vectors
            let r_shares_sum: Vec<_> = r_shares
                .iter()
                .fold(vec![0u64; self.param.ssp_dimension], |acc, x| {
                    acc.into_iter().zip(x).map(|(a, b)| a + b).collect()
                });
            let delta_rs: Vec<_> = rs
                .iter()
                .zip(&r_shares_sum)
                .map(|(r, share)| (*r as u64).wrapping_sub(*share))
                .collect();

            let h1 = hash1(&delta_rs, &coms);
            h1s.push(h1);

            // Create the state object
            let inner = ProverStateInner {
                mseed_inner,
                rs,
                seeds: seeds
                    .into_iter()
                    .map(|seed| WrapperArray::new(seed))
                    .collect(),
                rhos,
                r_shares,
                coms,
                r_shares_sum,
                delta_rs,
                h1,
            };
            state.push_inner(inner);
        }
        let h = hash2(&h1s);
        state.set_h(h);
        // TODO: possibly we need to store the state in the Prover object
        state
    }
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
