mod consts;
mod errors;
mod primitives;

use consts::*;
use errors::*;
use primitives::*;
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
}

impl Default for Param {
    fn default() -> Self {
        Param {
            ssp_dimension: 128,
            party_count: 4,
            cnc_param: 100,
            abort_param: 14,
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

#[derive(Debug, Serialize)]
/// The prover of the subset sum MPCitH protocol.
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
#[derive(Debug, Serialize)]
pub struct ProverStateInner {
    #[serde(with = "hex::serde")]
    mseed_inner: [u8; BLOCK_SIZE],
    #[serde(with = "hex::serde")]
    rs: Vec<u8>,
    // usually it should be Vec<[u8; BLOCK_SIZE]>,
    seeds: Vec<WrapperArray>,
    rhos: Vec<Opening>,
    r_shares: Vec<Vec<u64>>,
    coms: Vec<Commitment>,
    r_shares_sum: Vec<u64>,
    delta_rs: Vec<u64>,
    #[serde(with = "hex::serde")]
    h1: [u8; DIGEST_SIZE],
}

#[derive(Serialize, Debug)]
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

#[derive(Debug, Serialize)]
pub struct ProverState {
    step1_state: Vec<ProverStateInner>,
    #[serde(with = "hex::serde")]
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
    /// Create a new prover with a random witness-instance pair,
    /// generated using `rng` according to parameters `param`.
    /// Internally, the master seed is also sampled from the `rng`.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, param: Param) -> Self {
        let (witness, instance) = new_witness_instance(rng, param);
        let mut mseed = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut mseed);
        Self::from_witness_instance_unchecked(witness, instance, mseed, param)
    }

    /// Create a new prover from a given witness-instance pair.
    /// This function performs a sanity check and outputs
    /// an error if the check fails.
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

    /// Run the first step of the protocol and output the prover state.
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

    pub fn step2(&self, state: &ProverState, chalJ: &Vec<usize>) -> ([u8; DIGEST_SIZE], Vec<[u8; BLOCK_SIZE]>) {
        // TODO check length of chalJ
        // TODO check that J \subset [M]

        let h_primes = chalJ.iter().map(|e| {
            let xs_tilde: Vec<_> = self
                .witness
                .0
                .iter()
                .zip(state.step1_state[*e].rs.iter())
                .map(|(a, b)| a ^ b).collect();

            let t_shares = state.step1_state[*e].r_shares.iter().map(|r_share| {
                // x_share is [x], per c&c and per party i
                let x_share = xs_tilde
                    .iter()
                    .zip(r_share)
                    .map(|(x_tilde, r_share)| {
                        u64::from(1u8 - x_tilde) * r_share
                            + u64::from(*x_tilde) * (1u64.wrapping_sub(*r_share))
                    });
                let t_share: u64 = 
                    self.instance.weights.iter().zip(x_share).map(|(w, x)| {
                        *w*x
                    }).sum();
                t_share
            });

            // hash shares and xs_tilde
            // TODO: remove collect and hash incrementally
            let h_prime = hash3(&xs_tilde, t_shares);
            h_prime
        });
        
        // hash all the h_primes
        let h_prime = hash4(h_primes);
        
        // find the mseeds that are not in chalJ
        let mseeds: Vec<_> = chalJ.iter().map(|e| {
            // TODO: this is wrong, need e \notin J
            state.step1_state[*e].mseed_inner
        }).collect();
        (h_prime, mseeds)
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
