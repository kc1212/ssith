mod primitives;
mod consts;
mod errors;

use rand_core::{CryptoRng, RngCore};
use sha3::{Sha3_256, Digest};
use consts::{BLOCK_SIZE, DIGEST_SIZE};
use primitives::*;
use consts::*;
use errors::*;

#[derive(Debug, Copy, Clone)]
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

#[derive(Debug, Clone)]
pub struct Witness(Vec<u8>);

impl Witness {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone)]
pub struct Instance {
    weights: Vec<u64>,
    t: u64,
}

fn sanity_check(witness: &Witness, instance: &Instance, param: Param) -> Result<(), InternalError> {
    if witness.len() != param.ssp_dimension {
        return Err(InternalError::BadWitnessLength)
    }
    if instance.weights.len() != param.ssp_dimension {
        return Err(InternalError::BadInstanceLength)
    }
    if param.abort_param >= 64 {
        return Err(InternalError::BadAbortParam)
    }

    // recompute the inner product
    let t: u64 = witness.0.iter().zip(&instance.weights).map(|(witness, weight)| {
        (*witness as u64) * weight
    }).fold(0u64, |acc, s| {
        acc.wrapping_add(s)
    });
    if t != instance.t {
        return Err(InternalError::BadWitnessOrInstance)
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

    let t: u64 = weights.iter().zip(&w_vec).map(|(weight, witness)| {
        weight * (*witness as u64)
    }).fold(0u64, |acc, s| {
        acc.wrapping_add(s)
    });

    (Witness(w_vec),
     Instance {
        weights,
        t,
    })
}

pub struct Prover {
    witness: Witness,
    instance: Instance,
    mseed: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
    param: Param,
}

fn hash_witness_instance(witness: &Witness, instance: &Instance) -> [u8; BLOCK_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(WITNESS_PREFIX);
    hasher.update(&witness.len().to_le_bytes());
    hasher.update(&witness.0);

    hasher.update(INSTANCE_PREFIX);
    hasher.update(&instance.weights.len().to_le_bytes());
    for weight in &instance.weights {
        hasher.update(&weight.to_le_bytes());
    }
    hasher.update(&instance.t.to_le_bytes());

    let result = hasher.finalize();
    result.as_slice()[..BLOCK_SIZE].try_into().unwrap()
}

impl Prover {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, param: Param) -> Self {
        let (witness, instance) = new_witness_instance(rng, param);
        let mut mseed = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut mseed);
        Self::from_witness_instance_unchecked(witness, instance, mseed, param)
    }

    pub fn from_witness_instance(witness: Witness, instance: Instance, mseed: [u8; BLOCK_SIZE], param: Param) -> Result<Self, InternalError> {
        sanity_check(&witness, &instance, param)?;
        Ok(Self::from_witness_instance_unchecked(witness, instance, mseed, param))
    }

    fn from_witness_instance_unchecked(witness: Witness, instance: Instance, mseed: [u8; BLOCK_SIZE], param: Param) -> Self {
        let iv = hash_witness_instance(&witness, &instance);
        Prover {
            witness,
            instance,
            mseed,
            iv,
            param,
        }
    }

    pub fn step1(&self) -> [u8; DIGEST_SIZE] {
        let mseeds = prg_tree(&self.mseed, &self.iv, self.param.cnc_param);
        let mut h1s = Vec::with_capacity(self.param.cnc_param);

        for e in 0..self.param.cnc_param {
            let rs = prg_bin(&mseeds[e], &self.iv, self.param.ssp_dimension);
            let seeds_rhos = prg_tree(&mseeds[e], &self.iv, self.param.party_count * 2);
            let (seeds, rhos): (Vec<_>, Vec<_>) = seeds_rhos.chunks_exact(2).map(|arr| {
                (arr[0], arr[1])
            }).unzip();
            debug_assert_eq!(seeds.len(), self.param.party_count);
            debug_assert_eq!(rhos.len(), self.param.party_count);

            let r_shares: Vec<Vec<u64>> = seeds.iter().map(|seed| {
                prg_u64(seed, &self.iv, self.param.ssp_dimension).iter().map(|x| {
                    x % (1 << self.param.abort_param as u64)
                }).collect()
            }).collect();

            let coms: Vec<_> = seeds.iter().zip(rhos.iter()).map(|(seed, rho)| {
                commit(seed, &Opening(*rho))
            }).collect();

            // sum over the N vectors
            let r_shares_sum: Vec<u64> = r_shares.iter().fold(vec![0u64; self.param.ssp_dimension], |acc, x| {
                acc.into_iter().zip(x).map(|(a, b)| {
                    a + b
                }).collect()
            });
            let delta_rs: Vec<_> = rs.iter().zip(&r_shares_sum).map(|(r, share)| {
                (*r as u64).wrapping_sub(*share)
            }).collect();

            let h1 = hash1(&delta_rs, &coms);
            h1s.push(h1);
        }
        let h = hash2(&h1s);
        h
    }
}

struct FullTranscript {}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use super::*;

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
        assert_eq!(sanity_check(&short_witness, &short_instance, short_param), Ok(()));
        assert_eq!(sanity_check(&witness, &short_instance, short_param), Err(InternalError::BadWitnessLength));
        assert_eq!(sanity_check(&witness, &instance, short_param), Err(InternalError::BadWitnessLength));

        let bad_param = Param {
            abort_param: 64,
            ..param
        };
        assert_eq!(sanity_check(&witness, &instance, bad_param), Err(InternalError::BadAbortParam));
    }
}
