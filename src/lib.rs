mod primitive;
use primitive::*;


#[derive(Debug, Copy, Clone)]
struct Param {
    /// Dimension of the SSP
    n: usize,
    /// Number of parties
    N: usize,
    /// Parameter for cut and choose
    M: usize,
    /// Parameter for abort
    A: usize,
}

impl Param {
    fn default() -> Self {
        Param {
            n: 128,
            N: 4,
            M: 100,
            A: 1 << 14,
        }
    }
}

struct Witness(Vec<u8>);
struct Instance {
    weights: Vec<u64>,
    t: u64,
}

struct Prover {
    witness: Witness,
    instance: Instance,
    mseed: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
    param: Param,
}

fn hash_witness_instance(witness: &Witness, instance: &Instance) -> [u8; BLOCK_SIZE] {
    unimplemented!()
}

impl Prover {
    fn new(witness: Witness, instance: Instance, mseed: [u8; BLOCK_SIZE], param: Param) -> Self {
        let iv = hash_witness_instance(&witness, &instance);
        // TODO check params, A needs to be a power of 2
        Prover {
            witness,
            instance,
            mseed,
            iv,
            param,
        }
    }

    fn step1(&self) -> [u8; DIGEST_SIZE] {
        let mseeds = prg_tree(&self.mseed, &self.iv, self.param.M);
        let mut h1s = Vec::with_capacity(self.param.M);

        for e in 0..self.param.M {
            let rs = prg_bin(&mseeds[e], &self.iv, self.param.n);
            let seeds_rhos = prg_tree(&mseeds[e], &self.iv, self.param.N * 2);
            let (seeds, rhos): (Vec<_>, Vec<_>) = seeds_rhos.chunks_exact(2).map(|arr| {
                (arr[0], arr[1])
            }).unzip();
            debug_assert_eq!(seeds.len(), self.param.N);
            debug_assert_eq!(rhos.len(), self.param.N);

            let r_shares: Vec<Vec<u64>> = seeds.iter().map(|seed| {
                prg_u64(seed, &self.iv, self.param.n).iter().map(|x| {
                    x % (self.param.A as u64)
                }).collect()
            }).collect();

            let coms: Vec<_> = seeds.iter().zip(rhos.iter()).map(|(seed, rho)| {
                commit(seed, &Opening(*rho))
            }).collect();

            // sum over the N vectors
            let r_shares_sum: Vec<u64> = r_shares.iter().fold(vec![0u64; self.param.n], |acc, x| {
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
    use super::*;

    #[test]
    fn it_works() {
    }
}
