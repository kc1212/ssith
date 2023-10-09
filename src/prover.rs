use crate::primitives::*;
use crate::*;
use crossbeam::channel::{Receiver, Sender};
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;

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

    pub fn step2(
        &self,
        state: &ProverState,
        chalJ: &Vec<usize>,
    ) -> Result<([u8; DIGEST_SIZE], Vec<[u8; BLOCK_SIZE]>), InternalError> {
        // check length of chalJ
        if chalJ.len() != self.param.rep_param {
            return Err(InternalError::BadChallengeLength);
        }

        // TODO check that J \subset [M]

        let h_primes = chalJ.iter().map(|e| {
            let xs_tilde: Vec<_> = self
                .witness
                .0
                .iter()
                .zip(state.step1_state[*e].rs.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            let t_shares = state.step1_state[*e].r_shares.iter().map(|r_share| {
                // x_share is [x], per c&c and per party i
                let x_share = xs_tilde.iter().zip(r_share).map(|(x_tilde, r_share)| {
                    u64::from(1u8 - x_tilde) * r_share
                        + u64::from(*x_tilde) * (1u64.wrapping_sub(*r_share))
                });
                let t_share: u64 = self
                    .instance
                    .weights
                    .iter()
                    .zip(x_share)
                    .map(|(w, x)| *w * x)
                    .sum();
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
        let mseeds: Vec<_> = chalJ
            .iter()
            .map(|e| {
                // TODO: this is wrong, need e \notin J
                state.step1_state[*e].mseed_inner
            })
            .collect();
        Ok((h_prime, mseeds))
    }

    pub fn step3(&self, state: &ProverState, ells: &[usize]) {
        // not implemented yet
    }
}

// interactive prover
pub struct IProver {
    prover: Prover,
    tx: Sender<ProverMsg>,
    rx: Receiver<VerifierMsg>,
}

impl IProver {
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        param: Param,
        tx: Sender<ProverMsg>,
        rx: Receiver<VerifierMsg>,
    ) -> Self {
        Self {
            prover: Prover::new(rng, param),
            tx,
            rx,
        }
    }

    pub fn from_prover(prover: Prover, tx: Sender<ProverMsg>, rx: Receiver<VerifierMsg>) -> Self {
        Self { prover, tx, rx }
    }

    pub fn blocking_run(&mut self) -> Result<(), InternalError> {
        let state = self.prover.step1();
        self.tx.send(ProverMsg::Step1(state.h))?;

        // receive the first challenge J
        let chalJ = match self.rx.recv()? {
            VerifierMsg::Step1(chalJ) => chalJ,
            _ => return Err(InternalError::ProtocolError),
        };

        let (h_prime, mseeds) = self.prover.step2(&state, &chalJ)?;
        self.tx.send(ProverMsg::Step2((h_prime, mseeds)))?;

        // receive the second challenge L
        let chalL = match self.rx.recv()? {
            VerifierMsg::Step2(chalL) => chalL,
            _ => return Err(InternalError::ProtocolError),
        };

        self.prover.step3(&state, &chalL);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crossbeam::channel::unbounded;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::thread;

    #[test]
    fn test_iprover_wrong_chal1() {
        let mut rng = ChaChaRng::from_entropy();
        let param = Param::default();
        let (tx_p, rx_p) = unbounded();
        let (tx_v, rx_v) = unbounded();
        let mut iprover = IProver::new(&mut rng, param, tx_p, rx_v);

        // run the prover in a thread
        let handle = thread::spawn(move || iprover.blocking_run());

        // we should receive something from the prover automatically
        let _ = rx_p.recv().unwrap();

        // then sending the wrong verification message should fail
        tx_v.send(VerifierMsg::Step2(vec![])).unwrap();

        // the error should be ProtocolError
        let res = handle.join().unwrap();
        assert_eq!(res, Err(InternalError::ProtocolError));
    }
}
