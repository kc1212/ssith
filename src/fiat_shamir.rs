use std::thread;

use crossbeam::channel::unbounded;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::{
    consts::*,
    errors::InternalError,
    primitives::{fs_hash1, fs_hash2},
    prover::{IProver, Prover},
    verifier::Verifier,
    Param, ProverMsg, VerifierMsg,
};

pub struct NIProver {
    prover: Prover,
}

pub struct NIProverMsg {
    step1: [u8; DIGEST_SIZE],
    step2: ([u8; DIGEST_SIZE], Vec<[u8; BLOCK_SIZE]>),
}

impl NIProver {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R, param: Param) -> Self {
        Self {
            prover: Prover::new(rng, param),
        }
    }

    // Note that the rng is implicit in `prover`
    pub fn prove(self) -> Result<NIProverMsg, InternalError> {
        let (tx_p, rx_p) = unbounded();
        let (tx_v, rx_v) = unbounded();

        let param = self.prover.get_param();
        let verifier = Verifier::new(param);
        let mut iprover = IProver::from_prover(self.prover, tx_p, rx_v);

        let handler = thread::spawn(move || iprover.blocking_run());

        // wait prover for its message h
        let h = match rx_p.recv()? {
            ProverMsg::Step1(h) => h,
            _ => return Err(InternalError::ProtocolError),
        };

        // hash h, and use it to generate J
        let fs_seed1 = fs_hash1(&h);
        let mut rng1 = ChaChaRng::from_seed(fs_seed1);
        tx_v.send(VerifierMsg::Step1(verifier.step1(&mut rng1)))?;

        // wait for prover for its second message
        let (h_prime, mseeds) = match rx_p.recv()? {
            ProverMsg::Step2(inner) => inner,
            _ => return Err(InternalError::ProtocolError),
        };

        // hash the second message as seed for the second challenge L
        let fs_seed2 = fs_hash2(&h_prime, &mseeds);
        let mut rng2 = ChaChaRng::from_seed(fs_seed2);
        tx_v.send(VerifierMsg::Step2(verifier.step2(&mut rng2)))?;

        // TODO not sure how to handle this error in thiserror
        handler.join().unwrap()?;

        // put together the messages
        Ok(NIProverMsg {
            step1: h,
            step2: (h_prime, mseeds),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_fs() {
        let mut rng = ChaChaRng::from_entropy();
        let param = Param::default();
        let niprover = NIProver::new(&mut rng, param);
        let proof = niprover.prove().unwrap();

        // TODO verify the proof
        let _ = proof;
    }
}
