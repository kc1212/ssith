use crate::errors::InternalError;
use crate::{Param, ProverMsg, VerifierMsg};
use crossbeam::channel::{Receiver, Sender};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

pub struct Verifier {
    param: Param,
    chalJ: Vec<usize>,
    chalL: Vec<usize>,
}

impl Verifier {
    pub fn new<R: CryptoRng + RngCore>(param: Param, rng: &mut R) -> Self {
        // chalJ pick tau indices from [M], without rep
        let chalJ: Vec<_> = {
            let mut tmp: Vec<_> = (0usize..param.cnc_param).collect();
            tmp.shuffle(rng);
            tmp.into_iter().take(param.rep_param).collect()
        };

        // chalL pick tau values from [N], with rep
        let chalL: Vec<_> = (0..param.rep_param)
            .map(|_| rng.gen::<usize>() % param.party_count)
            .collect();

        Self {
            param,
            chalJ,
            chalL,
        }
    }

    pub fn verify(&self) -> bool {
        // TODO unimplemented
        true
    }
}

pub struct IVerifier {
    verifier: Verifier,
    tx: Sender<VerifierMsg>,
    rx: Receiver<ProverMsg>,
}

impl IVerifier {
    pub fn new(verifier: Verifier, tx: Sender<VerifierMsg>, rx: Receiver<ProverMsg>) -> Self {
        Self { verifier, tx, rx }
    }

    pub fn blocking_run(&mut self) -> Result<bool, InternalError> {
        // first wait for the prover to send h
        let h = match self.rx.recv()? {
            ProverMsg::Step1(h) => h,
            _ => return Err(InternalError::ProtocolError),
        };
        self.tx
            .send(VerifierMsg::Step1(self.verifier.chalJ.clone()))?;

        // wait for second message
        let (h_prime, mseeds) = match self.rx.recv()? {
            ProverMsg::Step2(inner) => inner,
            _ => return Err(InternalError::ProtocolError),
        };

        // TODO unimplemented
        Ok(self.verifier.verify())
    }
}
