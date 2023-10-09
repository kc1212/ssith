use crate::errors::InternalError;
use crate::{Param, ProverMsg, VerifierMsg};
use crossbeam::channel::{Receiver, Sender};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

pub struct Verifier {
    param: Param,
}

impl Verifier {
    pub fn new(param: Param) -> Self {
        Self { param }
    }

    pub fn step1<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Vec<usize> {
        // chalJ pick tau indices from [M], without rep
        let chalJ: Vec<_> = {
            let mut tmp: Vec<_> = (0usize..self.param.cnc_param).collect();
            tmp.shuffle(rng);
            tmp.into_iter().take(self.param.rep_param).collect()
        };
        chalJ
    }

    pub fn step2<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Vec<usize> {
        // chalL pick tau values from [N], with rep
        let chalL: Vec<_> = (0..self.param.rep_param)
            .map(|_| rng.gen::<usize>() % self.param.party_count)
            .collect();
        chalL
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

    pub fn blocking_run<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<bool, InternalError> {
        // first wait for the prover to send h
        let h = match self.rx.recv()? {
            ProverMsg::Step1(h) => h,
            _ => return Err(InternalError::ProtocolError),
        };
        self.tx.send(VerifierMsg::Step1(self.verifier.step1(rng)))?;

        // wait for second message
        let (h_prime, mseeds) = match self.rx.recv()? {
            ProverMsg::Step2(inner) => inner,
            _ => return Err(InternalError::ProtocolError),
        };
        self.tx.send(VerifierMsg::Step2(self.verifier.step2(rng)))?;

        // TODO unimplemented
        Ok(self.verifier.verify())
    }
}
