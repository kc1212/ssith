use crossbeam::channel;
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum InternalError {
    #[error("bad witness or instance")]
    BadWitnessOrInstance,
    #[error("bad witness length")]
    BadWitnessLength,
    #[error("bad instance length")]
    BadInstanceLength,
    #[error("bad abort param, must be less than 64")]
    BadAbortParam,
    #[error("bad challenge length")]
    BadChallengeLength,
    #[error("protocol error, unexpected message")]
    ProtocolError,
    #[error(transparent)]
    RecvError(#[from] channel::RecvError),
    #[error(transparent)]
    SendErrorProverMsg(#[from] channel::SendError<crate::ProverMsg>),
    #[error(transparent)]
    SendErrorVerifierMsg(#[from] channel::SendError<crate::VerifierMsg>),
}
