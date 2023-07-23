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
}
