use aya::maps::MapError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("bpf map error")]
    MapError(#[from] MapError),
    #[error("challenge not found")]
    ChallengeNotFound,
}
