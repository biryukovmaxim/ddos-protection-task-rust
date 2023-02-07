use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("specified nonce not found")]
    NonceNotFound,
}
