use crate::challenge::Engine as Interface;
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddrV4;

pub struct Engine {}
pub struct Error {}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl std::error::Error for Error {}

impl Interface for Engine {
    type Challenge = [u8; 8];
    type UK = SocketAddrV4;
    type Error = Error;

    fn create_challenge(&self, uk: &Self::UK) -> Result<[u8; 8], Self::Error> {
        todo!()
    }

    fn check_solution(
        &self,
        uk: &Self::UK,
        hash: [u8; 32],
        nonce: u64,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}
