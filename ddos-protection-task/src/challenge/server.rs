use crate::challenge::error::Error;
use crate::challenge::{Request, Response};
use bytes::Bytes;

pub trait Engine<const CHALLENGE_SIZE: usize> {
    // // https://github.com/rust-lang/rust/issues/60551
    // const CHALLENGE_SIZE: usize = 8;
    type UK;
    type Error: std::error::Error;
    fn create_challenge(&self, uk: &Self::UK) -> Result<[u8; CHALLENGE_SIZE], Self::Error>;
    fn check_solution(
        &self,
        uk: &Self::UK,
        hash: [u8; 32],
        nonce: u64,
    ) -> Result<bool, Self::Error>;
}

pub struct Processor<E> {
    engine: E,
}

impl<E: Engine<8>> Processor<E> {
    pub fn new(engine: E) -> Self {
        Self { engine }
    }
    pub fn process(
        &self,
        packet: Bytes,
        uniq_key: E::UK,
        // 8 instead of const generic because of https://github.com/rust-lang/rust/issues/60551
    ) -> Result<Response<8, E::UK>, Error<E::Error>> {
        let req = Request::try_from(packet).map_err(Error::ParseRequest)?;
        match req {
            Request::Challenge => {
                let challenge = self.engine.create_challenge(&uniq_key)?;
                Ok(Response::SendChallenge {
                    challenge,
                    uniq_key,
                })
            }
            Request::Solution { hash, nonce } => {
                let successful = self.engine.check_solution(&uniq_key, hash, nonce)?;
                Ok(Response::Confirmation(successful))
            }
        }
    }
}
