use crate::challenge::error::Error;
use crate::challenge::{Engine, Request, Response};
use bytes::Bytes;
pub struct Processor<E> {
    engine: E,
}

impl<E: Engine> Processor<E> {
    pub fn new(engine: E) -> Self {
        Self { engine }
    }
    pub fn process(
        &self,
        packet: Bytes,
        uniq_key: E::UK,
    ) -> Result<Response<E::Challenge, E::UK>, Error<E::Error>> {
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
