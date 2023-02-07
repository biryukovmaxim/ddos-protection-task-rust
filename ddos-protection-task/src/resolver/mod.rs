use crate::challenge::Resolver as Interface;
use crate::hashcash::Hashcash;
use crate::resolver::error::Error;
use std::marker::PhantomData;
use std::net::SocketAddrV4;

pub mod error;

pub struct Resolver<D: digest::Digest> {
    difficulty: u32,
    digest: PhantomData<D>,
}

impl<D: digest::Digest> Resolver<D> {
    pub fn new(difficulty: u32) -> Self {
        Self {
            difficulty,
            digest: PhantomData,
        }
    }
}

impl<D: digest::Digest> Interface for Resolver<D> {
    type Challenge = Vec<u8>;
    type UK = SocketAddrV4;
    type Error = error::Error;

    fn compute(
        &self,
        challenge: Self::Challenge,
        uniq_key: Self::UK,
    ) -> Result<([u8; 32], u64), Self::Error> {
        let address_bytes = uniq_key.ip().octets();
        let port_bytes: [u8; 2] = uniq_key.port().to_be_bytes();
        let mut data = [0; 8 + 4 + 2];
        data[0..8].copy_from_slice(challenge.as_ref());
        data[8..12].copy_from_slice(&address_bytes);
        data[12..].copy_from_slice(&port_bytes);
        let hk = Hashcash::<[u8; 14], D>::new(data);
        let (output, nonce) = hk.compute(self.difficulty).ok_or(Error::NonceNotFound)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output);

        Ok((hash, nonce))
    }
}
