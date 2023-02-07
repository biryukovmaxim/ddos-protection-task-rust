use crate::challenge::error::ParseResponseErr;
use crate::challenge::{Request, Resolver, Response};
use bytes::Bytes;
use std::marker::PhantomData;
use std::net::SocketAddrV4;

pub struct Client<T: Resolver> {
    resolver: PhantomData<T>,
}

impl<T: Resolver> Client<T> {
    pub fn new() -> Self {
        Self {
            resolver: PhantomData,
        }
    }

    pub fn challenge_request() -> Bytes {
        Request::Challenge.to_bytes()
    }

    pub fn decode_response(b: Bytes) -> Result<Response<Vec<u8>, SocketAddrV4>, ParseResponseErr> {
        return Response::try_from(b);
    }

    pub fn solution_request(hash: &[u8; 32], nonce: u64) -> Bytes {
        Request::Solution {
            hash: hash.clone(),
            nonce,
        }
        .to_bytes()
    }
}
