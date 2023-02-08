use crate::challenge::error::ParseResponseErr;
use crate::challenge::{Request, Response};
use bytes::Bytes;
use std::net::SocketAddrV4;

pub struct ClientHelper {}

impl ClientHelper {
    pub fn challenge_request() -> Bytes {
        Request::Challenge.to_bytes()
    }

    pub fn decode_response(b: Bytes) -> Result<Response<Vec<u8>, SocketAddrV4>, ParseResponseErr> {
        Response::try_from(b)
    }

    pub fn solution_request(hash: &[u8; 32], nonce: u64) -> Bytes {
        Request::Solution { hash: *hash, nonce }.to_bytes()
    }
}
