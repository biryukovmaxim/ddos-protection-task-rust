use crate::challenge::error::ParseRequestErr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{Read, Write};
use std::net::SocketAddrV4;

pub mod error;
pub mod server;

#[derive(Debug, Clone, Copy)]
enum RequestType {
    RequestChallenge,
    Solution,
}

impl TryFrom<u8> for RequestType {
    type Error = ParseRequestErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(RequestType::RequestChallenge),
            0x02 => Ok(RequestType::Solution),
            _ => Err(ParseRequestErr::UnknownRequestType(value)),
        }
    }
}

pub enum Request {
    Challenge,
    Solution { hash: [u8; 32], nonce: u64 },
}

impl TryFrom<Bytes> for Request {
    type Error = ParseRequestErr;

    fn try_from(mut value: Bytes) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(ParseRequestErr::EmptyRequest)
        } else {
            let rt = RequestType::try_from(value.get_u8())?;
            match rt {
                RequestType::RequestChallenge => Ok(Request::Challenge),
                RequestType::Solution => {
                    if value.len() < 40 {
                        Err(ParseRequestErr::BadRequest)
                    } else {
                        let mut hash = [0u8; 32];
                        value
                            .split_to(32)
                            .reader()
                            .read_exact(&mut hash)
                            .map_err(|_| ParseRequestErr::BadRequest)?;
                        let nonce = value.get_u64();
                        Ok(Request::Solution { hash, nonce })
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ResponseType {
    SendChallenge,
    Confirmation,
}

impl<UK, const CH: usize> From<&Response<CH, UK>> for ResponseType {
    fn from(value: &Response<CH, UK>) -> Self {
        match value {
            Response::SendChallenge { .. } => Self::SendChallenge,
            Response::Confirmation(_) => Self::Confirmation,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Response<const CHALLENGE_SIZE: usize, UK> {
    SendChallenge {
        challenge: [u8; CHALLENGE_SIZE],
        uniq_key: UK,
    },
    Confirmation(bool),
}

impl Response<8, SocketAddrV4> {
    pub fn to_bytes(self) -> Bytes {
        let rt = ResponseType::from(&self);

        match self {
            Response::SendChallenge {
                challenge,
                uniq_key,
            } => {
                let uniq_key_bytes = uniq_key.ip().octets();
                let port_bytes: [u8; 2] = uniq_key.port().to_be_bytes();
                let mut combined_array = [0; 1 + 4 + 2 + 8];
                combined_array[0] = rt as u8;
                combined_array[..5].copy_from_slice(&uniq_key_bytes);
                combined_array[5..7].copy_from_slice(&port_bytes);
                combined_array[7..].copy_from_slice(&challenge);

                Bytes::copy_from_slice(&combined_array)
            }
            Response::Confirmation(successful) => {
                Bytes::copy_from_slice(&[rt as u8, successful as u8])
            }
        }
    }
}
