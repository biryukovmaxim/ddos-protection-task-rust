use crate::challenge::error::{ParseRequestErr, ParseResponseErr};
use bytes::{Buf, Bytes};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};

pub mod error;
pub mod helper;
pub mod server;

#[derive(Debug, Clone, Copy)]
enum RequestType {
    RequestChallenge = 0,
    Solution = 2,
}

impl From<&Request> for RequestType {
    fn from(value: &Request) -> Self {
        match value {
            Request::Challenge => Self::RequestChallenge,
            Request::Solution { .. } => Self::Solution,
        }
    }
}

impl TryFrom<u8> for RequestType {
    type Error = ParseRequestErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RequestType::RequestChallenge),
            2 => Ok(RequestType::Solution),
            _ => Err(ParseRequestErr::UnknownRequestType(value)),
        }
    }
}

pub enum Request {
    Challenge,
    Solution { hash: [u8; 32], nonce: u64 },
}

impl Request {
    pub fn to_bytes(&self) -> Bytes {
        let rt_byte = RequestType::from(self) as u8;
        match self {
            Request::Challenge => Bytes::copy_from_slice(&[rt_byte]),
            Request::Solution { hash, nonce } => {
                let mut data = [0; 41];
                data[0] = rt_byte;
                data[1..33].copy_from_slice(hash);
                data[33..41].copy_from_slice(&nonce.to_be_bytes());

                Bytes::copy_from_slice(&data)
            }
        }
    }
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
    SendChallenge = 1,
    Confirmation = 3,
}

impl TryFrom<u8> for ResponseType {
    type Error = ParseResponseErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SendChallenge),
            3 => Ok(Self::Confirmation),
            _ => Err(ParseResponseErr::UnknownResponseType(value)),
        }
    }
}

impl<T: AsRef<[u8]>, UK> From<&Response<T, UK>> for ResponseType {
    fn from(value: &Response<T, UK>) -> Self {
        match value {
            Response::SendChallenge { .. } => Self::SendChallenge,
            Response::Confirmation(_) => Self::Confirmation,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Response<T: AsRef<[u8]>, UK> {
    SendChallenge { challenge: T, uniq_key: UK },
    Confirmation(bool),
}

impl TryFrom<Bytes> for Response<Vec<u8>, SocketAddrV4> {
    type Error = ParseResponseErr;

    fn try_from(mut value: Bytes) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(ParseResponseErr::EmptyResponse)
        } else {
            let rt = ResponseType::try_from(value.get_u8())?;
            match rt {
                ResponseType::Confirmation => Ok(Response::Confirmation(value.get_u8() > 0)),
                ResponseType::SendChallenge => {
                    let address = value.get_u32();
                    let port = value.get_u16();
                    let challenge = value.as_ref().to_vec();

                    Ok(Response::SendChallenge {
                        challenge,
                        uniq_key: SocketAddrV4::new(Ipv4Addr::from(address), port),
                    })
                }
            }
        }
    }
}

impl<T: AsRef<[u8]>> Response<T, SocketAddrV4> {
    pub fn to_bytes(self) -> Bytes {
        let rt = ResponseType::from(&self);

        match self {
            Response::SendChallenge {
                challenge,
                uniq_key,
            } => {
                let address_bytes = uniq_key.ip().octets();
                let port_bytes: [u8; 2] = uniq_key.port().to_be_bytes();
                let mut combined_array = [0; 1 + 4 + 2 + 8];
                combined_array[0] = rt as u8;
                combined_array[1..5].copy_from_slice(&address_bytes);
                combined_array[5..7].copy_from_slice(&port_bytes);
                combined_array[7..].copy_from_slice(challenge.as_ref());

                Bytes::copy_from_slice(&combined_array)
            }
            Response::Confirmation(successful) => {
                Bytes::copy_from_slice(&[rt as u8, successful as u8])
            }
        }
    }
}

pub trait Engine {
    type Challenge: AsRef<[u8]>;
    type UK;
    type Error: std::error::Error;
    fn create_challenge(&self, uk: &Self::UK) -> Result<Self::Challenge, Self::Error>;
    fn check_solution(
        &self,
        uk: &Self::UK,
        hash: [u8; 32],
        nonce: u64,
    ) -> Result<bool, Self::Error>;
}

pub trait Resolver {
    type Challenge: AsRef<[u8]>;
    type UK;
    type Error: std::error::Error;
    fn compute(
        &self,
        challenge: Self::Challenge,
        uk: Self::UK,
    ) -> Result<([u8; 32], u64), Self::Error>;
}
