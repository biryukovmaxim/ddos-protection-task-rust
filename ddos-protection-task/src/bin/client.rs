use log::{debug, error, info, warn};

use anyhow::anyhow;
use bytes::Bytes;
use ddos_protection_task::challenge::client::Client;
use ddos_protection_task::challenge::{Resolver, Response};
use ddos_protection_task::resolver::Resolver as ResolverImpl;
use sha2::Sha256;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use tokio::net::UdpSocket;

const TCP_ADDR: Option<&'static str> = option_env!("TCP_ADDR");
const UDP_ADDR: Option<&'static str> = option_env!("UDP_ADDR");
const DIFFICULTY: Option<&'static str> = option_env!("DIFFICULTY");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    //
    // let tcp_dest_addr = TCP_ADDR.unwrap_or("127.0.0.1:5051");
    // //
    // // socket.send(&data).await?;
    // // let mut data = vec![0u8; MAX_DATAGRAM_SIZE];
    // // let len = socket.recv(&mut data).await?;
    // println!(
    //     "Received {} bytes:\n{}",
    //     len,
    //     String::from_utf8_lossy(&data[..len])
    // );

    Ok(())
}

pub async fn udp_handshake() -> Result<SocketAddrV4, anyhow::Error> {
    let resolver = ResolverImpl::<Sha256>::new(DIFFICULTY.unwrap_or("22").parse().unwrap_or(22));

    let udp_challenge_addr = SocketAddr::from_str(UDP_ADDR.unwrap_or("127.0.0.1:1053"))?;

    // We use port 0 to let the operating system allocate an available port for us.
    let local_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(local_addr).await?;
    socket.connect(&udp_challenge_addr).await?;

    // send challenge request
    socket.send(Client::challenge_request().as_ref()).await?;

    // get response including challenge
    let mut resp = [0u8; 15];
    loop {
        match socket.recv_from(&mut resp).await {
            Err(e) => {
                warn!("receive udp err: {e}");
                continue;
            }
            Ok((_, remote)) if remote != udp_challenge_addr => continue,
            Ok((size, _)) if size != 15 => {
                return Err(anyhow!("wrong message size, expected: 15, actual: {size}"))
            }
            _ => break,
        }
    }
    let (challenge, uniq_key) = match Client::decode_response(Bytes::copy_from_slice(&resp))? {
        Response::Confirmation(_) => return Err(anyhow!("unexpected response")),
        Response::SendChallenge {
            challenge,
            uniq_key,
        } => (challenge, uniq_key),
    };

    // calculate solution
    let (hash, nonce) = resolver.compute(challenge, uniq_key)?;
    //send solution
    socket
        .send(Client::solution_request(&hash, nonce).as_ref())
        .await?;

    // get confirmation
    let mut resp = [0u8; 2];
    loop {
        match socket.recv_from(&mut resp).await {
            Err(e) => {
                warn!("receive udp err: {e}");
                continue;
            }
            Ok((_, remote)) if remote != udp_challenge_addr => continue,
            Ok((size, _)) if size != 2 => {
                return Err(anyhow!("wrong message size, expected: 2, actual: {size}"))
            }
            _ => break,
        }
    }
    match Response::try_from(Bytes::copy_from_slice(&resp))? {
        Response::SendChallenge { .. } => Err(anyhow!("unexpected response")),
        Response::Confirmation(false) => Err(anyhow!("challenge was solved wrong")),
        Response::Confirmation(true) => Ok(uniq_key),
    }
}
