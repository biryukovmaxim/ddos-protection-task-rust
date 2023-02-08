use log::{debug, info, warn};

use anyhow::anyhow;
use bytes::Bytes;
use ddos_protection_task::challenge::helper::ClientHelper;
use ddos_protection_task::challenge::{Resolver, Response};
use ddos_protection_task::resolver::Resolver as ResolverImpl;
use sha2::Sha256;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, UdpSocket};

const TCP_ADDR: Option<&'static str> = option_env!("TCP_ADDR");
const UDP_ADDR: Option<&'static str> = option_env!("UDP_ADDR");
const DIFFICULTY: Option<&'static str> = option_env!("DIFFICULTY");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let from = udp_handshake().await?;
    debug!("confirmation received");
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from(from))?;
    debug!("binding local address: {from}");
    let remote = TCP_ADDR.unwrap_or("127.0.0.1:5051").parse()?;
    let mut stream = socket.connect(remote).await?;
    debug!("connect to remote: {remote}");
    let mut data = [0u8; 1024];
    let size = stream.read(&mut data).await?;
    info!("received: {}", String::from_utf8_lossy(&data[..size]));

    Ok(())
}

pub async fn udp_handshake() -> Result<SocketAddrV4, anyhow::Error> {
    let resolver = ResolverImpl::<Sha256>::new(DIFFICULTY.unwrap_or("19").parse().unwrap_or(19));

    let udp_challenge_addr = SocketAddr::from_str(UDP_ADDR.unwrap_or("127.0.0.1:1053"))?;

    // We use port 0 to let the operating system allocate an available port for us.
    let local_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(local_addr).await?;
    socket.connect(&udp_challenge_addr).await?;

    // send challenge request
    socket
        .send(ClientHelper::challenge_request().as_ref())
        .await?;
    debug!("send challenge request");

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
    let (challenge, uniq_key) = match ClientHelper::decode_response(Bytes::copy_from_slice(&resp))?
    {
        Response::Confirmation(_) => return Err(anyhow!("unexpected response")),
        Response::SendChallenge {
            challenge,
            uniq_key,
        } => (challenge, uniq_key),
    };
    debug!("receive challenge: {challenge:?}, uniq_key: {uniq_key:?}");
    // calculate solution
    let (hash, nonce) = resolver.compute(challenge, uniq_key)?;
    //send solution
    socket
        .send(ClientHelper::solution_request(&hash, nonce).as_ref())
        .await?;
    debug!("send solution, hash: {hash:?}, nonce: {nonce}");
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
