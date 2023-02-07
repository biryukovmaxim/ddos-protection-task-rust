use anyhow::Context;
use aya::maps::MapRefMut;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use bytes::Bytes;
use ddos_protection_task::{challenge::server::Processor, engine::Engine};
use ddos_protection_task_common::SocketV4;
use log::{debug, error, info, warn};
use std::{
    net::SocketAddr::V4,
    sync::{Arc, Mutex},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    signal::unix::{signal, SignalKind},
};

const IFACE: Option<&'static str> = option_env!("IFACE");
const TCP_ADDR: Option<&'static str> = option_env!("TCP_ADDR");
const UDP_ADDR: Option<&'static str> = option_env!("UDP_ADDR");
const DIFFICULTY: Option<&'static str> = option_env!("DIFFICULTY");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/ddos-protection-task"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/ddos-protection-task"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf
        .program_mut("ddos_protection_task")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(IFACE.unwrap_or("lo"), XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let tcp_whitelist: Arc<Mutex<HashMap<MapRefMut, SocketV4, u32>>> =
        Arc::new(Mutex::new(HashMap::try_from(bpf.map_mut("WHITELIST")?)?));
    let engine_whitelist = Arc::clone(&tcp_whitelist);

    let tcp_listen_addr = TCP_ADDR.unwrap_or("127.0.0.1:5051");
    let udp_listen_addr = UDP_ADDR.unwrap_or("127.0.0.1:1053");
    let engine = Engine::<sha2::Sha256>::new(
        DIFFICULTY.unwrap_or("22").parse().unwrap_or(22),
        engine_whitelist,
    );
    let mut challenge_processor = Processor::new(engine);

    // TCP listener
    let tcp_listener = TcpListener::bind(tcp_listen_addr).await?;
    tokio::spawn(async move {
        info!("TCP server start listening on {}", tcp_listen_addr);

        while let Ok((mut socket, socket_addr)) = tcp_listener.accept().await {
            debug!("Accepted connection from {:?}", socket_addr);
            if let Err(e) = socket.write_all(b"Hello World\n").await {
                warn!("writing err: {:?}", e);
            }
            let V4(socket)= socket_addr  else {
                continue
            };
            if let Err(e) = tcp_whitelist.lock().unwrap().remove(&SocketV4::new(
                u32::from_be_bytes(socket.ip().octets()),
                socket.port(),
            )) {
                error!("remove key error: {:?}", e);
                continue;
            }
            debug!("removing key from whitelist {:?}", socket);
        }
    });

    // UDP listener
    let udp_socket = UdpSocket::bind(udp_listen_addr).await?;
    tokio::spawn(async move {
        info!("UDP server start listening on {}", udp_listen_addr);
        let mut buf = [0; 41];

        while let Ok((recv, peer)) = udp_socket.recv_from(&mut buf).await {
            let bytes = Bytes::copy_from_slice(&buf[..recv]);
            debug!("Received {} bytes from {:?}", recv, peer);
            let V4(peer) = peer else {
                continue;
            };
            let resp = match challenge_processor.process(bytes, peer) {
                Ok(r) => r,
                Err(err) => {
                    warn!("processing err: {err}");
                    continue;
                }
            };
            udp_socket.send_to(&resp.to_bytes(), &peer).await.unwrap();
        }
    });

    // Handle SIGTERM signal
    let mut signals = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    let handle_sigterm = async move {
        signals.recv().await;
        info!("Received SIGTERM signal, shutting down...");
    };
    let handle_sigterm = tokio::spawn(handle_sigterm);
    handle_sigterm.await.unwrap();

    Ok(())
}
