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
use rand::Rng;
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

const QUOTES: [&str; 35] = [
    "You create your own opportunities",
    "Never break your promises",
    "You are never as stuck as you think you are",
    "Happiness is a choice",
    "Habits develop into character",
    "Be happy with who you are",
    "Don’t seek happiness–create it",
    "If you want to be happy, stop complaining",
    "Asking for help is a sign of strength",
    "Replace every negative thought with a positive one",
    "Accept what is, let go of what was, have faith in what will be",
    "A mind that is stretched by a new experience can never go back to what it was",
    "If you are not willing to learn, no one can help you",
    "Be confident enough to encourage confidence in others",
    "Allow others to figure things out for themselves",
    "Confidence is essential for a successful life",
    "Admit your mistakes and don’t repeat them",
    "Be kind to yourself and forgive yourself",
    "Failures are lessons in progress",
    "Make amends with those who have wronged you",
    "Live your life on your terms",
    "When you don’t know, don’t speak as if you do",
    "Treat others the way you want to be treated",
    "Think before you speak",
    "Cultivate an attitude of gratitude",
    "Life isn’t as serious as our minds make it out to be",
    "Take risks and be bold",
    "Remember that “no” is a complete sentence",
    "Don’t feed yourself only on leftovers",
    "Build on your strengths",
    "Never doubt your instincts",
    "FEAR doesn’t have to stand for Forget Everything and Run",
    "Your attitude will influence your experience",
    "View your life with gentle hindsight",
    "This too shall pass",
];

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
        DIFFICULTY.unwrap_or("19").parse().unwrap_or(19),
        engine_whitelist,
    );
    let mut challenge_processor = Processor::new(engine);

    // TCP listener
    let tcp_listener = TcpListener::bind(tcp_listen_addr).await?;
    tokio::spawn(async move {
        info!("TCP server start listening on {}", tcp_listen_addr);

        while let Ok((mut socket, socket_addr)) = tcp_listener.accept().await {
            debug!("Accepted connection from {:?}", socket_addr);
            let idx: usize;
            {
                let mut rng = rand::thread_rng();
                idx = rng.gen_range(0..QUOTES.len());
            }
            if let Err(e) = socket.write_all(QUOTES[idx].as_ref()).await {
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
