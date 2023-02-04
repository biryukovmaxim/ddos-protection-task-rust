#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::LruHashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use core::str::FromStr;
use ddos_protection_task_common::SocketV4;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

static PORT: &'static str = env!("PORT");

#[map(name = "WHITELIST")]
static mut WHITELIST: LruHashMap<SocketV4, u32> = LruHashMap::with_max_entries(1024, 0);

#[xdp(name = "ddos_protection_task")]
pub fn ddos_protection_task(ctx: XdpContext) -> u32 {
    match try_ddos_protection_task(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn block_ip(address: SocketV4) -> bool {
    unsafe { WHITELIST.get(&address).is_none() }
}

fn try_ddos_protection_task(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // skip non ipv4 packets
    let EtherType::Ipv4 = (unsafe { (*ethhdr).ether_type }) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let IpProto::Tcp = (unsafe { (*ipv4hdr).proto }) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*tcphdr).syn() } == 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
    if dst_port != u16::from_str(PORT).unwrap() {
        return Ok(xdp_action::XDP_PASS);
    }
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let source_port = u16::from_be(unsafe { (*tcphdr).source });
    let source = SocketV4::new(source_addr, source_port);

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    info!(
        &ctx,
        "syn from: {:ipv4}:{}, ACTION: {}", source.address, source.port, action
    );

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
