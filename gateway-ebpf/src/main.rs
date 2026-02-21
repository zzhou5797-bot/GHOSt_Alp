#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use gateway_ebpf_common::SpaPayload;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn gateway_ebpf(ctx: XdpContext) -> u32 {
    match try_gateway_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_gateway_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet Header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    if ether_type != (EtherType::Ipv4 as u16) {
        return Ok(xdp_action::XDP_PASS); // Ignore non-IPv4
    }

    // 2. Parse IPv4 Header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let ipv4_source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS), // Ignore non-UDP
    }

    let ipv4hdr_len = (unsafe { (*ipv4hdr).ihl() } as usize) * 4;

    // 3. Parse UDP Header
    let udp_offset = EthHdr::LEN + ipv4hdr_len;
    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, udp_offset)? };

    // Only intercept our Gateway port (8080)
    let dest_port = u16::from_be_bytes(unsafe { (*udphdr).dst });
    if dest_port != 8080 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_len = u16::from_be_bytes(unsafe { (*udphdr).len }) as usize;
    let payload_offset = udp_offset + UdpHdr::LEN;
    let payload_len = udp_len - UdpHdr::LEN;

    // 4. SPA Payload Bounds Checking
    if payload_len < SpaPayload::LEN {
        // Too short for SPA Payload, potentially a blind scan
        info!(&ctx, "XDP_DROP: Port 8080 blind scan or invalid length");
        return Ok(xdp_action::XDP_DROP);
    }

    let payload: *const SpaPayload = unsafe { ptr_at(&ctx, payload_offset)? };

    // 5. Magic Number Check
    let magic = u32::from_be(unsafe { (*payload).magic });
    if magic != SpaPayload::MAGIC {
        info!(&ctx, "XDP_DROP: Invalid SPA magic number");
        return Ok(xdp_action::XDP_DROP);
    }

    let version = u32::from_be(unsafe { (*payload).version });
    let timestamp_ns = u64::from_be(unsafe { (*payload).timestamp_ns });

    info!(
        &ctx,
        "SPA Knock from IPv4 {:i}, Version: {}, Time: {}", ipv4_source, version, timestamp_ns
    );

    // TODO: Verify Time Delta Map, SipHash Signature, and record CID
    // For now, if magic matches, we pass to establish QUIC connection mapping.
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
