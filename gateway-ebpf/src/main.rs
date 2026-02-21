#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use core::mem;
use gateway_ebpf_common::SpaPayload;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static TIME_DELTA_MAP: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static REPLAY_FILTER_MAP: LruHashMap<[u8; 8], u64> = LruHashMap::with_max_entries(1024, 0);

#[map]
static ALLOW_LIST_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[inline(always)]
fn rotate_left(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

#[inline(always)]
fn siphash24_compress(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotate_left(*v0, 32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotate_left(*v2, 32);
}

// Minimal SipHash-2-4 tailored for exactly 16 bytes of message (Magic + Version + Timestamp)
// and an 8-byte output, designed for strict BPF verifier compliance and zero allocation.
// The message is composed of 2 u64 words: [magic_version, timestamp].
#[inline(always)]
pub fn siphash24_16b(k0: u64, k1: u64, m0: u64, m1: u64) -> [u8; 8] {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let b = (16 as u64) << 56;

    v3 ^= m0;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    v3 ^= m1;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    v3 ^= b;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);

    let h = v0 ^ v1 ^ v2 ^ v3;
    h.to_le_bytes()
}

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

    let bpf_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Check if IP is currently authorized (QUIC traffic)
    if let Some(expiry) = unsafe { ALLOW_LIST_MAP.get(&ipv4_source) } {
        if bpf_time < *expiry {
            // Already authorized, pass the packet up the network stack
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let udp_len = u16::from_be_bytes(unsafe { (*udphdr).len }) as usize;
    let payload_offset = udp_offset + UdpHdr::LEN;
    let payload_len = udp_len - UdpHdr::LEN;

    if payload_len < SpaPayload::LEN {
        // Too short for SPA Payload, potentially a blind scan
        // info!(&ctx, "XDP_DROP: Port 8080 blind scan or invalid length");
        return Ok(xdp_action::XDP_DROP);
    }

    let payload: *const SpaPayload = unsafe { ptr_at(&ctx, payload_offset)? };

    // 5. Magic Number Check
    let magic = u32::from_be(unsafe { (*payload).magic });
    if magic != SpaPayload::MAGIC {
        // info!(&ctx, "XDP_DROP: Invalid SPA magic number");
        return Ok(xdp_action::XDP_DROP);
    }

    let version = u32::from_be(unsafe { (*payload).version });
    let timestamp_ns = u64::from_be(unsafe { (*payload).timestamp_ns });

    // info!(&ctx, "SPA Knock from IPv4 {}, Version: {}, Time: {}", ipv4_source, version, timestamp_ns);

    // 6. Time Delta Verification
    // Retrieve the Time Delta (Host Boot Time difference)
    let time_delta = TIME_DELTA_MAP.get(0);
    let host_time_ns = match time_delta {
        Some(dt) => match unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() }.checked_add(*dt) {
            Some(t) => t,
            None => {
                // info!(&ctx, "XDP_DROP: Time Delta overflow");
                return Ok(xdp_action::XDP_DROP);
            }
        },
        None => {
            // info!(&ctx, "XDP_DROP: Time Delta Map not initialized");
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // Tolerate +/- 5 seconds of clock skew/latency (5_000_000_000 ns)
    let skew: u64 = 5_000_000_000;

    // Careful with subtraction overflow if timestamp_ns is smaller than host_time_ns
    let diff = if timestamp_ns > host_time_ns {
        timestamp_ns - host_time_ns
    } else {
        host_time_ns - timestamp_ns
    };

    if diff > skew {
        // info!(&ctx, "XDP_DROP: Timestamp out of valid window (skew: {} ns)", diff);
        return Ok(xdp_action::XDP_DROP);
    }

    // 7. SipHash-2-4 Signature Verification
    let secret_k0: u64 = 0x04030201efbeadde;
    let secret_k1: u64 = 0x0d0c0b0affe0dcba;

    // Message (m0, m1) consists of Magic + Version and Timestamp
    let m0 = ((magic as u64) << 32) | (version as u64);
    let m1 = timestamp_ns;

    let computed_sig = siphash24_16b(secret_k0, secret_k1, m0, m1);
    let packet_sig = unsafe { (*payload).signature };

    // Constant-time-like comparison for 8 bytes (since it's SipHash-2-4)
    let mut sig_match = true;
    for i in 0..8 {
        if computed_sig[i] != packet_sig[i] {
            sig_match = false;
        }
    }

    if !sig_match {
        // info!(&ctx, "XDP_DROP: SipHash Signature mismatch");
        return Ok(xdp_action::XDP_DROP);
    }

    // 8. Replay Filter Check
    // Create an 8 byte array representation from siphash output for key
    if unsafe { REPLAY_FILTER_MAP.get(&computed_sig).is_some() } {
        // info!(&ctx, "XDP_DROP: Replay Attack Detected (Signature already seen)");
        return Ok(xdp_action::XDP_DROP);
    }

    // Mark Signature as seen (value is just current time)
    let _ = REPLAY_FILTER_MAP.insert(&computed_sig, &host_time_ns, 0);

    // 9. Allow List Insertion
    // Open a 3-second window for this IP to establish QUIC connection (using monotonic time)
    let expiry_time = bpf_time + 3_000_000_000;
    let _ = ALLOW_LIST_MAP.insert(&ipv4_source, &expiry_time, 0);

    Ok(xdp_action::XDP_DROP) // Still drop the knock packet itself silently
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
