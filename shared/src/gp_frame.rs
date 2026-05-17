//! Ghost Protocol frame codec — transport-agnostic L2/L3 definitions.
//!
//! # Protocol Overview
//!
//! The Ghost Protocol (GP) has three layers:
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │  L3 SessionFrame  — stream mux + PTY │
//! ├──────────────────────────────────────┤
//! │  L2 GhostFrame   — DID + hash-chain  │
//! ├──────────────────────────────────────┤
//! │  L1 Substrate    — any byte carrier  │
//! │     (UDP socket for tech-validation) │
//! └──────────────────────────────────────┘
//! ```
//!
//! ## L2 Wire Layout (little-endian)
//!
//! ```text
//! Offset  Size  Field
//!  0       4    Magic: b"GPF1"
//!  4       1    frame_type (FrameType)
//!  5       1    flags
//!  6       2    reserved (zero)
//!  8       4    did_src (u32)
//! 12       4    did_dst (u32)
//! 16       8    chain_seq (u64, descending)
//! 24       8    chain_tag (u64, SipHash-2-4 proof)
//! 32       2    payload_len (u16)
//! 34       N    payload
//! ```
//! Total header: 34 bytes.
//!
//! ## L3 Wire Layout (little-endian, inside L2 payload)
//!
//! ```text
//! Offset  Size  Field
//!  0       2    stream_id (u16)
//!  2       1    session_type (SessionType)
//!  3       2    payload_len (u16)
//!  5       N    payload
//! ```
//! Total header: 5 bytes.

use std::io;

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes identifying a Ghost Protocol L2 frame.
pub const GP_MAGIC: [u8; 4] = *b"GPF1";

/// Minimum serialised size of a GhostFrame (header only, no payload).
pub const GHOST_FRAME_HEADER_LEN: usize = 34;

/// Minimum serialised size of a SessionFrame (header only, no payload).
pub const SESSION_FRAME_HEADER_LEN: usize = 5;

/// Maximum payload length in a single GhostFrame (64 KiB - 1).
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

// ── L2: FrameType ─────────────────────────────────────────────────────────

/// Discriminant for the L2 Ghost Frame type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Identity knock — establishes a channel; payload is empty.
    /// The chain_seq/chain_tag fields carry the full authentication proof.
    Knock = 0x01,
    /// Carries L3 SessionFrame(s) in the payload.
    Data  = 0x02,
    /// Control plane message (quota delta, slash vote, etc.).
    Ctrl  = 0x03,
    /// Acknowledgement.
    Ack   = 0x04,
    /// Orderly close of the channel.
    Fin   = 0x05,
}

impl FrameType {
    /// Parse a raw byte into a `FrameType`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Knock),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Ctrl),
            0x04 => Some(Self::Ack),
            0x05 => Some(Self::Fin),
            _    => None,
        }
    }
}

// ── L2: GhostFrame ───────────────────────────────────────────────────────

/// An L2 Ghost Protocol frame.
///
/// Every frame is *self-authenticating*: `chain_tag` is a SipHash-2-4 proof
/// that the sender knows `H_{chain_seq}`, derived from the shared SPA seed.
/// The receiver validates this without any prior handshake or TLS session.
#[derive(Debug, Clone)]
pub struct GhostFrame {
    /// Frame type.
    pub frame_type: FrameType,
    /// Flags (currently unused; must be 0).
    pub flags: u8,
    /// Source DID.
    pub did_src: u32,
    /// Destination DID.
    pub did_dst: u32,
    /// Descending hash-chain sequence number.
    pub chain_seq: u64,
    /// SipHash-2-4 authentication tag over `H_{chain_seq}`.
    pub chain_tag: u64,
    /// Frame payload (empty for Knock/Ack/Fin).
    pub payload: Vec<u8>,
}

impl GhostFrame {
    /// Encode the frame into `buf` (appends bytes).
    pub fn encode(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        let payload_len = self.payload.len();
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("GhostFrame payload too large: {} > {}", payload_len, MAX_PAYLOAD_LEN),
            ));
        }
        buf.extend_from_slice(&GP_MAGIC);
        buf.push(self.frame_type as u8);
        buf.push(self.flags);
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&self.did_src.to_le_bytes());
        buf.extend_from_slice(&self.did_dst.to_le_bytes());
        buf.extend_from_slice(&self.chain_seq.to_le_bytes());
        buf.extend_from_slice(&self.chain_tag.to_le_bytes());
        buf.extend_from_slice(&(payload_len as u16).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Decode one frame from `buf`.
    ///
    /// Returns `Ok(None)` when there are not enough bytes yet (caller should
    /// buffer and retry when more bytes arrive).
    pub fn decode(buf: &[u8]) -> io::Result<Option<(Self, usize)>> {
        if buf.len() < GHOST_FRAME_HEADER_LEN {
            return Ok(None);
        }
        if buf[0..4] != GP_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad GP magic: {:02x?}", &buf[0..4]),
            ));
        }
        let frame_type = FrameType::from_u8(buf[4]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown frame type: {:#x}", buf[4]))
        })?;
        let flags      = buf[5];
        // buf[6..8] reserved — ignored
        let did_src    = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let did_dst    = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let chain_seq  = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let chain_tag  = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let payload_len = u16::from_le_bytes(buf[32..34].try_into().unwrap()) as usize;

        let total = GHOST_FRAME_HEADER_LEN + payload_len;
        if buf.len() < total {
            return Ok(None); // wait for more bytes
        }
        let payload = buf[GHOST_FRAME_HEADER_LEN..total].to_vec();
        Ok(Some((
            GhostFrame { frame_type, flags, did_src, did_dst, chain_seq, chain_tag, payload },
            total,
        )))
    }

    /// Convenience: build a `Knock` frame (no payload).
    pub fn knock(did_src: u32, did_dst: u32, chain_seq: u64, chain_tag: u64) -> Self {
        GhostFrame {
            frame_type: FrameType::Knock,
            flags: 0,
            did_src,
            did_dst,
            chain_seq,
            chain_tag,
            payload: vec![],
        }
    }

    /// Convenience: wrap a `SessionFrame` payload into a `Data` frame.
    pub fn data(did_src: u32, did_dst: u32, chain_seq: u64, chain_tag: u64, payload: Vec<u8>) -> Self {
        GhostFrame {
            frame_type: FrameType::Data,
            flags: 0,
            did_src,
            did_dst,
            chain_seq,
            chain_tag,
            payload,
        }
    }
}

// ── L3: SessionType ──────────────────────────────────────────────────────

/// Discriminant for the L3 session frame type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    /// Raw PTY stdin/stdout bytes.
    PtyData   = 0x01,
    /// PTY window resize: payload is `[rows_lo, rows_hi, cols_lo, cols_hi]`.
    PtyResize = 0x02,
    /// Metadata: quota delta, audit event, etc. (bincode-serialised).
    Meta      = 0x03,
    /// Orderly close of this logical stream.
    StreamFin = 0x04,
}

impl SessionType {
    /// Parse a raw byte into a `SessionType`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::PtyData),
            0x02 => Some(Self::PtyResize),
            0x03 => Some(Self::Meta),
            0x04 => Some(Self::StreamFin),
            _    => None,
        }
    }
}

// ── L3: SessionFrame ─────────────────────────────────────────────────────

/// An L3 Session frame, carried inside a `GhostFrame::Data` payload.
#[derive(Debug, Clone)]
pub struct SessionFrame {
    /// Logical stream identifier for multiplexing (e.g. stream 0 = PTY, stream 1 = meta).
    pub stream_id: u16,
    /// Session frame type.
    pub session_type: SessionType,
    /// Frame payload.
    pub payload: Vec<u8>,
}

impl SessionFrame {
    /// Encode into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        let payload_len = self.payload.len();
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("SessionFrame payload too large: {} > {}", payload_len, MAX_PAYLOAD_LEN),
            ));
        }
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.push(self.session_type as u8);
        buf.extend_from_slice(&(payload_len as u16).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Decode one session frame from `buf`.
    ///
    /// Returns `Ok(None)` when not enough bytes are available yet.
    pub fn decode(buf: &[u8]) -> io::Result<Option<(Self, usize)>> {
        if buf.len() < SESSION_FRAME_HEADER_LEN {
            return Ok(None);
        }
        let stream_id    = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let session_type = SessionType::from_u8(buf[2]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown session type: {:#x}", buf[2]))
        })?;
        let payload_len  = u16::from_le_bytes(buf[3..5].try_into().unwrap()) as usize;
        let total        = SESSION_FRAME_HEADER_LEN + payload_len;
        if buf.len() < total {
            return Ok(None);
        }
        let payload = buf[SESSION_FRAME_HEADER_LEN..total].to_vec();
        Ok(Some((SessionFrame { stream_id, session_type, payload }, total)))
    }

    /// Convenience: build a `PtyData` session frame.
    pub fn pty_data(stream_id: u16, data: Vec<u8>) -> Self {
        SessionFrame { stream_id, session_type: SessionType::PtyData, payload: data }
    }

    /// Convenience: build a `PtyResize` session frame.
    pub fn pty_resize(stream_id: u16, rows: u16, cols: u16) -> Self {
        let mut p = Vec::with_capacity(4);
        p.extend_from_slice(&rows.to_le_bytes());
        p.extend_from_slice(&cols.to_le_bytes());
        SessionFrame { stream_id, session_type: SessionType::PtyResize, payload: p }
    }
}

// ── L1: Substrate trait ──────────────────────────────────────────────────

/// Abstraction over any byte-oriented link layer.
///
/// Current implementations:
/// - `UdpSubstrate` — tech-validation over UDP sockets (uses IP/UDP, not part of GP spec)
///
/// Planned:
/// - `XdpSubstrate`    — raw AF_XDP frames, bypasses kernel IP stack
/// - `LoraSubstrate`   — serial LoRa transceiver
/// - `Ieee80211Substrate` — raw 802.11 frames (Ad-hoc / monitor mode)
pub trait Substrate: Send + Sync {
    /// Send `bytes` to the substrate-level address `dst`.
    ///
    /// For UDP: `dst` is a 6-byte IPv4+port encoding `[a,b,c,d, port_hi, port_lo]`.
    /// For raw 802.11: `dst` is a 6-byte MAC address.
    fn send(&self, dst: &[u8], bytes: &[u8]) -> io::Result<()>;

    /// Receive the next frame. Blocks until one arrives.
    /// Returns `(src_addr, frame_bytes)`.
    fn recv(&self) -> io::Result<(Vec<u8>, Vec<u8>)>;
}

// ── Tech-val: UdpSubstrate ───────────────────────────────────────────────

/// UDP-based substrate for tech-validation.
///
/// Carries Ghost Protocol L2 frames inside UDP datagrams.
/// This is the current implementation — IP/UDP is treated as a dumb byte pipe.
pub struct UdpSubstrate {
    socket: std::net::UdpSocket,
}

impl UdpSubstrate {
    /// Bind to `bind_addr` (e.g. `"0.0.0.0:9000"`).
    /// Pass `"127.0.0.1:0"` to let the OS pick a free port.
    pub fn bind(bind_addr: &str) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        Ok(UdpSubstrate { socket })
    }

    /// Return the local address this substrate is bound to.
    /// Useful for tests that need to tell another party where to send frames.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }

    /// Set the read timeout for `recv()`.  Pass `None` to block indefinitely.
    /// Used in tests to prevent hangs; not required in production daemons.
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }
}

impl Substrate for UdpSubstrate {
    fn send(&self, dst: &[u8], bytes: &[u8]) -> io::Result<()> {
        // dst encoding: [a, b, c, d, port_hi, port_lo]
        if dst.len() != 6 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP dst must be 6 bytes"));
        }
        let ip   = std::net::Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);
        let port = u16::from_be_bytes([dst[4], dst[5]]);
        let addr = std::net::SocketAddrV4::new(ip, port);
        self.socket.send_to(bytes, addr)?;
        Ok(())
    }

    fn recv(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let (n, src) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        // encode src as 6-byte [a,b,c,d, port_hi, port_lo]
        let src_bytes = match src {
            std::net::SocketAddr::V4(v4) => {
                let [a, b, c, d] = v4.ip().octets();
                let [ph, pl] = v4.port().to_be_bytes();
                vec![a, b, c, d, ph, pl]
            }
            std::net::SocketAddr::V6(_) => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 not supported by UdpSubstrate"));
            }
        };
        Ok((src_bytes, buf))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghost_frame_roundtrip_knock() {
        let frame = GhostFrame::knock(1, 2, 9999, 0xdeadbeefcafebabe);
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), GHOST_FRAME_HEADER_LEN); // no payload
        let (decoded, consumed) = GhostFrame::decode(&buf).unwrap().unwrap();
        assert_eq!(consumed, GHOST_FRAME_HEADER_LEN);
        assert_eq!(decoded.frame_type, FrameType::Knock);
        assert_eq!(decoded.did_src, 1);
        assert_eq!(decoded.did_dst, 2);
        assert_eq!(decoded.chain_seq, 9999);
        assert_eq!(decoded.chain_tag, 0xdeadbeefcafebabe);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn ghost_frame_roundtrip_data() {
        let payload = b"hello ghost protocol".to_vec();
        let frame = GhostFrame::data(42, 7, 500, 0x1234567890abcdef, payload.clone());
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), GHOST_FRAME_HEADER_LEN + payload.len());
        let (decoded, consumed) = GhostFrame::decode(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn ghost_frame_partial_returns_none() {
        let frame = GhostFrame::knock(1, 2, 100, 0);
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        // Feed only half the bytes — should return None
        let half = buf.len() / 2;
        assert!(GhostFrame::decode(&buf[..half]).unwrap().is_none());
    }

    #[test]
    fn ghost_frame_bad_magic_errors() {
        let mut buf = vec![0u8; GHOST_FRAME_HEADER_LEN];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(GhostFrame::decode(&buf).is_err());
    }

    #[test]
    fn session_frame_roundtrip_pty_data() {
        let data = b"ls -la\r\n".to_vec();
        let sf = SessionFrame::pty_data(0, data.clone());
        let mut buf = Vec::new();
        sf.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), SESSION_FRAME_HEADER_LEN + data.len());
        let (decoded, consumed) = SessionFrame::decode(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(decoded.session_type, SessionType::PtyData);
        assert_eq!(decoded.payload, data);
    }

    #[test]
    fn session_frame_roundtrip_resize() {
        let sf = SessionFrame::pty_resize(0, 24, 80);
        let mut buf = Vec::new();
        sf.encode(&mut buf).unwrap();
        let (decoded, _) = SessionFrame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded.session_type, SessionType::PtyResize);
        let rows = u16::from_le_bytes(decoded.payload[0..2].try_into().unwrap());
        let cols = u16::from_le_bytes(decoded.payload[2..4].try_into().unwrap());
        assert_eq!(rows, 24);
        assert_eq!(cols, 80);
    }

    #[test]
    fn session_frame_partial_returns_none() {
        let sf = SessionFrame::pty_data(0, b"data".to_vec());
        let mut buf = Vec::new();
        sf.encode(&mut buf).unwrap();
        assert!(SessionFrame::decode(&buf[..2]).unwrap().is_none());
    }

    #[test]
    fn udp_substrate_dst_encoding() {
        // Verify 6-byte encoding round-trips
        let ip   = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let port = 9000u16;
        let [a, b, c, d] = ip.octets();
        let [ph, pl] = port.to_be_bytes();
        let dst = vec![a, b, c, d, ph, pl];
        let decoded_port = u16::from_be_bytes([dst[4], dst[5]]);
        assert_eq!(decoded_port, 9000);
        assert_eq!(&dst[..4], &[127, 0, 0, 1]);
    }
}
