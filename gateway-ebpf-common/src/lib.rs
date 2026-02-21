#![no_std]

// 48 bytes SPA Payload layout
#[repr(C, packed)]
pub struct SpaPayload {
    pub magic: u32,          // 0x54535054 ("TSPT")
    pub version: u32,        // 0x01
    pub timestamp_ns: u64,   // Big-endian network byte order Unix Nano
    pub signature: [u8; 32], // SipHash / Blake3
}

impl SpaPayload {
    pub const MAGIC: u32 = 0x54535054;
    pub const VERSION: u32 = 0x01;
    pub const LEN: usize = core::mem::size_of::<SpaPayload>();
}
