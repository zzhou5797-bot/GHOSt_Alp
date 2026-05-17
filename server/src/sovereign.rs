// No documentation.

#[repr(C)]
pub struct SovereignResult {
    pub action_id: u32,
    pub u32_param: u32,
    pub bytes_param: [u8; 32],
    pub str_len: u32,
    pub str_param: [u8; 64],
}

#[link(name = "gp_sovereign", kind = "static")]
extern "C" {
    fn gp_probe(buf: *const u8, len: usize, ts_ns: u64) -> i32;
    fn gp_seal(buf: *const u8, len: usize, out: *mut SovereignResult) -> i32;
}

const A1: u32 = 0x01;
const A2: u32 = 0x02;
const A3: u32 = 0x03;
const A4: u32 = 0x04;
const A5: u32 = 0x05;
const A6: u32 = 0x06;
const A7: u32 = 0x07;

pub fn apply(data: &[u8], vs: &mut crate::genesis::ValidatorSet) -> bool {
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    if unsafe { gp_probe(data.as_ptr(), data.len(), ts_ns) } != 0 {
        return false;
    }

    let mut r = SovereignResult {
        action_id: 0,
        u32_param: 0,
        bytes_param: [0u8; 32],
        str_len: 0,
        str_param: [0u8; 64],
    };

    if unsafe { gp_seal(data.as_ptr(), data.len(), &mut r) } != 0 {
        return false;
    }

    dispatch(&r, vs);
    true
}

fn dispatch(r: &SovereignResult, vs: &mut crate::genesis::ValidatorSet) {
    match r.action_id {
        A1 => vs.paused = true,
        A2 => vs.paused = false,
        A3 => vs.bft_threshold = r.u32_param as usize,
        A4 => {
            if !vs.genesis_keys.contains(&r.bytes_param) {
                vs.genesis_keys.push(r.bytes_param);
            }
        }
        A5 => vs.genesis_keys.retain(|k| k != &r.bytes_param),
        A6 => { vs.slash_keys.insert(r.u32_param, r.bytes_param); }
        A7 => { vs.slash_keys.remove(&r.u32_param); }
        _ => {}
    }
}
