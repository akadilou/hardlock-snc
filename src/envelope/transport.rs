use crate::envelope::PadProfile;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportHeader {
    pub ts_unix_s: u64,
    pub token_len: u32,
    pub profile: PadProfile,
}

fn profile_to_u8(p: PadProfile) -> u8 {
    match p {
        PadProfile::Stealth => 0,
        PadProfile::Balanced => 1,
        PadProfile::Throughput => 2,
    }
}
fn u8_to_profile(x: u8) -> PadProfile {
    match x {
        0 => PadProfile::Stealth,
        1 => PadProfile::Balanced,
        _ => PadProfile::Throughput,
    }
}

pub fn encode_transport_header(h: &TransportHeader, token: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 4 + 1 + token.len());
    out.extend_from_slice(&h.ts_unix_s.to_le_bytes());
    out.extend_from_slice(&h.token_len.to_le_bytes());
    out.push(profile_to_u8(h.profile));
    out.extend_from_slice(token);
    out
}

pub fn decode_transport_header(b: &[u8]) -> Option<(TransportHeader, Vec<u8>)> {
    if b.len() < 8 + 4 + 1 { return None; }
    let mut tsb = [0u8;8]; tsb.copy_from_slice(&b[0..8]);
    let ts = u64::from_le_bytes(tsb);
    let mut tlb = [0u8;4]; tlb.copy_from_slice(&b[8..12]);
    let tlen = u32::from_le_bytes(tlb) as usize;
    let prof = u8_to_profile(b[12]);
    if b.len() < 13 + tlen { return None; }
    let tok = b[13..13+tlen].to_vec();
    Some((TransportHeader{ ts_unix_s: ts, token_len: tlen as u32, profile: prof }, tok))
}
