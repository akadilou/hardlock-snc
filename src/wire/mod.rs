#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc, clippy::doc_markdown)]
use crate::ratchet::state::Header;

pub mod handshake;

pub const HEADER_LEN: usize = 32 + 4 + 4;

#[must_use]
pub fn header_to_bytes(h: &Header) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[0..32].copy_from_slice(&h.dh_pub);
    b[32..36].copy_from_slice(&h.pn.to_le_bytes());
    b[36..40].copy_from_slice(&h.n.to_le_bytes());
    b
}

/// # Errors
/// Erreur si trame trop courte.
///
/// # Panics
/// Panique si conversions internes échouent (données corrompues).
pub fn header_from_bytes(b: &[u8]) -> anyhow::Result<Header> {
    if b.len() < HEADER_LEN { anyhow::bail!("short header"); }
    let mut dh = [0u8;32]; dh.copy_from_slice(&b[0..32]);
    let pn = u32::from_le_bytes(b[32..36].try_into().unwrap());
    let n  = u32::from_le_bytes(b[36..40].try_into().unwrap());
    Ok(Header{ dh_pub: dh, pn, n })
}

#[must_use]
pub fn pack_message(ver: u16, header: &Header, nonce: &[u8;24], ct: &[u8], pad_to: usize) -> Vec<u8> {
    let hb = header_to_bytes(header);
    let mut out = Vec::with_capacity(2 + hb.len() + 24 + 4 + ct.len() + 4);
    out.extend_from_slice(&ver.to_le_bytes());
    out.extend_from_slice(&hb);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&u32::try_from(ct.len()).expect("ct len fits u32").to_le_bytes());
    out.extend_from_slice(ct);
    let cur = out.len() + 4;
    let pad_len = if pad_to == 0 { 0 } else { (pad_to - (cur % pad_to)) % pad_to };
    out.extend_from_slice(&u32::try_from(pad_len).expect("pad len fits u32").to_le_bytes());
    if pad_len > 0 {
        let zeros = vec![0u8; pad_len];
        out.extend_from_slice(&zeros);
    }
    out
}

/// # Errors
/// Erreur si trame trop courte ou tronquée.
///
/// # Panics
/// Panique si conversions internes échouent (données corrompues).
pub fn unpack_message(b: &[u8]) -> anyhow::Result<(u16, Header, [u8;24], Vec<u8>)> {
    if b.len() < 2 + HEADER_LEN + 24 + 4 { anyhow::bail!("short frame"); }
    let ver = u16::from_le_bytes(b[0..2].try_into().unwrap());
    let hdr = header_from_bytes(&b[2..2+HEADER_LEN])?;
    let mut nonce = [0u8;24]; nonce.copy_from_slice(&b[2+HEADER_LEN..2+HEADER_LEN+24]);
    let ct_len = u32::from_le_bytes(b[2+HEADER_LEN+24..2+HEADER_LEN+24+4].try_into().unwrap()) as usize;
    let start = 2+HEADER_LEN+24+4;
    if b.len() < start + ct_len + 4 { anyhow::bail!("truncated ct"); }
    let ct = b[start..start+ct_len].to_vec();
    let pad_len = u32::from_le_bytes(b[start+ct_len..start+ct_len+4].try_into().unwrap()) as usize;
    let end = start+ct_len+4+pad_len;
    if b.len() < end { anyhow::bail!("truncated pad"); }
    Ok((ver, hdr, nonce, ct))
}
