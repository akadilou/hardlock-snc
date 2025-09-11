#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::doc_markdown
)]

pub const TYPE_INIT: u8 = 0x01;
pub const TYPE_INIT_AUTH: u8 = 0x02;

#[must_use]
pub fn encode_init(enc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + enc.len());
    out.push(TYPE_INIT);
    out.extend_from_slice(&u32::try_from(enc.len()).expect("len").to_le_bytes());
    out.extend_from_slice(enc);
    out
}
pub fn decode_init(b: &[u8]) -> anyhow::Result<Vec<u8>> {
    if b.len() < 5 {
        anyhow::bail!("short");
    }
    if b[0] != TYPE_INIT {
        anyhow::bail!("bad type");
    }
    let len = u32::from_le_bytes(b[1..5].try_into().unwrap()) as usize;
    if b.len() < 5 + len {
        anyhow::bail!("truncated");
    }
    Ok(b[5..5 + len].to_vec())
}

#[must_use]
pub fn encode_init_v2(suite: u8, enc: &[u8], binder32: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 1 + 4 + enc.len() + 32);
    out.push(TYPE_INIT);
    out.push(suite);
    out.extend_from_slice(&u32::try_from(enc.len()).expect("len").to_le_bytes());
    out.extend_from_slice(enc);
    out.extend_from_slice(binder32);
    out
}
pub fn decode_init_v2(b: &[u8]) -> anyhow::Result<(u8, Vec<u8>, [u8; 32])> {
    if b.len() < 1 + 1 + 4 + 32 {
        anyhow::bail!("short");
    }
    if b[0] != TYPE_INIT {
        anyhow::bail!("bad type");
    }
    let suite = b[1];
    let len = u32::from_le_bytes(b[2..6].try_into().unwrap()) as usize;
    if b.len() < 6 + len + 32 {
        anyhow::bail!("truncated");
    }
    let enc = b[6..6 + len].to_vec();
    let mut binder = [0u8; 32];
    binder.copy_from_slice(&b[6 + len..6 + len + 32]);
    Ok((suite, enc, binder))
}

#[must_use]
pub fn encode_init_auth(enc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + enc.len());
    out.push(TYPE_INIT_AUTH);
    out.extend_from_slice(&u32::try_from(enc.len()).expect("len").to_le_bytes());
    out.extend_from_slice(enc);
    out
}
pub fn decode_init_auth(b: &[u8]) -> anyhow::Result<Vec<u8>> {
    if b.len() < 5 {
        anyhow::bail!("short");
    }
    if b[0] != TYPE_INIT_AUTH {
        anyhow::bail!("bad type");
    }
    let len = u32::from_le_bytes(b[1..5].try_into().unwrap()) as usize;
    if b.len() < 5 + len {
        anyhow::bail!("truncated");
    }
    Ok(b[5..5 + len].to_vec())
}
