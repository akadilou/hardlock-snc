use serde::{Serialize, Deserialize};
use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
use crate::ratchet::schedule::{kdf_rk, kdf_ck};
use std::collections::{HashMap, VecDeque};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header { pub dh_pub: [u8; 32], pub pn: u32, pub n: u32 }

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SkippedKey { pub mk: [u8;32] }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveredWindow {
    pub dh_pub: [u8;32],
    pub base: u32,
    #[serde(with = "serde_bytes")]
    pub bitmap: Vec<u8>,
}
impl DeliveredWindow {
    #[must_use]
    pub fn new(dh_pub: [u8;32]) -> Self {
        let bm = vec![0u8; 128];
        Self { dh_pub, base: 0, bitmap: bm }
    }
    fn window() -> u32 { 1024 }
    fn set_bit(&mut self, off: u32) {
        let i = (off / 8) as usize; let b = (off % 8) as u8;
        if i < self.bitmap.len() { self.bitmap[i] |= 1 << b; }
    }
    fn get_bit(&self, off: u32) -> bool {
        let i = (off / 8) as usize; let b = (off % 8) as u8;
        if i < self.bitmap.len() { (self.bitmap[i] >> b) & 1 == 1 } else { false }
    }
    #[must_use]
    pub fn was_delivered(&self, dh_pub: [u8;32], n: u32) -> bool {
        if dh_pub != self.dh_pub { return false; }
        if n < self.base { return true; }
        let off = n - self.base;
        if off >= Self::window() { return false; }
        self.get_bit(off)
    }
    pub fn mark(&mut self, dh_pub: [u8;32], n: u32) {
        if dh_pub != self.dh_pub {
            self.dh_pub = dh_pub; self.base = 0;
            for x in &mut self.bitmap { *x = 0; }
        }
        if n < self.base { return; }
        let mut off = n - self.base;
        if off >= Self::window() {
            self.base = n - Self::window() + 1;
            for x in &mut self.bitmap { *x = 0; }
            off = n - self.base;
        }
        self.set_bit(off);
    }
}

#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_s_priv: [u8;32], pub dh_s_pub: [u8;32], pub dh_r_pub: [u8;32],
    pub rk: [u8;32], pub ck_s: [u8;32], pub ck_r: [u8;32],
    pub ns: u32, pub nr: u32, pub pn: u32,
    #[serde(with = "serde_bytes")] pub skipped_index: Vec<u8>,
    #[serde(skip)] pub skipped: HashMap<([u8;32], u32), [u8;32]>,
    #[serde(skip)] pub skipped_order: VecDeque<([u8;32], u32)>,
    pub delivered_win: DeliveredWindow,
}
impl core::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetState")
            .field("ns",&self.ns).field("nr",&self.nr).field("pn",&self.pn)
            .finish_non_exhaustive()
    }
}

impl RatchetState {
    #[must_use]
    pub fn init_initiator(root_key: [u8;32], dh_s_priv: [u8;32], dh_r_pub: [u8;32]) -> Self {
        let dh_s = StaticSecret::from(dh_s_priv);
        let dh_s_public = X25519Public::from(&dh_s).to_bytes();
        let dh_out = dh_s.diffie_hellman(&X25519Public::from(dh_r_pub)).to_bytes();
        let (rk, ck_s) = kdf_rk(&root_key, &dh_out);
        Self {
            dh_s_priv, dh_s_pub: dh_s_public, dh_r_pub,
            rk, ck_s, ck_r: [0u8;32],
            ns:0, nr:0, pn:0,
            skipped_index:Vec::new(),
            skipped:HashMap::new(),
            skipped_order:VecDeque::new(),
            delivered_win: DeliveredWindow::new(dh_r_pub),
        }
    }
    #[must_use]
    pub fn init_responder(root_key: [u8;32], dh_s_priv: [u8;32], dh_r_pub: [u8;32]) -> Self {
        let dh_s = StaticSecret::from(dh_s_priv);
        let dh_s_public = X25519Public::from(&dh_s).to_bytes();
        let dh_out = dh_s.diffie_hellman(&X25519Public::from(dh_r_pub)).to_bytes();
        let (rk, ck_r) = kdf_rk(&root_key, &dh_out);
        Self {
            dh_s_priv, dh_s_pub: dh_s_public, dh_r_pub,
            rk, ck_s: [0u8;32], ck_r,
            ns:0, nr:0, pn:0,
            skipped_index:Vec::new(),
            skipped:HashMap::new(),
            skipped_order:VecDeque::new(),
            delivered_win: DeliveredWindow::new(dh_r_pub),
        }
    }
    #[must_use]
    pub fn next_sending_key(&mut self) -> ([u8;32], Header) {
        if self.ck_s == [0u8;32] { self.dh_ratchet_send(); }
        let (ck_s_next, mk) = kdf_ck(&self.ck_s);
        self.ck_s = ck_s_next;
        let h = Header { dh_pub: self.dh_s_pub, pn: self.pn, n: self.ns };
        self.ns = self.ns.wrapping_add(1);
        (mk, h)
    }
    #[must_use]
    pub fn next_recv_key(&mut self) -> [u8;32] {
        let (ck_r_next, mk) = kdf_ck(&self.ck_r);
        self.ck_r = ck_r_next;
        self.nr = self.nr.wrapping_add(1);
        mk
    }
    pub fn try_skipped(&mut self, header: &Header) -> Option<[u8;32]> {
        if let Some(mk) = self.skipped.remove(&(header.dh_pub, header.n)) {
            if let Some(pos) = self.skipped_order.iter().position(|k| *k == (header.dh_pub, header.n)) {
                self.skipped_order.remove(pos);
            }
            return Some(mk);
        }
        None
    }
    fn add_skipped(&mut self, key: ([u8;32], u32), mk: [u8;32]) {
        const SKIPPED_MAX: usize = 2048;
        if self.skipped.len() >= SKIPPED_MAX {
            if let Some(old) = self.skipped_order.pop_front() { self.skipped.remove(&old); }
        }
        self.skipped_order.push_back(key);
        self.skipped.insert(key, mk);
    }
    pub fn skip_recv_until(&mut self, target_n: u32) {
        while self.nr < target_n {
            let (ck_r_next, mk) = kdf_ck(&self.ck_r);
            self.ck_r = ck_r_next;
            self.add_skipped((self.dh_r_pub, self.nr), mk);
            self.nr = self.nr.wrapping_add(1);
        }
    }
    pub fn maybe_step(&mut self, header: &Header) -> bool {
        if header.dh_pub == self.dh_r_pub { return false; }
        while self.nr < header.pn {
            let (ck_r_next, mk) = kdf_ck(&self.ck_r);
            self.ck_r = ck_r_next;
            self.add_skipped((self.dh_r_pub, self.nr), mk);
            self.nr = self.nr.wrapping_add(1);
        }
        self.pn = self.ns; self.ns = 0; self.nr = 0;
        self.dh_r_pub = header.dh_pub;
        self.delivered_win = DeliveredWindow::new(header.dh_pub);
        self.dh_ratchet_recv();
        true
    }
    fn dh_ratchet_recv(&mut self) {
        let sk = x25519_dalek::StaticSecret::from(self.dh_s_priv);
        let dh_out = sk.diffie_hellman(&x25519_dalek::PublicKey::from(self.dh_r_pub)).to_bytes();
        let (rk_next, ck_r) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk_next; self.ck_r = ck_r;
        let rng = rand::rngs::OsRng;
        let new_s = x25519_dalek::StaticSecret::random_from_rng(rng);
        self.dh_s_priv = new_s.to_bytes(); self.dh_s_pub = x25519_dalek::PublicKey::from(&new_s).to_bytes();
        let dh_out2 = new_s.diffie_hellman(&x25519_dalek::PublicKey::from(self.dh_r_pub)).to_bytes();
        let (rk_next2, ck_s) = kdf_rk(&self.rk, &dh_out2);
        self.rk = rk_next2; self.ck_s = ck_s;
    }
    fn dh_ratchet_send(&mut self) {
        let rng = rand::rngs::OsRng;
        let new_s = x25519_dalek::StaticSecret::random_from_rng(rng);
        self.dh_s_priv = new_s.to_bytes(); self.dh_s_pub = x25519_dalek::PublicKey::from(&new_s).to_bytes();
        let dh_out = new_s.diffie_hellman(&x25519_dalek::PublicKey::from(self.dh_r_pub)).to_bytes();
        let (rk_next, ck_s) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk_next; self.ck_s = ck_s; self.pn = self.ns; self.ns = 0;
    }
    #[must_use]
    pub fn was_delivered(&self, header: &Header) -> bool {
        self.delivered_win.was_delivered(header.dh_pub, header.n)
    }
    pub fn mark_delivered(&mut self, header: &Header) { self.delivered_win.mark(header.dh_pub, header.n); }
}
impl Drop for RatchetState {
    fn drop(&mut self) {
        self.dh_s_priv.zeroize();
        self.dh_s_pub.zeroize();
        self.dh_r_pub.zeroize();
        self.rk.zeroize();
        self.ck_s.zeroize();
        self.ck_r.zeroize();
    }
}
