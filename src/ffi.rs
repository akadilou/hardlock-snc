#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ptr;
use crate::crypto::hpke_hybrid::{hpke_initiate, hpke_accept};
use crate::crypto::keys::X25519KeyPair;
use crate::ratchet;
use crate::wire::{header_to_bytes, HEADER_LEN};
use crate::crypto::aeadx::XNONCE_LEN;

#[repr(C)]
pub struct RatchetHandle {
    ptr: *mut ratchet::state::RatchetState,
}

#[no_mangle]
pub extern "C" fn hardlock_consts_header_len() -> usize { HEADER_LEN }

#[no_mangle]
pub extern "C" fn hardlock_consts_nonce_len() -> usize { XNONCE_LEN }

#[no_mangle]
pub extern "C" fn hardlock_x25519_keygen(sk_out: *mut u8, pk_out: *mut u8) -> c_int {
    if sk_out.is_null() || pk_out.is_null() { return -1; }
    let kp = X25519KeyPair::generate();
    unsafe {
        ptr::copy_nonoverlapping(kp.sk.as_ptr(), sk_out, 32);
        ptr::copy_nonoverlapping(kp.pk.as_ptr(), pk_out, 32);
    }
    0
}

#[no_mangle]
pub extern "C" fn hardlock_hpke_initiate(pk_recipient32: *const u8, enc_out: *mut u8, enc_cap: usize, okm_out32: *mut u8) -> c_int {
    if pk_recipient32.is_null() || enc_out.is_null() || okm_out32.is_null() { return -1; }
    let mut pk = [0u8;32];
    unsafe { ptr::copy_nonoverlapping(pk_recipient32, pk.as_mut_ptr(), 32); }
    let (enc, okm) = match hpke_initiate(&pk) { Ok(v)=>v, Err(_)=>return -2 };
    if enc.len() > enc_cap { return -3; }
    unsafe {
        ptr::copy_nonoverlapping(enc.as_ptr(), enc_out, enc.len());
        ptr::copy_nonoverlapping(okm.as_ptr(), okm_out32, 32);
    }
    enc.len() as c_int
}

#[no_mangle]
pub extern "C" fn hardlock_hpke_accept(sk_recipient32: *const u8, enc_ptr: *const u8, enc_len: usize, okm_out32: *mut u8) -> c_int {
    if sk_recipient32.is_null() || enc_ptr.is_null() || okm_out32.is_null() { return -1; }
    let mut sk = [0u8;32];
    unsafe { ptr::copy_nonoverlapping(sk_recipient32, sk.as_mut_ptr(), 32); }
    let enc = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };
    let okm = match hpke_accept(&sk, enc) { Ok(v)=>v, Err(_)=>return -2 };
    unsafe { ptr::copy_nonoverlapping(okm.as_ptr(), okm_out32, 32); }
    0
}

#[no_mangle]
pub extern "C" fn hardlock_ratchet_new_initiator(okm32: *const u8, dh_s_priv32: *const u8, dh_r_pub32: *const u8) -> *mut RatchetHandle {
    if okm32.is_null() || dh_s_priv32.is_null() || dh_r_pub32.is_null() { return ptr::null_mut(); }
    let mut okm = [0u8;32];
    let mut sk = [0u8;32];
    let mut pk = [0u8;32];
    unsafe {
        ptr::copy_nonoverlapping(okm32, okm.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dh_s_priv32, sk.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dh_r_pub32, pk.as_mut_ptr(), 32);
    }
    let st = ratchet::init_initiator(okm, sk, pk);
    let ptr = Box::into_raw(Box::new(st));
    Box::into_raw(Box::new(RatchetHandle{ ptr }))
}

#[no_mangle]
pub extern "C" fn hardlock_ratchet_new_responder(okm32: *const u8, dh_s_priv32: *const u8, dh_r_pub32: *const u8) -> *mut RatchetHandle {
    if okm32.is_null() || dh_s_priv32.is_null() || dh_r_pub32.is_null() { return ptr::null_mut(); }
    let mut okm = [0u8;32];
    let mut sk = [0u8;32];
    let mut pk = [0u8;32];
    unsafe {
        ptr::copy_nonoverlapping(okm32, okm.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dh_s_priv32, sk.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dh_r_pub32, pk.as_mut_ptr(), 32);
    }
    let st = ratchet::init_responder(okm, sk, pk);
    let ptr = Box::into_raw(Box::new(st));
    Box::into_raw(Box::new(RatchetHandle{ ptr }))
}

#[no_mangle]
pub extern "C" fn hardlock_ratchet_free(h: *mut RatchetHandle) {
    if h.is_null() { return; }
    unsafe {
        let handle = Box::from_raw(h);
        if !handle.ptr.is_null() { drop(Box::from_raw(handle.ptr)); }
    }
}

#[no_mangle]
pub extern "C" fn hardlock_ratchet_encrypt(h: *mut RatchetHandle, ad_ptr: *const u8, ad_len: usize, pt_ptr: *const u8, pt_len: usize, header_out: *mut u8, nonce_out: *mut u8, ct_out: *mut u8, ct_cap: usize) -> c_int {
    if h.is_null() || pt_ptr.is_null() || header_out.is_null() || nonce_out.is_null() || ct_out.is_null() { return -1; }
    let st = unsafe { &mut *(*h).ptr };
    let ad = if ad_ptr.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(ad_ptr, ad_len) } };
    let pt = unsafe { std::slice::from_raw_parts(pt_ptr, pt_len) };
    let (hdr, nonce, ct) = ratchet::encrypt(st, ad, pt);
    if ct.len() > ct_cap { return -2; }
    let hb = header_to_bytes(&hdr);
    unsafe {
        ptr::copy_nonoverlapping(hb.as_ptr(), header_out, HEADER_LEN);
        ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_out, XNONCE_LEN);
        ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, ct.len());
    }
    ct.len() as c_int
}

#[no_mangle]
pub extern "C" fn hardlock_ratchet_decrypt(h: *mut RatchetHandle, ad_ptr: *const u8, ad_len: usize, header_ptr: *const u8, nonce_ptr: *const u8, ct_ptr: *const u8, ct_len: usize, pt_out: *mut u8, pt_cap: usize) -> c_int {
    if h.is_null() || header_ptr.is_null() || nonce_ptr.is_null() || ct_ptr.is_null() || pt_out.is_null() { return -1; }
    let st = unsafe { &mut *(*h).ptr };
    let ad = if ad_ptr.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(ad_ptr, ad_len) } };
    let hb = unsafe { std::slice::from_raw_parts(header_ptr, HEADER_LEN) };
    let hdr = {
        use crate::wire::header_from_bytes;
        match header_from_bytes(hb) { Ok(h)=>h, Err(_)=>return -2 }
    };
    let mut nonce = [0u8; XNONCE_LEN];
    unsafe { ptr::copy_nonoverlapping(nonce_ptr, nonce.as_mut_ptr(), XNONCE_LEN); }
    let ct = unsafe { std::slice::from_raw_parts(ct_ptr, ct_len) };
    let pt = match ratchet::decrypt(st, ad, &hdr, &nonce, ct) { Ok(v)=>v, Err(_)=>return -3 };
    if pt.len() > pt_cap { return -4; }
    unsafe { ptr::copy_nonoverlapping(pt.as_ptr(), pt_out, pt.len()); }
    pt.len() as c_int
}
