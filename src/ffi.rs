#![allow(unsafe_code)]

use crate::crypto::aeadx::XNONCE_LEN;
use crate::crypto::hpke_hybrid::{hpke_accept, hpke_initiate};
use crate::crypto::keys::X25519KeyPair;
use crate::ratchet;
use crate::wire::{header_to_bytes, HEADER_LEN};
use std::ffi::c_int;
use std::ptr;

#[repr(C)]
pub struct RatchetHandle {
    ptr: *mut ratchet::state::RatchetState,
}

/// # Safety
/// Le chargeur d’ABI C doit fournir un pointeur de fonction valide.
/// Aucune précondition supplémentaire.
#[no_mangle]
pub unsafe extern "C" fn hardlock_consts_header_len() -> usize {
    HEADER_LEN
}

/// # Safety
/// Le chargeur d’ABI C doit fournir un pointeur de fonction valide.
/// Aucune précondition supplémentaire.
#[no_mangle]
pub unsafe extern "C" fn hardlock_consts_nonce_len() -> usize {
    XNONCE_LEN
}

/// # Safety
/// `sk_out` et `pk_out` doivent pointer vers des buffers d’au moins 32 octets valides et mutables.
#[no_mangle]
pub unsafe extern "C" fn hardlock_x25519_keygen(sk_out: *mut u8, pk_out: *mut u8) -> c_int {
    if sk_out.is_null() || pk_out.is_null() {
        return -1;
    }
    let kp = X25519KeyPair::generate();
    ptr::copy_nonoverlapping(kp.sk.as_ptr(), sk_out, 32);
    ptr::copy_nonoverlapping(kp.pk.as_ptr(), pk_out, 32);
    0
}

/// # Safety
/// `pk_recipient32` doit pointer vers 32 octets lisibles.
/// `enc_out` vers un buffer de capacité `enc_cap`.
/// `okm_out32` vers 32 octets mutables.
#[no_mangle]
pub unsafe extern "C" fn hardlock_hpke_initiate(
    pk_recipient32: *const u8,
    enc_out: *mut u8,
    enc_cap: usize,
    okm_out32: *mut u8,
) -> c_int {
    if pk_recipient32.is_null() || enc_out.is_null() || okm_out32.is_null() {
        return -1;
    }
    let mut pk = [0u8; 32];
    ptr::copy_nonoverlapping(pk_recipient32, pk.as_mut_ptr(), 32);
    let Ok((enc, okm)) = hpke_initiate(&pk) else {
        return -2;
    };
    if enc.len() > enc_cap {
        return -3;
    }
    ptr::copy_nonoverlapping(enc.as_ptr(), enc_out, enc.len());
    ptr::copy_nonoverlapping(okm.as_ptr(), okm_out32, 32);
    c_int::try_from(enc.len()).unwrap_or(-5)
}

/// # Safety
/// `sk_recipient32` doit pointer vers 32 octets lisibles.
/// `enc_ptr..enc_ptr+enc_len` doit être lisible.
/// `okm_out32` doit pointer vers 32 octets mutables.
#[no_mangle]
pub unsafe extern "C" fn hardlock_hpke_accept(
    sk_recipient32: *const u8,
    enc_ptr: *const u8,
    enc_len: usize,
    okm_out32: *mut u8,
) -> c_int {
    if sk_recipient32.is_null() || enc_ptr.is_null() || okm_out32.is_null() {
        return -1;
    }
    let mut sk = [0u8; 32];
    ptr::copy_nonoverlapping(sk_recipient32, sk.as_mut_ptr(), 32);
    let enc = std::slice::from_raw_parts(enc_ptr, enc_len);
    let Ok(okm) = hpke_accept(&sk, enc) else {
        return -2;
    };
    ptr::copy_nonoverlapping(okm.as_ptr(), okm_out32, 32);
    0
}

/// # Safety
/// Tous les pointeurs doivent référencer 32 octets lisibles (`okm32`, `dh_s_priv32`, `dh_r_pub32`).
#[no_mangle]
pub unsafe extern "C" fn hardlock_ratchet_new_initiator(
    okm32: *const u8,
    dh_s_priv32: *const u8,
    dh_r_pub32: *const u8,
) -> *mut RatchetHandle {
    if okm32.is_null() || dh_s_priv32.is_null() || dh_r_pub32.is_null() {
        return ptr::null_mut();
    }
    let mut okm = [0u8; 32];
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    ptr::copy_nonoverlapping(okm32, okm.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(dh_s_priv32, sk.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(dh_r_pub32, pk.as_mut_ptr(), 32);
    let st = ratchet::init_initiator(okm, sk, pk);
    let ptr = Box::into_raw(Box::new(st));
    Box::into_raw(Box::new(RatchetHandle { ptr }))
}

/// # Safety
/// Tous les pointeurs doivent référencer 32 octets lisibles (`okm32`, `dh_s_priv32`, `dh_r_pub32`).
#[no_mangle]
pub unsafe extern "C" fn hardlock_ratchet_new_responder(
    okm32: *const u8,
    dh_s_priv32: *const u8,
    dh_r_pub32: *const u8,
) -> *mut RatchetHandle {
    if okm32.is_null() || dh_s_priv32.is_null() || dh_r_pub32.is_null() {
        return ptr::null_mut();
    }
    let mut okm = [0u8; 32];
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    ptr::copy_nonoverlapping(okm32, okm.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(dh_s_priv32, sk.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(dh_r_pub32, pk.as_mut_ptr(), 32);
    let st = ratchet::init_responder(okm, sk, pk);
    let ptr = Box::into_raw(Box::new(st));
    Box::into_raw(Box::new(RatchetHandle { ptr }))
}

/// # Safety
/// `h` doit être un pointeur valide créé par `hardlock_ratchet_new_*` et non libéré auparavant.
#[no_mangle]
pub unsafe extern "C" fn hardlock_ratchet_free(h: *mut RatchetHandle) {
    if h.is_null() {
        return;
    }
    let handle = Box::from_raw(h);
    if !handle.ptr.is_null() {
        drop(Box::from_raw(handle.ptr));
    }
}

/// # Safety
/// `h` doit être valide. `ad_ptr/pt_ptr` doivent être lisibles.
/// `header_out/nonce_out/ct_out` doivent être mutables avec suffisamment de capacité (`ct_cap`).
#[no_mangle]
pub unsafe extern "C" fn hardlock_ratchet_encrypt(
    h: *mut RatchetHandle,
    ad_ptr: *const u8,
    ad_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    header_out: *mut u8,
    nonce_out: *mut u8,
    ct_out: *mut u8,
    ct_cap: usize,
) -> c_int {
    if h.is_null()
        || pt_ptr.is_null()
        || header_out.is_null()
        || nonce_out.is_null()
        || ct_out.is_null()
    {
        return -1;
    }
    let st = &mut *(*h).ptr;
    let ad = if ad_ptr.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(ad_ptr, ad_len)
    };
    let pt = std::slice::from_raw_parts(pt_ptr, pt_len);
    let (hdr, nonce, ct) = ratchet::encrypt(st, ad, pt);
    if ct.len() > ct_cap {
        return -2;
    }
    let hb = header_to_bytes(&hdr);
    ptr::copy_nonoverlapping(hb.as_ptr(), header_out, HEADER_LEN);
    ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_out, XNONCE_LEN);
    ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, ct.len());
    c_int::try_from(ct.len()).unwrap_or(-5)
}

/// # Safety
/// `h` doit être valide. `header_ptr` doit pointer vers `HEADER_LEN` octets.
/// `nonce_ptr` vers `XNONCE_LEN` octets. `ct_ptr..ct_ptr+ct_len` lisibles.
/// `pt_out` mutable avec `pt_cap` octets.
#[no_mangle]
pub unsafe extern "C" fn hardlock_ratchet_decrypt(
    h: *mut RatchetHandle,
    ad_ptr: *const u8,
    ad_len: usize,
    header_ptr: *const u8,
    nonce_ptr: *const u8,
    ct_ptr: *const u8,
    ct_len: usize,
    pt_out: *mut u8,
    pt_cap: usize,
) -> c_int {
    if h.is_null()
        || header_ptr.is_null()
        || nonce_ptr.is_null()
        || ct_ptr.is_null()
        || pt_out.is_null()
    {
        return -1;
    }
    let st = &mut *(*h).ptr;
    let ad = if ad_ptr.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(ad_ptr, ad_len)
    };
    let hb = std::slice::from_raw_parts(header_ptr, HEADER_LEN);
    let hdr = {
        use crate::wire::header_from_bytes;
        let Ok(hh) = header_from_bytes(hb) else {
            return -2;
        };
        hh
    };
    let mut nonce = [0u8; XNONCE_LEN];
    ptr::copy_nonoverlapping(nonce_ptr, nonce.as_mut_ptr(), XNONCE_LEN);
    let ct = std::slice::from_raw_parts(ct_ptr, ct_len);
    let Ok(pt) = ratchet::decrypt(st, ad, &hdr, &nonce, ct) else {
        return -3;
    };
    if pt.len() > pt_cap {
        return -4;
    }
    ptr::copy_nonoverlapping(pt.as_ptr(), pt_out, pt.len());
    c_int::try_from(pt.len()).unwrap_or(-5)
}

/// # Safety
/// `k_s32` doit pointer vers 32 octets lisibles, `sender_pub32` vers 32 octets,
/// `scope_ptr..scope_ptr+scope_len` lisibles, `nonce_out` 24o mutables, `ct_out` capacité `ct_cap`.
#[no_mangle]
pub unsafe extern "C" fn hardlock_token_build(
    k_s32: *const u8,
    expiry_unix_s: u64,
    sender_pub32: *const u8,
    scope_ptr: *const u8,
    scope_len: usize,
    nonce_out: *mut u8,
    ct_out: *mut u8,
    ct_cap: usize,
) -> c_int {
    if k_s32.is_null() || sender_pub32.is_null() || ct_out.is_null() || nonce_out.is_null() {
        return -1;
    }
    let k_s = {
        let mut k = [0u8; 32];
        ptr::copy_nonoverlapping(k_s32, k.as_mut_ptr(), 32);
        k
    };
    let sp = {
        let mut p = [0u8; 32];
        ptr::copy_nonoverlapping(sender_pub32, p.as_mut_ptr(), 32);
        p
    };
    let scope = if scope_ptr.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(scope_ptr, scope_len)
    };
    let t = crate::envelope::token_build(&k_s, expiry_unix_s, &sp, scope);
    if t.ct.len() > ct_cap {
        return -2;
    }
    ptr::copy_nonoverlapping(
        t.nonce.as_ptr(),
        nonce_out,
        crate::crypto::aeadx::XNONCE_LEN,
    );
    ptr::copy_nonoverlapping(t.ct.as_ptr(), ct_out, t.ct.len());
    c_int::try_from(t.ct.len()).unwrap_or(-5)
}

/// # Safety
/// `k_s32` 32o lisibles, `nonce_ptr` 24o lisibles, `ct_ptr..ct_ptr+ct_len` lisibles.
/// Retourne 0 si OK, <0 si échec.
#[no_mangle]
pub unsafe extern "C" fn hardlock_token_verify(
    k_s32: *const u8,
    nonce_ptr: *const u8,
    ct_ptr: *const u8,
    ct_len: usize,
    now_unix_s: u64,
) -> c_int {
    if k_s32.is_null() || nonce_ptr.is_null() || ct_ptr.is_null() {
        return -1;
    }
    let k_s = {
        let mut k = [0u8; 32];
        ptr::copy_nonoverlapping(k_s32, k.as_mut_ptr(), 32);
        k
    };
    let mut nonce = [0u8; crate::crypto::aeadx::XNONCE_LEN];
    ptr::copy_nonoverlapping(nonce_ptr, nonce.as_mut_ptr(), nonce.len());
    let ct = std::slice::from_raw_parts(ct_ptr, ct_len);
    let tok = crate::envelope::SenderToken {
        nonce,
        ct: ct.to_vec(),
    };
    match crate::envelope::token_verify(&k_s, &tok, now_unix_s) {
        Some(_) => 0,
        None => -2,
    }
}

/// # Safety
/// `frame_ptr..frame_ptr+frame_len` lisibles, `out_ptr` capacité `out_cap`.
/// `profile` : 0=Stealth,1=Balanced,2=Throughput. Retourne taille écrite.
#[no_mangle]
pub unsafe extern "C" fn hardlock_apply_padding(
    frame_ptr: *const u8,
    frame_len: usize,
    profile: i32,
    out_ptr: *mut u8,
    out_cap: usize,
) -> c_int {
    if frame_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let f = std::slice::from_raw_parts(frame_ptr, frame_len).to_vec();
    let p = match profile {
        0 => crate::envelope::PadProfile::Stealth,
        1 => crate::envelope::PadProfile::Balanced,
        _ => crate::envelope::PadProfile::Throughput,
    };
    let out = crate::envelope::apply_padding(f, p);
    if out.len() > out_cap {
        return -2;
    }
    ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, out.len());
    c_int::try_from(out.len()).unwrap_or(-5)
}
