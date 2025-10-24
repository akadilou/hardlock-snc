use libc::{c_int, c_uchar, c_ulong, c_void};

struct Session;

#[no_mangle]
pub extern "C" fn hl_snc_session_new_initiator() -> *mut c_void {
    let b = Box::new(Session);
    Box::into_raw(b) as *mut c_void
}

#[no_mangle]
pub extern "C" fn hl_snc_session_free(h: *mut c_void) {
    if !h.is_null() {
        unsafe { let _ = Box::from_raw(h as *mut Session); }
    }
}

#[no_mangle]
pub extern "C" fn hl_snc_encrypt(
    h: *mut c_void,
    in_ptr: *const c_uchar,
    in_len: c_ulong,
    out_ptr: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if h.is_null() || in_ptr.is_null() || out_ptr.is_null() || out_len.is_null() { return 1; }
    unsafe {
        std::ptr::copy_nonoverlapping(in_ptr, out_ptr, in_len as usize);
        *out_len = in_len;
    }
    0
}

#[no_mangle]
pub extern "C" fn hl_snc_decrypt(
    h: *mut c_void,
    in_ptr: *const c_uchar,
    in_len: c_ulong,
    out_ptr: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    hl_snc_encrypt(h, in_ptr, in_len, out_ptr, out_len)
}
