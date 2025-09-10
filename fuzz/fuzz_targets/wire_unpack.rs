#![no_main]
use libfuzzer_sys::fuzz_target;
use hardlock_snc::wire::unpack_message;

fuzz_target!(|data: &[u8]| {
    let _ = unpack_message(data);
});
