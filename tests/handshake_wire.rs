use hardlock_snc::wire::handshake::{encode_init, decode_init};

#[test]
fn handshake_encode_decode_roundtrip() {
    let enc = vec![1,2,3,4,5,6,7,8,9];
    let f = encode_init(&enc);
    let back = decode_init(&f).expect("decode");
    assert_eq!(back, enc);
}
