use hardlock_snc::wire::handshake::{
    decode_init_auth, decode_init_v2, encode_init_auth, encode_init_v2,
};

#[test]
fn wire_auth_roundtrip() {
    let enc = vec![1, 2, 3, 4, 5];

    let f = encode_init_auth(&enc);
    let e = decode_init_auth(&f).expect("decode");
    assert_eq!(e, enc);

    let suite = 1u8;
    let tag = [7u8; 32];
    let fb = encode_init_v2(suite, &enc, &tag);
    let (s2, e2, t2) = decode_init_v2(&fb).expect("decode v2");
    assert_eq!(s2, suite);
    assert_eq!(e2, enc);
    assert_eq!(t2, tag);
}
