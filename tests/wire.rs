use hardlock_snc::ratchet::state::Header;
use hardlock_snc::wire::*;

#[test]
fn pack_unpack_roundtrip() {
    let h = Header {
        dh_pub: [7u8; 32],
        pn: 3,
        n: 9,
    };
    let nonce = [5u8; 24];
    let ct = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let frame = pack_message(0x0110, &h, &nonce, &ct, 64);
    let (ver, h2, n2, ct2) = unpack_message(&frame).expect("unpack");
    assert_eq!(ver, 0x0110);
    assert_eq!(h2.dh_pub, h.dh_pub);
    assert_eq!(h2.pn, h.pn);
    assert_eq!(h2.n, h.n);
    assert_eq!(n2, nonce);
    assert_eq!(ct2, ct);
}
