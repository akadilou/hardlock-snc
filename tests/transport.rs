use hardlock_snc::envelope::{PadProfile};
use hardlock_snc::envelope::transport::{TransportHeader, encode_transport_header, decode_transport_header};

#[test]
fn transport_header_roundtrip() {
    let h = TransportHeader { ts_unix_s: 4102444800, token_len: 5, profile: PadProfile::Balanced };
    let tok = vec![1,2,3,4,5];
    let buf = encode_transport_header(&h, &tok);
    let (h2, tok2) = decode_transport_header(&buf).expect("decode");
    assert_eq!(h.ts_unix_s, h2.ts_unix_s);
    assert_eq!(h.token_len, h2.token_len);
    assert_eq!(h.profile as u8, h2.profile as u8);
    assert_eq!(tok, tok2);
}
