# Hardlock-SNC API

## Handshake (Base)
let (enc, okm) = hpke_initiate(&pkR)?;
let okm2 = hpke_accept(&skR, &enc)?;

## Handshake (Auth taggé)
let (enc, okmA, tag) = hpke_initiate_auth_tagged(&skA, &pkR)?;
let okmB = hpke_accept_auth_check(&pkA, &skR, &enc, &tag)?;

## Handshake v2 (binder anti-downgrade)
let (enc, okmA, binder) = hpke_initiate_with_binder(&pkR, suites::HL1_BASE)?;
let frame = encode_init_v2(suites::HL1_BASE, &enc, &binder);
let (suite, enc2, binder2) = decode_init_v2(&frame)?;
let okmB = hpke_accept_with_binder(suite, &skR, &enc2, &binder2)?;

## Ratchet
let mut ra = init_initiator(okmA, skA, pkR);
let mut rb = init_responder(okmB, skR, pkA);
let ad = b"ctx";
let (h,n,ct) = encrypt(&mut ra, ad, b"hello");
let pt = decrypt(&mut rb, ad, &h, &n, &ct)?;
