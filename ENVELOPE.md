# Network Envelope (sealed-sender + padding)

## Sealed-sender
token := AEAD_kS(expiry || sender_pub || scope)

header := suite || ts || nonce || token_len
payload := ratchet_frame
verify(token) -> ok, else drop

## Padding
- Bucket sizes: 256, 512, 1024, 2048, 4096 bytes
- pad_to(bucket) appliqué au wire frame
- Jitter d'envoi: 10–150 ms selon profil

## Profiles
- STEALTH: petits buckets, jitter haut
- BALANCED: buckets moyens, jitter modéré
- THROUGHPUT: grands buckets, jitter faible

## API hooks
- set_padding_profile(profile)
- attach_sealed_sender(token)
- verify_sealed_sender(token)
