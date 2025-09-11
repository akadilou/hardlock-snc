import CHardlockSNC

public struct Hardlock {
    public static func headerLen() -> Int { Int(hardlock_consts_header_len()) }
    public static func nonceLen() -> Int { Int(hardlock_consts_nonce_len()) }
    public static func genKeypair() -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: 32)
        var pk = [UInt8](repeating: 0, count: 32)
        _ = hardlock_x25519_keygen(&sk, &pk)
        return (sk, pk)
    }
}
