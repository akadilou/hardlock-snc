import Foundation
import CHardlockSNC

public final class HardlockSession {
    private var handle: UnsafeMutableRawPointer?
    private static let hdrLen = Int(hardlock_consts_header_len())
    private static let nonceLen = Int(hardlock_consts_nonce_len())
    private init(_ h: UnsafeMutableRawPointer) { self.handle = h }

    public static func initiator(_ peerPublicKey32: Data) -> HardlockSession {
        var enc = Data(count: 1024)
        var okm = Data(count: 32)
        var pk = [UInt8](peerPublicKey32)
        let encLen = okm.withUnsafeMutableBytes { okmPtr in
            enc.withUnsafeMutableBytes { encPtr in
                hardlock_hpke_initiate(pk, encPtr.bindMemory(to: UInt8.self).baseAddress!, enc.count, okmPtr.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        enc.count = Int(encLen)
        var sk = [UInt8](repeating: 0, count: 32)
        var mypk = [UInt8](repeating: 0, count: 32)
        hardlock_x25519_keygen(&sk, &mypk)
        let h = okm.withUnsafeBytes { okmPtr in
            sk.withUnsafeBytes { skPtr in
                peerPublicKey32.withUnsafeBytes { rpkPtr in
                    hardlock_ratchet_new_initiator(okmPtr.bindMemory(to: UInt8.self).baseAddress!, skPtr.bindMemory(to: UInt8.self).baseAddress!, rpkPtr.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
        }
        return HardlockSession(h!)
    }

    public func encrypt(_ plaintext: String) -> Data {
        let ad = Data()
        let pt = plaintext.data(using: .utf8)!
        var header = Data(count: Self.hdrLen)
        var nonce = Data(count: Self.nonceLen)
        var ct = Data(count: pt.count + 32)
        let ctLen = ad.withUnsafeBytes { adPtr in
            pt.withUnsafeBytes { ptPtr in
                header.withUnsafeMutableBytes { hb in
                    nonce.withUnsafeMutableBytes { nb in
                        ct.withUnsafeMutableBytes { ctb in
                            hardlock_ratchet_encrypt(self.handle, adPtr.bindMemory(to: UInt8.self).baseAddress, ad.count, ptPtr.bindMemory(to: UInt8.self).baseAddress!, pt.count, hb.bindMemory(to: UInt8.self).baseAddress!, nb.bindMemory(to: UInt8.self).baseAddress!, ctb.bindMemory(to: UInt8.self).baseAddress!, ct.count)
                        }
                    }
                }
            }
        }
        ct.count = Int(ctLen)
        var out = Data()
        out.append(header)
        out.append(nonce)
        var lenLE = withUnsafeBytes(of: UInt32(ct.count).littleEndian, { Data($0) })
        out.append(lenLE)
        out.append(ct)
        return out
    }

    public func decrypt(_ frame: Data) -> String {
        let ad = Data()
        let hb = frame.prefix(Self.hdrLen)
        let nb = frame.dropFirst(Self.hdrLen).prefix(Self.nonceLen)
        let rest = frame.dropFirst(Self.hdrLen + Self.nonceLen)
        let ctLen = Int(UInt32(littleEndian: rest.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }))
        let ct = rest.dropFirst(4).prefix(ctLen)
        var pt = Data(count: ctLen + 32)
        let ptLen = ad.withUnsafeBytes { adPtr in
            hb.withUnsafeBytes { hbPtr in
                nb.withUnsafeBytes { nbPtr in
                    ct.withUnsafeBytes { ctPtr in
                        pt.withUnsafeMutableBytes { ptb in
                            hardlock_ratchet_decrypt(self.handle, adPtr.bindMemory(to: UInt8.self).baseAddress, ad.count, hbPtr.bindMemory(to: UInt8.self).baseAddress!, nbPtr.bindMemory(to: UInt8.self).baseAddress!, ctPtr.bindMemory(to: UInt8.self).baseAddress!, ct.count, ptb.bindMemory(to: UInt8.self).baseAddress!, pt.count)
                        }
                    }
                }
            }
        }
        pt.count = Int(ptLen)
        return String(data: pt, encoding: .utf8) ?? ""
    }

    deinit {
        if let h = handle { hardlock_ratchet_free(h); handle = nil }
    }
}
