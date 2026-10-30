#if os(macOS)
import Foundation
import Security
import Darwin
import CFSafety

/// Installation health is a challenge/ack exchange with a kernel-authenticated root
/// peer, never a cleanup session. It constructs no user context or engine and
/// does not read an action, path, plan, or UID from that peer.
enum SystemServiceHealth {
    private struct Reply: Codable {
        let schemaVersion: Int
        let purpose: String
        let nonce: Data
    }
    static func frame(nonce: Data) throws -> Data {
        guard nonce.count == 32 else { throw SweepError.invalid("安装健康挑战长度无效") }
        return try SystemServiceReply.controlFrame(Reply(schemaVersion:1,purpose:"installation-health",nonce:nonce))
    }
    static func validate(_ frame: Data) throws {
        let value = try SystemServiceReply.controlValue(Reply.self,frame:frame)
        guard value.schemaVersion == 1, value.purpose == "installation-health", value.nonce.count == 32 else { throw SweepError.denied("安装健康回复无效") }
    }
    static func acknowledgement(for frame: Data) throws -> Data {
        try validate(frame)
        let value = try SystemServiceReply.controlValue(Reply.self,frame:frame)
        return try SystemServiceReply.controlFrame(Reply(schemaVersion:1,purpose:"installation-health-ack",nonce:value.nonce))
    }
    static func exchange(nonce: Data, socket: Int32, timeout: TimeInterval = 5) throws {
        try LocalControlChannel.write(frame(nonce:nonce),socket:socket,timeout:timeout)
        // Keep the endpoint alive while the Installer authenticates its kernel
        // peer and pinned code. Closing after write races those credential reads.
        let data = try LocalControlChannel.read(socket:socket,timeout:timeout)
        let reply = try SystemServiceReply.controlValue(Reply.self,frame:data)
        guard reply.schemaVersion == 1, reply.purpose == "installation-health-ack", reply.nonce == nonce else {
            throw SweepError.denied("安装健康确认没有绑定本次挑战")
        }
    }
    static func serveIfInstallationPeer(socket: Int32) throws -> Bool {
        var peer = ASPeerIdentity()
        guard as_peer_identity(socket,&peer) == 0, peer.pid > 0 else { throw SweepError.denied("安装探针内核身份未确认") }
        if peer.effective_uid != 0 { return false }
        guard peer.real_uid == 0, getuid() == 0, geteuid() == 0 else { throw SweepError.denied("安装健康探针要求独立root身份") }
        var nonce = Data(count:32)
        guard nonce.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault,$0.count,$0.baseAddress!) }) == errSecSuccess else { throw SweepError.incomplete("不能生成安装健康挑战") }
        try exchange(nonce:nonce,socket:socket)
        return true
    }
}
#endif
