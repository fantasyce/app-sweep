import Foundation
import CFSafety
#if os(macOS)
import Security
#endif

struct AuthenticatedLocalPeer: Sendable {
    let uid: UInt32
    let pid: Int32
    let auditToken: Data
}
/// Authentication foundation only; no privileged action or installation endpoint.
/// The requirement must come from verified service configuration, never a request.
enum LocalPeerAuthentication {
    static func authenticate(socket: Int32, requirement: String) throws -> AuthenticatedLocalPeer {
        try verify(socket: socket, requirement: requirement, rootService: false)
    }
    static func authenticateRootService(socket: Int32, requirement: String) throws -> AuthenticatedLocalPeer {
        try verify(socket: socket, requirement: requirement, rootService: true)
    }
    private static func verify(socket: Int32, requirement: String, rootService: Bool) throws -> AuthenticatedLocalPeer {
        var raw = ASPeerIdentity()
        guard !requirement.isEmpty, requirement.utf8.count <= 4096, !requirement.contains("\0"),
              as_peer_identity(socket, &raw) == 0, raw.pid > 0,
              (rootService ? raw.effective_uid == 0 : raw.effective_uid != 0), raw.effective_uid == raw.real_uid else { throw SweepError.denied("本机连接的内核凭据未确认") }
        let token = withUnsafeBytes(of: raw.audit_token) { Data($0) }
        guard token.count == 32 else { throw SweepError.denied("本机连接的审计凭据无效") }
        #if os(macOS)
        var expected: SecRequirement?, code: SecCode?
        let parsed = SecRequirementCreateWithString(requirement as CFString, [], &expected)
        guard parsed == errSecSuccess, let expected else { throw SweepError.denied("客户端签名要求无效（状态 \(parsed)）") }
        let located = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token] as CFDictionary, [], &code)
        guard located == errSecSuccess, let code else { throw SweepError.denied("内核连接对应的代码身份未确认（状态 \(located)）") }
        let checked = SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), expected)
        guard checked == errSecSuccess else { throw SweepError.denied("客户端不符合签名要求（状态 \(checked)）") }
        var staticCode: SecStaticCode?, signing: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signing) == errSecSuccess,
              let info = signing as? [String: Any], let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & SecCodeSignatureFlags.runtime.rawValue != 0 else { throw SweepError.denied("客户端未启用所需的运行时保护") }
        let entitlements: [String: Any]
        if let rawEntitlements = info[kSecCodeInfoEntitlementsDict as String] {
            guard let dictionary = rawEntitlements as? [String: Any] else { throw SweepError.denied("客户端运行时例外无法核对") }
            entitlements = dictionary
        } else { entitlements = [:] }
        for key in ["com.apple.security.get-task-allow", "get-task-allow", "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.disable-executable-page-protection", "com.apple.security.cs.allow-jit"] {
            if let value = entitlements[key] {
                guard let allowed = value as? Bool, !allowed else { throw SweepError.denied("客户端含有不允许的调试或代码注入例外") }
            }
        }
        return AuthenticatedLocalPeer(uid: raw.effective_uid, pid: raw.pid, auditToken: token)
        #else
        throw SweepError.denied("当前平台未验收本机代码身份")
        #endif
    }
}
