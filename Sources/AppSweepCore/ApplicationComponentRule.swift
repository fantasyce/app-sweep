import Foundation

/// The outer bundle seal establishes membership. Identical vendor prefixes or
/// similar names never establish this relationship.
public struct ApplicationComponentReference: Codable, Sendable, Equatable {
    public let ownerIdentifier: String
    public let relativePath: String
}
enum ApplicationComponentRule {
    static let supportedRules: Set<String> = [CacheDomainRule.name,SupportDomainRule.name,DarwinCacheRule.name,PreferenceRecoveryRecord.rule]
    static func valid(_ reference: ApplicationComponentReference) -> Bool {
        let path=reference.relativePath
        return AppInspector.validIdentifier(reference.ownerIdentifier) && !reference.ownerIdentifier.lowercased().hasPrefix("com.apple.") &&
            path.hasPrefix("Contents/") && path.utf8.count < 4096 && !path.contains("\0") && !path.contains("//") &&
            !path.split(separator:"/").contains(where:{$0 == "." || $0 == ".."}) &&
            [".app",".xpc",".appex"].contains(where:path.hasSuffix)
    }
    static func verifySource(_ reference: ApplicationComponentReference, root: String, identifier: String) throws -> String {
        guard valid(reference),identifier != reference.ownerIdentifier,!identifier.lowercased().hasPrefix("com.apple."),
              AppInspector.signatureMatches(path:root,identifier:reference.ownerIdentifier) else{throw SweepError.denied("内嵌组件的外层签名或关系未确认")}
        let path=root + "/" + reference.relativePath
        _=try SafeDirectory(path:path)
        let app=try AppInspector.inspect(path,component:true)
        guard app.bundleIdentifier == identifier,app.signed else{throw SweepError.denied("内嵌组件的标识或完整签名已改变")}
        return path
    }
    static func verifyOwner(_ reference: ApplicationComponentReference, application: String, identifier: String, home: String, signaturePath: String? = nil, inventory: [ApplicationIdentity]? = nil) throws -> [ApplicationIdentity] {
        if let signaturePath {try AppInspector.verifyIsolatedDataOwner(original:application,stored:signaturePath,identifier:reference.ownerIdentifier,home:home)}
        else {_=try AppInspector.verifiedDataOwner(path:application,identifier:reference.ownerIdentifier,home:home)}
        _=try verifySource(reference,root:signaturePath ?? application,identifier:identifier)
        let apps=try inventory ?? AppInspector.inventory(home:home,selectedApplication:signaturePath == nil ? application : nil,ownershipIdentifier:identifier)
        guard !apps.contains(where:{$0.bundleIdentifier.isEmpty}),
              !apps.contains(where:{ candidate in candidate.bundleIdentifier.lowercased() == identifier.lowercased() && !SafetyPolicy.contains(application,candidate.path) && !(signaturePath.map{SafetyPolicy.contains($0,candidate.path)} ?? false)}),
              signaturePath != nil || AppInspector.uniqueOwner(identifier:reference.ownerIdentifier,path:application,inventory:apps) else {
            throw SweepError.denied("其他安装可能使用该组件资料，保留")
        }
        return apps
    }
}
