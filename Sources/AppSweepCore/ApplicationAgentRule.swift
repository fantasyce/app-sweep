import Foundation
#if os(macOS)
import Security
#endif

/// A direct program reference and a unique signed application authorize this
/// current-user component. A matching vendor/label alone never does.
enum ApplicationAgentRule {
    static let name="signed-app-user-launch-agent-v1"
    static func codeHash(application:String,identifier:String)throws->Data {
        #if os(macOS)
        var code:SecStaticCode?,raw:CFDictionary?
        guard AppInspector.signatureMatches(path:application,identifier:identifier),
              SecStaticCodeCreateWithPath(URL(fileURLWithPath:application)as CFURL,[],&code) == errSecSuccess,let code,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw) == errSecSuccess,
              let info=raw as? [String:Any],let hash=info[kSecCodeInfoUnique as String]as? Data,[20,32].contains(hash.count) else{throw SweepError.denied("后台组件的主体代码摘要未确认")}
        return hash
        #else
        throw SweepError.denied("当前平台不支持原生后台组件")
        #endif
    }
    static func references(_ path:String,application:String)throws->Bool {
        let data=try SafeFilesystem.readMetadata(path,maximumBytes:1024*1024)
        guard let info=try PropertyListSerialization.propertyList(from:data,format:nil)as? [String:Any] else{throw SweepError.incomplete("后台项声明格式未确认")}
        let program=info["Program"]as? String ?? (info["ProgramArguments"]as? [String])?.first
        return program.map{SafetyPolicy.contains(application+"/Contents/MacOS",$0) && $0 != application+"/Contents/MacOS"} ?? false
    }
    private static func declaration(_ path:String,home:String,application:String,identifier:String,storedPath:String?=nil)throws->StaleUserAgentRule.Declaration {
        _=try AppInspector.verifiedDataOwner(path:application,identifier:identifier,home:home)
        guard try AppInspector.uniqueOwner(identifier:identifier,path:application,inventory:AppInspector.inventory(home:home,selectedApplication:application)) else{throw SweepError.denied("后台项缺少唯一签名应用主体")}
        let declaration=try StaleUserAgentRule.inspect(path,home:home,storedPath:storedPath,installedApplication:application)
        _=try StaleUserAgentRule.registered(declaration)
        return declaration
    }
    static func dormantDeclarations(home:String,application:String,identifier:String)throws->[StaleUserAgentRule.Declaration] {
        let root=home+"/Library/LaunchAgents"
        guard try SafeFilesystem.presence(root) else{return []}
        var result:[StaleUserAgentRule.Declaration]=[]
        for name in try XcodeArchiveRule.children(root) where name.hasSuffix(".plist"){
            let path=root+"/"+name
            if try references(path,application:application){result.append(try declaration(path,home:home,application:application,identifier:identifier))}
        }
        guard result.count<=32 else{throw SweepError.incomplete("应用后台项超过独立核对容量")}
        return result
    }
    static func inspect(_ path:String,home:String,application:String,identifier:String,storedPath:String?=nil)throws->StaleUserAgentRule.Declaration {
        let declaration=try declaration(path,home:home,application:application,identifier:identifier,storedPath:storedPath)
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:application,additionalIdentifiers:[declaration.label],userHome:home)
        return declaration
    }
}
