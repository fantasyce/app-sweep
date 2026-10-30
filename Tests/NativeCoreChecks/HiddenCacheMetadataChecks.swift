import Foundation
import Darwin
@testable import AppSweepCore

@MainActor func hiddenCacheMetadataChecks() async throws {
    let f=try OwnedFixture(),root=f.home + "/DarwinCache/" + f.identifier
    try fm.createDirectory(atPath:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    let path=root + "/.hidden-metadata"
    let bytes=Data([0,0,0,1,0x42,0x75,0x64,0x31])+Data(repeating:0,count:40)
    try bytes.write(to:URL(fileURLWithPath:path))
    try check(chflags(path,UInt32(UF_HIDDEN)) == 0,"Owned hidden flag setup failed")
    let scope=try DarwinCacheScope.fixture(home:f.home)
    _ = try DarwinCacheRule.verifyRoot(identifier:f.identifier,scope:scope)
    print("PASS hidden Finder metadata does not veto a complete private Darwin cache")
    let original=try SafeFilesystem.snapshot(path),item=Candidate(id:UUID(),path:path,category:.cache,bundleIdentifier:f.identifier,evidence:[.init(kind:.validatedRule,detail:"owned metadata fixture",verified:true)],rule:DarwinCacheRule.name,identity:original.identity,bytes:original.bytes,retentionReason:nil)
    let parent=try SafeDirectory(path:f.home),backups=try parent.privateChild("archive.noindex"),objects=try parent.privateChild("rebuilt.noindex")
    let prepared=try CacheArchive.prepare(original,candidate:item),archive=try CacheArchive.create(prepared,snapshot:original,candidate:item,in:backups)
    let entry=RecoveryEntry(id:item.id,original:item,state:.moved,contents:original.tree,backupDigest:prepared.digest,backupIdentity:archive.identity,backupFormat:CacheArchive.format)
    let rebuilt=try CacheArchive.materialize(entry,from:backups,into:objects)
    var flags=stat();try check(lstat(rebuilt.path,&flags) == 0 && flags.st_flags == UInt32(UF_HIDDEN),"Reconstruction lost Finder hidden flag")
    try check(Data(contentsOf:URL(fileURLWithPath:rebuilt.path)) == bytes,"Reconstruction changed bytes")
    try reject("archive reconstruction cannot replace existing object") {_=try CacheArchive.materialize(entry,from:backups,into:objects)}
    try check(chflags(path,UInt32(UF_IMMUTABLE)) == 0,"Owned immutable setup failed")
    do {try reject("immutable flags remain denied") {_=try CacheNodeMetadata.read(SafeFilesystem.snapshot(path))}}
    catch { _=chflags(path,0);throw error }
    try check(chflags(path,0) == 0,"Owned immutable cleanup failed")
    let old=try PropertyListSerialization.data(fromPropertyList:["group":NSNumber(value:getgid()),"attributes":Data()],format:.binary,options:0)
    let decoded=try PropertyListDecoder().decode(CacheNodeMetadata.self,from:old)
    try fm.setAttributes([.posixPermissions:0o600],ofItemAtPath:path)
    try decoded.apply(to:SafeFilesystem.snapshot(path),original:SafeFilesystem.snapshot(path).identity)
    try check(lstat(path,&flags) == 0 && flags.st_flags == 0,"Old metadata receipt must restore zero flags")
    print("PASS independent bytes and hidden flag restore; old metadata receipt remains readable")
    try f.finish()
}

@MainActor func frameworkNamespaceChecks() async throws {
    let f=try OwnedFixture(),scope=try DarwinCacheScope.fixture(home:f.home)
    for leaf in ["com.apple.metal","com.apple.metalfe","com.apple.gpuarchiver"] {
        try check(scope.identifier(path:scope.root + "/" + f.identifier + "/" + leaf) == f.identifier,"Third-party framework cache was confused with an Apple-owned domain")
    }
    let root=scope.root + "/com.apple.WebKit.GPU+" + f.identifier
    try check(WebKitCacheRule.root(path:root + "/com.apple.WebKit.GPU",identifier:f.identifier,scope:scope) == root,"Exact client GPU cache is missing")
    for leaf in ["com.apple.TCC","com.apple.WebKit.Networking","com.apple.security","keychains"] {
        try check(scope.identifier(path:scope.root + "/" + f.identifier + "/" + leaf) == nil,"Protected Darwin child accepted")
        try check(WebKitCacheRule.root(path:root + "/" + leaf,identifier:f.identifier,scope:scope) == nil,"Mismatched WebKit child accepted")
    }
    try check(scope.identifier(path:scope.root + "/com.apple.Safari/com.apple.metal") == nil,"System owner accepted")
    print("PASS framework leaf exceptions remain within exact third-party C namespaces")
    try f.finish()
}

@MainActor func frameworkTransactionChecks() async throws {
    let f=try OwnedFixture(),rules:Set<String>=[DarwinCacheRule.name,WebKitCacheRule.name]
    let paths=[f.home + "/DarwinCache/" + f.identifier + "/com.apple.metal",
               f.home + "/DarwinCache/com.apple.WebKit.GPU+" + f.identifier + "/com.apple.WebKit.GPU"]
    for path in paths {
        try fm.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try Data("independent cache data".utf8).write(to:URL(fileURLWithPath:path + "/cache.bin"))
        try Data("independent hidden metadata".utf8).write(to:URL(fileURLWithPath:path + "/.hidden-metadata"))
        try check(chflags(path + "/.hidden-metadata",UInt32(UF_HIDDEN)) == 0,"Owned hidden metadata setup failed")
    }
    let engine=try f.engine(rules:rules)
    var report=try await settledApplication(engine,app:f.app)
    let deadline=Date().addingTimeInterval(10)
    while report.candidates.contains(where:{rules.contains($0.rule) && ($0.retentionReason ?? "").contains("系统组件仍在读取")}) && Date()<deadline {
        try await Task.sleep(nanoseconds:250_000_000)
        report=try await settledApplication(engine,app:f.app)
    }
    let candidates=report.selectableCandidates(includeUserData:false).filter{paths.contains($0.path)}
    try check(candidates.count == paths.count,"Exact framework caches with hidden metadata not selectable: " + report.candidates.filter{rules.contains($0.rule)}.map{$0.path + ":" + ($0.retentionReason ?? "selectable")}.joined(separator:"; "))
    let body=try selectedBody(report,app:f.app)
    let plan=try await engine.makePlan(reportID:report.id,selected:Set(candidates.map(\.id) + [body.id]),includeUserData:false)
    let batch=try await engine.execute(planID:plan.id)
    try check(batch.status == .isolated,"Framework isolation failed: " + (batch.issue ?? ""))
    for path in paths {try check(!fm.fileExists(atPath:path),"Framework cache not moved")}
    let restored=try await f.engine(rules:rules).restore(batchID:batch.id)
    try check(restored.status == .restored,"Framework recovery failed: " + (restored.issue ?? ""))
    for path in paths {
        var info=stat()
        try check(lstat(path + "/.hidden-metadata",&info) == 0 && info.st_flags == UInt32(UF_HIDDEN),"Hidden flag changed during full recovery")
        try check(Data(contentsOf:URL(fileURLWithPath:path + "/cache.bin")) == Data("independent cache data".utf8),"Recovered contents changed")
    }
    try f.finish()
    print("PASS exact Metal/WebKit child scan, plan, isolation and fresh-engine recovery preserve hidden metadata")
}
