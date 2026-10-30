#if os(macOS)
import Foundation
import XCTest
import Darwin
@testable import AppSweepCore

final class ToolCacheTests: XCTestCase, @unchecked Sendable {
    private let rule="development-tool-cache-v1"
    private func engine(_ f:RecoveryTests.Fixture) throws -> SweepEngine {
        try FileManager.default.createDirectory(atPath:f.home + "/Library/Application Support",withIntermediateDirectories:true)
        return SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule,"development-homebrew-download-v1"]),vaultPath:f.home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
    }
    private func populate(_ home:String,tool:String) throws -> String {
        let base=home + "/Library/Caches/"
        let path:String,file:String
        switch tool {
        case "go":
            path=base + "go-build/00";file=String(repeating:"0",count:64) + "-d"
            try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true)
            try Data("This directory holds cached build artifacts from the Go build system.\n".utf8).write(to:URL(fileURLWithPath:base + "go-build/README"))
        case "clang":path=base + "clang/ModuleCache/ABC123";file="Darwin-ABC123.pcm"
        default:path=base + "pip/http-v2/a";file=String(repeating:"a",count:56) + ".body"
        }
        try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true)
        try Data("regenerable tool artifact".utf8).write(to:URL(fileURLWithPath:path + "/" + file))
        return path
    }
    func testStandardToolCachesAreDiscoveredAndFreshEngineRestoresExactObjects() async throws {
        for tool in ["go","clang","pip"] {
            let f=try RecoveryTests.Fixture();defer{try? f.clean()}
            let path=try populate(f.home,tool:tool),before=try SafeFilesystem.snapshot(path),e=try engine(f)
            let report=try await e.scanJunk()
            let item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path == path},tool + ": " + report.unconfirmedIssues.joined(separator:"; "))
            XCTAssertEqual(item.rule,rule);XCTAssertNil(item.applicationPath);XCTAssertNil(item.bundleIdentifier)
            let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
            let batch=try await e.execute(planID:plan.id)
            XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
            XCTAssertFalse(FileManager.default.fileExists(atPath:path))
            let restored=try await engine(f).restore(batchID:batch.id)
            XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
            let after=try SafeFilesystem.snapshot(path)
            XCTAssertEqual(after.identity.inode,before.identity.inode)
            XCTAssertEqual(after.tree,before.tree)
            XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
        }
    }
    func testLookalikeUnexpectedContentLinksAndSharedToolCacheCannotAuthorize() async throws {
        for mode in ["lookalike","unexpected","link","shared"] {
            let f=try RecoveryTests.Fixture();defer{try? f.clean()}
            let path=try populate(f.home,tool:"go")
            if mode == "lookalike" { try FileManager.default.moveItem(atPath:f.home + "/Library/Caches/go-build",toPath:f.home + "/Library/Caches/go-build-other") }
            if mode == "unexpected" { try Data("user document".utf8).write(to:URL(fileURLWithPath:path + "/notes.txt")) }
            if mode == "link" { try FileManager.default.createSymbolicLink(atPath:path + "/escape",withDestinationPath:f.source) }
            if mode == "shared" { XCTAssertEqual(chmod(path,0o777),0) }
            let report=try await engine(f).scanJunk()
            XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.rule == rule},mode)
            XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
        }
    }
    func testCompilerAliasesAndVersionedDriversAreStillActiveProducers() {
        for command in ["/usr/bin/cc -fmodules source.m", "/usr/bin/c++ -fmodules source.mm", "/usr/bin/gcc source.c", "/usr/bin/g++ source.cc", "/opt/llvm/bin/clang-18 -fmodules source.m", "/opt/llvm/bin/clang++-18 source.mm", "/opt/gnu/bin/gcc-14 source.c"] {
            XCTAssertTrue(ToolCacheRule.isProducer(command:command,producer:.clang),command)
        }
        XCTAssertFalse(ToolCacheRule.isProducer(command:"/usr/bin/echo compiler-not-running",producer:.clang))
    }
    func testEmptyCompilerBucketsAreNotOfferedAsJunk() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        _=try populate(f.home,tool:"go")
        let empty=f.home + "/Library/Caches/go-build/ff"
        try FileManager.default.createDirectory(atPath:empty,withIntermediateDirectories:true)
        let report=try await engine(f).scanJunk()
        XCTAssertFalse(report.candidates.contains{$0.path == empty},"Go creates empty buckets; they are not a cleanup finding")
    }
    func testHomebrewDownloadIsolatedAndRestoredWithoutTouchingInstalledFiles() async throws {
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Homebrew/downloads"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        let path=root + "/" + String(repeating:"a",count:64) + "--example--1.0.arm64.bottle.tar.gz"
        let bytes=Data("independent download fixture".utf8)
        try bytes.write(to:URL(fileURLWithPath:path))
        let unfinished=path + ".incomplete",unrelated=root + "/notes.txt"
        try bytes.write(to:URL(fileURLWithPath:unfinished))
        try bytes.write(to:URL(fileURLWithPath:unrelated))
        let e=try engine(f),report=try await e.scanJunk()
        let item=try XCTUnwrap(report.selectableCandidates(includeUserData:false).first{$0.path == path})
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == unfinished || $0.path == unrelated})
        let plan=try await e.makePlan(reportID:report.id,selected:[item.id],includeUserData:false)
        let batch=try await e.execute(planID:plan.id)
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:unfinished)),bytes)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:unrelated)),bytes)
        let restored=try await engine(f).restore(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),bytes)
        XCTAssertEqual(try String(contentsOfFile:f.source + "/data",encoding:.utf8),"regenerable")
    }
    func testHomebrewDownloadRejectsDirectoryHardlinkAndSharedAncestors() throws {
        for mode in ["directory","hardlink","shared"] {
            let f=try RecoveryTests.Fixture();defer{try? f.clean()}
            let root=f.home + "/Library/Caches/Homebrew/downloads"
            try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
            let path=root + "/" + String(repeating:"b",count:64) + "--package.tar.gz"
            if mode == "directory" { try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true) }
            else { try Data("cache".utf8).write(to:URL(fileURLWithPath:path)) }
            if mode == "hardlink" { XCTAssertEqual(link(path,root + "/alias"),0) }
            if mode == "shared" { XCTAssertEqual(chmod(root,0o777),0) }
            XCTAssertThrowsError(try ToolCacheRule.verify(path,home:f.home),mode)
        }
    }
    func testHomebrewProducerAndRuleDoNotReuseGenericToolAuthority() async throws {
        for command in ["/opt/homebrew/bin/brew fetch example", "/opt/homebrew/Library/Homebrew/vendor/portable-ruby/current/bin/ruby /opt/homebrew/Library/Homebrew/brew.rb fetch example"] {
            XCTAssertTrue(ToolCacheRule.isProducer(command:command,producer:.homebrew))
        }
        XCTAssertFalse(ToolCacheRule.isProducer(command:"/usr/bin/printf brewing",producer:.homebrew))
        let f=try RecoveryTests.Fixture();defer{try? f.clean()}
        let root=f.home + "/Library/Caches/Homebrew/downloads"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        let path=root + "/" + String(repeating:"a",count:64) + "--example.tar.gz"
        try Data("download".utf8).write(to:URL(fileURLWithPath:path))
        let e=SweepEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:[rule]),vaultPath:f.vault,fixture:false)
        let report=try await e.scanJunk()
        XCTAssertFalse(report.selectableCandidates(includeUserData:true).contains{$0.path == path})
    }
    func testRealToolProducersRebuildAfterIsolationAndRestoreWithoutOverwritingTheirNewCache() async throws {
        let env=ProcessInfo.processInfo.environment
        guard env["APP_SWEEP_TOOL_CACHE_ACCEPTANCE"] == "AppSweep-General-20261016" else{throw XCTSkip("Explicit disposable VM tool consumer acceptance")}
        guard getuid() == 501,try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else{throw SweepError.denied("Requires the registered disposable VM")}
        let task="/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let go=task + "/delivery-fix-20261026/tools/go/bin/go"
        let clang=try XCTUnwrap(env["APP_SWEEP_CLANG"]),sdk=try XCTUnwrap(env["APP_SWEEP_SDK"]),developer=try XCTUnwrap(env["DEVELOPER_DIR"])
        let tools=env["APP_SWEEP_TOOL_CACHE_CONSUMER"].map{[$0]} ?? ["go","clang","pip"]
        guard !tools.isEmpty,tools.allSatisfy({["go","clang","pip"].contains($0)}) else{throw SweepError.denied("Unregistered tool consumer")}
        for tool in tools {
            let f=try RecoveryTests.Fixture();defer{try? f.clean()}
            let work=f.home + "/producer"
            try FileManager.default.createDirectory(atPath:work,withIntermediateDirectories:true)
            if tool == "go" {
                try Data("package main\nfunc main(){println(42)}\n".utf8).write(to:URL(fileURLWithPath:work + "/main.go"))
            } else if tool == "clang" {
                try Data("module SweepHeader { header \"value.h\" export * }\n".utf8).write(to:URL(fileURLWithPath:work + "/module.modulemap"))
                try Data("static inline int sweepValue(void){return 42;}\n".utf8).write(to:URL(fileURLWithPath:work + "/value.h"))
                try Data("@import SweepHeader;\nint main(void){return sweepValue()==42 ? 0 : 1;}\n".utf8).write(to:URL(fileURLWithPath:work + "/main.m"))
            }
            let pipDependencies=task + "/delivery-fix-20261026/python-deps"
            if tool == "pip" {
                let distribution=work + "/appsweep-tool-fixture-0.0.1"
                try FileManager.default.createDirectory(atPath:distribution,withIntermediateDirectories:true)
                try Data("from setuptools import setup\nsetup(name='appsweep-tool-fixture',version='0.0.1',py_modules=['toolfixture'])\n".utf8).write(to:URL(fileURLWithPath:distribution + "/setup.py"))
                try Data("value = 42\n".utf8).write(to:URL(fileURLWithPath:distribution + "/toolfixture.py"))
                _=try BoundedProcess.run("/usr/bin/tar",arguments:["-czf",work + "/appsweep-tool-fixture-0.0.1.tar.gz","-C",work,"appsweep-tool-fixture-0.0.1"],timeout:3)
            }
            func runProducer(_ executable:String,_ arguments:[String]) throws {
                let result=try BoundedProcess.capture(executable,arguments:arguments,timeout:30,mergeStderr:true)
                guard result.status == 0 else{throw SweepError.incomplete(tool + " producer failed: " + String(result.text.prefix(4096)))}
            }
            func produce(_ pass:Int) throws {
                switch tool {
                case "go":
                    try runProducer("/usr/bin/env",["GOCACHE=" + f.home + "/Library/Caches/go-build","GOPATH=" + work + "/gopath","GOTOOLCHAIN=local",go,"build","-a","-o",work + "/consumer",work + "/main.go"])
                    _=try BoundedProcess.run(work + "/consumer",arguments:[],timeout:3)
                case "clang":
                    try runProducer(clang,["-isysroot",sdk,"-fmodules","-fimplicit-module-maps","-fmodules-cache-path=" + f.home + "/Library/Caches/clang/ModuleCache","-I",work,work + "/main.m","-o",work + "/consumer"])
                    _=try BoundedProcess.run(work + "/consumer",arguments:[],timeout:3)
                default:
                    let python=["PYTHONPATH=" + pipDependencies,"PYTHONNOUSERSITE=1",developer + "/usr/bin/python3","-m","pip","--isolated","--disable-pip-version-check","--cache-dir",f.home + "/Library/Caches/pip"]
                    try runProducer("/usr/bin/env",python + ["download","--no-deps","--index-url","https://pypi.org/simple","--dest",work + "/downloads-" + String(pass),"idna==3.10"])
                    try runProducer("/usr/bin/env",python + ["wheel","--no-deps","--no-build-isolation","--wheel-dir",work + "/wheels-" + String(pass),work + "/appsweep-tool-fixture-0.0.1.tar.gz"])
                }
            }
            try produce(1)
            let e=try engine(f),report=try await e.scanJunk(),items=report.selectableCandidates(includeUserData:false).filter{$0.rule == rule}
            XCTAssertFalse(items.isEmpty,tool + ": " + report.candidates.compactMap(\.retentionReason).joined(separator:"; "))
            guard !items.isEmpty else{continue}
            if tool == "pip" {
                XCTAssertTrue(items.contains{$0.path.contains("/pip/http-v2/")},"Native modern HTTP cache must be covered")
                XCTAssertTrue(items.contains{$0.path.contains("/pip/wheels/")},"Native built-wheel cache must be covered")
            }
            let before=try Dictionary(uniqueKeysWithValues:items.map{($0.path,try SafeFilesystem.snapshot($0.path))})
            let plan=try await e.makePlan(reportID:report.id,selected:Set(items.map(\.id)),includeUserData:false)
            let batch=try await e.execute(planID:plan.id)
            XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
            XCTAssertTrue(items.allSatisfy{!FileManager.default.fileExists(atPath:$0.path)})
            try produce(2)
            XCTAssertTrue(items.contains{FileManager.default.fileExists(atPath:$0.path)},tool + " must regenerate cache after isolation")
            let regeneratedPaths=Set(items.filter{FileManager.default.fileExists(atPath:$0.path)}.map(\.path))
            let conflict=try await engine(f).restore(batchID:batch.id)
            XCTAssertEqual(conflict.status,.needsAttention,"Newly generated cache is a real path conflict, never overwrite it")
            let generated=work + "/regenerated-cache"
            try FileManager.default.createDirectory(atPath:generated,withIntermediateDirectories:true)
            for (index,item) in items.enumerated() where regeneratedPaths.contains(item.path) {
                try FileManager.default.moveItem(atPath:item.path,toPath:generated + "/" + String(index))
            }
            let restored=try await engine(f).restore(batchID:batch.id)
            XCTAssertEqual(restored.status,.restored,restored.issue ?? "")
            for item in items {
                let actual=try SafeFilesystem.snapshot(item.path),original=try XCTUnwrap(before[item.path])
                XCTAssertEqual(actual.identity.inode,original.identity.inode);XCTAssertEqual(actual.tree,original.tree)
            }
            print("TOOL_NATIVE_ACCEPTED " + tool + " items=" + String(items.count) + " bytes=" + String(items.reduce(Int64(0)){$0+$1.bytes}) + " isolated-regenerated-conflict-restored")
        }
    }

}
#endif
