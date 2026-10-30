import Foundation
import CryptoKit
@testable import AppSweepCore

/// Pinned upstream producers, task-owned caches, no installer scripts or apps.
@MainActor func downloadProducerChecks() async throws {
    let env = ProcessInfo.processInfo.environment
    guard let node = env["APP_SWEEP_NODE_EXECUTABLE"], let deps = env["APP_SWEEP_DOWNLOAD_DEPS"],
          let work = env["APP_SWEEP_TEST_WORK_ROOT"] else { throw CheckFailure("Pinned downloader tools and task output required") }
    for tool in ["electron", "builder"] {
        let f = try OwnedFixture(), run = f.home + "/producer", evidence = work + "/download-producer-" + tool
        for path in [run, run + "/tmp", evidence] { try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        let quoted = String(data: try JSONSerialization.data(withJSONObject: f.home, options: [.fragmentsAllowed]), encoding: .utf8)!
        let profile = "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath " + quoted + ") (literal \"/dev/null\") (literal \"/dev/tty\"))\n"
        try Data(profile.utf8).write(to: URL(fileURLWithPath: run + "/online.sb"))
        try Data((profile + "(deny network*)\n").utf8).write(to: URL(fileURLWithPath: run + "/offline.sb"))
        let script = #"""
        const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process'),http=require('node:http');
        const [deps,home,kind,pass]=process.argv.slice(2),run=home+'/producer';
        (async()=>{
          if(kind==='electron'){
            const {downloadArtifact}=require(deps+'/@electron/get');
            const name='electron-v33.4.11-darwin-arm64.zip', receipt=run+'/checksums.json';
            // Official SHASUMS256.txt pins this already downloaded archive. Only
            // transport is local; upstream cache layout and checksum validation
            // still run, and the reuse pass forbids any transport at all.
            const checksums={[name]:'9c763751c280b20ec93cecdc7f369bed876fc6728863a9ba5d7435096401f048'};
            const file=await downloadArtifact({version:'33.4.11',platform:'darwin',arch:'arm64',artifactName:'electron',cacheRoot:home+'/Library/Caches/electron',checksums,
              downloader:{download:async(url,target)=>{if(pass==='3')throw new Error('Offline reuse attempted download'); if(!url.endsWith('/'+name))throw new Error('Unexpected producer input'); await fs.promises.copyFile(process.env.APP_SWEEP_ELECTRON_ARCHIVE,target);}}});
            const hash=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
            fs.writeFileSync(receipt,JSON.stringify({[name]:hash})); console.log(file,hash);
          }else{
            const binary=require(deps+'/app-builder-bin').appBuilderPath,seven=require(deps+'/7zip-bin').path7za;
            // Keep native app-builder's download, SHA512 and extraction code;
            // serve the official verified archive from a task-owned loopback
            // server so the lifecycle acceptance is independent of internet speed.
            let server,url;
            if(pass==='3')url=fs.readFileSync(run+'/builder-url','utf8');
            else{
              server=http.createServer((request,response)=>{if(request.url!=='/nsis-resources-3.4.1.7z'){response.writeHead(404).end();return;} fs.createReadStream(process.env.APP_SWEEP_BUILDER_ARCHIVE).pipe(response);});
              await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
              url='http://127.0.0.1:'+server.address().port+'/nsis-resources-3.4.1.7z';fs.writeFileSync(run+'/builder-url',url);
            }
            try{
              await new Promise((resolve,reject)=>{
                const child=cp.spawn(binary,['download-artifact','--name','nsis-resources-3.4.1','--url',url,'--sha512','Dqd6g+2buwwvoG1Vyf6BHR1b+25QMmPcwZx40atOT57gH27rkjOei1L0JTldxZu4NFoEmW4kJgZ3DlSWVON3+Q=='],{stdio:'inherit',env:{...process.env,NO_PROXY:'127.0.0.1',no_proxy:'127.0.0.1',ELECTRON_BUILDER_CACHE:home+'/Library/Caches/electron-builder',SZA_PATH:seven}});
                const timer=setTimeout(()=>{child.kill();reject(new Error('Producer timeout'));},25000);
                child.once('error',e=>{clearTimeout(timer);reject(e)});child.once('exit',code=>{clearTimeout(timer);code===0?resolve():reject(new Error('Producer exit '+code));});
              });
            }finally{if(server)await new Promise(resolve=>server.close(resolve));}
          }
        })().catch(e=>{console.error(e.message);process.exitCode=1});
        """#
        try Data(script.utf8).write(to: URL(fileURLWithPath: run + "/produce.cjs"))
        func produce(_ pass: Int) throws {
            guard let archive = env["APP_SWEEP_ELECTRON_ARCHIVE"] else { throw CheckFailure("Official checksum-pinned Electron input required") }
            var connection: [String] = ["APP_SWEEP_ELECTRON_ARCHIVE=" + archive]
            guard let builderArchive = env["APP_SWEEP_BUILDER_ARCHIVE"] else { throw CheckFailure("Official checksum-pinned builder input required") }
            connection.append("APP_SWEEP_BUILDER_ARCHIVE=" + builderArchive)
            if let proxy = env["APP_SWEEP_TEST_HTTP_PROXY"] {
                guard let url = URL(string: proxy), url.scheme == "http", ["127.0.0.1","localhost"].contains(url.host ?? ""), url.user == nil, url.password == nil else { throw CheckFailure("Only an explicit credential-free local test proxy is allowed") }
                connection += ["HTTP_PROXY="+proxy,"HTTPS_PROXY="+proxy]
            }
            let result = try BoundedProcess.capture("/usr/bin/env", arguments: ["-i", "PATH=/usr/bin:/bin", "NODE_DISABLE_COMPILE_CACHE=1", "TMPDIR="+run+"/tmp"] + connection + [
                "/usr/bin/sandbox-exec","-f",run + (pass == 3 ? "/offline.sb" : "/online.sb"),node,run+"/produce.cjs",deps,f.home,tool,String(pass)], timeout: 30, mergeStderr: true)
            try Data(result.text.utf8).write(to: URL(fileURLWithPath: evidence + "/pass-" + String(pass) + ".log"))
            try check(result.status == 0, tool + " upstream producer failed: " + String(result.text.suffix(2500)))
        }
        try produce(1)
        let rule = tool == "electron" ? DownloadCacheRule.electronName : DownloadCacheRule.builderName
        let engine = try f.engine(rules: [rule]), report = try await engine.scanJunk()
        let items = report.selectableCandidates(includeUserData: false).filter { $0.rule == rule }
        try check(items.count == 1, "Native downloader format not recognized: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
        let item = items[0], original = try ToolCacheRule.verify(item.path, home: f.home)
        func digests(_ snapshot: FileSnapshot) throws -> [String] {
            try snapshot.tree.filter { !$0.identity.isDirectory && !$0.identity.isLink }.map {
                $0.relative + ":" + (try VerifiedFileStream.digest(SafeFilesystem.snapshot(snapshot.path + "/" + $0.relative)))
            }.sorted()
        }
        let hashes = try digests(original)
        let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let batch = try await engine.execute(planID: plan.id)
        try check(batch.status == .isolated, "Producer cache quarantine failed: " + (batch.issue ?? ""))
        try produce(2)
        try check(ToolCacheRule.verify(item.path, home: f.home).identity.inode != original.identity.inode, "Producer did not regenerate its download")
        let conflict = try await f.engine(rules: [rule]).restore(batchID: batch.id)
        try check(conflict.status == .needsAttention, "Regenerated download was overwritten")
        try fm.moveItem(atPath: item.path, toPath: run + "/regenerated")
        let restored = try await f.engine(rules: [rule]).restore(batchID: batch.id)
        try check(restored.status == .restored, "Native download restore failed")
        let actual = try ToolCacheRule.verify(item.path, home: f.home)
        try check(actual.identity.inode == original.identity.inode && digests(actual) == hashes, "Restored download changed identity or bytes")
        try produce(3)
        let receipt: [String:Any] = ["producer":tool,"transport":"Local official-checksum-pinned archive; internet transport is not under test","relativePath":String(item.path.dropFirst(f.home.count)),"rule":rule,"sha256":hashes,"originalInode":original.identity.inode,"restoredInode":actual.identity.inode,"regenerated":true,"conflictPreserved":true,"offlineReuse":true,"batch":batch.id.uuidString]
        try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted,.sortedKeys]).write(to: URL(fileURLWithPath: evidence + "/receipt.json"))
        print("PASS pinned " + tool + " producer download, quarantine, regeneration, conflict-safe exact restore and offline reuse")
        try f.finish()
    }
}
