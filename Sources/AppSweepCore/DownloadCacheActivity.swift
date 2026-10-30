import Foundation
import CFSafety
import Darwin

/// Association evidence, not execution of user scripts. A generic runtime is
/// not itself a downloader. Explicit tools, imported APIs and installed package
/// dependencies are producers. No attribution is a bounded evidence result,
/// not a proof about every future instruction a general runtime could execute.
enum DownloadCacheActivity {
    enum Relation { case related, unattributed, unknown, exited }
    private static let packages: Set<String> = ["@electron/get", "electron-download", "electron-builder", "app-builder-lib", "app-builder-bin", "@electron/packager", "electron-packager"]
    static func relation(pid: Int32, home: String) -> Relation {
        do { return try inspect(pid: pid, home: home) }
        catch { return kill(pid, 0) == -1 && errno == ESRCH ? .exited : .unknown }
    }
    #if DEBUG
    static func diagnostic(pid: Int32, home: String) -> String {
        var reason=""
        do { let relation=try inspect(pid:pid,home:home,observe:{reason=$0});return String(describing:relation) + (reason.isEmpty ? "" : "-" + reason) }
        catch { return error.localizedDescription }
    }
    /// Private UUID fixture scoping only; never used by a release or real-home
    /// transaction. A changed process title must not hide the fixture's cwd.
    static func referencesFixture(pid: Int32, home: String) -> Bool {
        var birth=ASProcessBirth(),bytes=[CChar](repeating:0,count:262144),cwd=[CChar](repeating:0,count:4096),count=0
        guard as_process_birth(pid,&birth)==0,as_process_arguments(pid,&birth,&bytes,bytes.count,&count,&cwd,cwd.count)>=0 else{return true}
        let working=String(cString:cwd)
        return SafetyPolicy.contains(home,working) || Data(bytes:bytes,count:count).range(of:Data(home.utf8)) != nil
    }
    #endif
    private static func inspect(pid: Int32, home: String, observe: ((String)->Void)? = nil) throws -> Relation {
        var birth = ASProcessBirth(), bytes = [CChar](repeating: 0, count: 262144), cwd = [CChar](repeating: 0, count: 4096), count = 0
        guard as_process_birth(pid, &birth) == 0 else { throw SweepError.incomplete("运行时身份未确认") }
        let hints=as_process_arguments(pid, &birth, &bytes, bytes.count, &count, &cwd, cwd.count)
        guard hints >= 0 else { throw SweepError.incomplete("运行时参数未确认") }
        if hints & 4 != 0 {observe?("module-input");return .related}
        let data = Data(bytes: bytes, count: count)
        let arguments = try data.split(separator: 0, omittingEmptySubsequences: false).dropLast().map { part -> String in
            guard let value = String(data: part, encoding: .utf8) else { throw SweepError.incomplete("运行时参数未确认") }; return value
        }
        guard arguments.count >= 2, ["node", "nodejs"].contains(URL(fileURLWithPath: arguments[0]).lastPathComponent) else { throw SweepError.incomplete("运行时入口身份未确认") }
        let cacheRoots = [home + "/Library/Caches/electron", home + "/Library/Caches/electron-builder"]
        if arguments.dropFirst().contains(where: { value in
            packages.contains(where: { value.contains("/" + $0 + "/") }) || cacheRoots.contains(where: { value == $0 || value.hasPrefix($0 + "/") })
        }) { observe?("explicit-entry-specifier");return .related }
        // Concrete command arguments retain priority even if optional runtime
        // settings or inline code prevent inspection of a script file.
        guard hints & 2 == 0 else { throw SweepError.incomplete("运行时使用了额外加载设置") }
        let working = String(cString: cwd), started = Double(birth.started_seconds) + Double(birth.started_microseconds) / 1_000_000
        let deadline = Date().addingTimeInterval(1)
        var budget = 8 * 1024 * 1024
        var readCache:[String:(Data,FileIdentity)]=[:]
        func read(_ path: String) throws -> Data {
            try ScanCancellation.check()
            guard Date() < deadline, budget > 0 else { throw SweepError.incomplete("运行时依赖检查达到上限") }
            let url = URL(fileURLWithPath: path), parent = try SafeDirectory(path: url.deletingLastPathComponent().path)
            let identity = try parent.identity(url.lastPathComponent)
            if let cached=readCache[path] {
                guard cached.1 == identity else {throw SweepError.stale("运行时资料已改变")}
                return cached.0
            }
            guard Double(identity.modifiedSeconds) + Double(identity.modifiedNanoseconds) / 1_000_000_000 <= started,
                  Double(identity.changedSeconds) + Double(identity.changedNanoseconds) / 1_000_000_000 <= started else { throw SweepError.incomplete("运行时启动后依赖已变化") }
            let result = try SafeFilesystem.readMetadata(path, maximumBytes: min(budget, 4 * 1024 * 1024))
            guard try parent.identity(url.lastPathComponent) == identity else { throw SweepError.stale("运行时资料已改变") }
            budget -= result.count;readCache[path]=(result,identity);return result
        }
        var index = 1
        let harmless: Set<String> = ["--no-warnings", "--enable-source-maps", "--experimental-strip-types"]
        while index < arguments.count && harmless.contains(arguments[index]) { index += 1 }
        guard index < arguments.count, !arguments[index].hasPrefix("-"), arguments[index] != "" else { throw SweepError.incomplete("运行时启动选项尚未确认") }
        guard !arguments[index].split(separator:"/").contains("..") else { throw SweepError.incomplete("运行时入口含路径别名") }
        let script = URL(fileURLWithPath: arguments[index].hasPrefix("/") ? arguments[index] : working + "/" + arguments[index]).standardizedFileURL.path
        var root = URL(fileURLWithPath: script).deletingLastPathComponent().path
        var found = false
        for _ in 0..<16 {
            if try SafeFilesystem.presence(root + "/package.json") { found = true; break }
            if root == "/" { break }; root = URL(fileURLWithPath: root).deletingLastPathComponent().path
        }
        // Standalone scripts need not have a package manifest.
        if !found { root = "" }
        // Positive project declarations remain useful even when a bundled
        // entry is too large or a later optional import cannot be inspected.
        if !root.isEmpty,let bytes=try? read(root + "/package.json"),
           let manifest=(try? JSONSerialization.jsonObject(with:bytes)) as? [String:Any] {
            if let name=manifest["name"] as? String,packages.contains(name) {return .related}
            for field in ["dependencies","optionalDependencies","peerDependencies","devDependencies"] {
                if let dependencies=manifest[field] as? [String:Any],!packages.isDisjoint(with:dependencies.keys) {return .related}
            }
        }
        guard ["js", "cjs", "mjs", "ts"].contains(URL(fileURLWithPath: script).pathExtension),
              let source = String(data: try read(script), encoding: .utf8) else { throw SweepError.incomplete("运行时入口无法读取") }
        // Follow local modules too: an innocently named entry may have already
        // loaded a downloader indirectly and be waiting between cache opens.
        // Literal imports add relationship evidence. Generic loader syntax does
        // not itself attribute an unrelated server to a download cache.
        let imports = try [
            #"\b(?:require|import)\s*\(\s*['"]((?:\\.|[^'"\r\n\\])+)['"]\s*\)"#,
            #"\b(?:import|export)\s+(?:[^;\r\n]{0,1024}?\s+from\s*)?['"]((?:\\.|[^'"\r\n\\])+)['"]"#
        ].map { try NSRegularExpression(pattern:$0) }
        func resolve(_ dependency: String, from directory: String) -> String? {
            var ancestor = directory
            for _ in 0..<24 {
                let path = ancestor + "/node_modules/" + dependency
                if fmExists(path + "/package.json") { return path }
                if ancestor == "/" { break }; ancestor = URL(fileURLWithPath: ancestor).deletingLastPathComponent().path
            }
            return nil
        }
        var scripts = [(script, source)], visitedScripts = Set<String>(), importedPackages: [(String, String)] = []
        let builtins: Set<String> = ["assert","async_hooks","buffer","child_process","cluster","console","constants","crypto","dgram","diagnostics_channel","dns","events","fs","http","http2","https","module","net","os","path","perf_hooks","process","punycode","querystring","readline","repl","stream","string_decoder","sys","timers","tls","trace_events","tty","url","util","v8","vm","wasi","worker_threads","zlib","test","inspector"]
        while let (path, text) = scripts.popLast() {
            if !visitedScripts.insert(path).inserted { continue }
            guard visitedScripts.count <= 256 else { throw SweepError.incomplete("运行模块数量达到检查上限") }
            // Only explicit package specifiers/paths attribute a producer. A
            // bundled runtime may mention Electron in platform detection/docs.
            let literals=text.replacingOccurrences(of:#"\/"#,with:"/")
            if packages.contains(where: { package in
                let slash = "/" + package
                let doubleQuoted = "\"" + package + "\""
                let singleQuoted = "'" + package + "'"
                let spellings: [String] = [slash + "/", slash + "\"", slash + "'", doubleQuoted, singleQuoted]
                return spellings.contains { literals.contains($0) }
            }) { observe?("explicit-source-specifier");return .related }
            let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
            let matches = imports.flatMap { $0.matches(in:text,range:NSRange(text.startIndex...,in:text)) }
            for match in matches {
                guard let range = Range(match.range(at: 1), in: text) else { throw SweepError.incomplete("模块引用无法读取") }
                let module = String(text[range]).replacingOccurrences(of:#"\/"#,with:"/"); if module.contains("\\") { throw SweepError.incomplete("模块引用转义未确认") }
                if module.hasPrefix("node:") || builtins.contains(String(module.split(separator: "/").first ?? "")) { continue }
                if module.hasPrefix(".") || module.hasPrefix("/") {
                    // Validate any traversed directory before resolving ..;
                    // normalisation must not hide an alias in the original path.
                    var resolvedParts = (module.hasPrefix("/") ? "" : parent).split(separator:"/").map(String.init)
                    for component in module.split(separator:"/") {
                        if component == "." {continue}
                        if component == ".." {
                            _ = try SafeDirectory(path:"/" + resolvedParts.joined(separator:"/"))
                            guard !resolvedParts.isEmpty else {throw SweepError.incomplete("模块祖先路径未确认")}
                            resolvedParts.removeLast()
                        } else {resolvedParts.append(String(component))}
                    }
                    let base = "/" + resolvedParts.joined(separator:"/")
                    guard let target = [base,base + ".js",base + ".json",base + "/index.js"].first(where: {
                        var directory: ObjCBool = false
                        return FileManager.default.fileExists(atPath: $0, isDirectory: &directory) && !directory.boolValue
                    }) else { throw SweepError.incomplete("本地模块未找到") }
                    let resolved = target // readMetadata rejects links, including ancestors.
                    if resolved.hasSuffix(".json") { _ = try JSONSerialization.jsonObject(with: read(resolved)); continue }
                    guard ["js","cjs","mjs","ts"].contains(URL(fileURLWithPath: resolved).pathExtension), let contents = String(data: try read(resolved), encoding: .utf8) else { throw SweepError.incomplete("本地模块格式未确认") }
                    scripts.append((resolved,contents))
                } else {
                    let pieces = module.split(separator: "/")
                    let package = module.hasPrefix("@") ? pieces.prefix(2).joined(separator: "/") : String(pieces.first ?? "")
                    importedPackages.append((package,parent))
                    // A manifest can omit an imported implementation's API use.
                    // Read the selected ordinary entry too; never run its code.
                    if let directory=resolve(package,from:parent) {
                        let manifest=try JSONSerialization.jsonObject(with:read(directory + "/package.json")) as? [String:Any]
                        guard let manifest else {throw SweepError.incomplete("模块入口清单未确认")}
                        // An explicit package declaration is positive evidence,
                        // regardless of whether its export shape is understood.
                        if let name=manifest["name"] as? String,packages.contains(name) {return .related}
                        for field in ["dependencies","optionalDependencies","peerDependencies"] {
                            if let dependencies=manifest[field] as? [String:Any],!packages.isDisjoint(with:dependencies.keys) {return .related}
                        }
                        let suffix=pieces.dropFirst(package.hasPrefix("@") ? 2 : 1).joined(separator:"/")
                        let entry:String
                        if let exports=manifest["exports"] {
                            guard suffix.isEmpty,let path=exports as? String,path.hasPrefix("./") else {throw SweepError.incomplete("模块导出入口尚未确认")}
                            entry=path
                        } else {entry=suffix.isEmpty ? (manifest["main"] as? String ?? "index.js") : suffix}
                        let base=URL(fileURLWithPath:directory + "/" + entry).standardizedFileURL.path
                        guard SafetyPolicy.contains(directory,base) else {throw SweepError.incomplete("模块入口超出其安装目录")}
                        guard let target=[base,base + ".js",base + "/index.js"].first(where: {
                            var directory:ObjCBool=false
                            return FileManager.default.fileExists(atPath:$0,isDirectory:&directory) && !directory.boolValue
                        }),["js","cjs","mjs","ts"].contains(URL(fileURLWithPath:target).pathExtension) else {throw SweepError.incomplete("模块入口尚未确认")}
                        guard let contents=String(data:try read(target),encoding:.utf8) else{throw SweepError.incomplete("模块入口无法读取")}
                        scripts.append((target,contents))
                    } else {throw SweepError.incomplete("运行引用模块未找到")}
                }
            }
        }
        var pending = root.isEmpty ? [] : [root], seen = Set<String>()
        for (package,directory) in importedPackages {
            if packages.contains(package) { observe?("import-" + package);return .related }
            if let resolved=resolve(package,from:directory) {pending.append(resolved)}
        }
        while let directory = pending.popLast() {
            guard seen.count < 256 else { throw SweepError.incomplete("运行依赖数量达到检查上限") }
            if !seen.insert(directory).inserted { continue }
            guard let manifest = try JSONSerialization.jsonObject(with: read(directory + "/package.json")) as? [String: Any],
                  let name = manifest["name"] as? String, !name.isEmpty else { throw SweepError.incomplete("运行依赖清单未确认") }
            if packages.contains(name) {observe?("package-" + name);return .related}
            for field in ["dependencies", "optionalDependencies", "peerDependencies"] + (directory == root ? ["devDependencies"] : []) {
                guard let value = manifest[field] else { continue }
                guard let dependencies = value as? [String: String] else { throw SweepError.incomplete("运行依赖清单格式未确认") }
                for dependency in dependencies.keys.sorted() {
                    guard dependency.range(of: #"^(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_][A-Za-z0-9_.-]*$"#, options: .regularExpression) != nil else { throw SweepError.incomplete("运行依赖标识未确认") }
                    if packages.contains(dependency) {observe?("declared-dependency-" + dependency);return .related}
                    if let resolved = resolve(dependency,from:directory) { pending.append(resolved) }
                    else if field == "dependencies" {throw SweepError.incomplete("运行依赖未找到")}
                    // Uninstalled optional/dev/peer dependencies do not run. The
                    // declared name was still checked for a producer above.
                }
            }
        }
        for (path,cached) in readCache {
            let url=URL(fileURLWithPath:path),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
            guard try parent.identity(url.lastPathComponent) == cached.1 else {throw SweepError.stale("运行时资料已改变")}
        }
        var current = ASProcessBirth()
        guard as_process_birth(pid, &current) == 0, current.started_seconds == birth.started_seconds,
              current.started_microseconds == birth.started_microseconds else { throw SweepError.incomplete("运行时身份已变化") }
        return .unattributed
    }
    private static func fmExists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }
}
