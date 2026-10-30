import Foundation

/// Read-only lifecycle references. No rule here has a recovery registration or
/// an executable action. Shared settings never become a file deletion target.
enum UninstallRelatedReferences {
    struct Reference {
        let path: String
        let category: CandidateCategory
        let title: String
        let reason: String
    }
    struct Inspection {
        var references:[Reference]=[]
        var issues:[(path:String,message:String)]=[]
    }
    static func webKitNames(identifier: String) -> [String] {
        guard AppInspector.validIdentifier(identifier),!identifier.lowercased().hasPrefix("com.apple.") else{return []}
        return ["GPU","Networking","WebContent"].map{"com.apple.WebKit." + $0 + "+" + identifier}
    }
    static func dockReferences(_ data: Data, application: String) throws -> Bool {
        guard let values=try PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any],
              let tiles=values["persistent-apps"] as? [[String:Any]],tiles.count<=1000 else{return false}
        return tiles.contains { tile in
            guard let metadata=tile["tile-data"] as? [String:Any],let file=metadata["file-data"] as? [String:Any],
                  let text=file["_CFURLString"] as? String,let url=URL(string:text),url.isFileURL,url.host == nil || url.host == "localhost" else{return false}
            return url.standardizedFileURL.path == application
        }
    }
    static func locations(app: ApplicationIdentity, home: String, darwin: DarwinCacheScope?) throws -> Inspection {
        var result:[Reference]=[]
        var issues:[(path:String,message:String)]=[]
        let (info,_)=try AppInspector.metadata(app.path,component:false)
        for label in try UninstallDependencies.declaredLabels(info:info) {
            for path in ["/Library/PrivilegedHelperTools/" + label,"/Library/LaunchDaemons/" + label + ".plist"] {
                result.append(.init(path:path,category:.backgroundComponent,title:"系统组件 · " + label,reason:"应用声明的系统依赖；请先使用“核对独占系统组件”，不能直接移动此文件"))
            }
        }
        if let darwin {
            do {
                try darwin.verify()
                let temp=URL(fileURLWithPath:darwin.root).deletingLastPathComponent().appendingPathComponent("T").path
                for base in [darwin.root,temp] {
                    for name in webKitNames(identifier:app.bundleIdentifier) {
                        result.append(.init(path:base + "/" + name,category:.cache,title:base == temp ? "WebKit 临时数据 · " + name : "WebKit 派生缓存 · " + name,
                            reason:"按当前账户和精确应用标识发现的 WebKit 关联项；独立执行规则尚未验证，保留"))
                    }
                }
            }
            catch is CancellationError {throw CancellationError()}
            catch {issues.append((darwin.root,error.localizedDescription))}
        }
        // These fixed locations are retained clues, not ownership claims. A
        // repeated publisher/signature walk cannot grant them any action.
        if app.bundleIdentifier == "com.google.Chrome" {
            for path in [home + "/Library/Preferences/com.google.Keystone.Agent.plist",home + "/Library/LaunchAgents/com.google.keystone.agent.plist"] {
                result.append(.init(path:path,category:.backgroundComponent,title:"Google 更新组件",reason:"历史更新组件可能被其他 Google 应用共享，不能随 Chrome 删除"))
            }
            result.append(.init(path:home + "/Library/Google/Google Chrome Brand.plist",category:.userData,title:"Chrome 安装品牌记录",reason:"Chrome 各安装渠道共用的品牌记录；无法证明当前应用独占，保留"))
        }
        if app.bundleIdentifier == "com.docker.docker" {
            result.append(.init(path:"/Library/LaunchDaemons/com.docker.socket.plist",category:.backgroundComponent,title:"Docker socket 服务",reason:"Docker 系统登录服务；需核对完整生命周期，不能只移走此文件"))
        }
        let dock=home + "/Library/Preferences/com.apple.dock.plist"
        do {
            if try SafeFilesystem.presence(dock),try dockReferences(SafeFilesystem.readMetadata(dock,maximumBytes:2*1024*1024),application:app.path) {
                result.append(.init(path:dock,category:.protected,title:"Dock 中的此应用引用",reason:"仅提示精确应用引用；共享 Dock 配置始终保留，可在 Dock 中手动移除此图标"))
            }
        }
        catch is CancellationError {throw CancellationError()}
        catch {issues.append((dock,error.localizedDescription))}
        return Inspection(references:result,issues:issues)
    }
}
