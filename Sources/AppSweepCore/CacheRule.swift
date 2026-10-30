import Foundation
import CFSafety
#if canImport(SQLite3)
import SQLite3
#endif

/// Independent format validation. Only external HTTP response payloads move;
/// the source database, settings and other files are never opened for writing.
enum CacheRule {
    static let name = "foundation-http-response-v1"
    static let legacyName = "foundation-http-payload-v1"
    static func path(home: String, identifier: String) -> String { home + "/Library/Caches/" + identifier + "/fsCachedData" }
    static func matches(path: String, home: String, identifier: String) -> Bool {
        let directory = Self.path(home: home, identifier: identifier)
        return AppInspector.validIdentifier(identifier) && URL(fileURLWithPath: path).deletingLastPathComponent().path == directory && canonicalUUID(URL(fileURLWithPath: path).lastPathComponent)
    }
    static func verify(path: String, home: String, identifier: String) throws {
        let directory = Self.path(home: home, identifier: identifier)
        guard AppInspector.validIdentifier(identifier), path == directory || matches(path: path, home: home, identifier: identifier), SafetyPolicy(home: home, acceptedPlatform: false).lexicalDenial(path) == nil else { throw SweepError.denied("不在已识别的用户网络缓存范围") }
        let payload = try SafeFilesystem.snapshot(directory)
        guard payload.identity.isDirectory, payload.identity.owner == as_current_uid() else { throw SweepError.denied("网络缓存目录类型或所有者未确认，保留") }
        guard !payload.tree.isEmpty else { throw SweepError.denied("当前没有外部网络响应缓存文件；数据库等内容保留") }
        guard payload.tree.allSatisfy({ !$0.identity.isDirectory && $0.identity.owner == as_current_uid() && canonicalUUID($0.relative) }) else { throw SweepError.denied("网络缓存目录含未知内容或所有者，保留") }
        let deadline = ProcessInfo.processInfo.systemUptime + 20
        for entry in payload.tree {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("缓存元数据扫描超时，结果未确认") }
            _ = try CacheBackup.metadata(SafeFilesystem.snapshot(directory + "/" + entry.relative))
        }
        if path != directory { guard payload.tree.contains(where: { directory + "/" + $0.relative == path }) else { throw SweepError.stale("缓存响应文件已改变") } }
        let root = URL(fileURLWithPath: directory).deletingLastPathComponent().path
        var metadata: [FileSnapshot] = []
        var wal: Data?
        for suffix in ["", "-wal", "-shm"] {
            let file = root + "/Cache.db" + suffix
            if try suffix.isEmpty || SafeFilesystem.presence(file) {
                let snapshot = try SafeFilesystem.snapshot(file)
                guard !snapshot.identity.isDirectory, snapshot.identity.owner == as_current_uid() else { throw SweepError.denied("缓存元数据类型或归属未确认") }
                if suffix == "-shm", ![Int64(0), 32768].contains(snapshot.identity.size) { throw SweepError.denied("缓存共享内存结构未确认，保留") }
                try BusyInspector.ensureUnused(snapshot)
                if suffix == "-wal" { wal = try SafeFilesystem.readMetadata(file, maximumBytes: 16 * 1024 * 1024) }
                metadata.append(snapshot)
            }
        }
        let data = try SafeFilesystem.readMetadata(root + "/Cache.db", maximumBytes: 16 * 1024 * 1024)
        let references = try externalResponses(SQLiteCacheImage.committed(database: data, wal: wal))
        guard Set(payload.tree.map(\.relative)).isSubset(of: references) else { throw SweepError.denied("存在不能由网络响应元数据确认的文件，保留") }
        for snapshot in metadata + [payload] { try SafeFilesystem.verify(snapshot) }
    }
    private static func canonicalUUID(_ text: String) -> Bool { UUID(uuidString: text)?.uuidString == text }
    private static func httpURL(_ object: Any?) -> String? {
        guard let value = object as? [String: Any], value["_CFURLStringType"] as? Int == 15,
              let text = value["_CFURLString"] as? String, let url = URL(string: text),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil,
              url.user == nil, url.password == nil else { return nil }
        return text
    }
    private static func ownsHTTPResponse(request: Data, response: Data, key: String) -> Bool {
        guard let req = try? PropertyListSerialization.propertyList(from: request, format: nil) as? [String: Any],
              let res = try? PropertyListSerialization.propertyList(from: response, format: nil) as? [String: Any],
              req["Version"] as? Int == 9, res["Version"] as? Int == 1,
              let requestArray = req["Array"] as? [Any], [16, 22].contains(requestArray.count),
              let responseArray = res["Array"] as? [Any], responseArray.count == 7,
              httpURL(requestArray[1]) == key, httpURL(responseArray[0]) == key else { return false }
        // NSURLSession appends an explicit HTTP method, headers and body/stream
        // slots to the observed Version9 URLRequest representation. Only the
        // independently observed GET/no-body shape is accepted.
        if requestArray.count == 22 {
            let null = "__CFURLRequestNullTokenString__"
            guard requestArray[16] as? String == null, requestArray[17] as? Int == 2,
                  requestArray[18] as? String == "GET", requestArray[19] is [String: Any],
                  requestArray[20] as? String == null, requestArray[21] as? String == null else { return false }
        }
        // Known GET/no-body representation. Unknown methods and request bodies
        // remain untouched, regardless of the directory's name.
        for value in requestArray {
            if let string = value as? String, string != "__CFURLRequestNullTokenString__" && string != "GET" { return false }
            if value is Data { return false }
        }
        return true
    }
    private static func externalResponses(_ source: Data) throws -> Set<String> {
        #if canImport(SQLite3)
        guard source.starts(with: Data("SQLite format 3\0".utf8)), source.count >= 512,
              [UInt8(1), 2].contains(source[18]), source[18] == source[19] else { throw SweepError.denied("不是已识别的网络缓存数据库或日志格式") }
        var db: OpaquePointer?
        guard sqlite3_open(":memory:", &db) == SQLITE_OK, let db else { if let db { sqlite3_close(db) }; throw SweepError.incomplete("缓存元数据读取器不可用") }
        var mustClose = true
        defer { if mustClose { sqlite3_close(db) } }
        // Apple's SQLite module does not expose loadable extensions. The
        // deserialized connection also disables trusted schema and writes.
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
        let deadline = UnsafeMutablePointer<Double>.allocate(capacity: 1)
        deadline.initialize(to: ProcessInfo.processInfo.systemUptime + 2)
        defer { deadline.deinitialize(count: 1); deadline.deallocate() }
        sqlite3_progress_handler(db, 10_000, { context in
            guard let context else { return 1 }
            return ProcessInfo.processInfo.systemUptime > context.assumingMemoryBound(to: Double.self).pointee ? 1 : 0
        }, deadline)
        var data = source
        // The WAL has been resolved into a committed read image. Normalize only this memory copy as required
        // by sqlite3_deserialize; the source database is never changed. SQLite's
        // API also recommends 20 padding bytes for untrusted serialized input.
        data[18] = 1; data[19] = 1
        data.append(Data(repeating: 0, count: 20))
        return try data.withUnsafeMutableBytes { buffer in
            defer {
                sqlite3_progress_handler(db, 0, nil, nil)
                sqlite3_close(db); mustClose = false
            }
            guard let address = buffer.bindMemory(to: UInt8.self).baseAddress,
                  sqlite3_deserialize(db, "main", address, Int64(source.count), Int64(buffer.count), UInt32(SQLITE_DESERIALIZE_READONLY)) == SQLITE_OK,
                  sqlite3_exec(db, "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON", nil, nil, nil) == SQLITE_OK else { throw SweepError.denied("缓存数据库格式无法只读确认") }
            func rows(_ sql: String, body: (OpaquePointer) throws -> Void) throws {
                var statement: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw SweepError.denied("缓存数据库结构未确认") }
                defer { sqlite3_finalize(statement) }
                var count = 0
                while true {
                    let result = sqlite3_step(statement)
                    if result == SQLITE_DONE { return }
                    guard result == SQLITE_ROW, count < 10_000 else { throw SweepError.incomplete("缓存元数据读取失败、超时或截断") }
                    count += 1; try body(statement)
                }
            }
            func text(_ statement: OpaquePointer, _ index: Int32) -> String? {
                guard sqlite3_column_type(statement, index) == SQLITE_TEXT, let bytes = sqlite3_column_text(statement, index) else { return nil }
                return String(bytes: UnsafeBufferPointer(start: bytes, count: Int(sqlite3_column_bytes(statement, index))), encoding: .utf8)
            }
            func blob(_ statement: OpaquePointer, _ index: Int32) -> Data? {
                let count = Int(sqlite3_column_bytes(statement, index))
                guard sqlite3_column_type(statement, index) == SQLITE_BLOB, count > 0, let bytes = sqlite3_column_blob(statement, index) else { return nil }
                return Data(bytes: bytes, count: count)
            }
            var checked = false
            try rows("PRAGMA quick_check") { statement in
                guard !checked, text(statement, 0) == "ok" else { throw SweepError.denied("缓存数据库完整性未确认") }; checked = true
            }
            guard checked else { throw SweepError.denied("缓存数据库没有完整性结果") }
            var tables = Set<String>()
            try rows("SELECT name,type,sql FROM sqlite_master") { statement in
                guard let name = text(statement, 0), let type = text(statement, 1), ["table", "index"].contains(type), !(text(statement, 2)?.uppercased().contains("VIRTUAL") ?? false) else { throw SweepError.denied("缓存数据库含未知结构") }
                if type == "table" { tables.insert(name) }
            }
            guard tables == ["cfurl_cache_response", "cfurl_cache_blob_data", "cfurl_cache_receiver_data", "sqlite_sequence"] else { throw SweepError.denied("缓存数据库表结构未独立确认") }
            let expected = ["cfurl_cache_response": ["entry_ID", "version", "hash_value", "storage_policy", "request_key", "time_stamp", "partition"], "cfurl_cache_blob_data": ["entry_ID", "response_object", "request_object", "proto_props", "user_info"], "cfurl_cache_receiver_data": ["entry_ID", "isDataOnFS", "receiver_data"]]
            for (table, columns) in expected {
                var actual: [String] = []
                try rows("PRAGMA table_info(" + table + ")") { statement in guard let column = text(statement, 1) else { throw SweepError.denied("缓存列未确认") }; actual.append(column) }
                guard actual == columns else { throw SweepError.denied("缓存数据库版本或列结构未知") }
            }
            var references = Set<String>()
            try rows("SELECT r.version,r.storage_policy,r.request_key,b.request_object,b.response_object,b.user_info,d.receiver_data FROM cfurl_cache_response r JOIN cfurl_cache_blob_data b USING(entry_ID) JOIN cfurl_cache_receiver_data d USING(entry_ID) WHERE d.isDataOnFS=1") { statement in
                guard sqlite3_column_int(statement, 0) == 0, sqlite3_column_int(statement, 1) == 0,
                      sqlite3_column_type(statement, 5) == SQLITE_NULL,
                      let key = text(statement, 2), let request = blob(statement, 3), let response = blob(statement, 4),
                      let file = text(statement, 6), canonicalUUID(file),
                      ownsHTTPResponse(request: request, response: response, key: key), references.insert(file).inserted else { throw SweepError.denied("缓存响应包含未知格式、用户附加数据或共享引用") }
            }
            return references
        }
        #else
        throw SweepError.denied("当前平台没有已验证的只读缓存元数据读取器")
        #endif
    }
}
