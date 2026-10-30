import Foundation

/// Builds a bounded, offline read image from committed SQLite pages. No source
/// connection, checkpoint or recovery is performed. Independently implemented
/// from https://www.sqlite.org/fileformat2.html#wal_file_format .
enum SQLiteCacheImage {
    static func committed(database: Data, wal: Data?) throws -> Data {
        guard let wal, !wal.isEmpty else { return database }
        let limit = 16 * 1024 * 1024
        guard database.count >= 512, database.count <= limit, wal.count >= 32, wal.count <= limit,
              database[18] == 2, database[19] == 2 else { throw SweepError.denied("缓存日志格式或大小未确认") }
        func word(_ data: Data, _ at: Int, big: Bool = true) -> UInt32 {
            var value: UInt32 = 0
            for offset in 0..<4 { value = value << 8 | UInt32(data[at + (big ? offset : 3 - offset)]) }
            return value
        }
        let magic = word(wal, 0), pageSize = Int(word(wal, 8))
        let encodedSize = Int(database[16]) * 256 + Int(database[17])
        let databasePageSize = encodedSize == 1 ? 65536 : encodedSize
        guard [UInt32(0x377f0682), 0x377f0683].contains(magic), word(wal, 4) == 3_007_000,
              pageSize >= 512, pageSize <= 65536, pageSize & (pageSize - 1) == 0,
              pageSize == databasePageSize, database.count % pageSize == 0,
              wal.count > 32, (wal.count - 32) % (pageSize + 24) == 0 else { throw SweepError.denied("缓存日志头或页面边界未确认") }
        var first: UInt32 = 0, second: UInt32 = 0
        func checksum(_ range: Range<Int>) {
            for offset in stride(from: range.lowerBound, to: range.upperBound, by: 8) {
                first = first &+ word(wal, offset, big: magic == 0x377f0683) &+ second
                second = second &+ word(wal, offset + 4, big: magic == 0x377f0683) &+ first
            }
        }
        checksum(0..<24)
        guard first == word(wal, 24), second == word(wal, 28) else { throw SweepError.denied("缓存日志头校验失败，保留") }
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        var frames: [(page: Int, start: Int)] = []
        var committedPages = 0, lastCommit = -1
        for offset in stride(from: 32, to: wal.count, by: pageSize + 24) {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("缓存日志读取超时") }
            let page = Int(word(wal, offset)), pages = Int(word(wal, offset + 4))
            guard page > 0, page <= limit / pageSize, pages <= limit / pageSize,
                  word(wal, offset + 8) == word(wal, 16), word(wal, offset + 12) == word(wal, 20) else { throw SweepError.denied("缓存日志页面或批次标识未确认") }
            checksum(offset..<(offset + 8))
            checksum((offset + 24)..<(offset + 24 + pageSize))
            guard first == word(wal, offset + 16), second == word(wal, offset + 20) else { throw SweepError.denied("缓存日志页面校验失败，保留") }
            frames.append((page, offset + 24))
            if pages > 0 { committedPages = pages; lastCommit = frames.count - 1 }
        }
        // An uncommitted or recycled tail is deliberately not guessed away.
        guard committedPages > 0, lastCommit == frames.count - 1 else { throw SweepError.denied("缓存日志存在未确认的事务尾部，保留") }
        let size = committedPages * pageSize
        var result = Data(database.prefix(size))
        if result.count < size { result.append(Data(repeating: 0, count: size - result.count)) }
        for frame in frames where frame.page <= committedPages {
            let start = (frame.page - 1) * pageSize
            result.replaceSubrange(start..<(start + pageSize), with: wal[frame.start..<(frame.start + pageSize)])
        }
        return result
    }
}
