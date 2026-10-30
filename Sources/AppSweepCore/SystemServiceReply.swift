#if os(macOS)
import Foundation
import CryptoKit

/// A checksum binds bounded parts; socket credentials and code signing still
/// authenticate the endpoint. No partial value may become an execution authority.
enum SystemServiceReply {
    static let maximumBodyBytes = 32 * 1024 * 1024
    static let chunkBytes = 32 * 1024
    private struct Hello: Codable { let protocolVersion: Int; let nonce: Data }
    static func hello(nonce: Data) throws -> Data {
        guard nonce.count == 32 else { throw SweepError.denied("系统连接挑战长度无效") }
        return try controlFrame(Hello(protocolVersion:1,nonce:nonce))
    }
    static func helloNonce(_ frame: Data) throws -> Data {
        let hello = try controlValue(Hello.self,frame:frame)
        guard hello.protocolVersion == 1, hello.nonce.count == 32 else { throw SweepError.denied("系统连接挑战版本或长度无效") }
        return hello.nonce
    }
    static func controlFrame<Value: Encodable>(_ value: Value) throws -> Data {
        let data = try CanonicalControlJSON.encode(value), n = UInt32(data.count)
        return Data([65,83,87,80,UInt8(truncatingIfNeeded:n >> 24),UInt8(truncatingIfNeeded:n >> 16),UInt8(truncatingIfNeeded:n >> 8),UInt8(truncatingIfNeeded:n)]) + data
    }
    static func controlValue<Value: Codable>(_ type: Value.Type,frame: Data) throws -> Value {
        guard frame.count >= 8, frame.count <= PrivilegedFrame.maximumPayload + 8 else { throw SweepError.denied("系统回复帧截断或超限") }
        let prefix = [UInt8](frame.prefix(8)), n = prefix[4...7].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard prefix.prefix(4) == [65,83,87,80], n > 0, Int(n) == frame.count - 8 else { throw SweepError.denied("系统回复帧头无效") }
        return try CanonicalControlJSON.decode(type,from:Data(frame.dropFirst(8)))
    }
    private struct Part: Codable {
        let protocolVersion: Int
        let requestID: UUID
        let nonce: Data
        let sequence: UInt64
        let bodyBytes: Int
        let partCount: Int
        let index: Int
        let digest: String
        let payload: Data
    }
    struct Prepared {
        fileprivate let body: Data
        fileprivate let request: PrivilegedRequest
        fileprivate let digest: String
        var partCount: Int { (body.count + chunkBytes - 1) / chunkBytes }
        func frame(at index: Int) throws -> Data {
            guard index >= 0, index < partCount else { throw SweepError.invalid("系统回复分片编号无效") }
            let start = index * chunkBytes, end = min(start + chunkBytes,body.count)
            let part = Part(protocolVersion:1,requestID:request.id,nonce:request.nonce,sequence:request.sequence,
                            bodyBytes:body.count,partCount:partCount,index:index,digest:digest,payload:body.subdata(in:start..<end))
            return try controlFrame(part)
        }
    }
    static func prepare(_ value: SystemServiceResult, for request: PrivilegedRequest) throws -> Prepared {
        try PrivilegedFrame.validate(request)
        // Histories carry at most one small page, never an aggregate of manifests.
        // Check this before JSONEncoder can allocate a response body.
        if case .batches(let page) = value { try page.validate() }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        let body = try encoder.encode(value)
        guard !body.isEmpty, body.count <= maximumBodyBytes else { throw SweepError.incomplete("系统回复超过容量，请缩小本次范围或分页读取") }
        return Prepared(body:body,request:request,digest:hash(body))
    }
    struct Reader {
        private let request: PrivilegedRequest
        private var bytes = Data()
        private var next = 0
        private var header: (size: Int, count: Int, digest: String)?
        private var finished = false
        init(request: PrivilegedRequest) throws { try PrivilegedFrame.validate(request); self.request = request }
        mutating func append(_ frame: Data) throws -> SystemServiceResult? {
            guard !finished else { throw SweepError.denied("系统回复已结束或失效") }
            do {
                let part = try controlValue(Part.self,frame:frame)
                guard part.protocolVersion == 1, part.requestID == request.id, part.nonce == request.nonce, part.sequence == request.sequence,
                      part.bodyBytes > 0, part.bodyBytes <= maximumBodyBytes,
                      part.partCount == (part.bodyBytes + chunkBytes - 1) / chunkBytes,
                      part.index == next, next < part.partCount,
                      part.digest.utf8.count == 64, part.digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SweepError.denied("系统回复属于其他请求、乱序或超过容量") }
                if let header {
                    guard part.bodyBytes == header.size, part.partCount == header.count, part.digest == header.digest else { throw SweepError.denied("系统回复分片描述发生变化") }
                } else { header = (part.bodyBytes,part.partCount,part.digest) }
                let expected = min(chunkBytes,part.bodyBytes - next * chunkBytes)
                guard part.payload.count == expected, bytes.count <= part.bodyBytes - expected else { throw SweepError.denied("系统回复分片长度不一致") }
                bytes.append(part.payload); next += 1
                guard next == part.partCount else { return nil }
                guard bytes.count == part.bodyBytes, hash(bytes) == part.digest else { throw SweepError.denied("系统回复内容核对失败") }
                let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
                let value = try decoder.decode(SystemServiceResult.self,from:bytes)
                if case .batches(let page) = value { try page.validate() }
                finished = true; bytes.removeAll(keepingCapacity:false)
                return value
            } catch {
                finished = true; bytes.removeAll(keepingCapacity:false)
                throw error
            }
        }
    }
    private static func hash(_ data: Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
}
#endif
