import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Plaintext HTTP cache formats; unknown, pinned and encrypted entries stay.
enum FirefoxCacheFormat {
    static func permits(_ data: Data, filename: String) -> Bool {
        #if canImport(CryptoKit)
        guard data.count >= 48, data.count <= 16 * 1024 * 1024, filename.utf8.count == 40 else { return false }
        let bytes = [UInt8](data)
        // Format4 has an explicit version word and an encryption bit in the
        // trailing offset. No key access, decryption or legacy guessing.
        guard word(bytes, bytes.count - 8) == 4 else { return false }
        let encodedOffset = word(bytes, bytes.count - 4)
        guard encodedOffset & 0x80000000 == 0 else { return false }
        let offset = Int(encodedOffset)
        let chunks = (offset + 262143) / 262144
        let header = offset + 4 + chunks * 2
        let end = bytes.count - 8
        guard offset > 0, header <= end - 32,
              word(bytes, header) == 4, word(bytes, header + 28) == 0 else { return false }
        let keyLength = Int(word(bytes, header + 24))
        let keyStart = header + 32
        let elements = keyStart + keyLength + 1
        guard (1...4096).contains(keyLength), elements <= end, end - elements <= 65536,
              bytes[elements - 1] == 0,
              let key = String(bytes: bytes[keyStart..<elements-1], encoding: .utf8),
              !key.contains("\0"), let separator = key.range(of: ",:") else { return false }
        let context = String(key[..<separator.lowerBound])
        guard context == "O" || context.hasPrefix("O^"),
              context.utf8.allSatisfy({ $0 >= 33 && $0 < 127 }),
              let url = URL(string: String(key[separator.upperBound...])),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil, url.user == nil, url.password == nil,
              Insecure.SHA1.hash(data: Data(bytes[keyStart..<elements-1])).map({ String(format: "%02X", $0) }).joined() == filename else { return false }
        var fields = [String: String]()
        let parts = bytes[elements..<end].split(separator: 0, omittingEmptySubsequences: false)
        guard parts.last?.isEmpty == true, parts.count % 2 == 1 else { return false }
        let known: Set<String> = ["necko:classified", "peer-ip-address", "peer-port", "strongly-framed", "request-method", "response-head", "original-response-headers", "ctid", "net-response-time-onstart", "net-response-time-onstop", "security-info", "charset"]
        for index in stride(from: 0, to: parts.count - 1, by: 2) {
            guard let name = String(bytes: parts[index], encoding: .utf8), known.contains(name), fields[name] == nil,
                  let value = String(bytes: parts[index + 1], encoding: .utf8) else { return false }
            fields[name] = value
        }
        guard fields["request-method"] == "GET", let response = fields["response-head"],
              response.hasPrefix("HTTP/1.0 ") || response.hasPrefix("HTTP/1.1 "),
              checksum(Data(bytes[offset+4..<end])) == word(bytes, offset) else { return false }
        for chunk in 0..<chunks {
            let start = chunk * 262144, finish = min(start + 262144, offset)
            let expected = UInt16(bytes[offset + 4 + chunk * 2]) << 8 | UInt16(bytes[offset + 5 + chunk * 2])
            guard UInt16(truncatingIfNeeded: checksum(Data(bytes[start..<finish]))) == expected else { return false }
        }
        return true
        #else
        return false
        #endif
    }
    /// Independently expressed lookup2 arithmetic from Bob Jenkins' published
    /// public-domain algorithm (1997), used by this documented cache format.
    /// https://burtleburtle.net/bob/hash/evahash.html
    static func checksum(_ data: Data) -> UInt32 {
        let bytes = [UInt8](data)
        var state: [UInt32] = [0x9e3779b9, 0x9e3779b9, 0]
        func mix() {
            for shifts in [[13, 8, 13], [12, 16, 5], [3, 10, 15]] {
                for slot in 0..<3 {
                    let next = (slot + 1) % 3, previous = (slot + 2) % 3
                    state[slot] = state[slot] &- state[next] &- state[previous]
                    state[slot] ^= slot == 1 ? state[previous] << shifts[slot] : state[previous] >> shifts[slot]
                }
            }
        }
        var offset = 0
        while bytes.count - offset >= 12 {
            for slot in 0..<3 {
                for index in 0..<4 { state[slot] &+= UInt32(bytes[offset + slot * 4 + index]) << (index * 8) }
            }
            mix(); offset += 12
        }
        state[2] &+= UInt32(bytes.count)
        for index in 0..<bytes.count-offset {
            let slot = index / 4, shift = (index % 4 + (slot == 2 ? 1 : 0)) * 8
            state[slot] &+= UInt32(bytes[offset + index]) << shift
        }
        mix(); return state[2]
    }
    static func indexPermits(_ data: Data, journal: Bool) -> Bool {
        let header = journal ? 0 : 20, record = 45
        guard data.count >= header + 4, data.count <= 16 * 1024 * 1024, (data.count - header - 4) % record == 0 else { return false }
        let bytes = [UInt8](data)
        if !journal { guard word(bytes, 0) == 13, word(bytes, 8) <= 1, word(bytes, 16) == 0 else { return false } }
        let end = bytes.count - 4
        guard checksum(Data(bytes[header..<end])) == word(bytes, end) else { return false }
        for offset in stride(from: header, to: end, by: record) {
            // Pinned, dictionary and alternate-data records are retained.
            guard word(bytes, offset + 41) & 0x07000000 == 0 else { return false }
        }
        return true
    }
    private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        bytes[offset..<offset+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}
