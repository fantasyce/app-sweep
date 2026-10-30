import Foundation

enum MachOIndexError: Error, Equatable {
    case truncated, unsupportedMagic, invalidLayout, tooManySlices, headerTooLarge
}

/// Decodes declarations only. A valid index does not validate the slice bytes,
/// code signature, dependencies or eligibility for application optimization.
struct MachOContainerIndex: Equatable, Sendable {
    enum Kind: String, Equatable, Sendable { case thin32, thin64, universal32, universal64 }
    enum ByteOrder: String, Equatable, Sendable { case big, little }
    struct Slice: Equatable, Sendable {
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let offset: UInt64
        let size: UInt64
        let alignmentExponent: UInt32?
    }
    static let maximumHeaderBytes = 4096
    static let maximumSlices = 64
    let kind: Kind
    let byteOrder: ByteOrder
    let slices: [Slice]

    private struct Reader {
        let bytes: [UInt8]
        let order: ByteOrder
        func unsigned(_ offset: Int, width: Int = 4) throws -> UInt64 {
            guard offset >= 0, width == 4 || width == 8, offset <= bytes.count,
                  width <= bytes.count - offset else { throw MachOIndexError.truncated }
            var value: UInt64 = 0
            for index in 0..<width {
                let shift = (order == .little ? index : width - 1 - index) * 8
                value |= UInt64(bytes[offset + index]) << shift
            }
            return value
        }
    }
    static func parse(header: Data, fileSize: UInt64) throws -> Self {
        guard header.count <= maximumHeaderBytes else { throw MachOIndexError.headerTooLarge }
        guard fileSize > 0, UInt64(header.count) <= fileSize else { throw MachOIndexError.invalidLayout }
        // Data subsequences may have nonzero indices; normalize this bounded
        // prefix and decode bytes without aligned pointer loads.
        let bytes = [UInt8](header)
        let big = Reader(bytes:bytes,order:.big)
        let kind: Kind, order: ByteOrder
        switch try big.unsigned(0) {
        case 0xfeedface: kind = .thin32; order = .big
        case 0xcefaedfe: kind = .thin32; order = .little
        case 0xfeedfacf: kind = .thin64; order = .big
        case 0xcffaedfe: kind = .thin64; order = .little
        case 0xcafebabe: kind = .universal32; order = .big
        case 0xcafebabf: kind = .universal64; order = .big
        default: throw MachOIndexError.unsupportedMagic
        }
        let reader = Reader(bytes:bytes,order:order)
        if kind == .thin32 || kind == .thin64 {
            let size = kind == .thin64 ? 32 : 28
            guard bytes.count >= size else { throw MachOIndexError.truncated }
            let commands = try reader.unsigned(16), commandBytes = try reader.unsigned(20)
            guard UInt64(size) <= fileSize, commandBytes <= fileSize - UInt64(size),
                  commands * 8 <= commandBytes,
                  (commands == 0) == (commandBytes == 0) else { throw MachOIndexError.invalidLayout }
            if kind == .thin64, try reader.unsigned(28) != 0 { throw MachOIndexError.invalidLayout }
            return Self(kind:kind,byteOrder:order,slices:[Slice(
                cpuType:UInt32(try reader.unsigned(4)),cpuSubtype:UInt32(try reader.unsigned(8)),
                offset:0,size:fileSize,alignmentExponent:nil)])
        }
        let count = try reader.unsigned(4)
        guard count > 0 else { throw MachOIndexError.invalidLayout }
        guard count <= UInt64(maximumSlices) else { throw MachOIndexError.tooManySlices }
        let wide = kind == .universal64, stride = wide ? 32 : 20
        let end = 8 + Int(count) * stride
        guard UInt64(end) <= fileSize else { throw MachOIndexError.invalidLayout }
        guard bytes.count >= end else { throw MachOIndexError.truncated }
        var slices: [Slice] = [], identities = Set<UInt64>()
        for position in 0..<Int(count) {
            let row = 8 + position * stride
            let cpu = UInt32(try reader.unsigned(row)), subtype = UInt32(try reader.unsigned(row + 4))
            let offset = try reader.unsigned(row + 8,width:wide ? 8 : 4)
            let size = try reader.unsigned(row + (wide ? 16 : 12),width:wide ? 8 : 4)
            let alignment = UInt32(try reader.unsigned(row + (wide ? 24 : 16)))
            guard offset >= UInt64(end), offset <= fileSize, size > 0,
                  size <= fileSize - offset, alignment < 64 else { throw MachOIndexError.invalidLayout }
            let divisor = UInt64(1) << alignment
            guard offset % divisor == 0,
                  identities.insert(UInt64(cpu) << 32 | UInt64(subtype)).inserted else { throw MachOIndexError.invalidLayout }
            if wide, try reader.unsigned(row + 28) != 0 { throw MachOIndexError.invalidLayout }
            slices.append(Slice(cpuType:cpu,cpuSubtype:subtype,offset:offset,size:size,alignmentExponent:alignment))
        }
        let ordered = slices.sorted { $0.offset < $1.offset }
        for pair in zip(ordered,ordered.dropFirst()) {
            // Each addition is safe because its range was already bounded by
            // fileSize using subtraction before any endpoint was formed.
            guard pair.0.offset + pair.0.size <= pair.1.offset else { throw MachOIndexError.invalidLayout }
        }
        return Self(kind:kind,byteOrder:order,slices:slices)
    }
}
