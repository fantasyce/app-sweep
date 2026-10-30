import Foundation
import XCTest
@testable import AppSweepCore

final class MachOContainerIndexTests: XCTestCase {
    private let arm64: UInt32 = 0x0100_000c
    private let intel64: UInt32 = 0x0100_0007
    private struct Entry {
        var cpu: UInt32
        var subtype: UInt32 = 0
        var offset: UInt64
        var size: UInt64 = 512
        var alignment: UInt32 = 12
        var reserved: UInt32 = 0
    }
    private func word(_ value: UInt64, bytes: Int = 4, little: Bool = false) -> [UInt8] {
        let shifts = little ? Array(0..<bytes) : Array((0..<bytes).reversed())
        return shifts.map { UInt8(truncatingIfNeeded:value >> ($0 * 8)) }
    }
    private func thin(is64: Bool = true, little: Bool = true, cpu: UInt32? = nil,
                      commands: UInt32 = 1, commandBytes: UInt32 = 16) -> Data {
        var bytes = word(is64 ? 0xfeedfacf : 0xfeedface,little:little)
        let fields: [UInt32] = [cpu ?? arm64,0,2,commands,commandBytes,0]
        for value in fields { bytes += word(UInt64(value),little:little) }
        if is64 { bytes += word(0,little:little) }
        return Data(bytes)
    }
    private func fat(_ entries: [Entry], is64: Bool = false) -> Data {
        var bytes = word(is64 ? 0xcafebabf : 0xcafebabe) + word(UInt64(entries.count))
        for entry in entries {
            bytes += word(UInt64(entry.cpu)) + word(UInt64(entry.subtype))
            bytes += word(entry.offset,bytes:is64 ? 8 : 4) + word(entry.size,bytes:is64 ? 8 : 4)
            bytes += word(UInt64(entry.alignment))
            if is64 { bytes += word(UInt64(entry.reserved)) }
        }
        return Data(bytes)
    }
    private func rejected(_ header: Data, size: UInt64 = 32_768,
                          error: MachOIndexError, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try MachOContainerIndex.parse(header:header,fileSize:size),file:file,line:line) {
            XCTAssertEqual($0 as? MachOIndexError,error,file:file,line:line)
        }
    }
    func testNativeThin64AndBigEndianThin32() throws {
        let native = try MachOContainerIndex.parse(header:thin(),fileSize:128)
        XCTAssertEqual(native.kind,.thin64); XCTAssertEqual(native.byteOrder,.little)
        XCTAssertEqual(native.slices.count,1)
        XCTAssertEqual(native.slices[0].cpuType,arm64); XCTAssertEqual(native.slices[0].cpuSubtype,0)
        XCTAssertEqual(native.slices[0].offset,0); XCTAssertEqual(native.slices[0].size,128)
        XCTAssertNil(native.slices[0].alignmentExponent)
        let legacy = try MachOContainerIndex.parse(header:thin(is64:false,little:false,cpu:18),fileSize:128)
        XCTAssertEqual(legacy.kind,.thin32); XCTAssertEqual(legacy.byteOrder,.big)
        XCTAssertEqual(legacy.slices[0].cpuType,18)
    }
    func testBothThinWidthsHandleBothByteOrders() throws {
        for is64 in [false,true] {
            for little in [false,true] {
                let value = try MachOContainerIndex.parse(header:thin(is64:is64,little:little,cpu:intel64),fileSize:128)
                XCTAssertEqual(value.kind,is64 ? .thin64 : .thin32)
                XCTAssertEqual(value.byteOrder,little ? .little : .big)
                XCTAssertEqual(value.slices[0].cpuType,intel64)
            }
        }
    }
    func testCanonicalUniversal32KeepsDeclaredOrderAndSubtypes() throws {
        let value = try MachOContainerIndex.parse(header:fat([
            Entry(cpu:intel64,subtype:3,offset:8192),Entry(cpu:arm64,offset:4096)
        ]),fileSize:16_384)
        XCTAssertEqual(value.kind,.universal32); XCTAssertEqual(value.byteOrder,.big)
        XCTAssertEqual(value.slices.map(\.cpuType),[intel64,arm64])
        XCTAssertEqual(value.slices.map(\.offset),[8192,4096])
        XCTAssertEqual(value.slices[0].cpuSubtype,3)
        XCTAssertEqual(value.slices.map(\.alignmentExponent),[12,12])
    }
    func testUniversal64UsesFullWidthOffsetsAndLengths() throws {
        let offset: UInt64 = 1 << 34, length: UInt64 = (1 << 32) + 512
        let value = try MachOContainerIndex.parse(header:fat([Entry(cpu:arm64,offset:offset,size:length,alignment:14)],is64:true),fileSize:offset + length)
        XCTAssertEqual(value.kind,.universal64)
        XCTAssertEqual(value.slices[0].offset,offset); XCTAssertEqual(value.slices[0].size,length)
    }
    func testDistinctSubtypesAndUnknownCPUAreDeclarationsOnly() throws {
        let value = try MachOContainerIndex.parse(header:fat([
            Entry(cpu:arm64,offset:4096),Entry(cpu:arm64,subtype:2,offset:8192),
            Entry(cpu:0x1234_5678,subtype:0x8000_0001,offset:12_288)
        ]),fileSize:16_384)
        XCTAssertEqual(value.slices.map(\.cpuSubtype),[0,2,0x8000_0001])
        XCTAssertEqual(value.slices[2].cpuType,0x1234_5678)
    }
    func testMaximum64DeclaredSlicesFitsBoundedHeader() throws {
        let entries = (0..<64).map { Entry(cpu:UInt32($0 + 1),offset:UInt64($0 + 1) * 4096) }
        let value = try MachOContainerIndex.parse(header:fat(entries,is64:true),fileSize:300_000)
        XCTAssertEqual(value.slices.count,64)
        rejected(Data(word(0xcafebabe) + word(65)),error:.tooManySlices)
        rejected(Data(word(0xcafebabf) + word(UInt64(UInt32.max))),error:.tooManySlices)
    }
    func testHeaderBudgetAndDeclaredFileLengthAreEnforced() {
        rejected(Data(repeating:0,count:4097),size:8192,error:.headerTooLarge)
        rejected(thin(),size:12,error:.invalidLayout)
        rejected(Data(),size:0,error:.invalidLayout)
    }
    func testTruncatedHeadersNeverProduceAnEmptySuccessfulIndex() {
        for count in 0..<4 { rejected(Data(thin().prefix(count)),error:.truncated) }
        for count in 4..<32 { rejected(Data(thin().prefix(count)),error:.truncated) }
        for count in 4..<28 { rejected(Data(thin(is64:false).prefix(count)),error:.truncated) }
        let universal = fat([Entry(cpu:arm64,offset:4096)])
        for count in 4..<universal.count { rejected(Data(universal.prefix(count)),error:.truncated) }
    }
    func testUnknownAndNoncanonicalUniversalMagicRemainUnsupported() {
        rejected(Data([0x7f,0x45,0x4c,0x46]),error:.unsupportedMagic)
        rejected(Data([0xbe,0xba,0xfe,0xca] + word(1,little:true)),error:.unsupportedMagic)
        rejected(Data([0xbf,0xba,0xfe,0xca] + word(1,little:true)),error:.unsupportedMagic)
    }
    func testZeroSlicesAndZeroLengthSlicesAreInvalid() {
        rejected(fat([]),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:4096,size:0)]),error:.invalidLayout)
    }
    func testOverlappingOrTableContainedSlicesAreInvalid() {
        rejected(fat([Entry(cpu:arm64,offset:4096,size:8192),Entry(cpu:intel64,offset:8192)]),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:16,alignment:0)]),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:0,alignment:0)],is64:true),error:.invalidLayout)
    }
    func testExactEndBoundaryIsAllowedButOutOfBoundsAndOverflowAreNot() throws {
        XCTAssertNoThrow(try MachOContainerIndex.parse(header:fat([Entry(cpu:arm64,offset:4096,size:512)]),fileSize:4608))
        rejected(fat([Entry(cpu:arm64,offset:4096,size:513)]),size:4608,error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:8192)]),size:4608,error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:UInt64.max - 15,size:32,alignment:0)],is64:true),size:UInt64.max,error:.invalidLayout)
    }
    func testMisalignmentAndInvalidShiftAreRejected() {
        rejected(fat([Entry(cpu:arm64,offset:4097)]),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:4096,alignment:64)],is64:true),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:4096,alignment:UInt32.max)]),error:.invalidLayout)
    }
    func testDuplicateCPUSubtypePairsAndReservedBitsAreRejected() {
        rejected(fat([Entry(cpu:arm64,offset:4096),Entry(cpu:arm64,offset:8192)]),error:.invalidLayout)
        rejected(fat([Entry(cpu:arm64,offset:4096,reserved:1)],is64:true),error:.invalidLayout)
        var header = thin(); header[28] = 1
        rejected(header,size:128,error:.invalidLayout)
    }
    func testThinLoadCommandDeclarationsMustFitFileAndMinimumCommandWidth() {
        rejected(thin(commands:2,commandBytes:8),size:128,error:.invalidLayout)
        rejected(thin(commands:0,commandBytes:8),size:128,error:.invalidLayout)
        rejected(thin(commands:UInt32.max,commandBytes:UInt32.max),size:UInt64.max,error:.invalidLayout)
        rejected(thin(commandBytes:100),size:128,error:.invalidLayout)
        XCTAssertNoThrow(try MachOContainerIndex.parse(header:thin(commands:0,commandBytes:0),fileSize:32))
    }
    func testDataSubviewWithNonzeroStartIndexIsParsedWithoutUnalignedLoads() throws {
        let bytes = Data([0xaa,0xbb]) + thin()
        let view = bytes.dropFirst(2)
        let value = try MachOContainerIndex.parse(header:view,fileSize:128)
        XCTAssertEqual(value.slices[0].cpuType,arm64)
    }
    func testDeterministicCorruptionsEitherRejectOrSatisfyRangeInvariants() throws {
        let seed = fat([Entry(cpu:arm64,offset:4096),Entry(cpu:intel64,offset:8192)],is64:true)
        var state: UInt64 = 0x19a7_4cd1
        for turn in 0..<2000 {
            var bytes = seed
            state = state &* 6364136223846793005 &+ 1
            let position = Int(state % UInt64(bytes.count))
            bytes[position] ^= UInt8(truncatingIfNeeded:state >> 17)
            if turn % 5 == 0 { bytes = Data(bytes.prefix(Int(state % UInt64(bytes.count + 1)))) }
            do {
                let value = try MachOContainerIndex.parse(header:bytes,fileSize:16_384)
                XCTAssertFalse(value.slices.isEmpty); XCTAssertLessThanOrEqual(value.slices.count,64)
                let ordered = value.slices.sorted { $0.offset < $1.offset }
                let bounded = ordered.allSatisfy { $0.offset <= 16_384 && $0.size > 0 && $0.size <= 16_384 - $0.offset }
                XCTAssertTrue(bounded)
                guard bounded else { continue }
                for pair in zip(ordered,ordered.dropFirst()) { XCTAssertLessThanOrEqual(pair.0.offset + pair.0.size,pair.1.offset) }
            } catch { XCTAssertTrue(error is MachOIndexError) }
        }
    }
}
