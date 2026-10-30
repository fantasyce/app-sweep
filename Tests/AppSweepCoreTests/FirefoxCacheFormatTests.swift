#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class FirefoxCacheFormatTests: XCTestCase {
    private let filename = "4D98F8ADC63F3FDCAC73E06B81C4BD839480324C"
    private func fixture() throws -> Data {
        try Data(contentsOf: NativeAcceptanceTests.NativeFixture.resource("FirefoxCache4", extension: "response"))
    }
    private func word(_ bytes: Data, _ offset: Int) -> UInt32 {
        bytes[offset..<offset+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
    private func put(_ value: UInt32, into bytes: inout Data, at offset: Int) {
        for i in 0..<4 { bytes[offset+i] = UInt8(truncatingIfNeeded: value >> (24-i*8)) }
    }
    private func rewrite(_ bytes: inout Data, flags: UInt32? = nil, version: UInt32? = nil) {
        let offset = Int(word(bytes, bytes.count-4))
        let header = offset + 4 + 2*((offset+262143)/262144)
        if let flags { put(flags, into: &bytes, at: header+28) }
        if let version { put(version, into: &bytes, at: header); put(version, into: &bytes, at: bytes.count-8) }
        let hash = FirefoxCacheFormat.checksum(Data(bytes[offset+4..<bytes.count-8]))
        put(hash, into: &bytes, at: offset)
    }
    func testRealOfficialFirefoxPlaintextHTTPEntryIsRecognized() throws {
        XCTAssertTrue(FirefoxCacheFormat.permits(try fixture(), filename: filename))
    }
    func testPublishedChecksumMatchesIndependentNativeBytes() throws {
        let bytes = try fixture(); let offset = Int(word(bytes, bytes.count-4))
        XCTAssertEqual(FirefoxCacheFormat.checksum(Data(bytes[offset+4..<bytes.count-8])), word(bytes, offset))
        XCTAssertEqual(FirefoxCacheFormat.checksum(Data()), 0xBD49D10D)
    }
    func testPinnedEncryptedUnknownAndCorruptEntriesStay() throws {
        let original = try fixture()
        XCTAssertTrue(FirefoxCacheFormat.permits(original, filename: filename))
        for flags: UInt32 in [1,2,4,0x80000000] {
            var bytes = original; rewrite(&bytes, flags: flags)
            XCTAssertFalse(FirefoxCacheFormat.permits(bytes, filename: filename))
        }
        var encrypted = original; put(word(encrypted,encrypted.count-4) | 0x80000000, into:&encrypted, at:encrypted.count-4)
        XCTAssertFalse(FirefoxCacheFormat.permits(encrypted, filename:filename))
        var unknown = original; rewrite(&unknown, version:5)
        XCTAssertFalse(FirefoxCacheFormat.permits(unknown, filename:filename))
        var corrupt = original; corrupt[0] ^= 1
        XCTAssertFalse(FirefoxCacheFormat.permits(corrupt, filename:filename))
        XCTAssertFalse(FirefoxCacheFormat.permits(original, filename:String(repeating:"A",count:40)))
    }
    func testTruncatedAndOverflowingOffsetsStay() throws {
        let original = try fixture()
        for count in [0,1,7,8,32,100,original.count-1] {
            XCTAssertFalse(FirefoxCacheFormat.permits(Data(original.prefix(count)), filename:filename))
        }
        var bytes=original; put(UInt32.max,into:&bytes,at:bytes.count-4)
        XCTAssertFalse(FirefoxCacheFormat.permits(bytes,filename:filename))
    }
    func testKnownEmptyIndexAndJournalAreRecognizedButUnknownHeadersStay() {
        // Index v13: five network-order words, then record checksum. No records.
        var index=Data(repeating:0,count:24); put(13,into:&index,at:0); put(0xBD49D10D,into:&index,at:20)
        XCTAssertTrue(FirefoxCacheFormat.indexPermits(index,journal:false))
        var journal=Data(repeating:0,count:4); put(0xBD49D10D,into:&journal,at:0)
        XCTAssertTrue(FirefoxCacheFormat.indexPermits(journal,journal:true))
        var encrypted=index; put(1,into:&encrypted,at:16)
        XCTAssertFalse(FirefoxCacheFormat.indexPermits(encrypted,journal:false))
        var unknown=index; put(14,into:&unknown,at:0)
        XCTAssertFalse(FirefoxCacheFormat.indexPermits(unknown,journal:false))
        XCTAssertFalse(FirefoxCacheFormat.indexPermits(index.dropLast(),journal:false))
    }
}
#endif
