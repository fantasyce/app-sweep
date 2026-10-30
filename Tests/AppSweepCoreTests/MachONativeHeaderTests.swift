import Foundation
import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#endif

/// Private VM inputs contain only format headers, never application code or
/// resource bodies. The independent preparer checks signatures and lipo output.
final class MachONativeHeaderTests: XCTestCase {
    private struct Report: Decodable {
        let schemaVersion: Int
        let records: [Record]
    }
    private struct Record: Decodable {
        let application: String
        let fileSize: UInt64
        let header: Data
        let lipoCPUTypes: [UInt32]
        let rows: [Row]
        let sliceHeaders: [Data]
    }
    private struct Row: Decodable {
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let offset: UInt64
        let size: UInt64
        let alignmentExponent: UInt32?
    }
    func testPreparedSignedApplicationHeadersMatchNativeTools() throws {
        #if os(macOS)
        let expected = "/Users/localtest/AppSweepAcceptanceGeneral-20261016/macho-inspection.noindex/native-headers.json"
        guard getuid() == 501, NSHomeDirectory() == "/Users/localtest",
              ProcessInfo.processInfo.environment["APP_SWEEP_MACHO_HEADER_FIXTURE"] == expected else { throw XCTSkip("Prepared disposable VM read-only Mach-O headers only") }
        let fd = open(expected,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw CocoaError(.fileReadUnknown) }
        let handle = FileHandle(fileDescriptor:fd,closeOnDealloc:true)
        defer { try? handle.close() }
        var before = stat()
        guard fstat(fd,&before) == 0, before.st_mode & 0o170000 == 0o100000,
              before.st_uid == getuid(), before.st_nlink == 1, before.st_size > 0,
              before.st_size <= 256 * 1024 else { throw CocoaError(.fileReadUnknown) }
        let bytes = try XCTUnwrap(handle.read(upToCount:256 * 1024 + 1))
        var after = stat()
        guard fstat(fd,&after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_mode == after.st_mode, before.st_uid == after.st_uid,
              before.st_size == after.st_size, Int64(bytes.count) == before.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw CocoaError(.fileReadUnknown) }
        let report = try JSONDecoder().decode(Report.self,from:bytes)
        XCTAssertEqual(report.schemaVersion,1)
        XCTAssertEqual(Set(report.records.map(\.application)),Set(["IINA","Firefox","Vienna"]))
        XCTAssertEqual(report.records.count,3)
        for record in report.records {
            let index = try MachOContainerIndex.parse(header:record.header,fileSize:record.fileSize)
            XCTAssertEqual(index.slices.map(\.cpuType),record.lipoCPUTypes)
            XCTAssertEqual(index.slices.count,record.rows.count)
            XCTAssertEqual(index.slices.count,record.sliceHeaders.count)
            guard index.slices.count == record.rows.count, index.slices.count == record.sliceHeaders.count else { continue }
            for position in index.slices.indices {
                let slice = index.slices[position], row = record.rows[position]
                XCTAssertEqual(slice.cpuType,row.cpuType); XCTAssertEqual(slice.cpuSubtype,row.cpuSubtype)
                XCTAssertEqual(slice.offset,row.offset); XCTAssertEqual(slice.size,row.size)
                XCTAssertEqual(slice.alignmentExponent,row.alignmentExponent)
                let inner = try MachOContainerIndex.parse(header:record.sliceHeaders[position],fileSize:slice.size)
                XCTAssertTrue(inner.kind == .thin32 || inner.kind == .thin64)
                XCTAssertEqual(inner.slices.count,1)
                XCTAssertEqual(inner.slices.first?.cpuType,slice.cpuType)
                XCTAssertEqual(inner.slices.first?.cpuSubtype,slice.cpuSubtype)
            }
        }
        print("Three signed VM test applications: container tables match native lipo and actual slice headers; no application mutation or optimization execution")
        #else
        throw XCTSkip("Prepared native macOS format inputs only")
        #endif
    }
}
