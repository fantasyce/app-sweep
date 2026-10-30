#if canImport(CryptoKit)
import Foundation
import XCTest
@testable import AppSweepCore

final class TreeFingerprintTests: XCTestCase {
    func testFingerprintBindsEveryIdentityFieldAndRelativePath() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let entry = try XCTUnwrap(f.snapshot.tree.first)
        let original = try TreeFingerprint.capture([entry])
        XCTAssertTrue(try original.matches([entry]))
        XCTAssertFalse(try original.matches([]))
        XCTAssertNotEqual(try TreeFingerprint.capture([TreeEntry(relative: entry.relative + "-different", identity: entry.identity)]), original)
        let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(entry)) as? [String: Any])
        let identities = try XCTUnwrap(encoded["identity"] as? [String: Any])
        for (key, value) in identities {
            var changed = encoded, fields = identities
            if key == "volumeUUID"{fields[key]=UUID().uuidString}
            else{fields[key]=try XCTUnwrap(value as? NSNumber).int64Value+1}
            changed["identity"] = fields
            let replacement = try JSONDecoder().decode(TreeEntry.self, from: JSONSerialization.data(withJSONObject: changed))
            if key == "device",identities["volumeUUID"] != nil {
                XCTAssertEqual(try TreeFingerprint.capture([replacement]),original,"A volatile mount number is not persistent identity")
            }else{
                XCTAssertNotEqual(try TreeFingerprint.capture([replacement]), original, "Missing identity binding: " + key)
            }
        }
    }
    func testAmbiguousOrEscapingPathsCannotBeCommitted() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let entry = try XCTUnwrap(f.snapshot.tree.first)
        for path in ["", "/outside", "../outside", "a/../outside", "./data", "a//data", "data/", "data\0outside"] {
            XCTAssertThrowsError(try TreeFingerprint.capture([TreeEntry(relative: path, identity: entry.identity)]))
        }
        XCTAssertThrowsError(try TreeFingerprint.capture([entry, entry]))
        let later = TreeEntry(relative: entry.relative + "-later", identity: entry.identity)
        XCTAssertThrowsError(try TreeFingerprint.capture([later, entry]))
        let valid = TreeFingerprint(algorithm: "sha256-metadata-v1", count: 20_001, digest: String(repeating: "a", count: 64))
        XCTAssertTrue(valid.validLargeApplication)
        for bad in [TreeFingerprint(algorithm: "unknown", count: valid.count, digest: valid.digest), TreeFingerprint(algorithm: valid.algorithm, count: 1_000_001, digest: valid.digest), TreeFingerprint(algorithm: valid.algorithm, count: valid.count, digest: String(repeating: "z", count: 64))] {
            XCTAssertFalse(bad.validLargeApplication)
        }
    }
    func testDeclaredMetadataCapacityIsBoundedAtOneMillionEntries() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let identity = try XCTUnwrap(f.snapshot.tree.first?.identity)
        var tree = (0..<1_000_000).map { index -> TreeEntry in
            let digits = String(index)
            return TreeEntry(relative: String(repeating: "0", count: 7 - digits.count) + digits, identity: identity)
        }
        let fingerprint = try TreeFingerprint.capture(tree)
        XCTAssertEqual(fingerprint.count, 1_000_000)
        XCTAssertTrue(fingerprint.validLargeApplication)
        tree.append(TreeEntry(relative: "1000000", identity: identity))
        XCTAssertThrowsError(try TreeFingerprint.capture(tree))
    }
}
#endif
