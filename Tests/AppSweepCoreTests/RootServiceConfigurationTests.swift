import Foundation
import XCTest
@testable import AppSweepCore
#if os(macOS)
import Security
import CFSafety
import Darwin
#endif

final class RootServiceConfigurationTests: XCTestCase {
    private func pins(version: Int = 1, build: String = "acceptance-1", clients: [String] = [String(repeating: "a", count: 40)], services: [String] = [String(repeating: "b", count: 40)]) -> RootServicePins {
        RootServicePins(schemaVersion: version, serviceBuild: build, clientCodeHashes: clients, serviceCodeHashes: services)
    }
    func testRootPinsRoundtripAndExactRoleRequirements() throws {
        let value = pins()
        XCTAssertEqual(try RootServicePins.decode(value.encode()), value)
        let client = try value.requirement(for: .client), service = try value.requirement(for: .service)
        XCTAssertTrue(client.contains(String(repeating: "a", count: 40)))
        XCTAssertFalse(client.contains(String(repeating: "b", count: 40)))
        XCTAssertTrue(service.contains(String(repeating: "b", count: 40)))
        #if os(macOS)
        for text in [client, service] { var parsed: SecRequirement?; XCTAssertEqual(SecRequirementCreateWithString(text as CFString, [], &parsed), errSecSuccess); XCTAssertNotNil(parsed) }
        #endif
    }
    func testUnboundedArbitraryOrDuplicateSigningRequirementsCannotBeConfigured() {
        let same = String(repeating: "a", count: 40)
        for invalid in [pins(version: 2), pins(build: ""), pins(build: "arbitrary path /System"), pins(clients: []), pins(clients: [same,same]), pins(clients: [String(repeating: "a", count: 39)]), pins(clients: [String(repeating: "A", count: 40)]), pins(clients: ["anchor apple"]), pins(services: (0..<5).map { String(repeating: String($0), count: 40) })] {
            XCTAssertThrowsError(try invalid.encode())
            XCTAssertThrowsError(try invalid.requirement(for: .client))
        }
    }
    func testRootConfigurationRejectsUnknownFieldsDuplicateKeysAndMalformedData() throws {
        let data = try pins().encode(), text = try XCTUnwrap(String(data: data, encoding: .utf8)), tail = String(text.dropFirst())
        for variant in [Data(), Data(" ".utf8) + data, Data(("{\"schemaVersion\":1," + tail).utf8), Data(("{\"shell\":\"/bin/sh\"," + tail).utf8), Data(repeating: 32, count: 65 * 1024)] {
            XCTAssertThrowsError(try RootServicePins.decode(variant))
        }
    }
    #if os(macOS)
    func testKnownReadOnlySystemDescriptorsPassMetadataTrustWithoutReadingContents() throws {
        let directory = try SafeDirectory(path: "/Library")
        XCTAssertEqual(as_root_configuration_descriptor(directory.fd, 1), 1)
        let fd = open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw SweepError.incomplete("VM system metadata descriptor unavailable") }
        defer { close(fd) }
        XCTAssertEqual(as_root_configuration_descriptor(fd, 0), 1)
    }
    func testUserWritableDescriptorsCannotSupplyRootConfiguration() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let directory = try SafeDirectory(path: f.home)
        XCTAssertEqual(as_root_configuration_descriptor(directory.fd, 1), 0)
        let file = f.home + "/untrusted-config.json"
        try pins().encode().write(to: URL(fileURLWithPath: file))
        let fd = open(file, O_RDONLY | O_CLOEXEC); defer { if fd >= 0 { close(fd) } }
        XCTAssertEqual(as_root_configuration_descriptor(fd, 0), 0)
        XCTAssertEqual(as_root_configuration_descriptor(-1, 0), 0)
    }
    #endif
    func testFixedConfigurationPathHasNoRequestOrEnvironmentOverride() {
        XCTAssertEqual(RootServiceConfiguration.path, "/Library/Application Support/App Sweep/Service/config.json")
    }
}
