import XCTest
@testable import AppSweepCore

final class PlatformTests: XCTestCase {
    func testGodotCacheIsEnabledOnlyOnAcceptedARMPlatform() {
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        let intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.rules(for:arm).contains(GodotCacheRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for:intel).contains(GodotCacheRule.name))
    }
    func testInstalledSystemHelpersAreOnlyAnExplicitRootARMCandidate(){
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.systemRules(for:arm).contains("exclusive-installed-system-helper-v1"))
        XCTAssertFalse(NativeAcceptance.rules(for:arm).contains("exclusive-installed-system-helper-v1"))
        XCTAssertFalse(NativeAcceptance.systemRules(for:intel).contains("exclusive-installed-system-helper-v1"))
    }
    func testSimulatorCacheHasOnlyItsExactNativeARMCandidateGate(){
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.rules(for:arm).contains("registered-simulator-cache-v1"))
        XCTAssertFalse(NativeAcceptance.rules(for:intel).contains("registered-simulator-cache-v1"))
    }
    func testInstalledApplicationAgentsHaveOnlyTheirNativeARMCandidateGate(){
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        let intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.rules(for:arm).contains(ApplicationAgentRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for:intel).contains(ApplicationAgentRule.name))
    }
    func testDeletedAccountArchivesHaveOnlyAnExplicitRootARMCandidateGate(){
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        let intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.systemRules(for:arm).contains("deleted-user-archive-v1"))
        XCTAssertFalse(NativeAcceptance.rules(for:arm).contains("deleted-user-archive-v1"))
        XCTAssertFalse(NativeAcceptance.systemRules(for:intel).contains("deleted-user-archive-v1"))
    }
    func testDocumentHistoryHasOnlyItsNativeARMCandidateGate() {
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        let intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.rules(for:arm).contains("document-history-versions-v1"))
        XCTAssertFalse(NativeAcceptance.rules(for:intel).contains("document-history-versions-v1"))
    }
    func testCurrentUserLogRuleHasAnExplicitARMCandidateGate() {
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        let intel=PlatformStamp(major:13,minor:7,patch:8,build:"22H730",architecture:"x86_64")
        XCTAssertTrue(NativeAcceptance.rules(for:arm).contains(ApplicationLogRule.currentName))
        XCTAssertFalse(NativeAcceptance.rules(for:intel).contains(ApplicationLogRule.currentName))
    }
    func testDefaultReleaseIncludesVerifiedRuntimeBrowserCacheAndDataContracts() {
        let arm=PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64")
        for rule in [ChromiumCacheRule.name,ChromiumProfileRule.name,LocalizedResourceReader.name] {
            XCTAssertTrue(NativeAcceptance.rules(for:arm).contains(rule),"Native acceptance must apply to the shipped default configuration: " + rule)
        }
    }
    func testCandidateRulesUseOnlyExactIndependentlyVerifiedCombinations() {
        let arm = PlatformStamp(major: 27, minor: 0, patch: 1, build: "26A434", architecture: "arm64")
        let intel = PlatformStamp(major: 13, minor: 7, patch: 8, build: "22H730", architecture: "x86_64")
        let common: Set<String> = [ChosenApplicationRule.name, ChosenApplicationRule.largeName, SelectedApplicationRule.name, SupportDomainRule.name, CacheDomainRule.name, LegacyCrashRule.name, "signed-application-v1", "cfpreferences-exact-domain-v1", "ips-third-party-30d-v1"]
        XCTAssertEqual(NativeAcceptance.rules(for: arm), common.union([FirefoxRule.name, FirefoxFormatRule.name, CacheRule.name, ApplicationLogRule.name, XcodeRule.name, PreferenceRecoveryRecord.rule, ApplicationOptimizationEngine.rule, ApplicationOptimizationEngine.languageRule, ApplicationOptimizationEngine.purgeRule, GodotCacheRule.name, UserCacheNamespaceRule.name, ApplicationLogRule.currentName, ApplicationCacheRule.appleName, ApplicationCacheRule.containerName, XcodeGeneratedRule.name, DarwinCacheRule.name, XcodeArchiveRule.name, XcodeDeviceSupportRule.name, ContainerDataRule.name, ApplicationScriptsRule.name, ApplicationGroupRule.name, StaleUserAgentRule.name, CorruptPreferenceRule.name, DeviceBackupRule.name, DeviceBackupRule.largeName, DocumentVersionRule.name, ApplicationAgentRule.name, SimulatorCacheRule.name, ToolCacheRule.name, ChromiumCacheRule.name, ChromiumProfileRule.name, LocalizedResourceReader.name, NamedApplicationRule.cacheName, NamedApplicationRule.dataName, WebKitCacheRule.name, ToolCacheRule.homebrewName, ApplicationStorageRule.name, ToolCacheRule.npmName, ToolCacheRule.pnpmName]))
        XCTAssertEqual(NativeAcceptance.rules(for: intel), common)
        XCTAssertTrue(NativeAcceptance.rules(for: PlatformStamp(major: 27, minor: 0, patch: 1, build: "unknown", architecture: "arm64")).isEmpty)
        XCTAssertTrue(NativeAcceptance.rules(for: nil).isEmpty)
        XCTAssertFalse(NativeAcceptance.rules(for: arm).contains("exclusive-container-v1"))
        XCTAssertTrue(NativeAcceptance.rules(for: arm).contains(XcodeRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(XcodeRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(PreferenceRecoveryRecord.rule))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationOptimizationEngine.rule))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationOptimizationEngine.languageRule))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationOptimizationEngine.purgeRule))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(UserCacheNamespaceRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationCacheRule.appleName))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationCacheRule.containerName))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(XcodeGeneratedRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(DarwinCacheRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(XcodeArchiveRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(XcodeDeviceSupportRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ContainerDataRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationScriptsRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(ApplicationGroupRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(StaleUserAgentRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(CorruptPreferenceRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(DeviceBackupRule.name))
        XCTAssertFalse(NativeAcceptance.rules(for: intel).contains(DeviceBackupRule.largeName))
        XCTAssertEqual(NativeAcceptance.systemRules(for: arm), [SystemDomainRule.cacheName, SystemDomainRule.logName, SystemDomainRule.currentLogName, DeletedUserArchiveRule.name,InstalledSystemHelperRule.name])
        XCTAssertTrue(NativeAcceptance.systemRules(for: nil).isEmpty)
        XCTAssertTrue(NativeAcceptance.systemRules(for: PlatformStamp(major: 27, minor: 0, patch: 1, build: "unknown", architecture: "arm64")).isEmpty)
        XCTAssertTrue(NativeAcceptance.systemRules(for: intel).isEmpty)
    }
    func testPlatformAcceptanceRequiresExactBuildAndArchitecture() {
        let accepted = PlatformStamp(major: 13, minor: 7, patch: 8, build: "22H730", architecture: "x86_64")
        XCTAssertTrue(NativeAcceptance.matches(accepted, accepted: [accepted]))
        XCTAssertFalse(NativeAcceptance.matches(PlatformStamp(major: 13, minor: 7, patch: 9, build: "22H731", architecture: "x86_64"), accepted: [accepted]))
        XCTAssertFalse(NativeAcceptance.matches(PlatformStamp(major: 13, minor: 7, patch: 8, build: "22H730", architecture: "arm64"), accepted: [accepted]))
        XCTAssertFalse(NativeAcceptance.matches(accepted, accepted: []))
    }
    func testCurrentHomeComesFromAccountIdentity() throws {
        XCTAssertEqual(SafetyPolicy.current.home, try SystemIdentity.home())
        #if os(Linux)
        XCTAssertNotEqual(SafetyPolicy.current.home, "/tmp/test-home", "The container test deliberately sets HOME to a different path")
        #endif
    }
}
