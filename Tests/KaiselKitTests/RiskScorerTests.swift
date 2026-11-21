import XCTest
@testable import KaiselKit

final class RiskScorerTests: XCTestCase {
    private func sig(_ c: FindingCode, _ conf: UInt8 = 100, _ detail: String = "") -> Signal {
        Signal(code: c, confidence: conf, weight: c.metadata.weight, informational: false, detail: detail)
    }

    func testCleanIsTrusted() {
        let s = RiskScorer()
        XCTAssertEqual(s.score(s.categoryScores([])), 0)
        XCTAssertEqual(s.verdict(score: 0, signals: []), .trusted)
    }

    func testCorrelatedPathsAreDamped() {
        let s = RiskScorer()
        let many = (0..<40).map { sig(.jailbreakPathPresent, 95, "/p\($0)") }
        let score = s.score(s.categoryScores(many))
        XCTAssertLessThan(score, 85)
        XCTAssertGreaterThan(score, 50)
    }

    func testIndependentCategoriesCorroborate() {
        let s = RiskScorer()
        let one = s.score(s.categoryScores([sig(.jailbreakPathPresent)]))
        let two = s.score(s.categoryScores([sig(.jailbreakPathPresent), sig(.unexpectedImagePath)]))
        XCTAssertGreaterThan(two, one)
    }

    func testHardIndicatorFloorsVerdict() {
        XCTAssertGreaterThanOrEqual(RiskScorer().verdict(score: 10, signals: [sig(.fridaThread, 95)]), .high)
    }

    func testTwoHardCategoriesAreCompromised() {
        let signals = [sig(.fridaThread, 95), sig(.sandboxWrite, 98)]
        XCTAssertEqual(RiskScorer().verdict(score: 10, signals: signals), .compromised)
    }

    func testLowConfidenceHardDoesNotFloor() {
        XCTAssertEqual(RiskScorer().verdict(score: 5, signals: [sig(.fridaThread, 40)]), .trusted)
    }

    /// Regression: stock iPhone18,1 on iOS 27.2.1, Xcode-installed build.
    /// Build-context and Developer Mode signals must not make the device look compromised.
    func testStockXcodeBuildIsTrusted() {
        let raw: [RawSignal] = [
            .init(.binaryDecrypted, 90, "cryptid=0"),
            .init(.getTaskAllow, 90, "get-task-allow"),
            .init(.provisioningProfilePresent, 90, "signed as development"),
            .init(.developerModeEnabled, 95, "amfi developer_mode_status=1"),
            .init(.anonymousExecutableMemory, 55, "anonymous r-x region"),
        ]
        let cfg = IntegrityConfiguration()   // expectedDistribution nil
        let signals = IntegrityKit.requireCorroboration(IntegrityKit.makeSignals(raw, configuration: cfg))
        XCTAssertTrue(signals.allSatisfy(\.informational))
        let s = RiskScorer()
        XCTAssertEqual(s.assess(.device, signals).verdict, .trusted)
        XCTAssertEqual(s.assess(.runtime, signals).verdict, .trusted)
    }

    func testAppStoreExpectationScoresBuildSignals() {
        let cfg = IntegrityConfiguration(expectedDistribution: .appStore)
        let signals = IntegrityKit.makeSignals([.init(.binaryDecrypted, 90, "cryptid=0")], configuration: cfg)
        XCTAssertFalse(signals[0].informational)
        XCTAssertEqual(signals[0].domain, .app)
    }

    func testDeveloperModeIsNeverScored() {
        let cfg = IntegrityConfiguration(expectedDistribution: .appStore)
        XCTAssertTrue(cfg.treatment(for: .developerModeEnabled).informational)
    }

    func testFindingCodesMirrorCHeader() {
        XCTAssertEqual(FindingCode.libcSyscallMismatch.rawValue, 108)
        XCTAssertEqual(FindingCode.fridaDBus.rawValue, 502)
        XCTAssertEqual(FindingCode.suspiciousEntitlement.rawValue, 602)
    }
}
