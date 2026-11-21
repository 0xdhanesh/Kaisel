import XCTest
@testable import KaiselKit

/// Loaded-image classification (1.4.0). Runs the shared fixtures in
/// Tests/Fixtures/image_classification.json through the C classifier via the
/// Swift wrapper. The same file is checked against the server
/// (Server/tests/test_classification.py) and the C core on the host
/// (Tests/CClassifier/run_tests.py).
final class ImageClassificationTests: XCTestCase {
    private struct Fixture: Decodable {
        struct Case: Decodable {
            let name: String
            let path: String
            let bundle: String?
            let expected: String
            let simulator: Bool
            let remoteMarkers: [String]
        }
        let cases: [Case]
    }

    private func loadFixtures() throws -> [Fixture.Case] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/image_classification.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Fixture.self, from: data).cases
    }

    func testSharedFixtures() throws {
        let cases = try loadFixtures()
        XCTAssertGreaterThanOrEqual(cases.count, 30)
        defer { RulesRuntime.apply(nil) }
        for c in cases {
            if c.remoteMarkers.isEmpty {
                RulesRuntime.apply(nil)
            } else {
                RulesRuntime.apply(Self.rules(markers: c.remoteMarkers))
            }
            let got = ImageEvidence.classify(c.path, bundlePath: c.bundle, simulator: c.simulator)
            XCTAssertEqual(got.rawValue, c.expected, c.name)
        }
    }

    // Spec acceptance cases, stated directly so they survive fixture edits.

    func testBenignFrameworkNamesAreNotConclusive() {
        let app = "/var/containers/Bundle/Application/U/CraneBank.app"
        for path in [app + "/Frameworks/CraneBank.framework/CraneBank",
                     app + "/Frameworks/LibertyFinance.framework/LibertyFinance",
                     app + "/Frameworks/ChoicyAnalytics.framework/ChoicyAnalytics"] {
            XCTAssertEqual(ImageEvidence.classify(path, bundlePath: app, simulator: false), .trusted, path)
            let s = Signal(code: .suspiciousImage, confidence: 95, weight: 0.9, informational: false, detail: path)
            XCTAssertFalse(JailbreakEvidence.isConclusive(s), path)
        }
    }

    func testRootHideInjectorIsConclusive() {
        let path = "/private/var/containers/Bundle/Application/.jbroot-7351422000C774F3/usr/lib/roothideinit.dylib"
        XCTAssertEqual(ImageEvidence.classify(path, bundlePath: "/var/containers/Bundle/Application/U/App.app",
                                              simulator: false), .jailbreakInjector)
        XCTAssertTrue(JailbreakEvidence.isConclusive(code: .suspiciousImage, detail: path))
    }

    func testFridaGadgetIsInstrumentationNotJailbreak() {
        let app = "/var/containers/Bundle/Application/U/App.app"
        XCTAssertEqual(ImageEvidence.classify(app + "/Frameworks/FridaGadget.dylib", bundlePath: app, simulator: false),
                       .instrumentation)
        XCTAssertFalse(JailbreakEvidence.isConclusive(code: .instrumentationImage, detail: app + "/Frameworks/FridaGadget.dylib"))
        XCTAssertEqual(FindingCode.instrumentationImage.domain, .runtime)
        XCTAssertTrue(FindingCode.instrumentationImage.metadata.hard)
    }

    func testBundleBoundary() {
        XCTAssertEqual(ImageEvidence.classify("/var/App.app2/Frameworks/X.framework/X", bundlePath: "/var/App.app",
                                              simulator: false), .unknownExternal)
    }

    func testRemoteMarkerNeverConclusive() {
        RulesRuntime.apply(Self.rules(markers: ["evilhook"]))
        defer { RulesRuntime.apply(nil) }
        let path = "/var/mobile/Library/evilhook.dylib"
        XCTAssertEqual(ImageEvidence.classify(path, bundlePath: "/var/containers/Bundle/Application/U/App.app",
                                              simulator: false), .marker)
        XCTAssertFalse(JailbreakEvidence.isConclusive(code: .imageMarkerMatch, detail: path))
        XCTAssertFalse(JailbreakEvidence.isConclusive(code: .suspiciousImage, detail: path))
    }

    func testOldStyleRuntimeImageIsNoLongerConclusive() {
        // Before 1.4.0, imageAddedAtRuntime at confidence 95 without "frida" was conclusive.
        let s = Signal(code: .imageAddedAtRuntime, confidence: 95, weight: 0.6, informational: false,
                       detail: "/var/mobile/Library/CraneSDK.dylib")
        XCTAssertFalse(JailbreakEvidence.isConclusive(s))
    }

    func testStaleHistoryMarkerIsNotHonoured() {
        // A 1.3.x Keychain marker for a broad-marker match must not survive re-validation.
        XCTAssertFalse(JailbreakMemory.isStillConclusive(
            .suspiciousImage, detail: "/var/containers/Bundle/Application/U/CraneBank.app/Frameworks/CraneBank.framework/CraneBank"))
        XCTAssertTrue(JailbreakMemory.isStillConclusive(.suspiciousImage, detail: ".jbroot-0/usr/lib/roothideinit.dylib"))
    }

    func testConclusiveSetMatchesSharedManifestSize() {
        // Full name-level parity is checked by Server/tests/test_parity.py.
        XCTAssertEqual(JailbreakEvidence.conclusiveCodes.count, 12)
        XCTAssertTrue(JailbreakEvidence.conclusiveCodes.isDisjoint(with: JailbreakEvidence.indicatorCodes))
    }

    static func rules(markers: [String]) -> DetectionRules {
        DetectionRules(version: 1, issuedAt: Date(), expiresAt: Date().addingTimeInterval(3600), minSdkVersion: nil,
                       extraJailbreakPaths: [], extraImageMarkers: markers, extraURLSchemes: [], extraFridaPorts: [],
                       weightOverrides: [:], thresholds: nil)
    }
}
