import XCTest
@testable import KaiselKit

/// Lab case: iPhone9,3, iOS 15.8.2, Dopamine with RootHide, app not hidden.
/// JB Check said "Jailbroken"; the full app must not report the device as merely elevated.
final class JailbreakEvidenceTests: XCTestCase {
    private func sig(_ c: FindingCode, _ conf: UInt8 = 95, _ detail: String = "") -> Signal {
        Signal(code: c, confidence: conf, weight: c.metadata.weight, informational: false, detail: detail)
    }

    func testTweakInjectorIsConclusiveFridaIsNot() {
        XCTAssertTrue(JailbreakEvidence.isConclusive(
            sig(.suspiciousImage, 95, "/var/containers/Bundle/Application/.jbroot-0123/usr/lib/roothideinit.dylib")))
        XCTAssertFalse(JailbreakEvidence.isConclusive(sig(.suspiciousImage, 95, "/private/var/x/FridaGadget.dylib")))
        XCTAssertFalse(JailbreakEvidence.isConclusive(sig(.syscallStubAltered, 60, "csops")))
        XCTAssertFalse(JailbreakEvidence.isConclusive(sig(.jailbreakURLScheme, 80, "sileo://")))
        XCTAssertTrue(JailbreakEvidence.isConclusive(sig(.dyldModified, 95, "dyld __text differs")))
    }

    func testInformationalNeverConclusive() {
        let s = Signal(code: .rootlessJailbreakRoot, confidence: 100, weight: 0.95, informational: true, detail: "")
        XCTAssertFalse(JailbreakEvidence.isConclusive(s))
    }

    func testRootHideUnhiddenRunDeviceDomainAloneIsNotCompromised() {
        // Device-domain signals from that run score only "elevated"; the
        // conclusive injector lives in the runtime domain. IntegrityKit
        // escalates the device verdict using JailbreakEvidence.
        let signals = [sig(.jailbreakURLScheme, 80, "sileo://"),
                       sig(.suspiciousImage, 95, ".jbroot-x/usr/lib/roothideinit.dylib")]
        let device = RiskScorer().assess(.device, signals)
        XCTAssertLessThan(device.verdict, .compromised)
        XCTAssertTrue(signals.contains(where: JailbreakEvidence.isConclusive))
    }

    func testNewCodesMapToDevice() {
        XCTAssertEqual(FindingCode.dyldModified.domain, .device)
        XCTAssertEqual(FindingCode.userspaceReboot.domain, .device)
        XCTAssertEqual(FindingCode.previouslyJailbroken.domain, .device)
        XCTAssertFalse(FindingCode.userspaceReboot.metadata.hard)
    }
}
