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
        // Demoted in 1.3.1 after a stock iOS 27 false positive.
        XCTAssertFalse(JailbreakEvidence.isConclusive(sig(.dyldModified, 95, "dyld __text differs")))
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

    /// Regression fixture: stock iPhone18,1, iOS 27.2.1, Kaisel 1.3.0 said "Jailbroken"
    /// because dyld runs from the shared cache and differed from /usr/lib/dyld.
    func testStockIOS27DyldMismatchIsNotAJailbreak() {
        let signals = [sig(.dyldModified, 95, "dyld __text differs from disk: 162671 words, first at +0x0")]
        XCTAssertFalse(signals.contains(where: JailbreakEvidence.isConclusive))
        XCTAssertFalse(FindingCode.dyldModified.metadata.hard)
        XCTAssertLessThan(RiskScorer().assess(.device, signals).verdict, .high)
        XCTAssertFalse(JailbreakMemory.isStillConclusive(.dyldModified, detail: "dyld"))
        XCTAssertTrue(JailbreakMemory.isStillConclusive(.suspiciousImage, detail: ".jbroot-0/usr/lib/roothideinit.dylib"))
    }

    func testNewCodesMapToDevice() {
        XCTAssertEqual(FindingCode.dyldModified.domain, .device)
        XCTAssertEqual(FindingCode.userspaceReboot.domain, .device)
        XCTAssertEqual(FindingCode.previouslyJailbroken.domain, .device)
        XCTAssertFalse(FindingCode.userspaceReboot.metadata.hard)
    }
}
