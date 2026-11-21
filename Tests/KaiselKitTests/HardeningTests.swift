import XCTest
import CryptoKit
@testable import KaiselKit

final class HardeningTests: XCTestCase {
    func testRulesWeightsAreBounded() {
        // anonymousExecutableMemory built-in 0.35 -> allowed 0.175...0.525
        XCTAssertEqual(RulesRuntime.boundedWeight(.anonymousExecutableMemory, 0.0), 0.175, accuracy: 1e-9)
        XCTAssertEqual(RulesRuntime.boundedWeight(.anonymousExecutableMemory, 1.0), 0.525, accuracy: 1e-9)
        XCTAssertEqual(RulesRuntime.boundedWeight(.rootlessJailbreakRoot, 5.0), 1.0, accuracy: 1e-9)
        XCTAssertEqual(RulesRuntime.boundedThreshold(0, 60), 45)
        XCTAssertEqual(RulesRuntime.boundedThreshold(99, 60), 75)
    }

    func testSignedRulesVerifyAndRejectTampering() throws {
        let key = P256.Signing.PrivateKey()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = try RulesStore(publicKeyPEM: key.publicKey.pemRepresentation, directory: dir)
        let json = """
        {"version": 1, "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z",
         "extraJailbreakPaths": ["/var/jb/x"], "extraImageMarkers": [], "extraURLSchemes": [],
         "extraFridaPorts": [], "weightOverrides": {}}
        """
        let data = Data(json.utf8)
        let sig = try key.signature(for: data).derRepresentation.base64EncodedString()
        let rules = try store.verify(rulesData: data, signatureBase64: sig)
        XCTAssertEqual(rules.extraJailbreakPaths, ["/var/jb/x"])
        var tampered = data
        tampered[tampered.startIndex + 13] = UInt8(ascii: "9")
        XCTAssertThrowsError(try store.verify(rulesData: tampered, signatureBase64: sig))
    }

    func testProtectedVerdictRoundTrip() {
        let box = ProtectedVerdict()
        XCTAssertNil(box.read())
    }
}
