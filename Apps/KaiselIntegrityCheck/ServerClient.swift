import Foundation
import UIKit
import KaiselKit

/// Talks to Server/server.py. Demo-quality: no auth, plain HTTP on the LAN.
@MainActor
extension IntegrityModel {
    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        guard let url = URL(string: serverURL + path) else { throw URLError(.badURL) }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await URLSession.shared.data(for: req)
        let obj = try JSONSerialization.jsonObject(with: data)
        return obj as? [String: Any] ?? [:]
    }

    private func challenge() async throws -> (id: String, bytes: Data) {
        let r = try await post("/v1/challenge", [:])
        guard let id = r["challengeId"] as? String, let b64 = r["challenge"] as? String,
              let bytes = Data(base64Encoded: b64) else { throw URLError(.cannotParseResponse) }
        return (id, bytes)
    }

    private static func pretty(_ obj: [String: Any]) -> String {
        guard let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) else {
            return "\(obj)"
        }
        return String(decoding: d, as: UTF8.self)
    }

    /// One-time App Attest enrolment with the server.
    func enrol() async {
        guard IntegrityModel.appAttestBuild else {
            serverResult = "App Attest: not enrolled (this build has no App Attest entitlement).\n"
                + "Build the KaiselIntegrityCheckAttest scheme with a paid developer team to enable it.\n"
                + "Verify still works: the report is sealed with the Secure Enclave key only."
            return
        }
        do {
            let ch = try await challenge()
            let e = try await kit.attestKey(serverChallenge: ch.bytes)
            let body: [String: Any] = ["challengeId": ch.id, "keyId": e.keyId,
                                       "attestationObject": e.attestationObject.base64EncodedString()]
            serverResult = Self.pretty(try await post("/v1/attest", body))
        } catch IntegrityError.appAttestUnsupported {
            serverResult = "App Attest: unsupported on this device (simulator, Mac or virtual device)"
        } catch IntegrityError.appAttestUnavailable(let why) {
            serverResult = "App Attest: not enrolled (\(why))"
        } catch {
            serverResult = "enrol failed: \(error)"
        }
    }

    /// Evaluate, seal with the server's challenge, and ask the server to decide.
    func verifyWithServer() async {
        do {
            let ch = try await challenge()
            let r = await kit.evaluate()
            report = r
            let sealed = try await kit.seal(r, serverNonce: ch.bytes)
            let sealedData = try JSONEncoder().encode(sealed)
            let sealedObj = try JSONSerialization.jsonObject(with: sealedData)
            let body: [String: Any] = ["challengeId": ch.id, "sealed": sealedObj]
            serverResult = Self.pretty(try await post("/v1/verify", body))
        } catch {
            serverResult = "verify failed: \(error)"
        }
    }

    /// Downloads signed rules. Requires `rulesPublicKeyPEM` to be set.
    func updateRules() async {
        guard !IntegrityModel.rulesPublicKeyPEM.isEmpty else {
            serverResult = "Set IntegrityModel.rulesPublicKeyPEM to your rules_public.pem first."
            return
        }
        do {
            let store = try RulesStore(publicKeyPEM: IntegrityModel.rulesPublicKeyPEM)
            guard let rURL = URL(string: serverURL + "/v1/rules.json"),
                  let sURL = URL(string: serverURL + "/v1/rules.sig") else { throw URLError(.badURL) }
            let rules = try await store.update(rulesURL: rURL, signatureURL: sURL)
            serverResult = "rules v\(rules.version) installed (applies on next launch)"
        } catch {
            serverResult = "rules update failed: \(error)"
        }
    }

    func copyReportJSON() {
        guard let r = report, let d = try? r.canonicalJSON() else { return }
        UIPasteboard.general.string = String(decoding: d, as: UTF8.self)
        serverResult = "Report JSON copied (\(d.count) bytes)"
    }
}
