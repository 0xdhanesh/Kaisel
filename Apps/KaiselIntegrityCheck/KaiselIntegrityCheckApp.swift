import SwiftUI
import KaiselKit

@main
struct KaiselIntegrityCheckApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

@MainActor
final class IntegrityModel: ObservableObject {
    @Published var report: IntegrityReport?
    @Published var running = false
    @Published var monitorOn = false
    @Published var sealedSummary: String?
    @Published var serverURL: String = "http://192.168.1.10:8080"
    @Published var serverResult: String?

    /// True only in the KaiselIntegrityCheckAttest scheme, which carries the App Attest
    /// entitlement (paid developer team). The KaiselIntegrityCheck scheme builds with a
    /// free Personal Team and seals with the Secure Enclave key only.
    nonisolated static let appAttestBuild: Bool = {
        #if APP_ATTEST
        return true
        #else
        return false
        #endif
    }()

    /// Paste the contents of Server/keys/rules_public.pem here to enable rules updates.
    nonisolated static let rulesPublicKeyPEM: String = ""

    // No expectedDistribution: build/signing signals are informational, so an
    // Xcode or ad hoc install does not affect the device verdict. In a
    // production app set expectedDistribution: .appStore and your team ID.
    let kit: IntegrityKit = IntegrityModel.makeKit()

    nonisolated private static func makeKit() -> IntegrityKit {
        #if DEBUG
        let cfg = IntegrityConfiguration(allowedExceptionPorts: 1, debuggerExpected: true)
        #else
        let cfg = IntegrityConfiguration(allowedExceptionPorts: 1)
        #endif
        // Previously downloaded, verified rules (nil if none or invalid).
        var rules: DetectionRules? = nil
        if !rulesPublicKeyPEM.isEmpty, let store = try? RulesStore(publicKeyPEM: rulesPublicKeyPEM) {
            rules = store.current
        }
        return IntegrityKit(configuration: cfg, rules: rules)
    }
    private var monitor: IntegrityMonitor?

    func run() async {
        running = true
        report = await kit.evaluate()
        running = false
    }

    func toggleMonitor() {
        if let m = monitor { m.stop(); monitor = nil; monitorOn = false; return }
        let m = IntegrityMonitor(kit: kit, interval: 20, jitter: 5) { [weak self] r in
            Task { @MainActor in self?.report = r }
        }
        m.start()
        monitor = m
        monitorOn = true
    }

    func seal() async {
        guard let r = report else { return }
        // In production the nonce comes from your server.
        var nonce = Data(count: 32)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        do {
            let sealed = try await kit.seal(r, serverNonce: nonce)
            let hashHex: String = sealed.clientDataHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let attest: String = sealed.appAttestAssertion == nil ? "none" : "assertion"
            let se: String = sealed.secureEnclaveSignature == nil ? "none" : "signed"
            let err: String = sealed.attestationError ?? ""
            var lines: [String] = []
            lines.append("payload \(sealed.payload.count) B, hash \(hashHex)...")
            lines.append("App Attest: \(attest)")
            lines.append("Secure Enclave: \(se)")
            lines.append(err)
            sealedSummary = lines.joined(separator: "\n")
        } catch {
            sealedSummary = "seal failed: \(error)"
        }
    }
}
