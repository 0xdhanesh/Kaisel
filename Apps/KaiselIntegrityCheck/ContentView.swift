import SwiftUI
import KaiselKit

struct ContentView: View {
    @StateObject private var model = IntegrityModel()

    var body: some View {
        NavigationView {
            List {
                if let r = model.report {
                    Section("Device") {
                        verdictRow("Device integrity", r.device)
                        verdictRow("This app's runtime", r.runtime)
                        if let a = r.app { verdictRow("App build", a) }
                        else { infoRow("App build", "not enforced (informational)") }
                        infoRow("Last verdict (protected)", model.kit.lastVerdict.read()?.rawValue ?? "-")
                        infoRow("Inline guard", IntegrityGuard.isClean ? "clean" : "flags \(IntegrityGuard.flags.rawValue)")
                        infoRow("Rules", r.rulesVersion.map { "v\($0)" } ?? "built-in only")
                    }
                    Section("Phone") {
                        infoRow("Model", r.posture.model)
                        infoRow("iOS", r.posture.osVersion)
                        infoRow("Developer Mode", r.posture.developerMode.rawValue)
                        infoRow("Developer Disk Image", r.posture.developerDiskImageMounted ? "mounted" : "not mounted")
                        infoRow("Passcode set", r.posture.passcodeSet.rawValue)
                        infoRow("Biometry", r.posture.biometry)
                        infoRow("Secure Enclave", r.posture.secureEnclaveAvailable ? "available" : "unavailable")
                        infoRow("App Attest (device)", r.posture.appAttestSupported ? "supported" : "unsupported")
                        infoRow("App Attest (this build)", appAttestLabel)
                    }
                    Section("This app") {
                        infoRow("Signed as", r.build.detectedDistribution)
                        infoRow("Expected", r.build.expectedDistribution ?? "not set")
                        infoRow("FairPlay cryptid", "\(r.build.cryptID)")
                    }
                }
                Section {
                    if model.running { ProgressView() }
                    Button("Evaluate now") { Task { await model.run() } }
                    Button(model.monitorOn ? "Stop monitor" : "Start monitor (20 s ± 5 s)") { model.toggleMonitor() }
                    Button("Seal report (App Attest / Secure Enclave)") { Task { await model.seal() } }
                        .disabled(model.report == nil)
                    if let s = model.sealedSummary { Text(s).font(.caption.monospaced()) }
                    Button("Copy result JSON (lab log)") { model.copyReportJSON() }
                        .disabled(model.report == nil)
                }
                Section("Reference server") {
                    TextField("http://<mac-ip>:8080", text: $model.serverURL)
                        .keyboardType(.URL)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("1. Enrol App Attest") { Task { await model.enrol() } }
                        .disabled(!IntegrityModel.appAttestBuild)
                    Button("2. Verify with server") { Task { await model.verifyWithServer() } }
                    Button("Update signed rules") { Task { await model.updateRules() } }
                    if let s = model.serverResult { Text(s).font(.caption.monospaced()) }
                }
                if let r = model.report {
                    Section("Scored signals") {
                        if r.scoredSignals.isEmpty { Text("None").foregroundColor(.secondary) }
                        ForEach(Array(r.scoredSignals.enumerated()), id: \.offset) { _, s in signalRow(s) }
                    }
                    Section("Informational") {
                        if r.informationalSignals.isEmpty { Text("None").foregroundColor(.secondary) }
                        ForEach(Array(r.informationalSignals.enumerated()), id: \.offset) { _, s in signalRow(s) }
                    }
                    Section("Observability on this OS") {
                        ForEach(r.observabilityNotes, id: \.self) { Text($0).font(.caption) }
                    }
                }
            }
            .navigationTitle("Kaisel Integrity Check")
        }
        .task { await model.run() }
    }

    private var appAttestLabel: String {
        guard IntegrityModel.appAttestBuild else { return "not in this build" }
        return model.kit.appAttestStatus.rawValue
    }

    private func verdictRow(_ label: String, _ a: DomainAssessment) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(a.verdict.rawValue.capitalized).bold().foregroundColor(colour(a.verdict))
            Text("\(a.score)").monospacedDigit().foregroundColor(.secondary)
        }
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack { Text(label); Spacer(); Text(value).foregroundColor(.secondary) }
    }

    private func signalRow(_ s: Signal) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                if s.hard && !s.informational { Image(systemName: "exclamationmark.octagon.fill").foregroundColor(.red) }
                Text(s.title).font(.subheadline.bold())
                Spacer()
                Text("\(s.domain.rawValue) · \(s.code.rawValue)").font(.caption).foregroundColor(.secondary)
            }
            Text(s.detail).font(.caption.monospaced()).foregroundColor(.secondary)
        }
    }

    private func colour(_ v: Verdict) -> Color {
        switch v {
        case .trusted: return .green
        case .low: return .mint
        case .elevated: return .orange
        case .high, .compromised: return .red
        }
    }
}
