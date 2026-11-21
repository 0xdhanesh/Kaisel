import SwiftUI
import UIKit
import KaiselKit

/// Jailbreak-only checker. Says nothing about how this app was built or signed.
@main
struct KaiselJBCheckApp: App {
    var body: some Scene { WindowGroup { JailbreakView() } }
}

@MainActor
final class JailbreakModel: ObservableObject {
    @Published var result: JailbreakResult?
    @Published var running = false
    @Published var copied = false
    private let detector = JailbreakDetector()

    func copyJSON() {
        guard let r = result else { return }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        guard let d = try? enc.encode(r) else { return }
        UIPasteboard.general.string = String(decoding: d, as: UTF8.self)
        copied = true
    }

    func run() async {
        running = true
        result = await detector.check()
        running = false
    }
}

struct JailbreakView: View {
    @StateObject private var model = JailbreakModel()

    var body: some View {
        NavigationView {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Image(systemName: icon).font(.system(size: 44)).foregroundColor(colour)
                        Text(title).font(.largeTitle.bold()).foregroundColor(colour)
                        if let r = model.result {
                            Text("\(r.model) · iOS \(r.osVersion) · \(String(format: "%.0f", r.durationMs)) ms")
                                .font(.footnote).foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 8)
                    Button(model.running ? "Checking…" : "Check again") { Task { await model.run() } }
                        .disabled(model.running)
                    Button(model.copied ? "Copied" : "Copy result JSON (lab log)") { model.copyJSON() }
                        .disabled(model.result == nil)
                }

                if let r = model.result {
                    Section("Conclusive evidence") {
                        if r.conclusive.isEmpty { Text("None").foregroundColor(.secondary) }
                        ForEach(Array(r.conclusive.enumerated()), id: \.offset) { _, s in row(s) }
                    }
                    Section("Indicators") {
                        if r.indicators.isEmpty { Text("None").foregroundColor(.secondary) }
                        ForEach(Array(r.indicators.enumerated()), id: \.offset) { _, s in row(s) }
                    }
                    Section("Checks run") {
                        Text(r.checksRun.joined(separator: ", ")).font(.caption.monospaced())
                    }
                }
            }
            .navigationTitle("Kaisel JB Check")
        }
        .task { await model.run() }
    }

    private func row(_ s: Signal) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(s.title).font(.subheadline.bold())
            Text(s.detail).font(.caption.monospaced()).foregroundColor(.secondary)
        }
    }

    private var title: String {
        switch model.result?.status {
        case .jailbroken?: return "Jailbroken"
        case .suspicious?: return "Suspicious"
        case .notJailbroken?: return "Not jailbroken"
        case nil: return "Checking…"
        }
    }
    private var icon: String {
        switch model.result?.status {
        case .jailbroken?: return "xmark.shield.fill"
        case .suspicious?: return "exclamationmark.shield.fill"
        case .notJailbroken?: return "checkmark.shield.fill"
        case nil: return "shield"
        }
    }
    private var colour: Color {
        switch model.result?.status {
        case .jailbroken?: return .red
        case .suspicious?: return .orange
        case .notJailbroken?: return .green
        case nil: return .secondary
        }
    }
}
