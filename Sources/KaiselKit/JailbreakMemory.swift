import Foundation

/// Remembers, in this app's Keychain, that conclusive jailbreak evidence was
/// seen on this device. Keychain items survive app deletion and per-app
/// hiding (for example RootHide's Blacklist), but not an erase or restore.
///
/// A later run that sees no evidence reports `previouslyJailbroken` as an
/// indicator, which catches the common sequence "run once, then hide the app".
/// It is client-side state: a jailbreak user can delete it. The server-side
/// equivalent (DeviceCheck bits or a per-key history) is the robust version;
/// see docs/SERVER.md.
enum JailbreakMemory {
    private static let service = "integritykit.history"
    private static let account = "jailbreak.seen"

    static func remember(_ evidence: RawSignal) {
        guard recall() == nil else { return }       // keep the first sighting
        let f = ISO8601DateFormatter()
        let line = "\(f.string(from: Date()))|\(evidence.code.rawValue)|\(evidence.detail.prefix(120))"
        Keychain.write(Data(line.utf8), service: service, account: account)
    }

    static func recall() -> RawSignal? {
        guard let d = Keychain.read(service: service, account: account),
              let line = String(data: d, encoding: .utf8) else { return nil }
        let parts = line.split(separator: "|", maxSplits: 2).map(String.init)
        guard parts.count == 3 else { return nil }
        let title = Int(parts[1]).flatMap { FindingCode(rawValue: $0) }?.metadata.title ?? "code \(parts[1])"
        return RawSignal(.previouslyJailbroken, 80, "seen \(parts[0]): \(title) (\(parts[2]))")
    }

    /// For tests and for a "reset" action in a host app.
    static func forget() {
        Keychain.delete(service: service, account: account)
    }
}
