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

    /// Written only for conclusive evidence with high confidence, never for an
    /// indicator or a single weak signal.
    static func remember(_ evidence: RawSignal) {
        guard evidence.confidence >= 90 else { return }
        guard recall() == nil else { return }       // keep the first sighting
        let f = ISO8601DateFormatter()
        let line = "\(f.string(from: Date()))|\(evidence.code.rawValue)|\(evidence.detail.prefix(120))"
        Keychain.write(Data(line.utf8), service: service, account: account)
    }

    static func recall() -> RawSignal? {
        guard let d = Keychain.read(service: service, account: account),
              let line = String(data: d, encoding: .utf8) else { return nil }
        let parts = line.split(separator: "|", maxSplits: 2).map(String.init)
        // Only honour markers whose evidence is still conclusive under the
        // current rule. Markers left by checks that were later demoted (1.3.0's
        // dyld comparison gave a false positive on stock iOS 27) are deleted.
        guard parts.count == 3, let code = UInt16(parts[1]).flatMap({ FindingCode(rawValue: $0) }),
              isStillConclusive(code, detail: parts[2]) else {
            forget()
            return nil
        }
        let title = code.metadata.title
        return RawSignal(.previouslyJailbroken, 80, "seen \(parts[0]): \(title) (\(parts[2]))")
    }

    static func isStillConclusive(_ code: FindingCode, detail: String) -> Bool {
        let s = Signal(code: code, confidence: 100, weight: code.metadata.weight, informational: false, detail: detail)
        return JailbreakEvidence.isConclusive(s)
    }

    /// For tests and for a "reset" action in a host app.
    static func forget() {
        Keychain.delete(service: service, account: account)
    }
}

/// Public control over the on-device jailbreak history.
public enum JailbreakHistory {
    /// Deletes the "seen jailbroken" marker, for example after a false positive
    /// or after the device was erased and restored by its owner.
    public static func reset() { JailbreakMemory.forget() }

    /// The stored first sighting, if one is still valid under the current rule.
    public static var firstSighting: String? { JailbreakMemory.recall()?.detail }
}
