import Foundation
import CryptoKit
import CIntegrityCore

/// Cheap, inlined checks to scatter through the host app.
///
/// A single `evaluate()` call is one place to hook. Calling `IntegrityGuard`
/// at many sensitive sites (before login, payment, key use, screen entry)
/// means an attacker has to find and neutralise every site. The C guard is a
/// header-only `always_inline` function that uses raw syscalls only, so each
/// Swift module that calls it gets its own copy of the trap instructions.
///
/// ```swift
/// guard IntegrityGuard.isClean else { return presentBlockedScreen() }
/// ```
public enum IntegrityGuard {
    public struct Flags: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let traced = Flags(rawValue: UInt32(RASP_GUARD_TRACED))
        public static let codeSigningDebugged = Flags(rawValue: UInt32(RASP_GUARD_CS_DEBUGGED))
        public static let jailbreakRoot = Flags(rawValue: UInt32(RASP_GUARD_JB_ROOT))
    }

    /// Raw flags from the inline guard (debugger attached, CS_DEBUGGED, /var/jb).
    @inline(__always)
    public static var flags: Flags { Flags(rawValue: rasp_quick_guard()) }

    /// `false` if the guard saw anything. Development builds will report
    /// `.codeSigningDebugged` while Xcode is attached.
    @inline(__always)
    public static var isClean: Bool { rasp_quick_guard() == 0 }
}

/// Tamper-evident holder for the last verdict.
///
/// Storing `verdict` in a plain property lets an attacker flip one byte in
/// memory (or hook a getter) to turn `.compromised` into `.trusted`. The box
/// keeps the value XOR-masked with a random per-process key and an HMAC over
/// (value, report ID) with a second random key. Reading a box whose MAC does
/// not verify returns `.compromised`.
///
/// This raises the bar for casual memory patching only. An attacker with
/// code execution can hook `read()` itself, which is why the server, not the
/// client, should act on the verdict.
public final class ProtectedVerdict: @unchecked Sendable {
    private let lock = NSLock()
    private let maskKey: UInt8 = UInt8.random(in: 1...255)
    private let macKey = SymmetricKey(size: .bits256)
    private var masked: UInt8 = 0
    private var reportID = UUID()
    private var mac = Data()
    private var hasValue = false

    public init() {}

    private static func code(_ v: Verdict) -> UInt8 {
        switch v {
        case .trusted: return 0x11
        case .low: return 0x22
        case .elevated: return 0x33
        case .high: return 0x44
        case .compromised: return 0x55
        }
    }

    private static func verdict(_ c: UInt8) -> Verdict? {
        switch c {
        case 0x11: return .trusted
        case 0x22: return .low
        case 0x33: return .elevated
        case 0x44: return .high
        case 0x55: return .compromised
        default: return nil
        }
    }

    private func tag(_ code: UInt8, _ id: UUID) -> Data {
        var msg = Data([code])
        msg.append(Data(id.uuidString.utf8))
        return Data(HMAC<SHA256>.authenticationCode(for: msg, using: macKey))
    }

    func store(_ report: IntegrityReport) {
        let c = Self.code(report.verdict)
        lock.lock()
        masked = c ^ maskKey
        reportID = report.id
        mac = tag(c, report.id)
        hasValue = true
        lock.unlock()
    }

    /// The last verdict, or `.compromised` if the stored value was tampered with.
    /// `nil` before the first evaluation.
    public func read() -> Verdict? {
        lock.lock(); defer { lock.unlock() }
        guard hasValue else { return nil }
        let c = masked ^ maskKey
        guard tag(c, reportID) == mac, let v = Self.verdict(c) else { return .compromised }
        return v
    }
}
