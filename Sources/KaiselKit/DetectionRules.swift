import Foundation
import CryptoKit
import CIntegrityCore

/// Remotely updatable detection rules, signed with your ECDSA P-256 key.
///
/// Files served by your backend (see Server/):
///   rules.json  UTF-8 JSON, exactly the bytes that were signed
///   rules.sig   base64 DER ECDSA-P256-SHA256 signature over rules.json
///
/// Safety model:
/// - **Additive only.** Rules can add paths, image markers, URL schemes and
///   Frida ports on top of the compiled-in lists. They cannot remove built-in
///   indicators, so a compromised or blocked rules channel cannot disable detection.
/// - **Bounded tuning.** Weight overrides are clamped to [0.5x, 1.5x] of the
///   built-in weight (and to 0...1). Thresholds may move by at most +/-15 points.
/// - **Anti-rollback.** A rules file whose `version` is lower than the highest
///   version already accepted on this device is rejected.
/// - **Expiry.** Expired rules are ignored; the compiled-in lists still apply.
/// - **Fail safe.** Any parse, signature or policy error leaves the previous
///   valid rules (or none) in place.
public struct DetectionRules: Codable, Sendable, Equatable {
    public struct Thresholds: Codable, Sendable, Equatable {
        public var low: Int
        public var elevated: Int
        public var high: Int
        public var compromised: Int
    }

    public var version: Int
    public var issuedAt: Date
    public var expiresAt: Date
    public var minSdkVersion: String?
    public var extraJailbreakPaths: [String]
    public var extraImageMarkers: [String]
    /// Must also be listed under LSApplicationQueriesSchemes, or canOpenURL
    /// always returns false. Pre-declare a reserve list in Info.plist.
    public var extraURLSchemes: [String]
    public var extraFridaPorts: [UInt16]
    /// Keyed by finding code raw value as a string, e.g. "503": 0.4.
    public var weightOverrides: [String: Double]
    public var thresholds: Thresholds?
}

public enum RulesError: Error, Sendable {
    case badSignatureEncoding, signatureInvalid, decodeFailed(String), rollback(current: Int, offered: Int),
         expired, sdkTooOld(String), network(String)
}

/// Verifies, stores and serves the current rules.
public final class RulesStore: @unchecked Sendable {
    private let publicKey: P256.Signing.PublicKey
    private let directory: URL
    private let lock = NSLock()
    private var cached: DetectionRules?
    private let versionAccount = "rules.highest-version"
    private let keychainService = "integritykit.rules"

    /// - Parameter publicKeyPEM: your rules-signing public key ("-----BEGIN PUBLIC KEY-----...").
    ///   Pin it in the binary; rotate by shipping a new app version.
    public init(publicKeyPEM: String, directory: URL? = nil) throws {
        self.publicKey = try P256.Signing.PublicKey(pemRepresentation: publicKeyPEM)
        let base = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.directory = base.appendingPathComponent("IntegrityRules", isDirectory: true)
        try? FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
        self.cached = try? loadFromDisk()
    }

    /// Current valid, unexpired rules, or nil (compiled-in lists only).
    public var current: DetectionRules? {
        lock.lock(); defer { lock.unlock() }
        guard let r = cached, r.expiresAt > Date() else { return nil }
        return r
    }

    /// Verifies and installs a rules file. On success it is persisted.
    @discardableResult
    public func install(rulesData: Data, signatureBase64: String) throws -> DetectionRules {
        let rules = try verify(rulesData: rulesData, signatureBase64: signatureBase64)
        lock.lock(); defer { lock.unlock() }
        let highest = highestAcceptedVersion()
        if rules.version < highest { throw RulesError.rollback(current: highest, offered: rules.version) }
        try rulesData.write(to: directory.appendingPathComponent("rules.json"), options: .atomic)
        try Data(signatureBase64.utf8).write(to: directory.appendingPathComponent("rules.sig"), options: .atomic)
        Keychain.write(Data(String(rules.version).utf8), service: keychainService, account: versionAccount)
        cached = rules
        return rules
    }

    /// Downloads rules.json and rules.sig and installs them. Errors leave the
    /// previous rules in place.
    @discardableResult
    public func update(rulesURL: URL, signatureURL: URL, session: URLSession = .shared) async throws -> DetectionRules {
        do {
            let (rulesData, _) = try await session.data(from: rulesURL)
            let (sigData, _) = try await session.data(from: signatureURL)
            let sig = String(decoding: sigData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return try install(rulesData: rulesData, signatureBase64: sig)
        } catch let e as RulesError {
            throw e
        } catch {
            throw RulesError.network(error.localizedDescription)
        }
    }

    func verify(rulesData: Data, signatureBase64: String) throws -> DetectionRules {
        guard let der = Data(base64Encoded: signatureBase64),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: der) else {
            throw RulesError.badSignatureEncoding
        }
        guard publicKey.isValidSignature(sig, for: rulesData) else { throw RulesError.signatureInvalid }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let rules: DetectionRules
        do { rules = try dec.decode(DetectionRules.self, from: rulesData) }
        catch { throw RulesError.decodeFailed(String(describing: error)) }
        if rules.expiresAt <= Date() { throw RulesError.expired }
        if let min = rules.minSdkVersion,
           IntegrityKit.sdkVersion.compare(min, options: .numeric) == .orderedAscending {
            throw RulesError.sdkTooOld(min)
        }
        return rules
    }

    private func loadFromDisk() throws -> DetectionRules? {
        let r = directory.appendingPathComponent("rules.json")
        let s = directory.appendingPathComponent("rules.sig")
        guard let rd = try? Data(contentsOf: r), let sd = try? Data(contentsOf: s) else { return nil }
        let sig = String(decoding: sd, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        // Re-verified on every load: a file swapped on disk is rejected.
        return try verify(rulesData: rd, signatureBase64: sig)
    }

    private func highestAcceptedVersion() -> Int {
        guard let d = Keychain.read(service: keychainService, account: versionAccount),
              let v = Int(String(decoding: d, as: UTF8.self)) else { return 0 }
        return v
    }
}

/// Applies rules to the C core and Swift-side lists.
enum RulesRuntime {
    private static let lock = NSLock()
    private static var schemes: [String] = []

    static var extraURLSchemes: [String] {
        lock.lock(); defer { lock.unlock() }
        return schemes
    }

    static func apply(_ rules: DetectionRules?) {
        let paths: [String] = rules?.extraJailbreakPaths ?? []
        let markers: [String] = rules?.extraImageMarkers ?? []
        withCStringArray(paths) { p, np in
            withCStringArray(markers) { m, nm in
                rasp_rules_set(p, np, m, nm)
            }
        }
        lock.lock()
        schemes = rules?.extraURLSchemes ?? []
        lock.unlock()
    }

    /// Bounded weight: 0.5x to 1.5x of the built-in weight, within 0...1.
    static func boundedWeight(_ code: FindingCode, _ proposed: Double) -> Double {
        let base: Double = code.metadata.weight
        let lo: Double = Swift.max(0.0, base * 0.5)
        let hi: Double = Swift.min(1.0, base * 1.5)
        return Swift.min(Swift.max(proposed, lo), hi)
    }

    static func boundedThreshold(_ proposed: Int, _ base: Int) -> Int {
        Swift.min(Swift.max(proposed, base - 15), base + 15)
    }

    private static func withCStringArray(_ strings: [String],
                                         _ body: (UnsafePointer<UnsafePointer<CChar>?>?, UInt32) -> Void) {
        let owned: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) }
        defer { for p in owned { free(p) } }
        let ptrs: [UnsafePointer<CChar>?] = owned.map { UnsafePointer($0) }
        ptrs.withUnsafeBufferPointer { buf in
            body(buf.baseAddress, UInt32(buf.count))
        }
    }
}
