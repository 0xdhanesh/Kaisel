import Foundation

/// One piece of evidence.
public struct Signal: Codable, Hashable, Sendable {
    public let code: FindingCode
    public let category: SignalCategory
    public let domain: IntegrityDomain
    /// Evidence quality reported by the check (0...100).
    public let confidence: UInt8
    /// Weight after configuration overrides.
    public let weight: Double
    public let hard: Bool
    /// Shown for context only; never contributes to a score or verdict.
    public let informational: Bool
    public let detail: String

    public var title: String { code.metadata.title }
    /// weight x confidence, the value fed to the scorer (0 if informational).
    public var effectiveWeight: Double {
        if informational { return 0 }
        let c: Double = Double(confidence) / 100.0
        return weight * c
    }

    init(code: FindingCode, confidence: UInt8, weight: Double, informational: Bool, detail: String) {
        let m = code.metadata
        self.code = code
        self.category = m.category
        self.domain = code.domain
        self.confidence = confidence
        self.weight = weight
        self.hard = m.hard
        self.informational = informational
        self.detail = detail
    }
}

public enum Verdict: String, Codable, Comparable, Sendable {
    case trusted, low, elevated, high, compromised

    private var rank: Int {
        switch self {
        case .trusted: return 0
        case .low: return 1
        case .elevated: return 2
        case .high: return 3
        case .compromised: return 4
        }
    }
    public static func < (a: Verdict, b: Verdict) -> Bool { a.rank < b.rank }
}

public struct CategoryScore: Codable, Hashable, Sendable {
    public let category: SignalCategory
    public let score: Double
    public let signalCount: Int
}

/// Score and verdict for one domain.
public struct DomainAssessment: Codable, Hashable, Sendable {
    public let domain: IntegrityDomain
    public let score: Int
    public let verdict: Verdict
    public let categories: [CategoryScore]
}

/// Facts about the phone, comparable to what an Android root checker shows.
public struct DevicePosture: Codable, Hashable, Sendable {
    public enum TriState: String, Codable, Sendable { case on, off, unknown }
    public let model: String
    public let osVersion: String
    public let osMajor: Int
    public let isSimulator: Bool
    public let isiOSAppOnMac: Bool
    public let developerMode: TriState
    public let developerDiskImageMounted: Bool
    public let passcodeSet: TriState
    public let biometry: String
    public let secureEnclaveAvailable: Bool
    public let appAttestSupported: Bool
}

/// Facts about this app binary.
public struct AppBuildFacts: Codable, Hashable, Sendable {
    public let bundleIdentifier: String
    public let teamIdentifier: String?
    public let detectedDistribution: String     // appStore / development / adHoc / enterprise / unknown
    public let expectedDistribution: String?    // nil = not enforced
    public let codeSigningFlags: UInt32
    public let cryptID: Int32
    public let textSHA256: String
    public let exceptionPortCount: Int32
}

/// Result of one evaluation. There is no `isJailbroken: Bool`.
///
/// - `device`: is the phone jailbroken or its OS tampered with?
/// - `runtime`: is this process being hooked, injected, instrumented or debugged?
/// - `app`: does the binary match the distribution you expect? `nil` unless
///   `expectedDistribution` is set; app-build signals are then informational.
/// - `verdict`: worst of the enforced domains. Advisory: the server should
///   re-score `signals` from a `SealedReport` it can verify.
public struct IntegrityReport: Codable, Hashable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let sdkVersion: String
    public let verdict: Verdict
    public let score: Int
    public let device: DomainAssessment
    public let runtime: DomainAssessment
    public let app: DomainAssessment?
    public let posture: DevicePosture
    public let build: AppBuildFacts
    public let signals: [Signal]
    public let checksCompleted: UInt32
    public let checksExpected: UInt32
    public let observabilityNotes: [String]
    public let durationMs: Double
    /// Version of the signed remote rules applied, nil if none.
    public let rulesVersion: Int?

    public func signals(in domain: IntegrityDomain) -> [Signal] { signals.filter { $0.domain == domain } }
    public var scoredSignals: [Signal] { signals.filter { !$0.informational } }
    public var informationalSignals: [Signal] { signals.filter(\.informational) }

    /// Canonical JSON (sorted keys, ISO-8601 dates) used for hashing/signing.
    public func canonicalJSON() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        enc.dateEncodingStrategy = .iso8601
        return try enc.encode(self)
    }
}

public extension IntegrityReport {
    /// Signals that prove a jailbreak under the same rule Kaisel JB Check uses.
    /// Non-empty means the device verdict is `.compromised`.
    var jailbreakEvidence: [Signal] { signals.filter(JailbreakEvidence.isConclusive) }
}
