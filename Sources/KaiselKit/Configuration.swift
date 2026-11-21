import Foundation

public struct IntegrityConfiguration: Sendable {
    public enum Distribution: String, Codable, Sendable {
        /// App Store or TestFlight: FairPlay-encrypted, no embedded profile, no get-task-allow.
        case appStore
        /// Apple Developer Enterprise Program in-house distribution.
        case enterprise
        /// Ad hoc builds.
        case adHoc
        /// Xcode development builds.
        case development
    }

    /// The distribution you *expect* this binary to have in production.
    ///
    /// `nil` (default): app-build signals (provisioning profile, get-task-allow,
    /// FairPlay, team ID) are reported as **informational** and never affect
    /// any verdict. Use this for development, ad hoc and demo builds.
    ///
    /// `.appStore` etc.: app-build signals that contradict the expectation are
    /// scored into `appVerdict`, which then also feeds the overall verdict.
    public var expectedDistribution: Distribution?
    /// 10-character Apple team ID the app must be signed with (checked against
    /// the embedded profile when present).
    public var expectedTeamIdentifier: String?
    public var expectedBundleIdentifier: String?
    /// SHA-256 of the main executable's __TEXT,__text recorded at build time.
    public var expectedTextSHA256: String?

    /// Loopback ports probed for frida-server (27042 is Frida's default).
    public var fridaPorts: [UInt16]
    public var portProbeTimeoutMs: UInt32
    /// Scan the VM map for anonymous executable memory.
    public var scanMemory: Bool
    /// fork() probe (child exits immediately).
    public var allowForkProbe: Bool
    /// Task exception ports your own crash reporter registers.
    public var allowedExceptionPorts: Int32
    /// Probe jailbreak package-manager URL schemes (needs LSApplicationQueriesSchemes).
    public var probeURLSchemes: Bool
    /// Debugger evidence is expected while developing; discount it.
    public var debuggerExpected: Bool
    /// Per-code weight overrides (0...1).
    public var weightOverrides: [FindingCode: Double]
    /// Codes to drop entirely.
    public var suppressedCodes: Set<FindingCode>

    public init(expectedDistribution: Distribution? = nil,
                expectedTeamIdentifier: String? = nil,
                expectedBundleIdentifier: String? = nil,
                expectedTextSHA256: String? = nil,
                fridaPorts: [UInt16] = [27042, 27043],
                portProbeTimeoutMs: UInt32 = 120,
                scanMemory: Bool = true,
                allowForkProbe: Bool = true,
                allowedExceptionPorts: Int32 = 0,
                probeURLSchemes: Bool = true,
                debuggerExpected: Bool = false,
                weightOverrides: [FindingCode: Double] = [:],
                suppressedCodes: Set<FindingCode> = []) {
        self.expectedDistribution = expectedDistribution
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.expectedBundleIdentifier = expectedBundleIdentifier
        self.expectedTextSHA256 = expectedTextSHA256
        self.fridaPorts = fridaPorts
        self.portProbeTimeoutMs = portProbeTimeoutMs
        self.scanMemory = scanMemory
        self.allowForkProbe = allowForkProbe
        self.allowedExceptionPorts = allowedExceptionPorts
        self.probeURLSchemes = probeURLSchemes
        self.debuggerExpected = debuggerExpected
        self.weightOverrides = weightOverrides
        self.suppressedCodes = suppressedCodes
    }

    /// How a code is treated under this configuration.
    struct Treatment { let multiplier: Double; let informational: Bool }

    func treatment(for code: FindingCode) -> Treatment {
        switch code.domain {
        case .posture:
            // Developer Mode etc. describe the device, they are not compromise.
            return .init(multiplier: 0, informational: true)
        case .app:
            guard let expected = expectedDistribution else { return .init(multiplier: 0, informational: true) }
            switch (expected, code) {
            case (.appStore, _):
                return .init(multiplier: 1, informational: false)
            case (.enterprise, .provisioningProfilePresent), (.enterprise, .binaryDecrypted), (.enterprise, .enterpriseProfile),
                 (.adHoc, .provisioningProfilePresent), (.adHoc, .binaryDecrypted),
                 (.development, .provisioningProfilePresent), (.development, .binaryDecrypted), (.development, .getTaskAllow):
                return .init(multiplier: 0, informational: true)
            default:
                return .init(multiplier: 1, informational: false)
            }
        case .runtime:
            let debuggerCodes: Set<FindingCode> = [.ptraced, .codeSigningDebugged, .exceptionPorts,
                                                   .parentProcessUnexpected, .breakpointInstruction]
            if (debuggerExpected || expectedDistribution == .development) && debuggerCodes.contains(code) {
                return .init(multiplier: 0, informational: true)
            }
            return .init(multiplier: 1, informational: false)
        case .device:
            return .init(multiplier: 1, informational: false)
        }
    }
}
