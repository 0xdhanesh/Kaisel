import Foundation
import UIKit
import CIntegrityCore

/// Entry point.
///
/// ```swift
/// let kit = IntegrityKit(configuration: .init(expectedDistribution: .appStore,
///                                             expectedTeamIdentifier: "ABCDE12345"))
/// let report = await kit.evaluate()
/// let sealed = try await kit.seal(report, serverNonce: nonce)   // send to backend
/// ```
public final class IntegrityKit: @unchecked Sendable {
    public static let sdkVersion = "1.3.1"

    public let configuration: IntegrityConfiguration
    public var scorer = RiskScorer()
    /// Tamper-evident copy of the most recent verdict.
    public let lastVerdict = ProtectedVerdict()
    /// Signed remote rules in effect (nil = compiled-in lists only).
    public let rules: DetectionRules?
    private let queue = DispatchQueue(label: "integritykit.eval", qos: .userInitiated)
    private let attestation: AttestationClient

    /// - Parameter rules: verified rules from `RulesStore.current`. They are
    ///   additive and bounded; see `DetectionRules`.
    public init(configuration: IntegrityConfiguration = .init(), rules: DetectionRules? = nil) {
        rasp_integrity_baseline()
        var cfg = configuration
        var sc = RiskScorer()
        if let r = rules {
            for p in r.extraFridaPorts where !cfg.fridaPorts.contains(p) { cfg.fridaPorts.append(p) }
            for (key, w) in r.weightOverrides {
                guard let raw = UInt16(key), let code = FindingCode(rawValue: raw),
                      cfg.weightOverrides[code] == nil else { continue }   // local config wins
                cfg.weightOverrides[code] = RulesRuntime.boundedWeight(code, w)
            }
            if let t = r.thresholds {
                let d = sc.thresholds
                sc.thresholds = (RulesRuntime.boundedThreshold(t.low, d.low),
                                 RulesRuntime.boundedThreshold(t.elevated, d.elevated),
                                 RulesRuntime.boundedThreshold(t.high, d.high),
                                 RulesRuntime.boundedThreshold(t.compromised, d.compromised))
            }
        }
        RulesRuntime.apply(rules)
        self.configuration = cfg
        self.rules = rules
        self.scorer = sc
        self.attestation = AttestationClient()
        rasp_monitor_install()
    }

    // MARK: Evaluation

    /// Runs every check off the main thread. Typical cost on an A14-class device
    /// is 15-60 ms, dominated by port-probe timeouts and the VM-map walk.
    public func evaluate() async -> IntegrityReport {
        await withCheckedContinuation { cont in
            queue.async { cont.resume(returning: self.evaluateSync()) }
        }
    }

    /// Synchronous variant. Do not call on the main thread while the main thread
    /// is needed elsewhere: the URL-scheme probe hops to main.
    public func evaluateSync() -> IntegrityReport { evaluate(extra: []) }

    func evaluate(extra: [RawSignal]) -> IntegrityReport {
        let started = Date()
        var cf = CoreBridge.facts()
        let sys = Self.systemInfo()
        let profile = AppIntegrityChecks.loadProfile()
        let build = AppBuildFacts(
            bundleIdentifier: Bundle.main.bundleIdentifier ?? "",
            teamIdentifier: profile?.teamIdentifiers.first,
            detectedDistribution: AppIntegrityChecks.detectDistribution(profile: profile, cryptID: cf.cryptid, csFlags: cf.cs_flags),
            expectedDistribution: configuration.expectedDistribution?.rawValue,
            codeSigningFlags: cf.cs_flags,
            cryptID: cf.cryptid,
            textSHA256: CoreBridge.textHash(&cf),
            exceptionPortCount: cf.exception_port_count)

        let checks = CoreCheck.allCases
        let core = CoreBridge.run(checks: checks, configuration: configuration)
        var raw: [RawSignal] = core.findings.compactMap { f in
            guard let code = FindingCode(rawValue: f.code) else { return nil }
            return RawSignal(code, f.confidence, f.detail)
        }

        // Tamper: a check that never started or never completed was hooked,
        // patched out, or crashed mid-way under instrumentation.
        var expected: UInt32 = 0
        for c in checks { expected |= c.bit }
        for check in checks where core.completed & check.bit == 0 {
            let how = core.started & check.bit == 0 ? "never entered" : "entered but did not complete"
            raw.append(.init(.checkSuppressed, 95, "\(check.name): \(how)"))
        }
        if core.dropped > 0 { raw.append(.init(.findingsOverflow, 100, "\(core.dropped) findings dropped")) }

        // Exception ports: tolerate the number the host app's crash reporter registers.
        raw.removeAll { $0.code == .exceptionPorts && build.exceptionPortCount <= configuration.allowedExceptionPorts }

        raw += AppIntegrityChecks(configuration: configuration, build: build, osMajor: sys.osMajor,
                                  developerModeSysctl: cf.devmode_sysctl).run()
        raw += newlyLoadedImages()
        raw += extra

        #if targetEnvironment(simulator)
        raw.append(.init(.simulator, 100, "targetEnvironment(simulator)"))
        #endif

        var signals = Self.requireCorroboration(makeSignals(raw))
        if let first = signals.first(where: JailbreakEvidence.isConclusive) {
            JailbreakMemory.remember(RawSignal(first.code, first.confidence, first.detail))
        } else if let past = JailbreakMemory.recall() {
            signals = makeSignals(raw + [past])
            signals = Self.requireCorroboration(signals)
        }
        let posture = PostureProbe.collect(osVersion: sys.osVersion, osMajor: sys.osMajor, model: sys.model,
                                           devModeSysctl: cf.devmode_sysctl, csFlags: cf.cs_flags,
                                           ddiMounted: raw.contains { $0.code == .developerDiskImageMounted })
        var device = scorer.assess(.device, signals)
        // Same rule as Kaisel JB Check: conclusive jailbreak evidence in any
        // domain (for example a tweak injector such as roothideinit.dylib,
        // which is scored under runtime) makes the device compromised.
        if signals.contains(where: JailbreakEvidence.isConclusive), device.verdict < .compromised {
            device = DomainAssessment(domain: .device,
                                      score: Swift.max(device.score, scorer.thresholds.compromised),
                                      verdict: .compromised, categories: device.categories)
        }
        let runtime = scorer.assess(.runtime, signals)
        let app: DomainAssessment? = configuration.expectedDistribution == nil ? nil : scorer.assess(.app, signals)
        var worst: DomainAssessment = device
        var enforced: [DomainAssessment] = [runtime]
        if let a = app { enforced.append(a) }
        for d in enforced {
            let worseVerdict: Bool = worst.verdict < d.verdict
            let sameVerdictHigherScore: Bool = worst.verdict == d.verdict && worst.score < d.score
            if worseVerdict || sameVerdictHigherScore { worst = d }
        }
        let report = IntegrityReport(
            id: UUID(),
            timestamp: started,
            sdkVersion: Self.sdkVersion,
            verdict: worst.verdict,
            score: worst.score,
            device: device,
            runtime: runtime,
            app: app,
            posture: posture,
            build: build,
            signals: signals,
            checksCompleted: core.completed,
            checksExpected: expected,
            observabilityNotes: PlatformCapabilities.current.notes,
            durationMs: Date().timeIntervalSince(started) * 1000.0,
            rulesVersion: rules?.version)
        lastVerdict.store(report)
        return report
    }

    /// Images dlopen'ed since the previous evaluation, filtered to the ones
    /// that are suspicious or come from unexpected locations.
    private func newlyLoadedImages() -> [RawSignal] {
        CoreBridge.drainNewImages().compactMap { path in
            guard let c = CoreBridge.classifyImage(path) else { return nil }
            return RawSignal(.imageAddedAtRuntime, c == .suspiciousImage ? 95 : 70, path)
        }
    }

    private func makeSignals(_ raw: [RawSignal]) -> [Signal] {
        Self.makeSignals(raw, configuration: configuration)
    }

    static func makeSignals(_ raw: [RawSignal], configuration: IntegrityConfiguration) -> [Signal] {
        var seen = Set<String>()
        var out: [Signal] = []
        for r in raw {
            if configuration.suppressedCodes.contains(r.code) { continue }
            let key: String = "\(r.code.rawValue)|\(r.detail)"
            if !seen.insert(key).inserted { continue }
            let base: Double = configuration.weightOverrides[r.code] ?? r.code.metadata.weight
            let t: IntegrityConfiguration.Treatment = configuration.treatment(for: r.code)
            let multiplier: Double = t.informational ? 1.0 : t.multiplier
            let w: Double = Swift.min(Swift.max(base * multiplier, 0.0), 1.0)
            let informational: Bool = t.informational || w == 0
            out.append(Signal(code: r.code, confidence: r.confidence, weight: w,
                              informational: informational, detail: r.detail))
        }
        // Scored signals first, then by effective weight.
        out.sort { (a: Signal, b: Signal) -> Bool in
            if a.informational != b.informational { return !a.informational }
            return a.effectiveWeight > b.effectiveWeight
        }
        return out
    }

    /// Anonymous executable memory alone is too weak to score: OS runtimes can
    /// create such regions (seen on iOS 27 with no instrumentation present).
    /// It is scored only when another instrumentation or hooking signal in the
    /// same report corroborates it; otherwise it is kept as informational.
    static func requireCorroboration(_ signals: [Signal]) -> [Signal] {
        let corroborating: Set<FindingCode> = [.fridaThread, .fridaDBus, .fridaMemoryMarker, .fridaPortOpen,
                                               .inlineHook, .symbolRebound, .suspiciousImage, .imageListMismatch]
        let corroborated = signals.contains { corroborating.contains($0.code) && !$0.informational }
        guard !corroborated else { return signals }
        return signals.map { s in
            guard s.code == .anonymousExecutableMemory, !s.informational else { return s }
            return Signal(code: s.code, confidence: s.confidence, weight: s.weight, informational: true,
                          detail: s.detail + " (uncorroborated)")
        }
    }

    struct SystemInfo { let osVersion: String; let osMajor: Int; let model: String }

    static func systemInfo() -> SystemInfo {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        var sys = utsname()
        uname(&sys)
        let machineLen = MemoryLayout.size(ofValue: sys.machine)
        let model = withUnsafePointer(to: &sys.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: machineLen) { String(cString: $0) }
        }
        return SystemInfo(osVersion: "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)",
                          osMajor: v.majorVersion, model: model)
    }

    // MARK: Sealing and attestation

    /// Binds a report to a server-issued nonce and signs it with App Attest
    /// (preferred) and/or a Secure Enclave key. See `SealedReport`.
    public func seal(_ report: IntegrityReport, serverNonce: Data) async throws -> SealedReport {
        try await attestation.seal(report, nonce: serverNonce)
    }

    /// One-time App Attest enrolment. Send the result to your server, which
    /// verifies it against Apple's App Attest root CA and stores the public key.
    ///
    /// Throws `IntegrityError.appAttestUnavailable` when the build has no App
    /// Attest entitlement; `seal` then still works, without an assertion.
    public func attestKey(serverChallenge: Data) async throws -> AppAttestEnrolment {
        try await attestation.attestKey(challenge: serverChallenge)
    }

    /// Local App Attest state, for display. The server is the authority.
    public var appAttestStatus: AppAttestStatus { attestation.appAttestStatus }

    /// DeviceCheck token for per-device two-bit state on the server
    /// (e.g. "this device was previously seen jailbroken").
    public func deviceCheckToken() async throws -> Data {
        try await attestation.deviceCheckToken()
    }

    // MARK: Active countermeasures

    /// PT_DENY_ATTACH via a raw syscall. Opt-in: it terminates any attached
    /// debugger (and Xcode), and it is trivially neutralised on a jailbroken
    /// kernel. Use as a speed bump in release builds only.
    @discardableResult
    public static func denyDebuggerAttach() -> Int32 {
        #if DEBUG
        return 0
        #else
        return rasp_deny_debugger_attach()
        #endif
    }
}
