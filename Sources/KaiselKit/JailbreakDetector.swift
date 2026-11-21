import Foundation
import CIntegrityCore

/// Jailbreak-only check: answers "is this phone jailbroken?" and nothing about
/// how the calling app was built, signed or distributed, or whether a
/// debugger or Frida is attached to it.
///
/// Decision rule:
/// - `jailbroken`: at least one **conclusive** finding, meaning evidence that a
///   stock, sealed iOS cannot produce: the rootless jailbreak root `/var/jb`,
///   jailbreak files visible to the kernel, a writable or re-mounted root
///   volume, a broken app sandbox (write outside the container or fork()),
///   tweak-injection libraries (Substrate/ElleKit/TweakInject/systemhook) in
///   the process, jailbreak-only environment variables or entitlements, or a
///   hiding tweak caught lying (libc and the kernel disagree, or dyld's image
///   list is filtered).
/// - `suspicious`: only indirect evidence (package-manager URL schemes,
///   errno-inferred paths, unexpected image locations, hooks on file APIs,
///   a check that did not complete).
/// - `notJailbroken`: none of the above.
public struct JailbreakResult: Codable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable { case jailbroken, suspicious, notJailbroken }
    public let status: Status
    /// Evidence that made the result `jailbroken`.
    public let conclusive: [Signal]
    /// Indirect evidence.
    public let indicators: [Signal]
    public let model: String
    public let osVersion: String
    public let checkedAt: Date
    public let durationMs: Double
    /// Checks that ran (filesystem, sandbox, images, hooks, environment, code signing, canary).
    public let checksRun: [String]
}

public final class JailbreakDetector: @unchecked Sendable {
    public var probeURLSchemes: Bool
    private let queue = DispatchQueue(label: "integritykit.jailbreak", qos: .userInitiated)

    /// - Parameter rules: optional verified rules (extra paths, markers, schemes).
    public init(probeURLSchemes: Bool = true, rules: DetectionRules? = nil) {
        self.probeURLSchemes = probeURLSchemes
        rasp_integrity_baseline()
        if let r = rules { RulesRuntime.apply(r) }
    }

    public func check() async -> JailbreakResult {
        await withCheckedContinuation { cont in
            queue.async { cont.resume(returning: self.checkSync()) }
        }
    }

    static let conclusiveCodes: Set<FindingCode> = [
        .jailbreakPathPresent, .rootlessJailbreakRoot, .symlinkedSystemDirectory, .rootVolumeWritable,
        .sandboxWrite, .sandboxFork, .libcSyscallMismatch, .imageListMismatch, .envJailbreak,
        .suspiciousEntitlement, .bundlePathUnexpected,
    ]
    static let indicatorCodes: Set<FindingCode> = [
        .jailbreakPathErrnoOracle, .rootVolumeNotSealed, .sandboxRead, .unexpectedImagePath,
        .interposeSection, .inlineHook, .symbolRebound, .objcSwizzled, .syscallStubAltered,
        .symbolForeignImage, .envInjection, .envGetenvMismatch, .jailbreakURLScheme, .canaryFailed,
        .checkSuppressed,
    ]

    /// Tweak-injection libraries prove a jailbreak; Frida/FridaGadget does not
    /// (it can be embedded in a re-signed app on a stock phone).
    private static func isTweakInjector(_ detail: String) -> Bool {
        let d = detail.lowercased()
        return !(d.contains("frida") || d.contains("gadget") || d.contains("gum-js"))
    }

    public func checkSync() -> JailbreakResult {
        let started = Date()
        let checks: [CoreCheck] = [.filesystem, .sandbox, .images, .hooks, .environment, .codesign, .canary]
        let cfg = IntegrityConfiguration(fridaPorts: [], scanMemory: false, allowForkProbe: true)
        let core = CoreBridge.run(checks: checks, configuration: cfg)

        var raw: [RawSignal] = core.findings.compactMap { f in
            FindingCode(rawValue: f.code).map { RawSignal($0, f.confidence, f.detail) }
        }
        for check in checks where core.completed & check.bit == 0 {
            raw.append(.init(.checkSuppressed, 95, "\(check.name) did not complete"))
        }
        if probeURLSchemes { raw += AppIntegrityChecks.probeJailbreakURLSchemes() }

        var conclusive: [RawSignal] = []
        var indicators: [RawSignal] = []
        for r in raw {
            if r.code == .suspiciousImage {
                if Self.isTweakInjector(r.detail) { conclusive.append(r) } else { indicators.append(r) }
            } else if Self.conclusiveCodes.contains(r.code) {
                conclusive.append(r)
            } else if Self.indicatorCodes.contains(r.code) {
                indicators.append(r)
            }
        }

        #if targetEnvironment(simulator)
        indicators.append(.init(.simulator, 100, "running in the iOS Simulator; result is not meaningful"))
        #endif

        let c: [Signal] = IntegrityKit.makeSignals(conclusive, configuration: cfg)
        let i: [Signal] = IntegrityKit.makeSignals(indicators, configuration: cfg)
        let sys = IntegrityKit.systemInfo()
        let status: JailbreakResult.Status
        if !c.isEmpty { status = .jailbroken }
        else if !i.isEmpty { status = .suspicious }
        else { status = .notJailbroken }
        let elapsedMs: Double = Date().timeIntervalSince(started) * 1000.0
        var checksRun: [String] = checks.map { $0.name }
        if probeURLSchemes { checksRun.append("urlSchemes") }
        return JailbreakResult(
            status: status,
            conclusive: c,
            indicators: i,
            model: sys.model,
            osVersion: sys.osVersion,
            checkedAt: started,
            durationMs: elapsedMs,
            checksRun: checksRun)
    }
}
