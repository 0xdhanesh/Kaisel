import Foundation
import CIntegrityCore

/// Jailbreak-only check: answers "is this phone jailbroken?" and nothing about
/// how the calling app was built, signed or distributed, or whether a
/// debugger or Frida is attached to it.
///
/// Decision rule:
/// - `jailbroken`: at least one **conclusive** finding (`JailbreakEvidence`), meaning evidence that a
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
/// - `notJailbroken`: none of the above. This means no conclusive or indirect
///   evidence was observed by this process. It is not proof of a stock device:
///   per-app hiding (for example RootHide's Blacklist) is a known miss.
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
    /// Checks that were started but did not complete (1.4.0). Empty on a normal run.
    public let checksIncomplete: [String]
    /// SDK version that produced the result (1.4.0), for lab records.
    public let sdkVersion: String
}

/// Explicit loaded-image evidence classes (1.4.0). A thin wrapper over the C
/// classifier (`rasp_image_class`), so the image scan, the runtime monitor and
/// re-validation of stored evidence use one implementation. The lists come
/// from `Server/classification.json`, shared with the reference server.
public enum ImageEvidenceClass: String, Codable, Sendable {
    /// No usable path.
    case unknown
    /// System location, or inside the app bundle without a known identity.
    case trusted
    /// Exact jailbreak-injector identity outside the bundle, or a jailbreak-root path. Conclusive.
    case jailbreakInjector
    /// Frida/Cycript, or an injector inside the bundle (re-signed app). Runtime risk only.
    case instrumentation
    /// Broad marker (built-in or signed remote rules) in an external image name. Indicator.
    case marker
    /// Any other image outside the system and the bundle. Indicator.
    case unknownExternal
}

public enum ImageEvidence {
    /// Classifies an image path. `bundlePath` nil means "unknown bundle": an
    /// image is then treated as in-bundle when a directory component ends in ".app".
    public static func classify(_ path: String, bundlePath: String? = nil) -> ImageEvidenceClass {
        let c: rasp_image_class_t
        if let b = bundlePath { c = rasp_image_class(path, b) } else { c = rasp_image_class(path, nil) }
        switch c {
        case RASP_IMG_TRUSTED: return .trusted
        case RASP_IMG_JAILBREAK_INJECTOR: return .jailbreakInjector
        case RASP_IMG_INSTRUMENTATION: return .instrumentation
        case RASP_IMG_MARKER: return .marker
        case RASP_IMG_UNKNOWN_EXTERNAL: return .unknownExternal
        default: return .unknown
        }
    }

    /// Same as `classify`, with the simulator behaviour explicit. Used by the
    /// regression tests so results do not depend on where the tests run.
    static func classify(_ path: String, bundlePath: String?, simulator: Bool) -> ImageEvidenceClass {
        let c: rasp_image_class_t
        if let b = bundlePath { c = rasp_image_class_ex(path, b, simulator) } else { c = rasp_image_class_ex(path, nil, simulator) }
        switch c {
        case RASP_IMG_TRUSTED: return .trusted
        case RASP_IMG_JAILBREAK_INJECTOR: return .jailbreakInjector
        case RASP_IMG_INSTRUMENTATION: return .instrumentation
        case RASP_IMG_MARKER: return .marker
        case RASP_IMG_UNKNOWN_EXTERNAL: return .unknownExternal
        default: return .unknown
        }
    }
}

/// The single rule that decides whether evidence proves a jailbreak. Used by
/// `JailbreakDetector` (Kaisel JB Check), by `IntegrityKit` for the device
/// verdict and by `JailbreakMemory` for stored history, so all agree. The
/// reference server applies the same rule (`Server/policy.py`), and a parity
/// test checks both sets against `Server/classification.json`.
///
/// 1.4.0: conclusive evidence is an explicit allow-list of finding codes. An
/// image is conclusive only as `suspiciousImage` (200) whose path still
/// classifies as a known jailbreak injector. Before 1.4.0 any image finding
/// that did not mention Frida was treated as an injector, so a framework named
/// like a broad marker (for example "CraneBank") could produce "Jailbroken".
public enum JailbreakEvidence {
    /// Codes that a stock, sealed iOS cannot produce.
    public static let conclusiveCodes: Set<FindingCode> = [
        .jailbreakPathPresent, .rootlessJailbreakRoot, .symlinkedSystemDirectory, .rootVolumeWritable,
        .sandboxWrite, .sandboxFork, .libcSyscallMismatch, .imageListMismatch, .envJailbreak,
        .suspiciousEntitlement, .bundlePathUnexpected, .suspiciousImage,
    ]
    /// Indirect evidence only.
    public static let indicatorCodes: Set<FindingCode> = [
        .jailbreakPathErrnoOracle, .rootVolumeNotSealed, .sandboxRead, .unexpectedImagePath,
        .imageMarkerMatch, .instrumentationImage, .imageAddedAtRuntime,
        .interposeSection, .inlineHook, .symbolRebound, .objcSwizzled, .syscallStubAltered,
        .symbolForeignImage, .envInjection, .envGetenvMismatch, .jailbreakURLScheme, .canaryFailed,
        .checkSuppressed, .userspaceReboot, .previouslyJailbroken, .dyldModified,
    ]

    /// True when the image named in `detail` is a known jailbreak injector
    /// (RootHide's roothideinit, Substrate, ElleKit, TweakInject, systemhook, or
    /// anything under a jailbreak root). Frida/FridaGadget and injectors inside
    /// the app bundle are not: they run in re-signed apps on stock phones.
    /// Before 1.4.0 this returned true for any detail without "frida"/"gadget".
    public static func isTweakInjector(_ detail: String) -> Bool {
        ImageEvidence.classify(detail) == .jailbreakInjector
    }

    /// Code-and-detail form, for raw findings and stored history.
    public static func isConclusive(code: FindingCode, detail: String) -> Bool {
        guard conclusiveCodes.contains(code) else { return false }
        if code == .suspiciousImage { return isTweakInjector(detail) }
        return true
    }

    /// True when this one signal proves the device is jailbroken.
    public static func isConclusive(_ s: Signal) -> Bool {
        if s.informational { return false }
        return isConclusive(code: s.code, detail: s.detail)
    }
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

    static var conclusiveCodes: Set<FindingCode> { JailbreakEvidence.conclusiveCodes }
    static var indicatorCodes: Set<FindingCode> { JailbreakEvidence.indicatorCodes }

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
            if JailbreakEvidence.isConclusive(code: r.code, detail: r.detail) {
                conclusive.append(r)
            } else if Self.indicatorCodes.contains(r.code) || Self.conclusiveCodes.contains(r.code) {
                // A conclusive-code finding that fails re-validation (for
                // example an image path that no longer classifies as an
                // injector) is kept as an indicator, never dropped silently.
                indicators.append(r)
            }
        }

        if let first = conclusive.first {
            JailbreakMemory.remember(first)
        } else if let past = JailbreakMemory.recall() {
            indicators.append(past)
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
        let incomplete: [String] = checks.filter { core.completed & $0.bit == 0 }.map { $0.name }
        return JailbreakResult(
            status: status,
            conclusive: c,
            indicators: i,
            model: sys.model,
            osVersion: sys.osVersion,
            checkedAt: started,
            durationMs: elapsedMs,
            checksRun: checksRun,
            checksIncomplete: incomplete,
            sdkVersion: IntegrityKit.sdkVersion)
    }
}
