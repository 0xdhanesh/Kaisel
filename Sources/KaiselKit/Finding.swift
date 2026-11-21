import Foundation

/// Evidence category. Signals are combined with damping *within* a category
/// (correlated evidence) and without damping *across* categories (independent
/// corroboration).
public enum SignalCategory: String, Codable, CaseIterable, Sendable {
    case jailbreakArtefact
    case filesystemIntegrity
    case sandbox
    case injection
    case hooking
    case debugger
    case instrumentation
    case codeSigning
    case environment
    case developerMode
    case tamper
    case runtimeEnvironment
}

/// What a signal is evidence about. Mirrors the Android split between
/// device integrity, app integrity and the runtime of this process.
public enum IntegrityDomain: String, Codable, CaseIterable, Sendable {
    /// The phone itself: jailbreak, tampered OS, broken sandbox.
    case device
    /// This process right now: hooks, injection, Frida, debugger.
    case runtime
    /// How this app binary was built, signed and distributed.
    case app
    /// Facts about the device's configuration that are not compromise
    /// (Developer Mode, Developer Disk Image). Never scored.
    case posture
}

/// Finding codes. Raw values 1xx-8xx mirror `RASP_F_*` in rasp_core.h; 9xx+
/// are produced by the Swift layer.
public enum FindingCode: UInt16, Codable, CaseIterable, Sendable {
    // C core
    case jailbreakPathPresent       = 100
    case jailbreakPathErrnoOracle   = 101
    case symlinkedSystemDirectory   = 102
    case rootVolumeNotSealed        = 103
    case rootVolumeWritable         = 104
    case rootlessJailbreakRoot      = 105
    case libcSyscallMismatch        = 108
    case canaryFailed               = 109
    case dyldModified               = 110
    case userspaceReboot            = 111
    case sandboxWrite               = 120
    case sandboxFork                = 121
    case sandboxRead                = 122
    case suspiciousImage            = 200
    case unexpectedImagePath        = 201
    case imageListMismatch          = 202
    case imageAddedAtRuntime        = 203
    case interposeSection           = 204
    case inlineHook                 = 300
    case symbolRebound              = 301
    case breakpointInstruction      = 302
    case objcSwizzled               = 303
    case syscallStubAltered         = 304
    case symbolForeignImage         = 305
    case prologueChanged            = 306
    case ptraced                    = 400
    case codeSigningDebugged        = 401
    case exceptionPorts             = 402
    case parentProcessUnexpected    = 403
    case fridaThread                = 500
    case fridaPortOpen              = 501
    case fridaDBus                  = 502
    case anonymousExecutableMemory  = 503
    case fridaMemoryMarker          = 504
    case codeSignatureInvalid       = 600
    case getTaskAllow               = 601
    case suspiciousEntitlement      = 602
    case binaryDecrypted            = 603
    case textModified               = 610
    case envInjection               = 700
    case envJailbreak               = 701
    case envGetenvMismatch          = 702
    case developerModeEnabled       = 800
    case developerDiskImageMounted  = 802
    // Swift layer
    case developerModeInferred      = 801
    case provisioningProfilePresent = 900
    case teamIdentifierMismatch     = 901
    case bundleIdentifierMismatch   = 902
    case enterpriseProfile          = 903
    case bundlePathUnexpected       = 904
    case jailbreakURLScheme         = 905
    case textHashMismatch           = 907
    case previouslyJailbroken       = 908
    case checkSuppressed            = 1000
    case findingsOverflow           = 1001
    case simulator                  = 1002
    case monitorIntervalStarved     = 1003

    public struct Metadata: Sendable {
        public let category: SignalCategory
        /// Prior probability-like weight (0...1) that this signal alone means
        /// the runtime cannot be trusted. Multiplied by the check's confidence.
        public let weight: Double
        /// Hard indicators floor the verdict at `.high` regardless of score.
        public let hard: Bool
        public let title: String
    }

    public var metadata: Metadata {
        switch self {
        case .jailbreakPathPresent:       return .init(category: .jailbreakArtefact, weight: 0.60, hard: false, title: "Jailbreak artefact present")
        case .jailbreakPathErrnoOracle:   return .init(category: .jailbreakArtefact, weight: 0.45, hard: false, title: "Jailbreak artefact inferred from errno")
        case .symlinkedSystemDirectory:   return .init(category: .filesystemIntegrity, weight: 0.70, hard: false, title: "System directory replaced by symlink")
        case .rootVolumeNotSealed:        return .init(category: .filesystemIntegrity, weight: 0.55, hard: false, title: "Root volume is not the sealed snapshot")
        case .rootVolumeWritable:         return .init(category: .filesystemIntegrity, weight: 0.90, hard: true,  title: "Root volume mounted read-write")
        case .rootlessJailbreakRoot:      return .init(category: .jailbreakArtefact, weight: 0.95, hard: true,  title: "Rootless jailbreak root (/var/jb) present")
        case .libcSyscallMismatch:        return .init(category: .tamper,            weight: 0.95, hard: true,  title: "libc and kernel disagree (hiding hook)")
        case .dyldModified:               return .init(category: .tamper,            weight: 0.50, hard: false, title: "dyld code differs from disk (possible loader hook)")
        case .userspaceReboot:            return .init(category: .jailbreakArtefact, weight: 0.40, hard: false, title: "Userspace reboot since kernel boot")
        case .previouslyJailbroken:       return .init(category: .jailbreakArtefact, weight: 0.60, hard: false, title: "Jailbreak seen on this device before")
        case .canaryFailed:               return .init(category: .tamper,            weight: 0.80, hard: false, title: "Control probe failed")
        case .sandboxWrite:               return .init(category: .sandbox,           weight: 0.95, hard: true,  title: "Wrote outside the app container")
        case .sandboxFork:                return .init(category: .sandbox,           weight: 0.90, hard: true,  title: "fork() permitted")
        case .sandboxRead:                return .init(category: .sandbox,           weight: 0.55, hard: false, title: "Read another domain's directory")
        case .suspiciousImage:            return .init(category: .injection,         weight: 0.90, hard: true,  title: "Known injection/hooking library loaded")
        case .unexpectedImagePath:        return .init(category: .injection,         weight: 0.50, hard: false, title: "Image loaded from unexpected location")
        case .imageListMismatch:          return .init(category: .injection,         weight: 0.85, hard: true,  title: "dyld image list is being filtered")
        case .imageAddedAtRuntime:        return .init(category: .injection,         weight: 0.60, hard: false, title: "Suspicious image loaded at runtime")
        case .interposeSection:           return .init(category: .injection,         weight: 0.60, hard: false, title: "DYLD interposing section in non-system image")
        case .inlineHook:                 return .init(category: .hooking,           weight: 0.85, hard: true,  title: "Inline hook trampoline")
        case .symbolRebound:              return .init(category: .hooking,           weight: 0.85, hard: true,  title: "Symbol pointer rebound (fishhook/interposing)")
        case .breakpointInstruction:      return .init(category: .debugger,          weight: 0.60, hard: false, title: "Software breakpoint at function entry")
        case .objcSwizzled:               return .init(category: .hooking,           weight: 0.60, hard: false, title: "Objective-C method implementation moved")
        case .syscallStubAltered:         return .init(category: .hooking,           weight: 0.70, hard: false, title: "Syscall stub does not trap")
        case .symbolForeignImage:         return .init(category: .hooking,           weight: 0.80, hard: false, title: "System symbol resolves outside system images")
        case .prologueChanged:            return .init(category: .hooking,           weight: 0.90, hard: true,  title: "Function code changed after start-up")
        case .textModified:               return .init(category: .tamper,            weight: 0.95, hard: true,  title: "App code modified in memory")
        case .ptraced:                    return .init(category: .debugger,          weight: 0.80, hard: false, title: "Process is being traced")
        case .codeSigningDebugged:        return .init(category: .debugger,          weight: 0.60, hard: false, title: "Kernel marked process CS_DEBUGGED")
        case .exceptionPorts:             return .init(category: .debugger,          weight: 0.35, hard: false, title: "Task exception ports registered")
        case .parentProcessUnexpected:    return .init(category: .debugger,          weight: 0.50, hard: false, title: "Parent is not launchd")
        case .fridaThread:                return .init(category: .instrumentation,   weight: 0.95, hard: true,  title: "Frida runtime thread")
        case .fridaPortOpen:              return .init(category: .instrumentation,   weight: 0.35, hard: false, title: "Instrumentation port listening")
        case .fridaDBus:                  return .init(category: .instrumentation,   weight: 0.95, hard: true,  title: "frida-server D-Bus endpoint")
        case .anonymousExecutableMemory:  return .init(category: .instrumentation,   weight: 0.35, hard: false, title: "Anonymous executable memory")
        case .fridaMemoryMarker:          return .init(category: .instrumentation,   weight: 0.95, hard: true,  title: "Frida agent marker in memory")
        case .codeSignatureInvalid:       return .init(category: .codeSigning,       weight: 0.90, hard: true,  title: "Code signature not valid")
        case .getTaskAllow:               return .init(category: .codeSigning,       weight: 0.50, hard: false, title: "Debuggable build (get-task-allow)")
        case .suspiciousEntitlement:      return .init(category: .codeSigning,       weight: 0.85, hard: true,  title: "Entitlement not grantable to App Store apps")
        case .binaryDecrypted:            return .init(category: .codeSigning,       weight: 0.60, hard: false, title: "Binary not FairPlay-encrypted (not an App Store install)")
        case .envInjection:               return .init(category: .environment,       weight: 0.90, hard: true,  title: "DYLD_* injection variable set")
        case .envJailbreak:               return .init(category: .environment,       weight: 0.95, hard: true,  title: "Jailbreak environment variable set")
        case .envGetenvMismatch:          return .init(category: .tamper,            weight: 0.90, hard: true,  title: "getenv() hides variables")
        case .developerModeEnabled:       return .init(category: .developerMode,     weight: 0.20, hard: false, title: "Developer Mode enabled")
        case .developerModeInferred:      return .init(category: .developerMode,     weight: 0.15, hard: false, title: "Developer Mode inferred")
        case .developerDiskImageMounted:  return .init(category: .developerMode,     weight: 0.25, hard: false, title: "Developer Disk Image mounted")
        case .provisioningProfilePresent: return .init(category: .codeSigning,       weight: 0.35, hard: false, title: "Embedded provisioning profile (non-App Store signing)")
        case .teamIdentifierMismatch:     return .init(category: .codeSigning,       weight: 0.90, hard: true,  title: "Signed by an unexpected team (re-signed)")
        case .bundleIdentifierMismatch:   return .init(category: .codeSigning,       weight: 0.90, hard: true,  title: "Unexpected bundle identifier")
        case .enterpriseProfile:          return .init(category: .codeSigning,       weight: 0.40, hard: false, title: "Enterprise (in-house) profile")
        case .bundlePathUnexpected:       return .init(category: .filesystemIntegrity, weight: 0.70, hard: false, title: "App installed outside the user app container")
        case .jailbreakURLScheme:         return .init(category: .jailbreakArtefact, weight: 0.55, hard: false, title: "Package manager URL scheme registered")
        case .textHashMismatch:           return .init(category: .codeSigning,       weight: 0.90, hard: true,  title: "__TEXT hash differs from build")
        case .checkSuppressed:            return .init(category: .tamper,            weight: 0.85, hard: true,  title: "A check did not run to completion")
        case .findingsOverflow:           return .init(category: .tamper,            weight: 0.30, hard: false, title: "Findings buffer overflowed")
        case .simulator:                  return .init(category: .runtimeEnvironment, weight: 0.50, hard: false, title: "Running in the iOS Simulator")
        case .monitorIntervalStarved:     return .init(category: .tamper,            weight: 0.40, hard: false, title: "Monitor did not run on schedule")
        }
    }

    public var domain: IntegrityDomain {
        switch self {
        case .jailbreakPathPresent, .jailbreakPathErrnoOracle, .symlinkedSystemDirectory, .rootVolumeNotSealed,
             .rootVolumeWritable, .rootlessJailbreakRoot, .libcSyscallMismatch, .sandboxWrite, .sandboxFork,
             .sandboxRead, .suspiciousEntitlement, .envJailbreak, .bundlePathUnexpected, .jailbreakURLScheme,
             .simulator, .dyldModified, .userspaceReboot, .previouslyJailbroken:
            return .device
        case .canaryFailed, .suspiciousImage, .unexpectedImagePath, .imageListMismatch, .imageAddedAtRuntime,
             .interposeSection, .inlineHook, .symbolRebound, .breakpointInstruction, .objcSwizzled,
             .syscallStubAltered, .symbolForeignImage, .ptraced, .codeSigningDebugged, .exceptionPorts,
             .parentProcessUnexpected, .fridaThread, .fridaPortOpen, .fridaDBus, .anonymousExecutableMemory,
             .fridaMemoryMarker, .envInjection, .envGetenvMismatch, .checkSuppressed, .findingsOverflow,
             .monitorIntervalStarved, .prologueChanged, .textModified:
            return .runtime
        case .codeSignatureInvalid, .getTaskAllow, .binaryDecrypted, .provisioningProfilePresent,
             .teamIdentifierMismatch, .bundleIdentifierMismatch, .enterpriseProfile, .textHashMismatch:
            return .app
        case .developerModeEnabled, .developerModeInferred, .developerDiskImageMounted:
            return .posture
        }
    }
}
