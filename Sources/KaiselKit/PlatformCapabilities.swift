import Foundation

/// What each iOS version lets an unprivileged, sandboxed app observe.
/// Mirrors the table in README.md. Notes are attached to every report so the
/// server knows which absences of evidence are meaningful.
public struct PlatformCapabilities: Sendable {
    public let osMajor: Int
    public let osMinor: Int

    public static var current: PlatformCapabilities {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return PlatformCapabilities(osMajor: v.majorVersion, osMinor: v.minorVersion)
    }

    /// Developer Mode exists from iOS 16.
    public var developerModeExists: Bool { osMajor >= 16 }
    /// iOS 17 moved to personalised Developer Disk Images mounted under /System/Developer.
    public var personalisedDDI: Bool { osMajor >= 17 }
    /// Signed System Volume (sealed root snapshot) applies to all supported versions.
    public var sealedSystemVolume: Bool { osMajor >= 15 }

    public var notes: [String] {
        var n: [String] = []
        if !developerModeExists {
            n.append("iOS \(osMajor): Developer Mode does not exist; developer-mode signals are not applicable.")
        } else {
            n.append("Developer Mode has no public API; status comes from an AMFI sysctl when readable, otherwise inferred from get-task-allow.")
        }
        n.append(personalisedDDI
                 ? "Developer Disk Image is personalised and mounted on demand (/System/Developer)."
                 : "Developer Disk Image mounts at /Developer when Xcode has paired.")
        switch osMajor {
        case 15:
            n.append("iOS 15: rootful (checkra1n/palera1n rootful on A8-A11) and rootless (Dopamine, palera1n, XinaA15) jailbreaks exist; TrollStore supported.")
        case 16:
            n.append("iOS 16: rootless jailbreaks (Dopamine up to 16.6.1 on A12+, palera1n on A8-A11); TrollStore up to 16.6.1/16.7 RC.")
        case 17:
            n.append("iOS 17: palera1n on checkm8 devices that receive 17; TrollStore on 17.0 only; no public A12+ kernel jailbreak at release.")
        case 18...25:
            n.append("iOS \(osMajor): no public kernel jailbreak for A12+ known at SDK release; checkm8-class iPads may be jailbreakable. Instrumentation on non-jailbroken devices uses re-signed IPAs with FridaGadget.")
        default:
            n.append("iOS \(osMajor): no public jailbreak known at SDK release. Main threat is repackaging plus FridaGadget, and debugging via Developer Mode. Validate the check set on-device for each new major.")
        }
        n.append("Hiding tweaks that patch the kernel (not libc) defeat raw-syscall filesystem checks; rely on server-side attestation for trust decisions.")
        return n
    }
}
