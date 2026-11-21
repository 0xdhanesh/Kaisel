import Foundation
import UIKit
import LocalAuthentication
import CryptoKit
import DeviceCheck

/// Swift-side checks that need Foundation/UIKit or the configuration.
/// They always report what they see; `IntegrityConfiguration.treatment(for:)`
/// decides whether a signal is scored or informational.
struct AppIntegrityChecks {
    let configuration: IntegrityConfiguration
    let build: AppBuildFacts
    let osMajor: Int
    let developerModeSysctl: Int32

    func run() -> [RawSignal] {
        var s: [RawSignal] = []
        s += provisioning()
        s += bundleIdentity()
        s += encryption()
        s += developerModeInference()
        s += textHash()
        if configuration.probeURLSchemes { s += Self.probeJailbreakURLSchemes() }
        return s
    }

    // MARK: Provisioning profile

    struct Profile {
        let teamIdentifiers: [String]
        let provisionsAllDevices: Bool
        let hasProvisionedDevices: Bool
        let getTaskAllow: Bool
    }

    /// embedded.mobileprovision is a CMS envelope with a plain XML plist inside.
    static func loadProfile() -> Profile? {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex)
        else { return nil }
        let plistData = data.subdata(in: start.lowerBound..<end.upperBound)
        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any]
        else { return nil }
        let ent = plist["Entitlements"] as? [String: Any] ?? [:]
        return Profile(teamIdentifiers: plist["TeamIdentifier"] as? [String] ?? [],
                       provisionsAllDevices: plist["ProvisionsAllDevices"] as? Bool ?? false,
                       hasProvisionedDevices: plist["ProvisionedDevices"] != nil,
                       getTaskAllow: ent["get-task-allow"] as? Bool ?? false)
    }

    /// Best-effort classification of how this binary was signed.
    static func detectDistribution(profile: Profile?, cryptID: Int32, csFlags: UInt32) -> String {
        #if targetEnvironment(simulator)
        return "simulator"
        #else
        guard let p = profile else { return cryptID == 1 ? "appStore" : "unknown" }
        if p.provisionsAllDevices { return "enterprise" }
        if p.getTaskAllow || csFlags & 0x4 != 0 { return "development" }
        if p.hasProvisionedDevices { return "adHoc" }
        return "unknown"
        #endif
    }

    private func provisioning() -> [RawSignal] {
        guard let profile = Self.loadProfile() else { return [] }
        var s: [RawSignal] = [.init(.provisioningProfilePresent, 90, "signed as \(build.detectedDistribution)")]
        if profile.provisionsAllDevices {
            s.append(.init(.enterpriseProfile, 90, "ProvisionsAllDevices=true"))
        }
        if let expected = configuration.expectedTeamIdentifier,
           !profile.teamIdentifiers.isEmpty, !profile.teamIdentifiers.contains(expected) {
            s.append(.init(.teamIdentifierMismatch, 95, "profile team \(profile.teamIdentifiers.joined(separator: ","))"))
        }
        return s
    }

    // MARK: Bundle identity and location

    private func bundleIdentity() -> [RawSignal] {
        var s: [RawSignal] = []
        if let expected = configuration.expectedBundleIdentifier, build.bundleIdentifier != expected {
            s.append(.init(.bundleIdentifierMismatch, 95, "bundle id \(build.bundleIdentifier)"))
        }
        #if !targetEnvironment(simulator)
        if !ProcessInfo.processInfo.isiOSAppOnMac {
            let path = (Bundle.main.bundlePath as NSString).resolvingSymlinksInPath
            let base: UInt16 = ObfuscatedList.misc.lowerBound
            var roots: [String] = []
            if let r = CoreBridge.decode(base + 2) { roots.append(r) }
            if let r = CoreBridge.decode(base + 3) { roots.append(r) }
            if !roots.contains(where: { path.hasPrefix($0) }) {
                s.append(.init(.bundlePathUnexpected, 85, path))
            }
        }
        #endif
        return s
    }

    // MARK: FairPlay

    private func encryption() -> [RawSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        // App Store/TestFlight binaries are FairPlay-encrypted (cryptid=1).
        // Xcode, ad hoc and enterprise builds are not, and neither is a
        // dumped-and-resigned IPA. Scored only when expectedDistribution == .appStore.
        if build.cryptID == 0 { return [.init(.binaryDecrypted, 90, "cryptid=0")] }
        if build.cryptID == -1 { return [.init(.binaryDecrypted, 60, "no LC_ENCRYPTION_INFO")] }
        return []
        #endif
    }

    // MARK: Developer Mode inference (posture)

    private func developerModeInference() -> [RawSignal] {
        let getTaskAllow = build.codeSigningFlags & 0x4 != 0
        guard osMajor >= 16, getTaskAllow, developerModeSysctl != 1 else { return [] }
        return [.init(.developerModeInferred, 85, "get-task-allow on iOS \(osMajor)")]
    }

    // MARK: __TEXT hash

    private func textHash() -> [RawSignal] {
        guard let expected = configuration.expectedTextSHA256?.lowercased(), !build.textSHA256.isEmpty,
              expected != build.textSHA256 else { return [] }
        return [.init(.textHashMismatch, 90, "text sha256 \(build.textSHA256.prefix(16))...")]
    }

    // MARK: URL schemes

    /// Only schemes that no stock Apple app registers on iOS 15-27. Each
    /// candidate must be audited against stock apps before being added (see
    /// Scripts/gen_strings.py). TrollStore's `apple-magnifier` is excluded:
    /// the stock Magnifier app owns it.
    static func probeJailbreakURLSchemes() -> [RawSignal] {
        var schemes: [String] = ObfuscatedList.urlSchemes.compactMap(CoreBridge.decode)
        for extra in RulesRuntime.extraURLSchemes where !schemes.contains(extra) { schemes.append(extra) }
        let probe: () -> [RawSignal] = {
            schemes.compactMap { scheme in
                guard let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) else { return nil }
                return RawSignal(.jailbreakURLScheme, 80, "\(scheme)://")
            }
        }
        if Thread.isMainThread { return probe() }
        return DispatchQueue.main.sync(execute: probe)
    }
}

/// Swift-side equivalent of a C finding.
struct RawSignal {
    let code: FindingCode
    let confidence: UInt8
    let detail: String
    init(_ code: FindingCode, _ confidence: UInt8, _ detail: String) {
        self.code = code; self.confidence = confidence; self.detail = detail
    }
}

enum PostureProbe {
    static func collect(osVersion: String, osMajor: Int, model: String, devModeSysctl: Int32,
                        csFlags: UInt32, ddiMounted: Bool) -> DevicePosture {
        #if targetEnvironment(simulator)
        let isSim = true
        #else
        let isSim = false
        #endif
        let devMode: DevicePosture.TriState
        if osMajor < 16 { devMode = .off }                       // does not exist before 16
        else if devModeSysctl == 1 { devMode = .on }
        else if devModeSysctl == 0 { devMode = .off }
        else if csFlags & 0x4 != 0 { devMode = .on }             // get-task-allow app running => on
        else { devMode = .unknown }

        let ctx = LAContext()
        var err: NSError?
        let canOwnerAuth = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
        let passcode: DevicePosture.TriState
        if canOwnerAuth { passcode = .on }
        else if let e = err as? LAError, e.code == .passcodeNotSet { passcode = .off }
        else { passcode = .unknown }

        let bioCtx = LAContext()
        _ = bioCtx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let biometry: String
        switch bioCtx.biometryType {
        case .faceID: biometry = "Face ID"
        case .touchID: biometry = "Touch ID"
        case .none: biometry = "none"
        default: biometry = "other"
        }

        return DevicePosture(model: model, osVersion: osVersion, osMajor: osMajor, isSimulator: isSim,
                             isiOSAppOnMac: ProcessInfo.processInfo.isiOSAppOnMac,
                             developerMode: devMode, developerDiskImageMounted: ddiMounted,
                             passcodeSet: passcode, biometry: biometry,
                             secureEnclaveAvailable: SecureEnclave.isAvailable,
                             appAttestSupported: DCAppAttestService.shared.isSupported)
    }
}
