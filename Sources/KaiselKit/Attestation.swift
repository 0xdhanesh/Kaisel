import Foundation
import CryptoKit
import DeviceCheck
import Security

/// One-time App Attest enrolment payload for the server.
public struct AppAttestEnrolment: Codable, Sendable {
    public let keyId: String
    public let attestationObject: Data     // CBOR, verify against Apple App Attest root CA
}

/// A report bound to a server nonce and signed by hardware-backed keys.
///
/// Server verification:
///  1. `clientDataHash == SHA256(payload || nonce)` and the nonce is the one it issued (single use, short TTL).
///  2. If `appAttestAssertion` is present: verify it with the public key from enrolment, check the
///     counter is strictly increasing and the RP ID hash matches your App ID. This proves the payload
///     came from a genuine, unmodified instance of your app on a real Apple device.
///  3. If `secureEnclaveSignature` is present: verify ECDSA-P256-SHA256 over `clientDataHash` with the
///     enrolled SE public key. Proves continuity of the device-bound key, not app genuineness.
///  4. Re-score `payload.signals` under server policy; never trust `payload.verdict` alone.
public struct SealedReport: Codable, Sendable {
    public let payload: Data                       // canonical JSON of IntegrityReport
    public let nonce: Data
    public let clientDataHash: Data                // SHA256(payload || nonce)
    public let appAttestKeyId: String?
    public let appAttestAssertion: Data?
    public let secureEnclaveSignature: Data?       // DER ECDSA
    public let secureEnclavePublicKey: Data?       // X9.63 uncompressed
    public let attestationError: String?
}

final class AttestationClient: @unchecked Sendable {
    private let keychainService = "integritykit.keys"
    private let appAttestAccount = "appattest.keyid"
    private let seAccount = "secureenclave.p256"

    // MARK: App Attest

    /// `.enrolled` only means a key ID is stored locally; the server decides
    /// whether that key was ever accepted.
    var appAttestStatus: AppAttestStatus {
        guard DCAppAttestService.shared.isSupported else { return .unsupported }
        return Keychain.read(service: keychainService, account: appAttestAccount) == nil ? .notEnrolled : .enrolled
    }

    func attestKey(challenge: Data) async throws -> AppAttestEnrolment {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw IntegrityError.appAttestUnsupported }
        do {
            let keyId = try await existingOrNewKeyId(service)
            let hash = Data(SHA256.hash(data: challenge))
            let obj = try await service.attestKey(keyId, clientDataHash: hash)
            return AppAttestEnrolment(keyId: keyId, attestationObject: obj)
        } catch let e as DCError {
            // A build without the App Attest entitlement (for example a free
            // Personal Team) fails here. Drop any stale key so a later, entitled
            // build starts clean, and report "unavailable" instead of crashing.
            Keychain.delete(service: keychainService, account: appAttestAccount)
            throw IntegrityError.appAttestUnavailable("DCError \(e.code.rawValue): \(e.localizedDescription)")
        }
    }

    private func existingOrNewKeyId(_ service: DCAppAttestService) async throws -> String {
        if let data = Keychain.read(service: keychainService, account: appAttestAccount),
           let id = String(data: data, encoding: .utf8) { return id }
        let id = try await service.generateKey()
        Keychain.write(Data(id.utf8), service: keychainService, account: appAttestAccount)
        return id
    }

    func seal(_ report: IntegrityReport, nonce: Data) async throws -> SealedReport {
        let payload = try report.canonicalJSON()
        let clientDataHash = Data(SHA256.hash(data: payload + nonce))

        var keyId: String?
        var assertion: Data?
        var errors: [String] = []
        let service = DCAppAttestService.shared
        if service.isSupported,
           let data = Keychain.read(service: keychainService, account: appAttestAccount),
           let id = String(data: data, encoding: .utf8) {
            do {
                assertion = try await service.generateAssertion(id, clientDataHash: clientDataHash)
                keyId = id
            } catch {
                // DCError.invalidKey: key lost (restore/reinstall) -> re-enrol.
                errors.append("appattest: \(error.localizedDescription)")
            }
        } else {
            errors.append(service.isSupported ? "appattest: not enrolled" : "appattest: unsupported")
        }
        // Without an assertion the server must treat App Attest as absent; the
        // Secure Enclave seal below still works on any team, including a Personal Team.

        var seSig: Data?
        var sePub: Data?
        if SecureEnclave.isAvailable {
            do {
                let key = try secureEnclaveKey()
                seSig = try key.signature(for: clientDataHash).derRepresentation
                sePub = key.publicKey.x963Representation
            } catch {
                errors.append("secureenclave: \(error.localizedDescription)")
            }
        } else {
            errors.append("secureenclave: unavailable")
        }

        return SealedReport(payload: payload, nonce: nonce, clientDataHash: clientDataHash,
                            appAttestKeyId: keyId, appAttestAssertion: assertion,
                            secureEnclaveSignature: seSig, secureEnclavePublicKey: sePub,
                            attestationError: errors.isEmpty ? nil : errors.joined(separator: "; "))
    }

    // MARK: Secure Enclave

    /// The private key never leaves the Secure Enclave; `dataRepresentation` is an
    /// encrypted blob only that device's SE can use.
    private func secureEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        if let blob = Keychain.read(service: keychainService, account: seAccount) {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           .privateKeyUsage, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        Keychain.write(key.dataRepresentation, service: keychainService, account: seAccount)
        return key
    }

    // MARK: DeviceCheck

    func deviceCheckToken() async throws -> Data {
        guard DCDevice.current.isSupported else { throw IntegrityError.deviceCheckUnsupported }
        return try await DCDevice.current.generateToken()
    }
}

public enum AppAttestStatus: String, Codable, Sendable {
    /// Device or OS cannot do App Attest (simulator, Mac, virtual device).
    case unsupported
    /// Supported, but no key enrolled yet, or the build lacks the entitlement.
    case notEnrolled
    case enrolled
}

public enum IntegrityError: Error, Sendable {
    case appAttestUnsupported
    /// App Attest failed, typically because the build lacks the
    /// `com.apple.developer.devicecheck.appattest-environment` entitlement.
    case appAttestUnavailable(String)
    case deviceCheckUnsupported
}

enum Keychain {
    static func read(service: String, account: String) -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: account,
                                kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    static func delete(service: String, account: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
    }

    @discardableResult
    static func write(_ data: Data, service: String, account: String) -> Bool {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: service,
                                   kSecAttrAccount as String: account]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}
