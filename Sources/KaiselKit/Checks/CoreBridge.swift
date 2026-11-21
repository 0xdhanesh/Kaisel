import Foundation
import CIntegrityCore

/// Thin bridge over the C core. Owns the findings buffer and context lifetime.
struct RawFinding {
    let code: UInt16
    let confidence: UInt8
    let detail: String
}

enum CoreCheck: CaseIterable {
    case filesystem, sandbox, images, hooks, debugger, frida, codesign, environment, devmode, canary, selfIntegrity

    var bit: UInt32 {
        switch self {
        case .filesystem:  return UInt32(RASP_CHECK_FILESYSTEM)
        case .sandbox:     return UInt32(RASP_CHECK_SANDBOX)
        case .images:      return UInt32(RASP_CHECK_IMAGES)
        case .hooks:       return UInt32(RASP_CHECK_HOOKS)
        case .debugger:    return UInt32(RASP_CHECK_DEBUGGER)
        case .frida:       return UInt32(RASP_CHECK_FRIDA)
        case .codesign:    return UInt32(RASP_CHECK_CODESIGN)
        case .environment: return UInt32(RASP_CHECK_ENVIRONMENT)
        case .devmode:     return UInt32(RASP_CHECK_DEVMODE)
        case .canary:      return UInt32(RASP_CHECK_CANARY)
        case .selfIntegrity: return UInt32(RASP_CHECK_SELF)
        }
    }

    var name: String { String(describing: self) }

    func run(_ ctx: UnsafePointer<rasp_context_t>, _ out: UnsafeMutablePointer<rasp_findings_t>) {
        switch self {
        case .filesystem:  rasp_check_filesystem(ctx, out)
        case .sandbox:     rasp_check_sandbox(ctx, out)
        case .images:      rasp_check_images(ctx, out)
        case .hooks:       rasp_check_hooks(ctx, out)
        case .debugger:    rasp_check_debugger(ctx, out)
        case .frida:       rasp_check_frida(ctx, out)
        case .codesign:    rasp_check_codesign(ctx, out)
        case .environment: rasp_check_environment(ctx, out)
        case .devmode:     rasp_check_devmode(ctx, out)
        case .canary:      rasp_check_canary(ctx, out)
        case .selfIntegrity: rasp_check_self(ctx, out)
        }
    }
}

struct CoreRunResult {
    var findings: [RawFinding]
    var started: UInt32
    var completed: UInt32
    var dropped: UInt32
}

enum CoreBridge {
    static func run(checks: [CoreCheck], configuration: IntegrityConfiguration) -> CoreRunResult {
        let bundlePath = strdup((Bundle.main.bundlePath as NSString).resolvingSymlinksInPath)
        let execPath = strdup(Bundle.main.executablePath ?? "")
        let tmp = strdup((NSTemporaryDirectory() as NSString).standardizingPath)
        defer { free(bundlePath); free(execPath); free(tmp) }

        let out = UnsafeMutablePointer<rasp_findings_t>.allocate(capacity: 1)
        memset(out, 0, MemoryLayout<rasp_findings_t>.size)
        defer {
            memset(out, 0, MemoryLayout<rasp_findings_t>.size)
            out.deallocate()
        }

        configuration.fridaPorts.withUnsafeBufferPointer { ports in
            var ctx = rasp_context_t(
                bundle_path: bundlePath,
                executable_path: execPath,
                container_tmp: tmp,
                frida_ports: ports.baseAddress,
                frida_port_count: UInt32(ports.count),
                probe_timeout_ms: configuration.portProbeTimeoutMs,
                allow_fork_probe: configuration.allowForkProbe,
                scan_memory: configuration.scanMemory)
            withUnsafePointer(to: &ctx) { ctxPtr in
                // Randomised order: an attacker cannot rely on a fixed call
                // sequence to time a hook or to patch "the third check".
                for check in checks.shuffled() { check.run(ctxPtr, out) }
            }
        }
        return CoreRunResult(findings: readFindings(out),
                             started: out.pointee.checks_started,
                             completed: out.pointee.checks_completed,
                             dropped: out.pointee.dropped)
    }

    private static func readFindings(_ out: UnsafeMutablePointer<rasp_findings_t>) -> [RawFinding] {
        let count = min(Int(out.pointee.count), Int(RASP_MAX_FINDINGS))
        return withUnsafeMutablePointer(to: &out.pointee.items) { tuplePtr in
            tuplePtr.withMemoryRebound(to: rasp_finding_t.self, capacity: Int(RASP_MAX_FINDINGS)) { items in
                (0..<count).map { i in
                    var item = items[i]
                    let detail = withUnsafePointer(to: &item.detail) {
                        $0.withMemoryRebound(to: CChar.self, capacity: Int(RASP_DETAIL_LEN)) { String(cString: $0) }
                    }
                    return RawFinding(code: item.code, confidence: item.confidence, detail: detail)
                }
            }
        }
    }

    static func facts() -> rasp_facts_t {
        var f = rasp_facts_t()
        rasp_collect_facts(&f)
        return f
    }

    static func textHash(_ f: inout rasp_facts_t) -> String {
        withUnsafePointer(to: &f.text_sha256) {
            $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) }
        }
    }

    /// Decodes one obfuscated string. Callers should not retain the result longer than needed.
    static func decode(_ index: UInt16) -> String? {
        var buf = [CChar](repeating: 0, count: 256)
        let n = rasp_obf_decode(index, &buf, buf.count)
        defer { rasp_secure_zero(&buf, buf.count) }
        return n > 0 ? String(cString: buf) : nil
    }

    static func classifyImage(_ path: String) -> FindingCode? {
        classifyImageEvidence(path)?.code
    }

    /// Finding code and confidence for an image path, nil when trusted or unknown.
    static func classifyImageEvidence(_ path: String) -> (code: FindingCode, confidence: UInt8)? {
        let bundle = (Bundle.main.bundlePath as NSString).resolvingSymlinksInPath
        let cls = rasp_image_class(path, bundle)
        let raw = rasp_image_class_code(cls)
        guard raw != 0, let code = FindingCode(rawValue: raw) else { return nil }
        return (code, rasp_image_class_confidence(cls))
    }

    static func drainNewImages() -> [String] {
        let slots = 32
        let stride = Int(RASP_DETAIL_LEN)
        var buf = [CChar](repeating: 0, count: slots * stride)
        let n = Int(rasp_drain_new_images(&buf, UInt32(slots)))
        return (0..<n).map { i in
            buf.withUnsafeBufferPointer { String(cString: $0.baseAddress! + i * stride) }
        }
    }
}
