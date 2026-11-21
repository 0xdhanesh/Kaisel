import Foundation

/// Periodic re-evaluation. Attach-after-launch attacks (frida -U -n, lldb attach,
/// runtime dlopen) are invisible to a launch-time check, so sensitive flows
/// should either evaluate on demand or keep a monitor running.
public final class IntegrityMonitor: @unchecked Sendable {
    public typealias Handler = @Sendable (IntegrityReport) -> Void

    private let kit: IntegrityKit
    private let interval: TimeInterval
    private let jitter: TimeInterval
    private let handler: Handler
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "integritykit.monitor", qos: .utility)
    private var lastRun: Date?

    /// - Parameters:
    ///   - interval: base period between evaluations.
    ///   - jitter: random +/- jitter so the schedule is not predictable.
    ///   - handler: called on a background queue with every report.
    public init(kit: IntegrityKit, interval: TimeInterval = 30, jitter: TimeInterval = 10, handler: @escaping Handler) {
        self.kit = kit
        self.interval = interval
        self.jitter = jitter
        self.handler = handler
    }

    public func start() {
        queue.async { [weak self] in self?.schedule() }
    }

    public func stop() {
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
        }
    }

    private func schedule() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        let offset: Double = Double.random(in: -jitter...jitter)
        let delay: Double = Swift.max(1.0, interval + offset)
        t.schedule(deadline: .now() + delay)
        t.setEventHandler { [weak self] in self?.fire() }
        timer?.cancel()
        timer = t
        t.resume()
    }

    private func fire() {
        // A gap far beyond the schedule means the process was suspended (e.g. a
        // debugger stopped it) or the timer was interfered with.
        var extra: [RawSignal] = []
        if let last = lastRun {
            let gap = Date().timeIntervalSince(last)
            let limit: Double = (interval + jitter) * 4.0
            if gap > limit {
                extra.append(.init(.monitorIntervalStarved, 70, String(format: "%.0fs since previous run", gap)))
            }
        }
        handler(kit.evaluate(extra: extra))
        lastRun = Date()
        schedule()
    }
}
