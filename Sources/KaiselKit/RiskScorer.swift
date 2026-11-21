import Foundation

/// Combines signals into a 0...100 score.
///
/// Within a category, signals are sorted by effective weight and damped
/// geometrically (w1, w2*0.5, w3*0.25, ...) before a noisy-OR, because 40 hits
/// on jailbreak paths are one piece of evidence, not forty. Across categories a
/// plain noisy-OR is used: independent evidence corroborates.
///
///   p_cat = 1 - prod_i (1 - w_i * d^i)
///   p     = 1 - prod_cat (1 - p_cat)
///
/// Hard indicators (evidence with no benign explanation on a production
/// device) floor the verdict at `.high`; two or more hard indicators in
/// different categories floor it at `.compromised`.
public struct RiskScorer: Sendable {
    public var damping: Double = 0.5
    public var thresholds: (low: Int, elevated: Int, high: Int, compromised: Int) = (15, 35, 60, 85)
    public var hardConfidenceFloor: UInt8 = 75

    public init() {}

    /// Scores one domain using only its non-informational signals.
    public func assess(_ domain: IntegrityDomain, _ signals: [Signal]) -> DomainAssessment {
        let scored = signals.filter { $0.domain == domain && !$0.informational }
        let cats = categoryScores(scored)
        let s = score(cats)
        return DomainAssessment(domain: domain, score: s, verdict: verdict(score: s, signals: scored), categories: cats)
    }

    public func categoryScores(_ signals: [Signal]) -> [CategoryScore] {
        let scored: [Signal] = signals.filter { !$0.informational }
        let grouped: [SignalCategory: [Signal]] = Dictionary(grouping: scored, by: { $0.category })
        var result: [CategoryScore] = []
        for (cat, sigs) in grouped {
            let ws: [Double] = sigs.map { $0.effectiveWeight }.sorted(by: >)
            var survive: Double = 1.0
            var factor: Double = 1.0
            for w in ws {
                let damped: Double = Swift.min(Swift.max(w * factor, 0.0), 1.0)
                survive *= (1.0 - damped)
                factor *= damping
            }
            result.append(CategoryScore(category: cat, score: 1.0 - survive, signalCount: sigs.count))
        }
        result.sort { $0.score > $1.score }
        return result
    }

    public func score(_ categories: [CategoryScore]) -> Int {
        var survive: Double = 1.0
        for c in categories { survive *= (1.0 - c.score) }
        let pct: Double = (1.0 - survive) * 100.0
        return Int(pct.rounded())
    }

    public func verdict(score: Int, signals: [Signal]) -> Verdict {
        var v: Verdict
        switch score {
        case ..<thresholds.low: v = .trusted
        case ..<thresholds.elevated: v = .low
        case ..<thresholds.high: v = .elevated
        case ..<thresholds.compromised: v = .high
        default: v = .compromised
        }
        let floor: UInt8 = hardConfidenceFloor
        let hard: [Signal] = signals.filter { (s: Signal) -> Bool in
            s.hard && !s.informational && s.confidence >= floor && s.weight > 0
        }
        if !hard.isEmpty && v < .high { v = .high }
        let hardCategories: Set<SignalCategory> = Set(hard.map { $0.category })
        if hardCategories.count >= 2 { v = .compromised }
        return v
    }
}
