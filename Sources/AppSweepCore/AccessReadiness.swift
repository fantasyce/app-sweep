import Foundation

/// Read-only preparation evidence. This never authorizes an execution plan.
public struct AccessReadiness: Equatable, Sendable {
    public enum State: String, Sendable { case notChecked, limited, ready, needsRelaunch, blocked }
    public enum Scope: String, Sendable { case user, system }
    public enum Result: String, Codable, Sendable { case readable, denied, unavailable, missing, unknown }
    public struct Evidence: Equatable, Sendable {
        public let scope: Scope
        public let result: Result
        public let subject: String
        public let checkedAt: Date
        public init(scope: Scope, result: Result, subject: String, checkedAt: Date) {
            self.scope = scope; self.result = result; self.subject = subject; self.checkedAt = checkedAt
        }
    }
    public let state: State
    public let evidence: [Evidence]
}

public enum AccessReadinessEvaluator {
    public struct Input: Sendable {
        public let userSubject: String
        public let systemSubject: String
        public let evidence: [AccessReadiness.Evidence]
        public let relaunchRequired: Bool
        public init(userSubject: String, systemSubject: String, evidence: [AccessReadiness.Evidence], relaunchRequired: Bool = false) {
            self.userSubject = userSubject; self.systemSubject = systemSubject; self.evidence = evidence; self.relaunchRequired = relaunchRequired
        }
    }
    public static func evaluate(_ input: Input, now: Date) -> AccessReadiness {
        if input.relaunchRequired { return .init(state: .needsRelaunch, evidence: []) }
        if input.evidence.isEmpty { return .init(state: .notChecked, evidence: []) }
        var current: [AccessReadiness.Evidence] = []
        for scope in [AccessReadiness.Scope.user, .system] {
            let subject = scope == .user ? input.userSubject : input.systemSubject
            let eligible = input.evidence.filter {
                $0.scope == scope && !subject.isEmpty && $0.subject == subject &&
                now.timeIntervalSince($0.checkedAt) >= 0 && now.timeIntervalSince($0.checkedAt) <= 300
            }
            guard let latest = eligible.map(\.checkedAt).max() else { continue }
            let simultaneous = eligible.filter { $0.checkedAt == latest }
            let result: AccessReadiness.Result = Set(simultaneous.map(\.result)).count == 1 ? simultaneous[0].result : .unknown
            current.append(.init(scope: scope, result: result, subject: subject, checkedAt: latest))
        }
        let state: AccessReadiness.State
        if current.count == 2 && current.allSatisfy({ $0.result == .readable }) { state = .ready }
        else if current.count == 2 && current.allSatisfy({ $0.result == .denied }) { state = .blocked }
        else { state = .limited }
        return .init(state: state, evidence: current)
    }
}
