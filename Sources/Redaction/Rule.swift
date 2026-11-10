import Foundation

/// The facts about one match that a rule needs to write its replacement.
struct MatchContext {
    /// The text being redacted at this step.
    let text: String
    /// The match.
    let match: PatternMatch
    /// The replacement token for the policy's style.
    let token: String
    /// The policy's style.
    let style: RedactionPolicy.Style
    /// How the app-specific-password rule decides.
    let appSpecificPassword: RedactionPolicy.AppSpecificPasswordContext
    /// Every token any rule writes in this style, so a rule can leave an already-redacted value alone.
    let tokens: Set<String>

    /// The text of capture group `index`, empty when the group did not take part.
    func group(_ index: Int) -> Substring {
        guard index < match.groups.count, let range = match.groups[index] else { return "" }
        return text[range]
    }

    /// Whether capture group `index` took part in the match.
    func hasGroup(_ index: Int) -> Bool {
        index < match.groups.count && match.groups[index] != nil
    }
}

/// One named rule of the ``RuleCatalogue``: what it removes, what it writes in its place, and how it finds it.
///
/// A rule is a value; the catalogue builds each once, so a pattern is compiled once per process, never per call.
public struct Rule: Sendable {
    /// The rule's stable name.
    public let id: RuleID
    /// One line saying what the rule removes, for documentation and reports.
    public let summary: String
    /// What the rule writes in place of the secret part of a match in the ``RedactionPolicy/Style/uniform`` style.
    public let uniformReplacement: String
    /// What the rule writes in place of the secret part of a match in the ``RedactionPolicy/Style/typed`` style.
    public let typedReplacement: String

    /// The patterns, in Swift Regex syntax. A rule may have several, applied in order. Empty for a rule with its own matcher.
    let patterns: [String]
    /// The compiled patterns, or why one did not compile.
    let compiled: Result<[any PatternMatcher], RuleCompileFailure>
    /// Writes the replacement for one match, or `nil` to leave the match untouched.
    let render: @Sendable (MatchContext) -> String?

    /// Whether every pattern of the rule compiled. A rule that did not compile makes a ``Redactor`` fail closed.
    public var isOperational: Bool {
        if case .success = compiled { return true }
        return false
    }

    /// A rule whose work is done by hand-written matchers instead of patterns (see `JWTScanner`).
    init(
        id: RuleID, summary: String, uniform: String, typed: String, matchers: [any PatternMatcher],
        render: @escaping @Sendable (MatchContext) -> String?
    ) {
        self.id = id
        self.summary = summary
        self.uniformReplacement = uniform
        self.typedReplacement = typed
        self.patterns = []
        self.render = render
        self.compiled = .success(matchers)
    }

    init(
        id: RuleID, summary: String, uniform: String, typed: String, patterns: [String],
        render: @escaping @Sendable (MatchContext) -> String?
    ) {
        self.id = id
        self.summary = summary
        self.uniformReplacement = uniform
        self.typedReplacement = typed
        self.patterns = patterns
        self.render = render
        self.compiled = Result {
            try patterns.map { try SwiftRegexMatcher(pattern: $0) as any PatternMatcher }
        }.mapError { _ in RuleCompileFailure() }
    }
}

/// A rule's pattern did not compile. The reason is not kept: a failing pattern is a defect found by the catalogue test.
struct RuleCompileFailure: Error, Sendable {}
