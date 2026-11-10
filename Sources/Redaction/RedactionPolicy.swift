import Foundation

/// Which rules apply, how a removed secret is written, and what happens to an input that is too long.
///
/// A policy is a value. It chooses a *set* of rules; the engine applies them in the ``RuleCatalogue``'s order, so
/// listing the same rules in another order changes nothing. Build one with ``init(rules:style:maxInputLength:overlong:appSpecificPassword:)``,
/// which refuses anything that would make redaction non-deterministic or non-idempotent, or use ``buildTool``.
public struct RedactionPolicy: Sendable, Equatable {
    /// How a removed secret is written.
    public enum Style: Sendable, Equatable {
        /// Every removal reads `[REDACTED]` (a private key reads `[REDACTED PRIVATE KEY]`).
        case uniform
        /// Every removal names what it was: `[token]`, `[ip]`, `[uuid]`, `[email]` and so on.
        case typed
    }

    /// What happens to an input longer than ``maxInputLength``.
    ///
    /// There is deliberately one case. A scrubber that cannot afford to search a line must not pass it on, and
    /// truncating then redacting would leave the start of a secret that the cut split, so the line is replaced.
    public enum OverlongInput: Sendable, Equatable {
        /// The whole input becomes this text (fail closed).
        case replaceWhole(String)
    }

    /// How much context the app-specific-password rule needs before it fires.
    ///
    /// The shape `xxxx-xxxx-xxxx-xxxx` is also four ordinary hyphenated words. See the README for the measurement that
    /// chose the defaults.
    public enum AppSpecificPasswordContext: Sendable, Equatable {
        /// Any match of the shape is removed (the old `Redactor` behaviour; false positives on hyphenated words).
        case anywhere
        /// A credential word (`password`, `app-specific`, `sign in`, ...) must be on the same line, within 80 bytes.
        case requiresCredentialWord
    }

    /// The default ``maxInputLength``: 4,096 UTF-8 bytes, a limit no real log line reaches.
    public static let defaultMaxInputLength = 4_096

    /// The default text that replaces an over-long input.
    public static let defaultOverlongPlaceholder = "[line too long, removed]"

    /// The rules this policy applies. Order here is irrelevant; the catalogue's order is used.
    public let rules: [RuleID]
    /// How a removed secret is written.
    public let style: Style
    /// The longest input the engine will search, in UTF-8 bytes. A longer input is replaced, never passed through.
    /// An output longer than this is replaced as well, so redacting twice cannot differ from redacting once.
    public let maxInputLength: Int
    /// What an over-long input becomes.
    public let overlong: OverlongInput
    /// How the app-specific-password rule decides.
    public let appSpecificPassword: AppSpecificPasswordContext
    /// Literal secrets to remove wherever they appear. Added with ``adding(literalSecrets:)``.
    public let literalSecrets: [String]

    /// Builds a policy, refusing a configuration that would break determinism or idempotence.
    ///
    /// - Parameters:
    ///   - rules: The rules to apply, each at most once.
    ///   - style: How a removal is written.
    ///   - maxInputLength: The longest input, in UTF-8 bytes. Defaults to ``defaultMaxInputLength``.
    ///   - overlong: What an over-long input becomes.
    ///   - appSpecificPassword: How much context the app-specific-password rule needs.
    /// - Throws: ``RedactionError`` for an unknown or repeated rule, a non-positive cap, a placeholder that is empty or
    ///   longer than the cap, or a replacement token that the policy itself would change.
    public init(
        rules: [RuleID], style: Style, maxInputLength: Int = RedactionPolicy.defaultMaxInputLength,
        overlong: OverlongInput = .replaceWhole(RedactionPolicy.defaultOverlongPlaceholder),
        appSpecificPassword: AppSpecificPasswordContext = .requiresCredentialWord
    ) throws {
        var seen = Set<RuleID>()
        for id in rules {
            guard RuleCatalogue.rule(id) != nil else { throw RedactionError.unknownRule(id) }
            guard seen.insert(id).inserted else { throw RedactionError.duplicateRule(id) }
        }
        guard maxInputLength > 0 else { throw RedactionError.invalidMaxInputLength(maxInputLength) }
        let policy = RedactionPolicy(
            validated: rules, style: style, maxInputLength: maxInputLength, overlong: overlong,
            appSpecificPassword: appSpecificPassword, literalSecrets: [])
        guard case .replaceWhole(let placeholder) = overlong, !placeholder.isEmpty,
              placeholder.utf8.count <= maxInputLength else { throw RedactionError.invalidOverlongPlaceholder }
        try policy.verifyReplacementsAreStable()
        self = policy
    }

    /// Memberwise, unchecked. Used for the shipped policies (a test builds each again through the checked initialiser)
    /// and by ``adding(literalSecrets:)``.
    init(
        validated rules: [RuleID], style: Style, maxInputLength: Int, overlong: OverlongInput,
        appSpecificPassword: AppSpecificPasswordContext, literalSecrets: [String]
    ) {
        self.rules = rules
        self.style = style
        self.maxInputLength = maxInputLength
        self.overlong = overlong
        self.appSpecificPassword = appSpecificPassword
        self.literalSecrets = literalSecrets
    }

    /// The same policy with `literalSecrets` added to those it already removes.
    ///
    /// Literals run first, are matched on bytes, and are removed wherever they appear: the caller who holds a secret is
    /// the only party who knows it. Empty strings are ignored. The literal rule is added to ``rules`` once.
    /// - Parameter literalSecrets: Strings to remove.
    public func adding(literalSecrets: [String]) -> RedactionPolicy {
        RedactionPolicy(
            validated: rules.contains(.literalSecret) ? rules : rules + [.literalSecret], style: style,
            maxInputLength: maxInputLength, overlong: overlong, appSpecificPassword: appSpecificPassword,
            literalSecrets: self.literalSecrets + literalSecrets.filter { !$0.isEmpty })
    }

    /// The text an over-long input becomes.
    var overlongPlaceholder: String {
        switch overlong {
        case .replaceWhole(let text): return text
        }
    }

    /// Every replacement token this policy can write, plus its overlong placeholder.
    var tokens: Set<String> {
        var all: Set<String> = [overlongPlaceholder]
        for rule in RuleCatalogue.all {
            all.formUnion(rule.tokens(for: style))
        }
        return all
    }

    /// Checks that redacting any replacement token leaves it as it was.
    private func verifyReplacementsAreStable() throws {
        let probe = Redactor(unchecked: self)
        for token in tokens.sorted() {
            let report = probe.report(token)
            guard report.output == token, !report.overlong else {
                let culprit = report.fired.keys.sorted { $0.rawValue < $1.rawValue }.first ?? .literalSecret
                throw RedactionError.replacementNotStable(culprit)
            }
        }
    }
}

extension Rule {
    /// The replacement written for `style`.
    func token(for style: RedactionPolicy.Style) -> String {
        switch style {
        case .uniform: return uniformReplacement
        case .typed: return typedReplacement
        }
    }

    /// The strings the rule may write in `style`; a rule with several typed forms lists each.
    func tokens(for style: RedactionPolicy.Style) -> [String] {
        guard style == .typed, id == .homePath else { return [token(for: style)] }
        return ["/Users/[user]", "/home/[user]", "/var/mobile/[path]"]
    }
}
