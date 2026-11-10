import Foundation

/// Removes secret-shaped and personal-looking text according to a ``RedactionPolicy``.
///
/// A redactor holds the policy and its compiled rules; build one and reuse it. It is a value and is safe to share
/// across threads. Redaction is deterministic and idempotent: `redact(redact(x)) == redact(x)`.
///
/// ```swift
/// let redactor = Redactor.buildTool
/// redactor.redact("Authorization: Bearer abc123")   // "Authorization: Bearer [REDACTED]"
/// ```
///
/// A redactor works by shape. It is a net under the type system, not a replacement for not logging secrets; read
/// <doc:WhatRedactionCannotDo> before relying on it.
public struct Redactor: Sendable, Equatable {
    /// The policy this redactor applies.
    public let policy: RedactionPolicy

    private let compiled: [CompiledRule]
    private let isFailClosed: Bool
    private let tokenBytes: [[UInt8]]
    private let literalBytes: [[UInt8]]
    private let allTokens: Set<String>

    /// A rule with the matchers it runs.
    private struct CompiledRule: Sendable {
        let rule: Rule
        let matchers: [any PatternMatcher]
    }

    /// What one pass over a text produced.
    struct Outcome {
        let output: String
        let fired: [RuleID: Int]
        let overlong: Bool
        /// Whether a private-key block began in this text and was not closed.
        let pemOpen: Bool
    }

    /// Creates a redactor.
    /// - Parameter policy: The policy to apply.
    /// - Throws: ``RedactionError/invalidRule(_:)`` when an enabled rule's pattern did not compile, and
    ///   ``RedactionError/unknownRule(_:)`` for a rule that is not in the catalogue.
    public init(_ policy: RedactionPolicy) throws {
        for id in policy.rules {
            guard let rule = RuleCatalogue.rule(id) else { throw RedactionError.unknownRule(id) }
            guard rule.isOperational else { throw RedactionError.invalidRule(id) }
        }
        self.init(unchecked: policy)
    }

    /// Builds the engine without throwing. A rule that did not compile makes the redactor replace every input (fail
    /// closed); the catalogue test and the checked initialiser exist so that never happens in a shipped policy.
    init(unchecked policy: RedactionPolicy) {
        self.init(unchecked: policy, matchers: { rule in
            guard case .success(let matchers) = rule.compiled else { return nil }
            return matchers
        })
    }

    /// As ``init(unchecked:)``, with the matchers for each rule supplied by `matchers`, which returns `nil` for a rule
    /// that could not be built. The tests use it to run the same policy on a second engine.
    init(unchecked policy: RedactionPolicy, matchers makeMatchers: (Rule) -> [any PatternMatcher]?) {
        self.policy = policy
        let enabled = Set(policy.rules)
        var broken = false
        var rules: [CompiledRule] = []
        for rule in RuleCatalogue.all where enabled.contains(rule.id) && rule.id != .literalSecret {
            guard let matchers = makeMatchers(rule) else {
                broken = true
                continue
            }
            rules.append(CompiledRule(rule: rule, matchers: matchers))
        }
        self.compiled = rules
        self.isFailClosed = broken
        let tokens = policy.tokens
        self.allTokens = tokens
        self.tokenBytes = tokens.sorted().map { Array($0.utf8) }
        let unique = Set(policy.literalSecrets.filter { !$0.isEmpty })
        self.literalBytes = unique.sorted { $0.utf8.count == $1.utf8.count ? $0 < $1 : $0.utf8.count > $1.utf8.count }
            .map { Array($0.utf8) }
    }

    /// `text` with every secret-shaped substring replaced according to the policy.
    ///
    /// An input over ``RedactionPolicy/maxInputLength`` is replaced by the policy's placeholder, never passed through.
    /// - Parameter text: One line, or any text no longer than the cap.
    public func redact(_ text: String) -> String {
        process(text).output
    }

    /// The same as ``redact(_:)`` together with which rules fired and how often.
    ///
    /// `report(x).output == redact(x)` always: both call one code path, so an audit cannot disagree with production.
    /// - Parameter text: The text to redact.
    public func report(_ text: String) -> RedactionReport {
        let outcome = process(text)
        return RedactionReport(output: outcome.output, fired: outcome.fired, overlong: outcome.overlong)
    }

    /// Each line redacted. A private-key block that spans lines is removed line by line, so the key's body lines are
    /// not left behind when each line is handled on its own: lines inside a block become the private-key token and the
    /// line count is preserved.
    /// - Parameter lines: Lines without their terminators.
    public func redact(lines: [String]) -> [String] {
        guard policy.rules.contains(.pemPrivateKey) else { return lines.map { redact($0) } }
        let pemToken = RuleCatalogue.rule(.pemPrivateKey)?.token(for: policy.style) ?? "[REDACTED PRIVATE KEY]"
        var inBlock = false
        var result: [String] = []
        result.reserveCapacity(lines.count)
        for line in lines {
            guard inBlock else {
                let outcome = process(line)
                result.append(outcome.output)
                inBlock = outcome.pemOpen
                continue
            }
            guard let end = line.firstMatch(of: Self.pemEnd.regex) else {
                result.append(pemToken)
                continue
            }
            inBlock = false
            result.append(pemToken + redact(String(line[end.range.upperBound...])))
        }
        return result
    }

    /// An argv with each element redacted, and the element after a secret-named flag (`--password`, `--token`)
    /// replaced outright, since a flag's value does not look like a secret by itself.
    /// - Parameter arguments: The arguments, program name included or not.
    public func redactArguments(_ arguments: [String]) -> [String] {
        let replacement = RuleCatalogue.rule(.secretFlag)?.token(for: policy.style) ?? "[REDACTED]"
        var previousNamesSecret = false
        var result: [String] = []
        result.reserveCapacity(arguments.count)
        for argument in arguments {
            result.append(previousNamesSecret ? replacement : redact(argument))
            previousNamesSecret = argument.wholeMatch(of: Self.secretFlagName.regex) != nil
        }
        return result
    }

    /// Two redactors are equal when their policies are.
    public static func == (lhs: Redactor, rhs: Redactor) -> Bool {
        lhs.policy == rhs.policy
    }

    private static let pemEnd = SharedRegex(regex: /-----END [A-Z0-9 ]*PRIVATE KEY-----/)
    private static let secretFlagName = SharedRegex(regex: /(?i)--?[a-z-]*(?:password|passwd|secret|token)/)

    /// The one code path behind `redact` and `report`.
    func process(_ text: String) -> Outcome {
        let replaced = Outcome(output: policy.overlongPlaceholder, fired: [:], overlong: true, pemOpen: Redactor.opensBlock(text))
        guard !isFailClosed, text.utf8.count <= policy.maxInputLength else { return replaced }
        var current = text
        var fired: [RuleID: Int] = [:]
        var pemOpen = false
        if !literalBytes.isEmpty {
            let token = RuleCatalogue.rule(.literalSecret)?.token(for: policy.style) ?? "[REDACTED]"
            let result = LiteralSecrets.redact(current, literals: literalBytes, protectedTokens: tokenBytes, replacement: token)
            current = result.output
            if result.count > 0 { fired[.literalSecret] = result.count }
        }
        for entry in compiled {
            let result = apply(entry, to: current)
            current = result.output
            if result.count > 0 { fired[entry.rule.id] = result.count }
            if entry.rule.id == .pemPrivateKey { pemOpen = result.opensBlock }
        }
        guard current.utf8.count <= policy.maxInputLength else { return replaced }
        return Outcome(output: current, fired: fired, overlong: false, pemOpen: pemOpen)
    }

    /// Whether `text` begins a private-key block it does not close; the conservative test used when a line is replaced
    /// for length before the rules could look at it.
    private static func opensBlock(_ text: String) -> Bool {
        guard text.contains("PRIVATE KEY-----") else { return false }
        return !text.contains("-----END")
    }

    /// Applies one rule's patterns to `text`.
    private func apply(_ entry: CompiledRule, to text: String) -> (output: String, count: Int, opensBlock: Bool) {
        var current = text
        var count = 0
        var opensBlock = false
        for matcher in entry.matchers {
            let matches = matcher.matches(in: current)
            guard !matches.isEmpty else { continue }
            var output = ""
            var cursor = current.startIndex
            for match in matches {
                guard match.range.lowerBound >= cursor else { continue }
                let context = MatchContext(
                    text: current, match: match, token: entry.rule.token(for: policy.style), style: policy.style,
                    appSpecificPassword: policy.appSpecificPassword, tokens: allTokens)
                guard let rendered = entry.rule.render(context), rendered != current[match.range] else { continue }
                if entry.rule.id == .pemPrivateKey, !context.hasGroup(1) { opensBlock = true }
                output += current[cursor..<match.range.lowerBound]
                output += rendered
                cursor = match.range.upperBound
                count += 1
            }
            output += current[cursor...]
            current = output
        }
        return (current, count, opensBlock)
    }
}
