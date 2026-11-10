import Foundation

/// One match of a pattern in a string: where it is and where each capture group is.
///
/// Indices belong to the string that was searched; do not use them on another string.
struct PatternMatch: Sendable {
    /// The whole match.
    let range: Range<String.Index>
    /// Capture groups by number; index 0 is the whole match, a group that did not take part is `nil`.
    let groups: [Range<String.Index>?]
}

/// Finds every non-overlapping match of one pattern in a string.
///
/// The regular-expression engine sits behind this protocol so a rule can be moved to another engine, or to a
/// hand-written scanner, without touching the catalogue or the policies. Implementations are compiled once and
/// shared across threads.
protocol PatternMatcher: Sendable {
    /// The matches of the pattern in `text`, left to right, none overlapping.
    func matches(in text: String) -> [PatternMatch]
}

/// A compiled Swift Regex that can be shared across threads.
///
/// `Regex` is not declared `Sendable` by the standard library. A compiled expression is never mutated by matching, and a
/// concurrent test in this package runs the shipped policies from many tasks at once to keep that claim honest.
// Justification: a compiled Regex is an immutable program; matching reads it and never writes it (see the concurrent test).
struct SharedRegex<Output>: @unchecked Sendable {
    let regex: Regex<Output>
}

/// A pattern compiled once with Swift Regex, matching on Unicode scalars.
///
/// Scalar semantics, not the default grapheme clusters: with clusters, a hex digit followed by a combining mark is one
/// non-hex `Character`, which would end a secret's run early and leave its tail in the output.
struct SwiftRegexMatcher: PatternMatcher {
    private let shared: SharedRegex<AnyRegexOutput>

    /// Compiles `pattern`, which uses Swift Regex syntax (no lookbehind: the engine does not support it).
    init(pattern: String) throws {
        shared = SharedRegex(regex: try Regex(pattern).matchingSemantics(.unicodeScalar))
    }

    func matches(in text: String) -> [PatternMatch] {
        text.matches(of: shared.regex).map { match in
            PatternMatch(range: match.range, groups: (0..<match.output.count).map { match.output[$0].range })
        }
    }
}
