import Foundation
@testable import Redaction

/// A pattern compiled once with `NSRegularExpression` (ICU).
///
/// Not used by the shipped policies. It is the second engine behind `PatternMatcher`, so the two can be compared on the
/// same inputs (the equivalence test and the measurements in the README), and it is the fallback a rule would move to
/// if Swift Regex were ever found super-linear on it.
struct ICUMatcher: PatternMatcher {
    // Justification: NSRegularExpression is documented as immutable and safe to share across threads once built.
    private struct Box: @unchecked Sendable {
        let expression: NSRegularExpression
    }

    private let box: Box

    /// Compiles `pattern` with ICU syntax.
    init(pattern: String) throws {
        box = Box(expression: try NSRegularExpression(pattern: pattern, options: []))
    }

    func matches(in text: String) -> [PatternMatch] {
        let whole = NSRange(text.startIndex..., in: text)
        return box.expression.matches(in: text, options: [], range: whole).compactMap { result in
            guard let range = Range(result.range, in: text) else { return nil }
            let groups: [Range<String.Index>?] = (0..<result.numberOfRanges).map { index in
                let nsRange = result.range(at: index)
                guard nsRange.location != NSNotFound else { return nil }
                return Range(nsRange, in: text)
            }
            return PatternMatch(range: range, groups: groups)
        }
    }
}
