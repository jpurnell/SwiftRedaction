import Foundation

/// Removes the literal strings a caller names, on the bytes of the text rather than its characters.
///
/// Three properties the old `Redactor` loop lacked, each with a test:
/// - **No fragments.** Every occurrence of every literal is found first, overlapping ones are merged into one span, and
///   the spans are replaced in a single pass, so `["abc", "abcdef"]` cannot leave `def` behind, whatever the order.
/// - **No effect on the replacement.** An occurrence lying wholly inside a replacement token already present in the
///   text is ignored, so a literal that is a substring of `[REDACTED]` (such as `RED`) removes the real occurrences and
///   leaves the tokens intact, which keeps redaction idempotent.
/// - **Scalar matching.** A literal followed by a combining mark is still found; character-level comparison would treat
///   `hunter2` + U+0301 as a different string and miss it.
enum LiteralSecrets {
    /// `text` with every occurrence of every literal replaced by `replacement`, and the number of spans replaced.
    /// - Parameters:
    ///   - text: The text to search.
    ///   - literals: The secrets as UTF-8 bytes; empty ones are ignored.
    ///   - protectedTokens: Replacement tokens whose occurrences in `text` are never altered by a match lying inside them.
    ///   - replacement: What replaces each span.
    static func redact(
        _ text: String, literals: [[UInt8]], protectedTokens: [[UInt8]], replacement: String
    ) -> (output: String, count: Int) {
        let bytes = Array(text.utf8)
        var spans: [Range<Int>] = []
        for literal in literals where !literal.isEmpty {
            spans.append(contentsOf: occurrences(of: literal, in: bytes))
        }
        guard !spans.isEmpty else { return (text, 0) }
        var protected: [Range<Int>] = []
        for token in protectedTokens where !token.isEmpty {
            protected.append(contentsOf: occurrences(of: token, in: bytes))
        }
        let shield = merge(protected)
        spans = spans.filter { span in !isInside(span, shield) }
        let merged = merge(spans)
        guard !merged.isEmpty else { return (text, 0) }
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count)
        var cursor = 0
        let replacementBytes = Array(replacement.utf8)
        for span in merged {
            output.append(contentsOf: bytes[cursor..<span.lowerBound])
            output.append(contentsOf: replacementBytes)
            cursor = span.upperBound
        }
        output.append(contentsOf: bytes[cursor...])
        return (String(decoding: output, as: UTF8.self), merged.count)
    }

    /// Every position of `needle` in `haystack`, overlapping occurrences included.
    private static func occurrences(of needle: [UInt8], in haystack: [UInt8]) -> [Range<Int>] {
        guard let first = needle.first, needle.count <= haystack.count else { return [] }
        var found: [Range<Int>] = []
        var start = 0
        let last = haystack.count - needle.count
        while start <= last {
            if haystack[start] == first, haystack[start..<start + needle.count].elementsEqual(needle) {
                found.append(start..<start + needle.count)
            }
            start += 1
        }
        return found
    }

    /// Sorts spans and joins those that overlap. Spans that merely touch stay separate.
    private static func merge(_ spans: [Range<Int>]) -> [Range<Int>] {
        let sorted = spans.sorted { $0.lowerBound == $1.lowerBound ? $0.upperBound < $1.upperBound : $0.lowerBound < $1.lowerBound }
        var merged: [Range<Int>] = []
        for span in sorted {
            guard let last = merged.last, span.lowerBound < last.upperBound else {
                merged.append(span)
                continue
            }
            merged[merged.count - 1] = last.lowerBound..<max(last.upperBound, span.upperBound)
        }
        return merged
    }

    /// Whether `span` lies wholly inside one of the sorted, disjoint `shield` spans.
    private static func isInside(_ span: Range<Int>, _ shield: [Range<Int>]) -> Bool {
        var low = 0
        var high = shield.count
        while low < high {
            let middle = low + (high - low) / 2
            if shield[middle].lowerBound <= span.lowerBound {
                low = middle + 1
            } else {
                high = middle
            }
        }
        guard low > 0 else { return false }
        return span.upperBound <= shield[low - 1].upperBound
    }
}
