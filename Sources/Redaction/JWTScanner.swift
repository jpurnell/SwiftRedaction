import Foundation

/// A hand-written scanner for the `jwt` rule: finds a JSON Web Token wherever it starts, in work proportional to the text.
///
/// A JWT (RFC 7519 section 3) here is `eyJ`, at least five base64url characters, a dot, at least five base64url
/// characters, a dot, then any number of base64url characters (possibly none). It may be glued to whatever precedes it:
/// `mytokeneyJ...`, `id-eyJ...`, `Bearer:eyJ...`. Matching is leftmost and greedy, as an unanchored regular expression
/// would do it, and the matched token is consumed.
///
/// ## Why this is not a regular expression
///
/// Unanchored, the pattern is quadratic under Swift Regex on `eyJeyJeyJ...`: every `eyJ` start rescans the rest of one
/// long run of base64url characters and fails at its end (3.9 s at 16 KiB, 17 s at 32 KiB; see the README). Anchoring the
/// token to a word start was linear but missed a glued token, which is a leak.
///
/// ## Why this scanner is linear
///
/// The scan is one left-to-right pass over the UTF-8 bytes. Every byte of a token or of a failed attempt is read by one
/// attempt only, because of one fact: **a failed attempt that read a run of base64url characters can skip the whole run.**
/// A start inside the run would read the same run to the same end and meet the same character there (the first segment
/// needs a dot after the run, the second needs five characters and a dot), so it fails the same way. After a failure the
/// cursor therefore jumps to the end of the last run read, and after a success to the end of the token. No byte is read by
/// more than one attempt, plus a constant for the lookahead, so the work is at most about twice the text's length
/// whatever the input. The fixture in `JWTScannerTests` asserts that on the step count (``Scan/steps``), which does not
/// depend on the machine, unlike a wall-clock bound.
///
/// Non-ASCII bytes are never base64url characters, and a match begins and ends on ASCII bytes, so every range returned is
/// on a Unicode scalar boundary, as the regex engine's are.
struct JWTScanner: PatternMatcher {
    /// What one scan found and what it cost.
    struct Scan {
        /// The token ranges, left to right, none overlapping.
        let ranges: [Range<Int>]
        /// The bytes read, counting every read of a byte (a byte read twice counts twice).
        let steps: Int
    }

    /// The fewest characters of each of the first two segments (the first counted after `eyJ`).
    private static let minimumSegment = 5

    private static let isBase64URL: [Bool] = (0..<256).map { value in
        switch UInt8(truncatingIfNeeded: value) {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "-"), UInt8(ascii: "_"):
            return true
        default:
            return false
        }
    }

    /// The token ranges in `bytes` (offsets into the array) and the work done.
    static func scan(_ bytes: [UInt8]) -> Scan {
        var ranges: [Range<Int>] = []
        var steps = 0
        var cursor = 0
        let count = bytes.count
        let dot = UInt8(ascii: ".")

        /// The end of the run of base64url characters that starts at `start`.
        func runEnd(from start: Int) -> Int {
            var position = start
            while position < count, isBase64URL[Int(bytes[position])] {
                position += 1
            }
            steps += position - start + 1
            return position
        }

        while cursor + 3 <= count {
            steps += 1
            guard bytes[cursor] == UInt8(ascii: "e"), bytes[cursor + 1] == UInt8(ascii: "y"), bytes[cursor + 2] == UInt8(ascii: "J") else {
                cursor += 1
                continue
            }
            let firstEnd = runEnd(from: cursor + 3)
            guard firstEnd - (cursor + 3) >= minimumSegment, firstEnd < count, bytes[firstEnd] == dot else {
                cursor = firstEnd
                continue
            }
            let secondEnd = runEnd(from: firstEnd + 1)
            guard secondEnd - (firstEnd + 1) >= minimumSegment, secondEnd < count, bytes[secondEnd] == dot else {
                cursor = secondEnd
                continue
            }
            let end = runEnd(from: secondEnd + 1)
            ranges.append(cursor..<end)
            cursor = end
        }
        return Scan(ranges: ranges, steps: steps)
    }

    func matches(in text: String) -> [PatternMatch] {
        let utf8 = text.utf8
        let found = Self.scan(Array(utf8)).ranges
        var result: [PatternMatch] = []
        result.reserveCapacity(found.count)
        var offset = 0
        var index = utf8.startIndex
        for range in found {
            let lower = utf8.index(index, offsetBy: range.lowerBound - offset)
            let upper = utf8.index(lower, offsetBy: range.count)
            result.append(PatternMatch(range: lower..<upper, groups: [lower..<upper]))
            offset = range.upperBound
            index = upper
        }
        return result
    }
}
