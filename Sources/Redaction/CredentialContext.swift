import Foundation

/// Decides whether a credential word is near a match, for the rules whose shape alone is ambiguous.
enum CredentialContext {
    /// How far, in UTF-8 bytes, a credential word may be from the match on the same line.
    static let window = 80

    /// Lower-case words and phrases that mean "what follows or precedes is a credential".
    static let words: [[UInt8]] = [
        "password", "passwd", "passcode", "app-specific", "app specific", "appspecific",
        "credential", "secret", "token", "sign in", "sign-in", "signin", "login", "log in", "apple id", "apple_id",
    ].map { Array($0.utf8) }

    /// Whether any of ``words`` appears, ASCII case-insensitively, on the same line as `range` within ``window`` bytes of it.
    ///
    /// Works on bytes without allocating a string per call: a match is checked for every candidate in the text, and a
    /// log of repeated candidates (a measured 7 s per MiB with a `lowercased()` copy per match) must not make that quadratic in cost.
    static func hasCredentialWord(near range: Range<String.Index>, in text: String) -> Bool {
        let utf8 = text.utf8
        var start = range.lowerBound
        var steps = 0
        while start > utf8.startIndex, steps < window {
            let previous = utf8.index(before: start)
            guard utf8[previous] != UInt8(ascii: "\n") else { break }
            start = previous
            steps += 1
        }
        var end = range.upperBound
        steps = 0
        while end < utf8.endIndex, steps < window {
            guard utf8[end] != UInt8(ascii: "\n") else { break }
            end = utf8.index(after: end)
            steps += 1
        }
        let line = utf8[start..<end].map { byte in (byte >= 65 && byte <= 90) ? byte + 32 : byte }
        return words.contains { SecretBytes.contains(line, $0) }
    }
}

/// Byte-level search shared by the context check.
enum SecretBytes {
    /// Whether `needle` occurs in `haystack`.
    static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard let first = needle.first, needle.count <= haystack.count else { return false }
        var start = 0
        let last = haystack.count - needle.count
        while start <= last {
            if haystack[start] == first, haystack[start..<start + needle.count].elementsEqual(needle) { return true }
            start += 1
        }
        return false
    }
}
