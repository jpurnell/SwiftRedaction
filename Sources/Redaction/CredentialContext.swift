import Foundation

/// Decides whether a credential word is near a match, for the rules whose shape alone is ambiguous.
enum CredentialContext {
    /// How far, in UTF-8 bytes, a credential word may be from the match on the same line.
    static let window = 80

    /// Lower-case words and phrases that mean "what follows or precedes is a credential".
    static let words = [
        "password", "passwd", "passcode", "app-specific", "app specific", "appspecific",
        "credential", "secret", "token", "sign in", "sign-in", "signin", "login", "log in", "apple id", "apple_id",
    ]

    /// Whether any of ``words`` appears, case-insensitively, on the same line as `range` within ``window`` bytes of it.
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
        let line = String(decoding: utf8[start..<end], as: UTF8.self).lowercased()
        return words.contains { line.contains($0) }
    }
}
