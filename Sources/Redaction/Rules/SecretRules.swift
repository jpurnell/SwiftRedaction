import Foundation

/// The rules that remove credentials: keys, tokens, passwords.
///
/// Each rule carries the fixtures that define it in its documentation, and a test per rule pins them.
extension Rule {
    /// The characters a boundary-consuming pattern uses to say "not in the middle of a word": Swift Regex has no
    /// lookbehind, so a pattern that must not start inside a run consumes the character before it (or the start of the
    /// text) in capture group 1 and the rule writes it back.
    private static let wordBoundary = "(^|[^A-Za-z0-9_-])"

    /// Whole-match replacement by the style's token.
    private static let replaceMatch: @Sendable (MatchContext) -> String? = { context in context.token }

    /// Caller-supplied literal strings. The engine, not a pattern, does this work (see `LiteralSecrets`).
    static let literalSecret = Rule(
        id: .literalSecret,
        summary: "Strings the caller names (a password it holds, a token it just minted), removed wherever they appear.",
        uniform: "[REDACTED]", typed: "[secret]", patterns: [], render: replaceMatch)

    /// A PEM private-key block.
    ///
    /// Removes `-----BEGIN ... PRIVATE KEY-----` through the matching END line, or to the end of the text when the END
    /// line is missing (a capture cut off mid-key). The truncated alternative consumes the rest of the text, so a text
    /// holding many BEGIN lines and no END is scanned once, not once per block.
    ///
    /// - Positive: `-----BEGIN EC PRIVATE KEY-----\nMHcCAQ...` (to the end, truncated).
    /// - Negative: `-----BEGIN CERTIFICATE-----` (a certificate is public).
    static let pemPrivateKey = Rule(
        id: .pemPrivateKey,
        summary: "A PEM private-key block, whole or cut off before its END line.",
        uniform: "[REDACTED PRIVATE KEY]", typed: "[private-key]",
        patterns: [#"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)|[\s\S]*)"#],
        render: replaceMatch)

    /// A JSON Web Token (RFC 7519 section 3): three base64url segments, the first starting with the encoded `{"`.
    ///
    /// - Positive: `eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.MEUCIQDabcdef`.
    /// - Negative: `eyJ.a.b` (segments too short to be a token).
    static let jwt = Rule(
        id: .jwt, summary: "A JSON Web Token, such as an App Store Connect API token.",
        uniform: "[REDACTED]", typed: "[token]",
        patterns: [#"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"#],
        render: replaceMatch)

    /// An opaque `Bearer` credential, on the same line as the word.
    ///
    /// - Positive: `Authorization: Bearer abc123XYZ.def-456_ghi`.
    /// - Negative: `Bearer` at the end of a line (the next line is not the credential).
    static let bearer = Rule(
        id: .bearer, summary: "An opaque Bearer credential.",
        uniform: "Bearer [REDACTED]", typed: "Bearer [token]",
        patterns: [#"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]+"#],
        render: replaceMatch)

    /// A labelled Apple Music user or developer token; the label is kept and written back with `=`.
    ///
    /// - Positive: `Music-User-Token: AqWeRt...`, `developer token = abc.def.ghi`.
    /// - Negative: `user token count: 3` (the label must be followed by `:` or `=` and a value; a value that is
    ///   already a token is left alone).
    static let appleMusicToken = Rule(
        id: .appleMusicToken, summary: "A labelled Apple Music user or developer token.",
        uniform: "[REDACTED]", typed: "[token]",
        patterns: [#"(?i)\b((?:music[-_ ]?)?(?:user|developer)[-_ ]?token)[ \t]*[:=]\s*(\S+)"#],
        render: { context in
            "\(context.group(1))=\(context.token)"
        })

    /// A password, secret or token given as a command-line flag: `--password X`, `--api-secret=X`, `-token X`.
    ///
    /// The flag must start a word (preceded by the start of the text or a character that is not a letter, digit,
    /// underscore or hyphen), so `some-token x` in prose is not a flag. A quoted value may contain spaces and is
    /// removed whole.
    ///
    /// - Positive: `notarytool --password hunter2xyz store`, `--api-secret=hunter2xyz`,
    ///   `--password "hunter two"`.
    /// - Negative: `some-token x`, `--team-id ABC`.
    static let secretFlag = Rule(
        id: .secretFlag, summary: "A password, secret or token given as a command-line flag.",
        uniform: "[REDACTED]", typed: "[secret]",
        patterns: [#"(?i)(^|[^A-Za-z0-9_-])(--?[a-z-]*(?:password|passwd|secret|token))([ =]+)("[^"\n]+"?|'[^'\n]+'?|\S+)"#],
        render: { context in
            let value = context.group(4)
            guard !context.tokens.contains(String(value)) else { return nil }
            return "\(context.group(1))\(context.group(2))\(context.group(3))\(context.token)"
        })

    /// A password, secret or token given as `name=value`, `name: value` or JSON.
    ///
    /// The name is anything ending in `password`, `passwd`, `secret` or `token`, optionally quoted. A quoted value may
    /// contain spaces; an unterminated quote runs to the end of the line. The quotes are kept. A value that is already
    /// a replacement token is left alone, which is what keeps the rule idempotent.
    ///
    /// This rule also removes harmless text such as `token: expired`; the policies that enable it accept that.
    ///
    /// - Positive: `password: hunter2`, `{"password": "hunter two"}`, `NOTARY_PASSWORD=x`, `token = x`.
    /// - Negative: `tokens=5`, `passwordless: true`.
    static let secretAssignment = Rule(
        id: .secretAssignment, summary: "A password, secret or token given as name=value, name: value or JSON.",
        uniform: "[REDACTED]", typed: "[secret]",
        patterns: [#"(?i)((?:password|passwd|secret|token)["']?[ \t]*[:=]\s*)("[^"\n]+"?|'[^'\n]+'?|[^\s"',}]+)"#],
        render: { context in
            let value = context.group(2)
            guard let quote = value.first, quote == "\"" || quote == "'" else {
                guard !context.tokens.contains(String(value)) else { return nil }
                return "\(context.group(1))\(context.token)"
            }
            let closed = value.count > 1 && value.last == quote
            let inner = closed ? value.dropFirst().dropLast() : value.dropFirst()
            guard !context.tokens.contains(String(inner)) else { return nil }
            return "\(context.group(1))\(quote)\(context.token)\(closed ? String(quote) : "")"
        })

    /// Apple's app-specific password shape, `xxxx-xxxx-xxxx-xxxx` (lowercase letters only).
    ///
    /// The shape alone is also four ordinary hyphenated words, so the policy decides how much context is required
    /// (``RedactionPolicy/AppSpecificPasswordContext``). The match must stand alone: not glued to more letters, digits
    /// or hyphens.
    ///
    /// - Positive: `app-specific password: abcd-efgh-ijkl-mnop`.
    /// - Negative: `some-test-case-name` (no credential word), `abcd-efgh-ijkl-mnop-qrst` (longer slug).
    static let appSpecificPassword = Rule(
        id: .appSpecificPassword, summary: "An Apple app-specific password, xxxx-xxxx-xxxx-xxxx.",
        uniform: "[REDACTED]", typed: "[secret]",
        patterns: ["\(wordBoundary)([a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4})(?![A-Za-z0-9_-])"],
        render: { context in
            let range = context.match.groups[2] ?? context.match.range
            if context.appSpecificPassword == .requiresCredentialWord {
                guard CredentialContext.hasCredentialWord(near: range, in: context.text) else { return nil }
            }
            return "\(context.group(1))\(context.token)"
        })
}
