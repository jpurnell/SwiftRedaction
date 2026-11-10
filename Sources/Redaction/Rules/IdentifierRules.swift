import Foundation

/// The rules that remove identifiers and personal-looking text: UUIDs, long hex and base64 runs, emails, home paths,
/// MusicKit ids and IP addresses.
extension Rule {
    private static let hex = "[0-9A-Fa-f]"

    /// Whole-match replacement by the style's token.
    private static let replaceMatch: @Sendable (MatchContext) -> String? = { context in context.token }

    /// Replaces the match but writes capture group 1 (the character in front of it) back.
    private static let replaceKeepingPrefix: @Sendable (MatchContext) -> String? = { context in
        "\(context.group(1))\(context.token)"
    }

    /// A UUID (RFC 4122 text form), in either case.
    ///
    /// - Positive: `6F9619FF-8B86-D011-B42D-00C04FC964FF`.
    /// - Negative: a UUID with a missing group, or one with a trailing hex digit.
    static let uuid = Rule(
        id: .uuid, summary: "A UUID, such as an installation ID.",
        uniform: "[REDACTED]", typed: "[uuid]",
        patterns: ["\\b\(hex){8}-\(hex){4}-\(hex){4}-\(hex){4}-\(hex){12}\\b"],
        render: replaceMatch)

    /// A hexadecimal run of 32 or more digits (keys, digests, device tokens), except exactly 40 digits.
    ///
    /// A 40-digit run is a git SHA-1, which the build-to-commit link needs, so it is kept; 41 or more (a SHA-256, a
    /// key) and 32 to 39 (an MD5, a 128-bit key) are removed. A 40-digit secret would pass; that is the owner's call.
    ///
    /// - Positive: `0123456789abcdef0123456789abcdef0123` (36), a 64-digit digest.
    /// - Negative: `5cd503b1f0a2c9e8d7b6a5f4e3d2c1b0a9f8e7d6` (40), `0123456789abcdef` (16).
    static let longHex = Rule(
        id: .longHex, summary: "A long hexadecimal run (keys, digests), except a 40-digit git SHA.",
        uniform: "[REDACTED]", typed: "[hex]",
        patterns: ["\\b(?:\(hex){32,39}|\(hex){41,})\\b"],
        render: replaceMatch)

    /// A long base64 run, only when it mixes upper case, lower case and digits, so a long slug is not taken for one.
    ///
    /// Swift Regex has no lookbehind, so the character in front of the run is consumed in group 1 and written back.
    ///
    /// - Positive: a 60-character mixed-case alphanumeric run.
    /// - Negative: `the-morning-show-with-john-richards-2026-11-09` (hyphens end the run).
    static let longBase64 = Rule(
        id: .longBase64, summary: "A long mixed-case base64 run.",
        uniform: "[REDACTED]", typed: "[token]",
        patterns: [
            "(^|[^A-Za-z0-9+/])((?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])[A-Za-z0-9+/]{40,}={0,2})",
        ],
        render: replaceKeepingPrefix)

    /// An email address, with every part bounded (RFC 5321: 64 for the local part, 63 per label).
    ///
    /// An unbounded local part is rescanned from each start position, which is quadratic on a long run of its
    /// characters with no `@` (20,000 characters took 5.9 s with `NSRegularExpression`).
    ///
    /// - Positive: `justin.purnell+beta@example.co.uk`.
    /// - Negative: `@handle`, `a@b`, `user@localhost` (no dot in the domain).
    static let email = Rule(
        id: .email, summary: "An email address.",
        uniform: "[REDACTED]", typed: "[email]",
        patterns: [#"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}"#],
        render: replaceMatch)

    /// A home-folder path: the account name of `/Users/<name>` and `/home/<name>`, and everything after `/var/mobile/`.
    ///
    /// Typed replacements keep the rest of the line readable: `/Users/[user]/Library`, `/home/[user]`,
    /// `/var/mobile/[path]`.
    ///
    /// - Positive: `/Users/jpurnell/Library/Caches/x.db`, `/home/alice/.config`, `/var/mobile/Containers/Data`.
    /// - Negative: `/usr/local/bin`, `/Library/Caches`.
    static let homePath = Rule(
        id: .homePath, summary: "A home-folder path: /Users, /home, /var/mobile.",
        uniform: "[REDACTED]", typed: "/Users/[user]",
        patterns: [#"/Users/[^/\s]+|/home/[^/\s]+|/var/mobile/\S*"#],
        render: { context in
            guard context.style == .typed else { return context.token }
            let matched = context.text[context.match.range]
            if matched.hasPrefix("/Users/") { return "/Users/[user]" }
            if matched.hasPrefix("/home/") { return "/home/[user]" }
            return "/var/mobile/[path]"
        })

    /// An Apple Music or MusicKit library, playlist or catalog identifier: `i.`, `l.`, `p.` and `pl.u-` ids.
    ///
    /// Known false positive, kept from the scrubber: `p.sharedInstance` (a letter, a dot, eight alphanumerics) is read
    /// as an id. Real ids are random base-62 and a fifth of them have no digit, so a digit requirement would leak.
    ///
    /// - Positive: `i.AbCdEf123456`, `pl.u-8aAVxxJtEdpkDq9`, `p.XyZ12345678`.
    /// - Negative: `x.AbCdEf123456`, `i.short`.
    static let musicID = Rule(
        id: .musicID, summary: "An Apple Music or MusicKit library, playlist or catalog identifier.",
        uniform: "[REDACTED]", typed: "[music-id]",
        patterns: [#"\bpl\.(?:u-)?[A-Za-z0-9]{6,}\b"#, #"\b[ilp]\.[A-Za-z0-9]{8,}\b"#],
        render: replaceMatch)

    /// An IPv4 address (dotted quad, each part 0 to 255).
    ///
    /// - Positive: `192.168.1.42`, `10.0.1.114`.
    /// - Negative: `3.4.0` (a version), `999.1.1.1`.
    static let ipv4 = Rule(
        id: .ipv4, summary: "An IPv4 address.",
        uniform: "[REDACTED]", typed: "[ip]",
        patterns: [#"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"#],
        render: replaceMatch)

    /// An IPv6 address in full, compressed (`::` inside or at the end, with an optional zone such as `%en0`) or
    /// leading-`::` form (RFC 4291 section 2.2).
    ///
    /// The address must stand alone: the character in front (consumed in group 1) is not a letter, digit or colon, and
    /// the one after is not either, so a time such as `12:34:56` and a scope such as `Spinner::AudioEngine` are not read as addresses.
    ///
    /// - Positive: `2001:db8::8a2e:370:7334`, `::1`, `fe80::1ff:fe23:4567:890a`.
    /// - Negative: `12:34:56`, `Spinner::AudioEngine`.
    static let ipv6 = Rule(
        id: .ipv6, summary: "An IPv6 address.",
        uniform: "[REDACTED]", typed: "[ip]",
        patterns: [
            "(^|[^0-9A-Za-z:])((?:\(hex){1,4}:){7}\(hex){1,4})(?![0-9A-Za-z:])",
            "(^|[^0-9A-Za-z:])((?:\(hex){1,4}:){1,7}:(?:\(hex){1,4}(?::\(hex){1,4}){0,6})?(?:%[A-Za-z0-9]+)?)(?![0-9A-Za-z:])",
            "(^|[^0-9A-Za-z:])(:(?::\(hex){1,4}){1,7})(?![0-9A-Za-z:])",
        ],
        render: replaceKeepingPrefix)
}
