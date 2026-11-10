import Foundation

/// The stable name of one redaction rule.
///
/// A rule's identifier is part of the public API: it appears in a ``RedactionReport`` and in a ``RedactionPolicy``, so
/// renaming one is a breaking change. Compare identifiers with `==`; the raw value is the name shown in reports.
public struct RuleID: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    /// The name shown in reports and in the README table, such as `"jwt"`.
    public let rawValue: String

    /// Creates an identifier from its name.
    /// - Parameter rawValue: The rule's name.
    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// The rule's name.
    public var description: String { rawValue }

    /// Caller-supplied literal strings, removed wherever they appear. Runs first.
    public static let literalSecret = RuleID(rawValue: "literalSecret")
    /// A PEM private-key block, whole or cut off before its END line.
    public static let pemPrivateKey = RuleID(rawValue: "pemPrivateKey")
    /// A JSON Web Token.
    public static let jwt = RuleID(rawValue: "jwt")
    /// An opaque `Bearer` credential.
    public static let bearer = RuleID(rawValue: "bearer")
    /// A labelled Apple Music user or developer token.
    public static let appleMusicToken = RuleID(rawValue: "appleMusicToken")
    /// A password, secret or token given as a command-line flag.
    public static let secretFlag = RuleID(rawValue: "secretFlag")
    /// A password, secret or token given as `name=value`, `name: value` or JSON.
    public static let secretAssignment = RuleID(rawValue: "secretAssignment")
    /// An Apple app-specific password, `xxxx-xxxx-xxxx-xxxx`.
    public static let appSpecificPassword = RuleID(rawValue: "appSpecificPassword")
    /// A UUID.
    public static let uuid = RuleID(rawValue: "uuid")
    /// A long hexadecimal run (keys, digests), except a 40-digit git SHA.
    public static let longHex = RuleID(rawValue: "longHex")
    /// A long mixed-case base64 run.
    public static let longBase64 = RuleID(rawValue: "longBase64")
    /// An email address.
    public static let email = RuleID(rawValue: "email")
    /// A home-folder path: `/Users/<name>`, `/home/<name>`, `/var/mobile/...`.
    public static let homePath = RuleID(rawValue: "homePath")
    /// An Apple Music or MusicKit library, playlist or catalog identifier.
    public static let musicID = RuleID(rawValue: "musicID")
    /// An IPv4 address.
    public static let ipv4 = RuleID(rawValue: "ipv4")
    /// An IPv6 address.
    public static let ipv6 = RuleID(rawValue: "ipv6")
}
