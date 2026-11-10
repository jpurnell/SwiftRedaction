import Foundation

extension RedactionPolicy {
    /// For app log lines before they leave the device (a TestFlight log upload), where a line may carry text a peer sent.
    ///
    /// A superset of SwiftDiagnosticsHub's `LogScrubber`: a PEM private key, a JWT, an opaque `Bearer` credential,
    /// labelled Apple Music tokens, UUIDs, long hex runs (not a 40-digit git SHA), long mixed-case base64 runs, email
    /// addresses, home-folder paths (`/Users`, `/home`, `/var/mobile`), MusicKit ids and IPv4 and IPv6 addresses, plus
    /// the `key=value` rule (`password=`, `token:`, JSON), which also removes harmless text such as `token: expired`.
    /// Replacements are typed (`[ip]`, `[uuid]`, `[token]`). A line over 4,096 UTF-8 bytes is replaced by
    /// `[line too long, removed]`.
    public static let appLog = RedactionPolicy(
        validated: [
            .pemPrivateKey, .jwt, .bearer, .appleMusicToken, .secretAssignment, .uuid, .longHex, .longBase64,
            .email, .homePath, .musicID, .ipv4, .ipv6,
        ],
        style: .typed, maxInputLength: defaultMaxInputLength,
        overlong: .replaceWhole(defaultOverlongPlaceholder),
        appSpecificPassword: .requiresCredentialWord, literalSecrets: [])
}

extension Redactor {
    /// A redactor for ``RedactionPolicy/appLog``, built once.
    public static let appLog = Redactor(failClosed: .appLog)
}
