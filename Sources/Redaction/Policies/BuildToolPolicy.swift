import Foundation

extension RedactionPolicy {
    /// The largest input the `.buildTool` policy will search: 8 MiB, a captured tool log, not one line.
    public static let buildToolMaxInputLength = 8 * 1_024 * 1_024

    /// For captured build-tool output (`xcodebuild`, `notarytool`) before it reaches a run log or the terminal.
    ///
    /// Removes a PEM private key (also one cut off before its END line), a JWT, an opaque `Bearer` credential,
    /// a password, secret or token given as a flag, `name=value`, `name: value` or JSON, an Apple app-specific
    /// password (when a credential word is nearby), and any literal the caller adds with
    /// ``adding(literalSecrets:)``. Every removal reads `[REDACTED]`.
    ///
    /// It keeps, on purpose, what a build log needs to be useful and what is not secret: an App Store Connect key ID,
    /// an issuer UUID, a team ID, a notary profile name, and the *path* of a `.p8` key file (under a home folder or
    /// not). The key file's contents are a PEM block and are removed.
    public static let buildTool = RedactionPolicy(
        validated: [.literalSecret, .pemPrivateKey, .jwt, .bearer, .secretFlag, .secretAssignment, .appSpecificPassword],
        style: .uniform, maxInputLength: buildToolMaxInputLength,
        overlong: .replaceWhole("[output too long, removed]"),
        appSpecificPassword: .requiresCredentialWord, literalSecrets: [])
}

extension Redactor {
    /// A redactor for ``RedactionPolicy/buildTool``, built once.
    public static let buildTool = Redactor(unchecked: .buildTool)
}
