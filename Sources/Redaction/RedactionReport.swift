import Foundation

/// The result of ``Redactor/report(_:)``: the redacted text and which rules fired, never what they matched.
///
/// `fired` holds counts only. It carries no matched text and no offsets, so a report can be logged, stored or sent
/// without becoming a second copy of the secret.
public struct RedactionReport: Sendable, Equatable {
    /// The redacted text, identical to what ``Redactor/redact(_:)`` returns for the same input.
    public let output: String
    /// How many times each rule replaced something. A rule that did not fire is absent.
    public let fired: [RuleID: Int]
    /// Whether the input (or the output) exceeded the policy's cap and was replaced whole.
    public let overlong: Bool

    /// Creates a report.
    /// - Parameters:
    ///   - output: The redacted text.
    ///   - fired: Replacement counts by rule.
    ///   - overlong: Whether the text was replaced for length.
    public init(output: String, fired: [RuleID: Int], overlong: Bool) {
        self.output = output
        self.fired = fired
        self.overlong = overlong
    }
}
