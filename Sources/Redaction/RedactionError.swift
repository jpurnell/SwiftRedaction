import Foundation

/// Why a ``RedactionPolicy`` or a ``Redactor`` could not be built.
///
/// A scrubber must fail at construction, never quietly at run time, so every case here is raised before any text is
/// processed.
public enum RedactionError: Error, Equatable, Sendable {
    /// The policy lists a rule that is not in the ``RuleCatalogue``.
    case unknownRule(RuleID)
    /// The policy lists the same rule twice.
    case duplicateRule(RuleID)
    /// `maxInputLength` is not positive.
    case invalidMaxInputLength(Int)
    /// The overlong placeholder is empty or longer than `maxInputLength`, so a replaced line would itself be overlong.
    case invalidOverlongPlaceholder
    /// A rule's pattern did not compile.
    case invalidRule(RuleID)
    /// A replacement token is itself changed by the policy, so redacting twice would differ from redacting once.
    case replacementNotStable(RuleID)
}
