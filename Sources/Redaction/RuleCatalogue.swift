import Foundation

/// Every rule the package knows, in the fixed order in which they run.
///
/// The order is the algorithm: a later rule sees the replacement tokens an earlier one wrote, and several rules
/// depend on that (a JWT is removed before the `Bearer` rule looks at the word in front of it). A policy chooses
/// which rules apply; it never chooses their order.
public enum RuleCatalogue {
    /// All rules, in the order they run.
    public static let all: [Rule] = [
        .literalSecret,
        .pemPrivateKey,
        .jwt,
        .bearer,
        .appleMusicToken,
        .secretFlag,
        .secretAssignment,
        .appSpecificPassword,
    ]

    /// The rule named `id`, or `nil` when the catalogue has none.
    /// - Parameter id: A rule identifier.
    public static func rule(_ id: RuleID) -> Rule? {
        all.first { $0.id == id }
    }
}
