import Foundation

/// A secret-shaped fixture a test hands to ``findLeaks(of:in:)-(_,[String])`` and the other searches.
///
/// The `label` is what a failure message prints; the value never is. A `Secret` does not print its value in
/// `print`, `String(describing:)` or `String(reflecting:)` either, so a failing privacy test does not itself write the
/// secret into a CI log.
public struct Secret: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The name shown in a failure message, such as `"notary password"`.
    public let label: String

    let value: String

    /// Creates a fixture.
    /// - Parameters:
    ///   - label: A name for the fixture; this is all a failure message shows.
    ///   - value: The secret text to search for. An empty value matches nothing.
    public init(label: String, value: String) {
        self.label = label
        self.value = value
    }

    /// The label only.
    public var description: String { "Secret(\(label))" }

    /// The label only.
    public var debugDescription: String { "Secret(label: \(label))" }
}

/// One place a secret was found. It names the fixture's label, the form it was found in and where, never the value.
public struct Leak: Sendable, Equatable, CustomStringConvertible {
    /// The ``Secret/label`` of the secret that was found.
    public let secretLabel: String
    /// The form that matched: `raw`, `base64`, `base64url`, `percent`, `hex`, `utf16le`, ...
    public let form: String
    /// Where it was found: `string 3`, `file run.json`, `data`, `error localizedDescription`.
    public let location: String

    /// Creates a leak record.
    /// - Parameters:
    ///   - secretLabel: The label of the secret.
    ///   - form: The form that matched.
    ///   - location: Where it matched.
    public init(secretLabel: String, form: String, location: String) {
        self.secretLabel = secretLabel
        self.form = form
        self.location = location
    }

    /// A sentence naming the label, the form and the place.
    public var description: String {
        "secret \"\(secretLabel)\" found (\(form) form) in \(location)"
    }
}
