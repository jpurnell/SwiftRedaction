import Foundation
import Testing

/// The places a secret can have gone, searched for one or more ``Secret`` fixtures.
///
/// Each search looks for the value and for its base64, percent-encoded, hex and UTF-16 forms, because a secret that was
/// re-encoded before it was logged is still a leak. Every result names the fixture's label and where it was found, never the value.

/// Searches strings.
///
/// - Parameters:
///   - secrets: The fixtures to look for.
///   - strings: The strings to search, such as a redactor's outputs.
/// - Returns: One ``Leak`` per fixture, form and string in which a fixture was found; empty when nothing leaked.
public func findLeaks(of secrets: [Secret], in strings: [String]) -> [Leak] {
    var leaks: [Leak] = []
    for (index, string) in strings.enumerated() {
        leaks.append(contentsOf: search(secrets, in: Array(string.utf8), location: "string \(index)"))
    }
    return leaks
}

/// Searches the contents of a file.
///
/// - Parameters:
///   - secrets: The fixtures to look for.
///   - url: The file; only its last path component appears in a result.
/// - Returns: The leaks found in the file's bytes.
/// - Throws: The error from reading the file. An unreadable file is an error, not a clean result.
public func findLeaks(of secrets: [Secret], inFileAt url: URL) throws -> [Leak] {
    let data = try Data(contentsOf: url)
    return search(secrets, in: Array(data), location: "file \(url.lastPathComponent)")
}

/// Searches raw bytes: the bytes as they are (which covers UTF-8 and, through the UTF-16 forms, UTF-16 text).
///
/// - Parameters:
///   - secrets: The fixtures to look for.
///   - data: The bytes to search.
/// - Returns: The leaks found in the data.
public func findLeaks(of secrets: [Secret], in data: Data) -> [Leak] {
    search(secrets, in: Array(data), location: "data")
}

/// Searches every rendering of an error: `String(describing:)`, `String(reflecting:)`, `localizedDescription`,
/// and `debugDescription` when the error has one.
///
/// A failure that carries a secret usually shows it in only one of these, which is why all are searched.
/// - Parameters:
///   - secrets: The fixtures to look for.
///   - error: The error, typically one a test provoked on purpose.
/// - Returns: The leaks found, each naming the rendering.
public func findLeaks(of secrets: [Secret], inRenderingsOf error: any Error) -> [Leak] {
    var renderings: [(name: String, text: String)] = [
        ("String(describing:)", String(describing: error)),
        ("String(reflecting:)", String(reflecting: error)),
        ("localizedDescription", error.localizedDescription),
    ]
    if let debuggable = (error as Any) as? any CustomDebugStringConvertible {
        renderings.append(("debugDescription", debuggable.debugDescription))
    }
    var dumped = ""
    dump(error, to: &dumped)
    renderings.append(("dump", dumped))
    var leaks: [Leak] = []
    for rendering in renderings {
        leaks.append(contentsOf: search(secrets, in: Array(rendering.text.utf8), location: "error \(rendering.name)"))
    }
    return leaks
}

/// Records a test issue for each secret found in `strings`; the message names labels and places, never values.
///
/// - Parameters:
///   - secrets: The fixtures that must not appear.
///   - strings: The strings to search.
///   - sourceLocation: Where the issue is reported.
public func expectNoLeaks(of secrets: [Secret], in strings: [String], sourceLocation: SourceLocation = #_sourceLocation) {
    report(findLeaks(of: secrets, in: strings), sourceLocation: sourceLocation)
}

/// Records a test issue for each secret found in the file at `url`.
///
/// - Parameters:
///   - secrets: The fixtures that must not appear.
///   - url: The file to search.
///   - sourceLocation: Where the issue is reported.
/// - Throws: The error from reading the file.
public func expectNoLeaks(of secrets: [Secret], inFileAt url: URL, sourceLocation: SourceLocation = #_sourceLocation) throws {
    report(try findLeaks(of: secrets, inFileAt: url), sourceLocation: sourceLocation)
}

/// Records a test issue for each secret found in `data`.
///
/// - Parameters:
///   - secrets: The fixtures that must not appear.
///   - data: The bytes to search.
///   - sourceLocation: Where the issue is reported.
public func expectNoLeaks(of secrets: [Secret], in data: Data, sourceLocation: SourceLocation = #_sourceLocation) {
    report(findLeaks(of: secrets, in: data), sourceLocation: sourceLocation)
}

/// Records a test issue for each secret found in any rendering of `error`.
///
/// - Parameters:
///   - secrets: The fixtures that must not appear.
///   - error: The error to render and search.
///   - sourceLocation: Where the issue is reported.
public func expectNoLeaks(of secrets: [Secret], inRenderingsOf error: any Error, sourceLocation: SourceLocation = #_sourceLocation) {
    report(findLeaks(of: secrets, inRenderingsOf: error), sourceLocation: sourceLocation)
}

private func report(_ leaks: [Leak], sourceLocation: SourceLocation) {
    for leak in leaks {
        Issue.record(Comment(rawValue: leak.description), sourceLocation: sourceLocation)
    }
}

private func search(_ secrets: [Secret], in haystack: [UInt8], location: String) -> [Leak] {
    var leaks: [Leak] = []
    for secret in secrets {
        for form in SecretForms.forms(of: secret.value) where SecretForms.contains(haystack, form.bytes) {
            leaks.append(Leak(secretLabel: secret.label, form: form.name, location: location))
        }
    }
    return leaks
}
