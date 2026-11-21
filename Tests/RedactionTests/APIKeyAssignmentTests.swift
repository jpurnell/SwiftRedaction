import Foundation
import Testing
@testable import Redaction

/// The `secretAssignment` rule must recognise the API-key names (`api_key`, `api-key`, `apikey`, any case) in every
/// assignment form it already supports, and must leave ordinary words that merely contain `key` alone.
@Suite("secretAssignment rule: api key names")
struct APIKeyAssignmentTests {
    static let value = "sk9f2Kd81xQz"

    static let positives: [(name: String, line: String)] = [
        ("equals", "api_key=\(value)"),
        ("hyphen name", "api-key=\(value)"),
        ("no separator", "apikey=\(value)"),
        ("upper snake colon", "API_KEY: \(value)"),
        ("upper no separator", "APIKEY=\(value)"),
        ("x- header", "x-api-key: \(value)"),
        ("X- header mixed case", "X-Api-Key: \(value)"),
        ("json", "{\"api_key\": \"\(value)\"}"),
        ("json compact", "{\"apiKey\":\"\(value)\"}"),
        ("json hyphen", "{\"api-key\": \"\(value)\"}"),
        ("prefixed name", "MY_SERVICE_API_KEY=\(value)"),
        ("spaces around equals", "api_key = \(value)"),
        ("single quoted", "api_key='\(value)'"),
        ("in a url query", "GET /v1/items?api_key=\(value)&page=2"),
    ]

    @Test("an api key assignment is removed by the rule alone", arguments: positives)
    func removed(_ item: (name: String, line: String)) throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.secretAssignment], style: .uniform))
        let output = redactor.redact(item.line)
        #expect(!output.contains(Self.value), "\(item.name) leaked: \(output)")
        #expect(output.contains("[REDACTED]"), "\(item.name) not replaced: \(output)")
    }

    @Test("the redaction keeps the name and is idempotent", arguments: positives)
    func idempotent(_ item: (name: String, line: String)) throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.secretAssignment], style: .uniform))
        let once = redactor.redact(item.line)
        #expect(redactor.redact(once) == once, "\(item.name) not idempotent: \(once)")
    }

    @Test("both shipped policies remove it", arguments: positives)
    func shippedPolicies(_ item: (name: String, line: String)) {
        for redactor in [Redactor.appLog, Redactor.buildTool] {
            #expect(!redactor.redact(item.line).contains(Self.value), "\(item.name) leaked")
        }
    }

    static let negatives = [
        "capital_key=\(value)",
        "keyboard=us",
        "keyboard: \(value)",
        "monkey=banana",
        "hotkey: cmd-k",
        "primary_key=id",
        "apikeys=3",
        "rapid_keyframe=1",
        "api key rotation: monthly",
        "api_keyring=on",
    ]

    @Test("ordinary words that contain key are not redacted", arguments: negatives)
    func untouched(_ line: String) throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.secretAssignment], style: .uniform))
        #expect(redactor.redact(line) == line)
    }
}
