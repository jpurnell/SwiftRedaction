import Foundation
import Testing
@testable import Redaction

/// The README's rule table is checked against the catalogue so the documentation cannot drift from it.
@Suite("documentation matches the catalogue")
struct DocumentationTests {
    private static func readme() throws -> String {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("README.md"), encoding: .utf8)
    }

    @Test("every rule appears in the README's catalogue table, with its summary")
    func readmeListsEveryRule() throws {
        let readme = try Self.readme()
        for rule in RuleCatalogue.all {
            #expect(readme.contains("| `\(rule.id.rawValue)` |"), "README table lacks \(rule.id)")
            #expect(readme.contains(rule.summary), "README lacks the summary of \(rule.id)")
        }
    }

    @Test("the README's table marks exactly the rules each shipped policy enables")
    func readmeMarksPolicies() throws {
        let readme = try Self.readme()
        for rule in RuleCatalogue.all {
            guard let row = readme.split(whereSeparator: \.isNewline).first(where: { $0.hasPrefix("| `\(rule.id.rawValue)` |") }) else {
                Issue.record("README table lacks \(rule.id)")
                continue
            }
            let cells = row.split(separator: "|", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            #expect(cells.count >= 5, "row for \(rule.id) is malformed")
            guard cells.count >= 5 else { continue }
            #expect((cells[2] == "yes") == RedactionPolicy.buildTool.rules.contains(rule.id), "buildTool column wrong for \(rule.id)")
            #expect((cells[3] == "yes") == RedactionPolicy.appLog.rules.contains(rule.id), "appLog column wrong for \(rule.id)")
        }
    }
}
