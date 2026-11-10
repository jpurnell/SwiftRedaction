import Foundation
import Testing
import Redaction
@testable import RedactionTestSupport

/// A privacy helper that cannot fail is the standard defect, so each way of leaking is planted on purpose and must be found.
@Suite("findLeaks: the helper can fail")
struct FindLeaksTests {
    static let secret = Secret(label: "notary password", value: "hunter2-Zq9!x")

    @Test("clean strings have no leaks")
    func clean() {
        #expect(findLeaks(of: [Self.secret], in: ["nothing here", "", "password=[REDACTED]"]).isEmpty)
    }

    @Test("a planted leak in a string is found, and the leak names the label and the place, never the value")
    func plantedString() {
        let leaks = findLeaks(of: [Self.secret], in: ["fine", "x hunter2-Zq9!x y"])
        #expect(leaks.count == 1)
        #expect(leaks.first?.secretLabel == "notary password")
        #expect(leaks.first?.form == "raw")
        #expect(leaks.first?.location == "string 1")
        let rendered = leaks.map(\.description).joined() + String(describing: leaks) + String(reflecting: leaks)
        #expect(!rendered.contains("hunter2"))
        #expect(rendered.contains("notary password"))
    }

    @Test("the secret does not print itself")
    func secretDoesNotPrint() {
        let rendered = String(describing: Self.secret) + String(reflecting: Self.secret)
        #expect(!rendered.contains("hunter2"))
        #expect(rendered.contains("notary password"))
    }

    @Test("a planted leak in a file is found, a clean file is not, and an unreadable file throws")
    func files() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("redaction-leaks-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let dirty = directory.appendingPathComponent("run.json")
        let clean = directory.appendingPathComponent("clean.json")
        try Data("{\"pw\":\"hunter2-Zq9!x\"}".utf8).write(to: dirty)
        try Data("{\"pw\":\"[REDACTED]\"}".utf8).write(to: clean)
        let leaks = try findLeaks(of: [Self.secret], inFileAt: dirty)
        #expect(leaks.count == 1)
        #expect(leaks.first?.location == "file run.json")
        #expect(try findLeaks(of: [Self.secret], inFileAt: clean).isEmpty)
        #expect(throws: (any Error).self) {
            _ = try findLeaks(of: [Self.secret], inFileAt: directory.appendingPathComponent("missing.json"))
        }
        try FileManager.default.removeItem(at: directory)
    }

    @Test("a planted leak in Data is found as raw bytes, also when the Data is UTF-16")
    func data() {
        #expect(findLeaks(of: [Self.secret], in: Data("abc hunter2-Zq9!x".utf8)).count == 1)
        let utf16 = Data("abc hunter2-Zq9!x".utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] })
        let leaks = findLeaks(of: [Self.secret], in: utf16)
        // The big-endian form also occurs, shifted by the zero byte of the preceding character.
        #expect(leaks.contains { $0.form == "utf16le" })
        #expect(findLeaks(of: [Self.secret], in: Data([0, 1, 2, 3])).isEmpty)
    }

    static func hex(_ text: String, uppercase: Bool) -> String {
        text.utf8.map { byte in
            let digits = String(byte, radix: 16, uppercase: uppercase)
            return digits.count == 1 ? "0" + digits : digits
        }.joined()
    }

    @Test("a secret re-encoded before it was written is still a leak",
          arguments: [
            ("base64", Data("hunter2-Zq9!x".utf8).base64EncodedString()),
            ("base64 without padding", Data("hunter2-Zq9!x".utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")),
            ("base64url", Data("hunter2-Zq9!x".utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")),
            ("percent", "hunter2-Zq9%21x"),
            ("hex lower", Self.hex("hunter2-Zq9!x", uppercase: false)),
            ("hex upper", Self.hex("hunter2-Zq9!x", uppercase: true)),
            ("base64 inside a longer blob", Data("user:hunter2-Zq9!x".utf8).base64EncodedString()),
            ("base64 at another alignment", Data("ab:hunter2-Zq9!x:z".utf8).base64EncodedString()),
          ])
    func encodedForms(form: String, text: String) {
        let leaks = findLeaks(of: [Self.secret], in: ["header: \(text) end"])
        #expect(leaks.count == 1, "\(form) not found in: \(text)")
        #expect(leaks.first?.secretLabel == "notary password")
    }

    @Test("every rendering of an error is searched: describing, reflecting, localizedDescription, debugDescription")
    func errorRenderings() {
        struct InDescription: Error, CustomStringConvertible { var description: String { "failed with hunter2-Zq9!x" } }
        struct InDebug: Error, CustomDebugStringConvertible { var debugDescription: String { "debug hunter2-Zq9!x" } }
        struct InLocalized: LocalizedError { var errorDescription: String? { "localized hunter2-Zq9!x" } }
        struct InStoredProperty: Error { let payload = "hunter2-Zq9!x" }
        struct Clean: Error, CustomStringConvertible { var description: String { "network down" } }

        let found = [
            findLeaks(of: [Self.secret], inRenderingsOf: InDescription()),
            findLeaks(of: [Self.secret], inRenderingsOf: InDebug()),
            findLeaks(of: [Self.secret], inRenderingsOf: InLocalized()),
            findLeaks(of: [Self.secret], inRenderingsOf: InStoredProperty()),
        ]
        for leaks in found { #expect(!leaks.isEmpty) }
        #expect(found[0].contains { $0.location == "error String(describing:)" })
        #expect(found[1].contains { $0.location == "error debugDescription" })
        #expect(found[2].contains { $0.location == "error localizedDescription" })
        #expect(found[3].contains { $0.location == "error String(reflecting:)" })
        #expect(findLeaks(of: [Self.secret], inRenderingsOf: Clean()).isEmpty)
    }

    @Test("an empty secret matches nothing instead of everything")
    func emptySecret() {
        #expect(findLeaks(of: [Secret(label: "empty", value: "")], in: ["anything"]).isEmpty)
    }

    @Test("several secrets are each reported under their own label")
    func severalSecrets() {
        let other = Secret(label: "api key", value: "k-12345-abcde")
        let leaks = findLeaks(of: [Self.secret, other], in: ["hunter2-Zq9!x and k-12345-abcde"])
        #expect(Set(leaks.map(\.secretLabel)) == ["notary password", "api key"])
    }

    @Test("expectNoLeaks records an issue when a secret leaked, and none when the input is clean")
    func expectNoLeaksCanFail() {
        withKnownIssue("a deliberate leak must be reported") {
            expectNoLeaks(of: [Self.secret], in: ["leaked hunter2-Zq9!x"])
        }
        withKnownIssue("a deliberate leak in an error rendering must be reported") {
            struct Bad: Error, CustomStringConvertible { var description: String { "hunter2-Zq9!x" } }
            expectNoLeaks(of: [Self.secret], inRenderingsOf: Bad())
        }
        withKnownIssue("a deliberate leak in Data must be reported") {
            expectNoLeaks(of: [Self.secret], in: Data("hunter2-Zq9!x".utf8))
        }
        expectNoLeaks(of: [Self.secret], in: ["clean"])
        #expect(findLeaks(of: [Self.secret], in: ["clean"]).isEmpty)
    }

    @Test("the helper finds what a redactor with the wrong rules lets through, and nothing once the right rules run")
    func againstARedactor() throws {
        let line = "notarytool --password hunter2-Zq9!x submit"
        let blind = try Redactor(RedactionPolicy(rules: [.uuid], style: .uniform))
        #expect(!findLeaks(of: [Self.secret], in: [blind.redact(line)]).isEmpty)
        expectNoLeaks(of: [Self.secret], in: [Redactor.buildTool.redact(line)])
    }
}
