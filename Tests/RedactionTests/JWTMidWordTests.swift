import Foundation
import Testing
@testable import Redaction

/// The `jwt` rule must find a token wherever it starts, glued to letters or punctuation included, and must stay linear on
/// inputs built to make a rescanning matcher quadratic.
@Suite("jwt rule: detection inside a word, and linear work")
struct JWTMidWordTests {
    static let token = RuleFixtures.jwtFixture
    static let secrets = ["eyJhbGci", "eyJpc3Mi", "MEUCIQ"]

    /// Each case is a line with a token in it and the text that must survive around it.
    static let glued: [(name: String, line: String, prefix: String, suffix: String)] = [
        ("letters in front", "mytoken" + token, "mytoken", ""),
        ("one letter in front", "x" + token, "x", ""),
        ("digit in front", "id9" + token + " end", "id9", " end"),
        ("underscore in front", "id_" + token, "id_", ""),
        ("hyphen in front", "id-" + token, "id-", ""),
        ("colon, no space", "idtoken:" + token + " end", "idtoken:", " end"),
        ("Bearer and colon", "Bearer:" + token, "Bearer:", ""),
        ("quoted JSON", "{\"jwt\":\"" + token + "\"}", "{\"jwt\":\"", "\"}"),
        ("pasted after text", "see" + token + "then", "see", ""),
        ("two tokens, one glued", token + " and abc" + token, "", ""),
    ]

    @Test("a token glued to what precedes it is removed under both shipped policies, and the text around it is kept",
          arguments: glued)
    func gluedIsRedacted(_ item: (name: String, line: String, prefix: String, suffix: String)) {
        for redactor in [Redactor.appLog, Redactor.buildTool] {
            let output = redactor.redact(item.line)
            for secret in Self.secrets {
                #expect(!output.contains(secret), "\(item.name) leaked \(secret): \(output)")
            }
            #expect(output.hasPrefix(item.prefix), "\(item.name) lost its prefix: \(output)")
            #expect(output.hasSuffix(item.suffix) || item.name == "pasted after text", "\(item.name) lost its suffix: \(output)")
        }
    }

    @Test("the jwt rule alone replaces the whole glued token with exactly the token")
    func exactReplacement() throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.jwt], style: .typed))
        #expect(redactor.redact("mytoken" + Self.token) == "mytoken[token]")
        #expect(redactor.redact("a-" + Self.token + "-z") == "a-[token]")
        #expect(redactor.redact("x" + Self.token + " y") == "x[token] y")
        let uniform = try Redactor(RedactionPolicy(rules: [.jwt], style: .uniform))
        #expect(uniform.redact("id_" + Self.token) == "id_[REDACTED]")
    }

    @Test("ordinary text that merely contains eyJ is left alone unless it is JWT-shaped")
    func lookalikesSurvive() throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.jwt], style: .typed))
        let survivors = [
            "Meyjer and the-eyJ-slug and eyJ alone",
            "https://example.com/posts/eyJabc-def-ghi/page",
            "eyJ.a.b and eyJabc",
            "eyJabcde.fghij",                 // two segments only
            "eyJabcde.fgh.ijklmn",            // second segment under five
            "eyJabc.defghi.jklmno",           // first segment under five after eyJ
            "keyJabcde.fghijk",               // not three segments
            "eyJeyJeyJeyJ.eyJeyJ",            // two segments
        ]
        for line in survivors {
            #expect(redactor.redact(line) == line, "changed: \(line)")
        }
    }

    @Test("the shape that defines a JWT is exactly eyJ, five, a dot, five, a dot, then more base64url")
    func shapeBoundaries() throws {
        let redactor = try Redactor(RedactionPolicy(rules: [.jwt], style: .typed))
        #expect(redactor.redact("pre-eyJabcde.fghij.klmno-post") == "pre-[token]")
        #expect(redactor.redact("eyJabcde.fghij.") == "[token]")          // an empty third segment still matches
        #expect(redactor.redact("eyJabcde.fghij.klmno.extra") == "[token].extra")
        #expect(redactor.redact("eyJabcd.fghij.klmno") == "eyJabcd.fghij.klmno")
        #expect(redactor.redact("Zé" + Self.token) == "Zé[token]")        // non-ASCII in front
        #expect(redactor.redact(Self.token + "é tail") == "[token]é tail")
    }

    @Test("a replaced token is a fixed point, glued or not")
    func idempotent() {
        for item in Self.glued {
            for redactor in [Redactor.appLog, Redactor.buildTool] {
                let once = redactor.redact(item.line)
                #expect(redactor.redact(once) == once, "not idempotent: \(item.name)")
            }
        }
    }

    /// Pathological shapes for a matcher that rescans: all must complete and stay a fixed point.
    static let pathological: [(name: String, make: @Sendable (Int) -> String)] = [
        ("eyJ x n", { String(repeating: "eyJ", count: $0 / 3) }),
        ("eyJ. x n", { String(repeating: "eyJ.", count: $0 / 4) }),
        ("eyJ.. x n", { String(repeating: "eyJ..", count: $0 / 5) }),
        ("eyJaaaaa. x n", { String(repeating: "eyJaaaaa.", count: $0 / 9) }),
        ("eyJaaaaa.bbbbb x n", { String(repeating: "eyJaaaaa.bbbbb", count: $0 / 14) }),
        ("long run, no dots", { "eyJ" + String(repeating: "A", count: $0) }),
        ("long run starting eyJ then dot at the end", { "eyJ" + String(repeating: "Ab_-", count: $0 / 4) + "." }),
        ("many short starts", { String(repeating: "eyJab ", count: $0 / 6) }),
        ("eyJ, run, no dot, repeated", { String(repeating: "eyJ" + String(repeating: "x", count: 40) + " ", count: $0 / 44) }),
    ]

    @Test("every pathological input completes, keeps its length class, and is a fixed point (timing is measured, not asserted)",
          .timeLimit(.minutes(3)), arguments: [65_536, 262_144])
    func pathologicalCompletes(size: Int) throws {
        let policy = try RedactionPolicy(rules: [.jwt], style: .typed, maxInputLength: 1 << 20)
        let redactor = try Redactor(policy)
        for item in Self.pathological {
            let text = item.make(size)
            let report = redactor.report(text)
            #expect(!report.overlong, "\(item.name)")
            #expect(redactor.redact(report.output) == report.output, "\(item.name) not idempotent")
        }
    }
}

/// The scanner's cost, asserted on what it reads rather than on how long it takes.
@Suite("JWTScanner: work is proportional to the text")
struct JWTScannerTests {
    /// The bytes read by a scan of `text`, and the length of `text` in bytes. A byte read twice counts twice. Each byte is
    /// read by one attempt, plus the lookahead at the end of each run, so three times the length is a generous bound and a
    /// quadratic scan fails it.
    private func cost(_ text: String) -> (steps: Int, bytes: Int) {
        let bytes = Array(text.utf8)
        return (JWTScanner.scan(bytes).steps, bytes.count)
    }

    @Test("the pathological shapes cost at most three reads per byte at 64 KiB and 256 KiB")
    func linear() {
        for size in [65_536, 262_144] {
            for item in JWTMidWordTests.pathological {
                let measured = cost(item.make(size))
                #expect(measured.steps <= 3 * measured.bytes + 16, "\(item.name) \(size): \(measured.steps) steps for \(measured.bytes) bytes")
            }
        }
    }

    @Test("doubling the input at most doubles the steps, on the shape that made the regex quadratic")
    func doubling() {
        let small = JWTScanner.scan(Array(String(repeating: "eyJ", count: 20_000).utf8)).steps
        let large = JWTScanner.scan(Array(String(repeating: "eyJ", count: 40_000).utf8)).steps
        #expect(large <= 2 * small + 16)
    }

    @Test("the scanner finds the ranges a leftmost greedy match would, in bytes")
    func ranges() {
        let text = "ab eyJabcde.fghij.klmno cd-eyJvwxyz1.fghij2.k eyJ.a.b"
        let scan = JWTScanner.scan(Array(text.utf8))
        let pieces = scan.ranges.map { String(decoding: Array(text.utf8)[$0], as: UTF8.self) }
        #expect(pieces == ["eyJabcde.fghij.klmno", "eyJvwxyz1.fghij2.k"])
    }

    @Test("an overlapping start inside a token or a failed run is not tried again")
    func noOverlap() {
        let text = "eyJeyJeyJeyJ.eyJeyJeyJ.eyJeyJeyJ"   // one token: the first segment runs to the first dot
        let pieces = JWTScanner.scan(Array(text.utf8)).ranges
        #expect(pieces == [0..<text.utf8.count])
    }
}
