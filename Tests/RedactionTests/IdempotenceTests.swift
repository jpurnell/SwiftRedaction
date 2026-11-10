import Foundation
import Testing
@testable import Redaction

/// `redact(redact(x)) == redact(x)` for every shipped policy, over the fixtures and over many generated inputs.
@Suite("idempotence and determinism")
struct IdempotenceTests {
    /// Policies under test: the two shipped ones, each with literals that are hard cases (a substring of a replacement
    /// token, of another literal, and a single bracket), and every rule in each style.
    static func policies() throws -> [(name: String, redactor: Redactor)] {
        let hard = ["RED", "REDACTED", "ACT", "[", "]", "tok", "hunter2", "abc", "abcdef", "ip", "Bearer"]
        let everyRule = RuleCatalogue.all.map(\.id)
        return try [
            ("buildTool", Redactor(.buildTool)),
            ("buildTool+literals", Redactor(.buildTool.adding(literalSecrets: hard))),
            ("appLog", Redactor(.appLog)),
            ("appLog+literals", Redactor(.appLog.adding(literalSecrets: hard))),
            ("all typed", Redactor(RedactionPolicy(rules: everyRule, style: .typed, appSpecificPassword: .anywhere))),
            ("all uniform", Redactor(RedactionPolicy(rules: everyRule, style: .uniform, appSpecificPassword: .anywhere))),
            ("all typed+literals", Redactor(RedactionPolicy(rules: everyRule, style: .typed).adding(literalSecrets: hard))),
        ]
    }

    /// Every input the suite knows: fixtures, the golden corpus, and lines that mix several shapes.
    static let pool: [String] =
        RuleFixtures.all.map(\.input) + GoldenCorpusTests.ordinaryLines + [
            "u /Users/jpurnell/x a@b.com 10.0.0.1 6F9619FF-8B86-D011-B42D-00C04FC964FF Bearer abcdef123456",
            "key ABC123DEFG issuer 69a6de80-1234-47e3-e053-5b8c7c11a4d1 file /Users/me/.appstoreconnect/private_keys/AuthKey_ABC123DEFG.p8",
            "token=[token] password: [REDACTED] secret='[secret]' Bearer [REDACTED]",
            "[REDACTED PRIVATE KEY] [private-key] /Users/[user]/x /var/mobile/[path]",
            "Music-User-Token=[token] --password [REDACTED] --password=[secret]",
        ]

    /// The pieces random strings are made of: shape fragments and the characters that join and split them.
    static let alphabet: [String] = [
        "a", "b", "Z", "9", "0", "f", "-", "_", ".", ":", "=", "@", "/", "[", "]", " ", " ", "\n", "\"", "'", ",", "%", "+",
        "token", "password", "secret", "Bearer ", "eyJ", "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
        "RED", "REDACTED", "[REDACTED]", "[token]", "[secret]", "[ip]", "[uuid]", "[hex]", "[email]", "10.0.0.1", "::1",
        "abcd-efgh-ijkl-mnop", "Users", "/Users/", "i.AbCdEf123456", "e\u{301}", "😀",
        "0123456789abcdef", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789",
    ]

    @Test("redacting the fixtures twice gives what redacting once did, for every policy")
    func fixturesAreIdempotent() throws {
        for (name, redactor) in try Self.policies() {
            for input in Self.pool {
                let once = redactor.redact(input)
                #expect(redactor.redact(once) == once, "\(name) not idempotent on: \(input)")
            }
        }
    }

    @Test("random concatenations of fixtures, and random strings of the shapes' own pieces, are idempotent",
          .timeLimit(.minutes(2)))
    func randomInputsAreIdempotent() throws {
        var rng = SeededGenerator(seed: 20_261_109)
        let policies = try Self.policies()
        for round in 0..<1_500 {
            let text: String
            if round.isMultiple(of: 2) {
                let count = Int.random(in: 1...5, using: &rng)
                text = (0..<count).map { _ in Self.pool.randomElement(using: &rng) ?? "" }
                    .joined(separator: [" ", "", "\n", "-", "="].randomElement(using: &rng) ?? " ")
            } else {
                let count = Int.random(in: 1...40, using: &rng)
                text = (0..<count).map { _ in Self.alphabet.randomElement(using: &rng) ?? "" }.joined()
            }
            for (name, redactor) in policies {
                let report = redactor.report(text)
                #expect(!report.overlong, "\(name) round \(round) did not settle or expanded past the cap: \(text.debugDescription)")
                let once = report.output
                let twice = redactor.redact(once)
                #expect(twice == once, "\(name) round \(round) not idempotent on \(text.debugDescription): \(once.debugDescription) then \(twice.debugDescription)")
            }
        }
    }

    @Test("the same input and policy give the same output on every run")
    func deterministic() throws {
        let line = "Bearer abc123 a@b.com 10.0.0.1 password=hunter2 6F9619FF-8B86-D011-B42D-00C04FC964FF"
        for (_, redactor) in try Self.policies() {
            let first = redactor.redact(line)
            for _ in 0..<20 { #expect(redactor.redact(line) == first) }
        }
    }

    @Test("concurrent use of one redactor from many tasks gives the same output (a compiled rule is shared safely)")
    func concurrentUse() async {
        let line = "peer 10.0.1.114 Bearer abc123 a@b.com password=hunter2 6F9619FF-8B86-D011-B42D-00C04FC964FF /Users/x/y"
        let expected = Redactor.appLog.redact(line)
        let results = await withTaskGroup(of: String.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    var last = ""
                    for _ in 0..<50 { last = Redactor.appLog.redact(line) }
                    return last
                }
            }
            var all: [String] = []
            for await result in group { all.append(result) }
            return all
        }
        #expect(results.count == 64)
        #expect(results.allSatisfy { $0 == expected })
    }
}

@Suite("report")
struct ReportTests {
    @Test("redact and report share one code path: report(x).output == redact(x)")
    func sameOutput() throws {
        for redactor in [Redactor.buildTool, Redactor.appLog] {
            for input in IdempotenceTests.pool {
                #expect(redactor.report(input).output == redactor.redact(input))
            }
        }
    }

    @Test("the report counts what fired, by rule, and an untouched line fires nothing")
    func counts() {
        let report = Redactor.appLog.report("peer 10.0.1.114 and 10.0.1.115 mail a@b.com token=hunter2")
        #expect(report.fired == [.ipv4: 2, .email: 1, .secretAssignment: 1])
        #expect(report.overlong == false)
        #expect(report.output == "peer [ip] and [ip] mail [email] token=[secret]")
        #expect(Redactor.appLog.report("nothing to see").fired.isEmpty)
    }

    @Test("a literal secret is counted under its own rule")
    func literalCount() throws {
        let redactor = try Redactor(.buildTool.adding(literalSecrets: ["xyzzy"]))
        #expect(redactor.report("a xyzzy b xyzzy").fired == [.literalSecret: 2])
    }

    @Test("an over-long input reports overlong and no counts, and the report holds no part of the input")
    func overlong() {
        let planted = "hunter2-should-never-appear"
        let report = Redactor.appLog.report(String(repeating: "a", count: 5_000) + planted)
        #expect(report.overlong)
        #expect(report.fired.isEmpty)
        #expect(!String(describing: report).contains(planted))
    }

    @Test("the report carries no matched text: its description holds none of the secrets that fired")
    func noMatchedText() {
        let report = Redactor.appLog.report("token=hunter2 mail a@b.com peer 10.0.1.114")
        let rendered = String(describing: report) + String(reflecting: report)
        for secret in ["hunter2", "a@b.com", "10.0.1.114"] {
            #expect(!rendered.contains(secret))
        }
    }
}
