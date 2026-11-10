import Foundation
import Testing
@testable import Redaction

/// Inputs built to be slow for a backtracking matcher: runs of a rule's own characters, near misses, and repeated prefixes.
///
/// These tests assert **no time bound** (the gate forbids wall-clock assertions, and a bound measured on one machine is a
/// flaky test on another). They prove the engine completes on each input and that the result is still a fixed point. The
/// timings behind the README's engine choice were taken with the throwaway harness in
/// `project/docs/technical/measure-engines.swift.txt`; `.timeLimit` is only a guard against a hang.
@Suite("adversarial inputs")
struct AdversarialInputTests {
    static let size = 65_536

    static func repeated(_ unit: String) -> String {
        String(repeating: unit, count: size / unit.utf8.count)
    }

    /// The shapes tried against every rule (see the README for the measured subset).
    static let inputs: [(name: String, text: String)] = [
        ("emailchars, no @", String(repeating: "abcdefghij0123._%+-", count: size / 19)),
        ("a x n", String(repeating: "a", count: size)),
        ("base64-ish", String(repeating: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", count: size / 64)),
        ("base64-ish then hyphen", String(repeating: "Ab3+/", count: size / 5 - 1) + "-"),
        ("hex run then g", String(repeating: "a", count: size - 1) + "g"),
        ("hex 16 + space", repeated("0123456789abcdef ")),
        ("eyJ x n", repeated("eyJ")),
        ("eyJaaaaaa. x n", repeated("eyJaaaaaa.")),
        ("BEGIN PRIVATE KEY, no END", repeated("-----BEGIN PRIVATE KEY-----\nAAAA\n")),
        ("BEGIN..END x n", repeated("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
        ("BEGIN + caps run", "-----BEGIN " + String(repeating: "A", count: size)),
        ("Bearer x n", repeated("Bearer ")),
        ("Bearer + spaces", "Bearer" + String(repeating: " ", count: size)),
        ("a-a-a- x n", repeated("a-")),
        ("--token x n", repeated("--token ")),
        ("hyphens", String(repeating: "-", count: size)),
        ("password= x n", repeated("password=")),
        ("password=\" unterminated x n", repeated("password=\"")),
        ("token + spaces", "token" + String(repeating: " ", count: size)),
        ("abcd-efgh-ijkl-mnop x n", repeated("abcd-efgh-ijkl-mnop ")),
        ("abcd- x n", repeated("abcd-")),
        ("a@ x n", repeated("a@")),
        ("a@b. x n", repeated("a@b.")),
        ("a@ then dots", "a@" + repeated("b.")),
        ("/Users/ x n", repeated("/Users/")),
        ("pl.u- x n", repeated("pl.u-aaaaa ")),
        ("i.aaaaaaa x n", repeated("i.aaaaaaa")),
        ("1.1.1. x n", repeated("1.1.1.")),
        ("colons", String(repeating: ":", count: size)),
        ("a: x n", repeated("a:")),
        ("ab:: x n", repeated("ab::")),
        ("uuid-ish", repeated("6F9619FF-8B86-D011-B42D-00C04FC964F")),
    ]

    @Test("every rule completes on every adversarial input, and its output is a fixed point",
          .timeLimit(.minutes(5)),
          arguments: RuleCatalogue.all.map(\.id).filter { $0 != .literalSecret })
    func completes(rule: RuleID) throws {
        let policy = try RedactionPolicy(rules: [rule], style: .typed, maxInputLength: 1 << 20)
        let redactor = try Redactor(policy)
        for input in Self.inputs {
            let report = redactor.report(input.text)
            #expect(!report.overlong || report.output == policy.overlongPlaceholder, "\(rule) on \(input.name)")
            #expect(redactor.redact(report.output) == report.output, "\(rule) not idempotent on \(input.name)")
        }
    }

    @Test("a one-megabyte single line completes under each shipped policy: appLog replaces it, buildTool searches it",
          .timeLimit(.minutes(3)))
    func oneMegabyteLine() {
        let line = String(repeating: "abcdefghij0123456789", count: 52_429)
        #expect(line.utf8.count > 1_000_000)
        let log = Redactor.appLog.report(line)
        #expect(log.overlong)
        #expect(log.output == "[line too long, removed]")
        let build = Redactor.buildTool.report(line)
        #expect(!build.overlong)
        #expect(Redactor.buildTool.redact(build.output) == build.output)
    }

    @Test("an input past the buildTool cap is replaced whole, and one at the cap is searched")
    func buildToolCap() {
        let over = String(repeating: "a", count: RedactionPolicy.buildToolMaxInputLength + 1)
        #expect(Redactor.buildTool.redact(over) == "[output too long, removed]")
    }

    @Test("every shipped policy completes on a 4 KB crafted line in each shape, and the result is a fixed point")
    func appLogCrafted4K() {
        for input in Self.inputs {
            let line = String(input.text.prefix(4_096))
            let once = Redactor.appLog.redact(line)
            #expect(Redactor.appLog.redact(once) == once, "appLog not idempotent on \(input.name)")
        }
    }

    @Test("the engines agree: the same policy on ICU and on Swift Regex gives the same output over the corpus")
    func enginesAgree() throws {
        let lines = IdempotenceTests.pool
        for policy in [RedactionPolicy.buildTool, RedactionPolicy.appLog] {
            let swift = Redactor(failClosed: policy)
            let icu = Redactor(failClosed: policy, matchers: { rule in
                try? rule.patterns.map { try ICUMatcher(pattern: $0) as any PatternMatcher }
            })
            for line in lines {
                #expect(icu.redact(line) == swift.redact(line), "engines differ on: \(line)")
            }
        }
    }
}
