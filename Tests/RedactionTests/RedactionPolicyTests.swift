import Foundation
import Testing
@testable import Redaction

@Suite("RedactionPolicy")
struct RedactionPolicyTests {
    @Test("a rule listed twice is an error")
    func duplicateRule() {
        #expect(throws: RedactionError.duplicateRule(.jwt)) {
            _ = try RedactionPolicy(rules: [.jwt, .bearer, .jwt], style: .uniform)
        }
    }

    @Test("a rule that is not in the catalogue is an error")
    func unknownRule() {
        let bogus = RuleID(rawValue: "notARule")
        #expect(throws: RedactionError.unknownRule(bogus)) {
            _ = try RedactionPolicy(rules: [.jwt, bogus], style: .uniform)
        }
    }

    @Test("a non-positive length cap is an error", arguments: [0, -1])
    func invalidCap(cap: Int) {
        #expect(throws: RedactionError.invalidMaxInputLength(cap)) {
            _ = try RedactionPolicy(rules: [.jwt], style: .uniform, maxInputLength: cap)
        }
    }

    @Test("a placeholder that would itself exceed the cap is an error, since the replaced line would be overlong")
    func placeholderLongerThanCap() {
        #expect(throws: RedactionError.invalidOverlongPlaceholder) {
            _ = try RedactionPolicy(rules: [.jwt], style: .uniform, maxInputLength: 4, overlong: .replaceWhole("[too long]"))
        }
        #expect(throws: RedactionError.invalidOverlongPlaceholder) {
            _ = try RedactionPolicy(rules: [.jwt], style: .uniform, overlong: .replaceWhole(""))
        }
    }

    @Test("a placeholder that a rule of the same policy would change is rejected, so redacting twice cannot differ")
    func placeholderMatchedByRule() {
        #expect(throws: RedactionError.replacementNotStable(.secretAssignment)) {
            _ = try RedactionPolicy(rules: [.secretAssignment], style: .uniform, overlong: .replaceWhole("token=abcdef"))
        }
    }

    @Test("the order of the rules in a policy does not change the output: the catalogue's order is the algorithm")
    func ruleOrderDoesNotMatter() throws {
        let input = "Bearer abc123 --password hunter2 token=hunter2 eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.MEUCIQDabcdef using abcd-efgh-ijkl-mnop to sign in"
        let rules = RedactionPolicy.buildTool.rules
        let reference = try Redactor(RedactionPolicy(rules: rules, style: .uniform)).redact(input)
        var rng = SeededGenerator(seed: 7)
        for _ in 0..<20 {
            let shuffled = try Redactor(RedactionPolicy(rules: rules.shuffled(using: &rng), style: .uniform)).redact(input)
            #expect(shuffled == reference)
        }
    }

    @Test("the order of the rules does not change the output of the appLog rule set either")
    func appLogRuleOrderDoesNotMatter() throws {
        let input = "peer 10.0.1.114 Bearer abc123 user a@b.com token=hunter2 id 6F9619FF-8B86-D011-B42D-00C04FC964FF"
        let rules = RedactionPolicy.appLog.rules
        let reference = Redactor.appLog.redact(input)
        var rng = SeededGenerator(seed: 11)
        for _ in 0..<20 {
            let policy = try RedactionPolicy(rules: rules.shuffled(using: &rng), style: .typed)
            #expect(try Redactor(policy).redact(input) == reference)
        }
    }

    @Test("both shipped policies are accepted by the public, validating initialiser")
    func shippedPoliciesValidate() throws {
        for policy in [RedactionPolicy.buildTool, RedactionPolicy.appLog] {
            let rebuilt = try RedactionPolicy(
                rules: policy.rules, style: policy.style, maxInputLength: policy.maxInputLength,
                overlong: policy.overlong, appSpecificPassword: policy.appSpecificPassword)
            #expect(rebuilt == policy)
        }
    }

    @Test("adding literal secrets keeps the rules and adds the literal rule once")
    func addingLiterals() {
        let policy = RedactionPolicy.buildTool.adding(literalSecrets: ["a", "b"]).adding(literalSecrets: ["c"])
        #expect(policy.literalSecrets == ["a", "b", "c"])
        #expect(policy.rules.filter { $0 == .literalSecret }.count == 1)
        #expect(RedactionPolicy.appLog.adding(literalSecrets: ["x"]).rules.contains(.literalSecret))
    }
}
