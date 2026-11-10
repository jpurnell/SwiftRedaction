import Foundation
import Testing
@testable import Redaction

@Suite("RuleCatalogue")
struct RuleCatalogueTests {
    /// The order is the algorithm, so it is pinned: a change here changes every output.
    static let expectedOrder: [RuleID] = [
        .literalSecret, .pemPrivateKey, .jwt, .bearer, .appleMusicToken, .secretFlag, .secretAssignment,
        .appSpecificPassword, .uuid, .longHex, .longBase64, .email, .homePath, .musicID, .ipv4, .ipv6,
    ]

    @Test("the catalogue holds every rule once, in the fixed order")
    func order() {
        #expect(RuleCatalogue.all.map(\.id) == Self.expectedOrder)
        #expect(Set(RuleCatalogue.all.map(\.id)).count == RuleCatalogue.all.count)
    }

    @Test("every rule compiles, so a typo cannot silently turn a category off")
    func everyPatternCompiles() {
        let compiled = RuleCatalogue.all.filter(\.isOperational).count
        #expect(compiled == RuleCatalogue.all.count)
        for rule in RuleCatalogue.all {
            #expect(rule.isOperational, "rule \(rule.id) did not compile")
        }
    }

    @Test("a rule can be looked up by its identifier, and an unknown identifier finds nothing")
    func lookup() {
        #expect(RuleCatalogue.rule(.jwt)?.id == .jwt)
        #expect(RuleCatalogue.rule(RuleID(rawValue: "nope")) == nil)
    }

    @Test("every rule has a summary and both replacement forms")
    func described() {
        for rule in RuleCatalogue.all {
            #expect(!rule.summary.isEmpty && !rule.uniformReplacement.isEmpty && !rule.typedReplacement.isEmpty, "\(rule.id)")
        }
    }

    @Test("every rule except the literal rule has a positive and a negative fixture")
    func everyRuleHasFixtures() {
        for rule in RuleCatalogue.all where rule.id != .literalSecret {
            let mine = RuleFixtures.all.filter { $0.rule == rule.id }
            #expect(mine.contains { !$0.isNegative }, "\(rule.id) has no positive fixture")
            #expect(mine.contains { $0.isNegative }, "\(rule.id) has no negative fixture")
        }
    }

    @Test("each rule on its own removes what its positive fixtures name and leaves its negative fixtures alone",
          arguments: RuleFixtures.all)
    func fixture(_ fixture: RuleFixture) throws {
        let policy = try RedactionPolicy(rules: [fixture.rule], style: .typed)
        let redacted = try Redactor(policy).redact(fixture.input)
        if fixture.isNegative {
            #expect(redacted == fixture.input, "changed: \(fixture)")
        } else {
            for secret in fixture.mustNotSurvive {
                #expect(!redacted.contains(secret), "survived in: \(fixture)")
            }
            #expect(redacted != fixture.input)
        }
    }

    @Test("the literal rule removes the strings it is given and nothing else")
    func literal() throws {
        let policy = try RedactionPolicy(rules: [.literalSecret], style: .typed).adding(literalSecrets: ["hunter2"])
        let redactor = try Redactor(policy)
        #expect(redactor.redact("pw hunter2 and 10.0.0.1") == "pw [secret] and 10.0.0.1")
    }
}
