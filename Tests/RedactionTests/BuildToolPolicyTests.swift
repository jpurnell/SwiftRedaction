import Foundation
import Testing
@testable import Redaction

/// The eight tests of SwiftReleaseKit's `RedactorTests`, ported unchanged in what they assert (only the way the
/// redactor is built differs), followed by the tests of the defects this package fixes.
@Suite("buildTool policy: ported RedactorTests")
struct BuildToolPortedTests {
    let redactor = Redactor.buildTool

    @Test("a private key block is replaced whole, however many lines it spans")
    func pemBlock() {
        let text = """
            before
            -----BEGIN PRIVATE KEY-----
            MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg
            Zm9vYmFyYmF6cXV4
            -----END PRIVATE KEY-----
            after
            """
        let redacted = redactor.redact(text)
        #expect(!redacted.contains("MIGTAgEAMBMGByqGSM49"))
        #expect(!redacted.contains("Zm9vYmFyYmF6cXV4"))
        #expect(redacted.contains("before") && redacted.contains("after"))
    }

    @Test("a key block with no END marker (a truncated capture) is still removed to the end")
    func truncatedPem() {
        let redacted = redactor.redact("x\n-----BEGIN EC PRIVATE KEY-----\nSECRETBYTES\nMORESECRET")
        #expect(!redacted.contains("SECRETBYTES") && !redacted.contains("MORESECRET"))
    }

    @Test("a password given as a flag, a key=value or JSON never survives",
          arguments: [
            "notarytool --password hunter2xyz store",
            "NOTARY_PASSWORD=hunter2xyz",
            "password: hunter2xyz",
            #"{"password": "hunter2xyz"}"#,
            "--api-secret=hunter2xyz",
            "token = hunter2xyz",
          ])
    func passwordShapes(text: String) {
        let redacted = redactor.redact(text)
        #expect(!redacted.contains("hunter2xyz"), "leaked in: \(redacted)")
        #expect(redacted.contains("[REDACTED]"))
    }

    @Test("a JWT (an App Store Connect API token) is removed")
    func jwt() {
        let jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQzEyM0RFRkcifQ.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE3fQ.MEUCIQDabcdefghijkl"
        let redacted = redactor.redact("Authorization: Bearer \(jwt)")
        #expect(!redacted.contains("eyJhbGci") && !redacted.contains("MEUCIQD"))
    }

    @Test("an app-specific password in Apple's xxxx-xxxx-xxxx-xxxx shape is removed")
    func appSpecificPassword() {
        let redacted = redactor.redact("using abcd-efgh-ijkl-mnop to sign in")
        #expect(!redacted.contains("abcd-efgh-ijkl-mnop"))
    }

    @Test("identifiers the design allows in a log survive: key ID, issuer ID, the .p8 path (not its contents)")
    func identifiersSurvive() {
        let text = "key ABC123DEFG issuer 69a6de80-1234-47e3-e053-5b8c7c11a4d1 file /Users/me/.appstoreconnect/private_keys/AuthKey_ABC123DEFG.p8 profile fleetwatch-notary team BNDA9Y6YV9"
        #expect(redactor.redact(text) == text)
    }

    @Test("literal secrets the caller knows are removed wherever they appear")
    func literalSecrets() throws {
        let redactor = try Redactor(.buildTool.adding(literalSecrets: ["s3cr3t-value", ""]))
        let redacted = redactor.redact("a s3cr3t-value b s3cr3t-value")
        #expect(redacted == "a [REDACTED] b [REDACTED]")
    }

    @Test("an argument following a secret-named flag is redacted in an argv, and the flag itself is kept")
    func argv() {
        let redacted = redactor.redactArguments(["notarytool", "store-credentials", "--password", "hunter2xyz", "--team-id", "BNDA9Y6YV9"])
        #expect(redacted == ["notarytool", "store-credentials", "--password", "[REDACTED]", "--team-id", "BNDA9Y6YV9"])
    }
}

/// Each defect found in `Redactor` by reading it (proposal section 3.3), with the input that exposed it.
@Suite("buildTool policy: fixed defects")
struct BuildToolFixedDefectTests {
    let redactor = Redactor.buildTool

    @Test("an opaque Bearer token is removed, not only a JWT-shaped one")
    func opaqueBearer() {
        let redacted = redactor.redact("Authorization: Bearer abc123XYZ.def-456_ghi sent")
        #expect(redacted == "Authorization: Bearer [REDACTED] sent")
    }

    @Test("a Bearer credential does not reach across a line break to eat the next line's first word")
    func bearerStaysOnItsLine() {
        let redacted = redactor.redact("Authorization: Bearer\nnext line")
        #expect(redacted == "Authorization: Bearer\nnext line")
    }

    @Test("hyphenated words of four letters are not taken for an app-specific password",
          arguments: ["some-test-case-name", "run some-test-case-name now", "build-with-more-care.log", "a-b-c-d-e-f"])
    func hyphenatedWordsSurvive(text: String) {
        #expect(redactor.redact(text) == text)
    }

    @Test("the four-by-four shape is removed when a credential word is nearby, before or after it",
          arguments: [
            "app-specific password: abcd-efgh-ijkl-mnop",
            "using abcd-efgh-ijkl-mnop to sign in",
            "APPLE_PASSWORD abcd-efgh-ijkl-mnop",
          ])
    func appSpecificPasswordWithContext(text: String) {
        #expect(!redactor.redact(text).contains("abcd-efgh-ijkl-mnop"))
    }

    @Test("a quoted value containing spaces is removed whole, including its tail",
          arguments: [
            (#"password: "hunter two""#, #"password: "[REDACTED]""#),
            (#"{"secret": "hunter two three"}"#, #"{"secret": "[REDACTED]"}"#),
            ("token='hunter two'", "token='[REDACTED]'"),
            (#"--password "hunter two" --team-id X"#, "--password [REDACTED] --team-id X"),
            (#"password: "unterminated hunter two"#, #"password: "[REDACTED]"#),
          ])
    func quotedValueWithSpaces(text: String, expected: String) {
        let redacted = redactor.redact(text)
        #expect(redacted == expected)
        #expect(!redacted.contains("two"))
    }

    @Test("overlapping and nested literal secrets leave no fragment, whatever their order",
          arguments: [
            (["abc", "abcdef"], "x [REDACTED]gh y"),
            (["abcdef", "abc"], "x [REDACTED]gh y"),
            (["cdefgh", "abcdef"], "x [REDACTED] y"),
            (["abcdef", "cdefgh"], "x [REDACTED] y"),
          ])
    func overlappingLiterals(secrets: [String], expected: String) throws {
        let redactor = try Redactor(.buildTool.adding(literalSecrets: secrets))
        #expect(redactor.redact("x abcdefgh y") == expected)
    }

    @Test("a literal secret that is a substring of the replacement token is removed and the result is stable")
    func literalInsideToken() throws {
        let redactor = try Redactor(.buildTool.adding(literalSecrets: ["RED", "ACT", "[", "]"]))
        let once = redactor.redact("the RED fox says ACT [now]")
        #expect(!once.contains("the RED") && !once.contains("says ACT"))
        #expect(redactor.redact(once) == once)
    }

    @Test("a literal secret is matched on its Unicode scalars, so a following combining mark does not hide it")
    func literalBeforeCombiningMark() throws {
        let redactor = try Redactor(.buildTool.adding(literalSecrets: ["hunter2"]))
        let redacted = redactor.redact("pw hunter2\u{301} end")
        #expect(!redacted.contains("hunter2"))
    }

    @Test("a many-block PEM capture with no END lines is linear, not quadratic, and is all removed")
    func manyTruncatedBlocks() {
        let text = String(repeating: "-----BEGIN PRIVATE KEY-----\nAAAA\n", count: 2_000)
        let redacted = redactor.redact(text)
        #expect(!redacted.contains("AAAA"))
    }

    @Test("a PEM block split across lines is removed line by line when lines are redacted separately")
    func pemAcrossLines() {
        let lines = ["before", "-----BEGIN PRIVATE KEY-----", "MIGTAgEAMBMG", "Zm9vYmFy", "-----END PRIVATE KEY----- tail", "after"]
        let out = redactor.redact(lines: lines)
        #expect(out.count == lines.count)
        #expect(out.joined(separator: "\n").contains("MIGTAgEAMBMG") == false)
        #expect(out.joined(separator: "\n").contains("Zm9vYmFy") == false)
        #expect(out.first == "before" && out.last == "after")
        #expect(out[4].hasSuffix("tail"))
    }

    @Test("a PEM block that begins on a line replaced for length still has its body lines removed")
    func pemBeginsOnOverlongLine() throws {
        let policy = try RedactionPolicy(rules: [.pemPrivateKey], style: .uniform, maxInputLength: 64, overlong: .replaceWhole("[too long]"))
        let redactor = try Redactor(policy)
        let lines = [String(repeating: "x", count: 80) + "-----BEGIN PRIVATE KEY-----", "BODYBODY", "-----END PRIVATE KEY-----", "after"]
        let out = redactor.redact(lines: lines)
        #expect(out == ["[too long]", "[REDACTED PRIVATE KEY]", "[REDACTED PRIVATE KEY]", "after"])
    }
}
