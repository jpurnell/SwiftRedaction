import Foundation
@testable import Redaction

/// One fixture of one rule: an input, and either what must not survive it (a positive fixture) or nothing (a negative
/// fixture, which the rule must leave exactly as it was). Fixtures are synthetic; no real credential is committed.
struct RuleFixture: Sendable, CustomStringConvertible {
    let rule: RuleID
    let input: String
    /// Substrings that must be absent from the output. Empty means the input must survive unchanged.
    let mustNotSurvive: [String]

    var description: String { "\(rule): \(input.prefix(60))" }

    var isNegative: Bool { mustNotSurvive.isEmpty }
}

/// The reference fixtures, one table for every rule. Each rule needs at least one positive and one negative.
///
/// Sources of the formats: JWT RFC 7519 section 3 (three base64url segments); PEM RFC 7468 (`-----BEGIN ... -----`);
/// email RFC 5321 length limits (64 local part, 255 domain); UUID RFC 4122; IPv4 and IPv6 RFC 4291 text forms; Apple's
/// `xxxx-xxxx-xxxx-xxxx` app-specific password shape, taken from the existing code (Apple's page was not re-checked).
enum RuleFixtures {
    static let jwtFixture = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQ0QifQ.eyJpc3MiOiJURVNUMTIzIiwiaWF0IjoxNzAwMDAwMDAwfQ.MEUCIQDabcDEFghiJKLmnoPQRstuVWxyz"

    static let all: [RuleFixture] = [
        // pemPrivateKey
        RuleFixture(rule: .pemPrivateKey, input: "k\n-----BEGIN PRIVATE KEY-----\nAAAABBBB\n-----END PRIVATE KEY-----\nz", mustNotSurvive: ["AAAABBBB"]),
        RuleFixture(rule: .pemPrivateKey, input: "-----BEGIN EC PRIVATE KEY-----\nCCCCDDDD", mustNotSurvive: ["CCCCDDDD"]),
        RuleFixture(rule: .pemPrivateKey, input: "-----BEGIN CERTIFICATE-----\nAAAABBBB\n-----END CERTIFICATE-----", mustNotSurvive: []),
        // jwt
        RuleFixture(rule: .jwt, input: "auth \(jwtFixture) ok", mustNotSurvive: ["eyJhbGci", "MEUCIQ"]),
        RuleFixture(rule: .jwt, input: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.MEUCIQDabcdef", mustNotSurvive: ["MEUCIQD"]),
        RuleFixture(rule: .jwt, input: "eyJ.a.b and eyJabc", mustNotSurvive: []),
        // bearer
        RuleFixture(rule: .bearer, input: "Authorization: Bearer abc123XYZ.def-456_ghi sent", mustNotSurvive: ["abc123XYZ"]),
        RuleFixture(rule: .bearer, input: "authorization: bearer abc123", mustNotSurvive: ["abc123"]),
        RuleFixture(rule: .bearer, input: "Authorization: Bearer\nabc123", mustNotSurvive: []),
        // appleMusicToken
        RuleFixture(rule: .appleMusicToken, input: "Music-User-Token: AqWeRtYuIoPaSdFg", mustNotSurvive: ["AqWeRtYuIo"]),
        RuleFixture(rule: .appleMusicToken, input: "developer token = abc.def.ghi", mustNotSurvive: ["abc.def.ghi"]),
        RuleFixture(rule: .appleMusicToken, input: "user token count: 3", mustNotSurvive: []),
        // secretFlag
        RuleFixture(rule: .secretFlag, input: "notarytool --password hunter2xyz store", mustNotSurvive: ["hunter2xyz"]),
        RuleFixture(rule: .secretFlag, input: "--api-secret=hunter2xyz", mustNotSurvive: ["hunter2xyz"]),
        RuleFixture(rule: .secretFlag, input: #"--password "hunter two" --team-id X"#, mustNotSurvive: ["hunter", "two"]),
        RuleFixture(rule: .secretFlag, input: "some-token x and --team-id ABC", mustNotSurvive: []),
        // secretAssignment
        RuleFixture(rule: .secretAssignment, input: "password=hunter2xyz", mustNotSurvive: ["hunter2xyz"]),
        RuleFixture(rule: .secretAssignment, input: #"{"password": "hunter two"}"#, mustNotSurvive: ["hunter", "two"]),
        RuleFixture(rule: .secretAssignment, input: "NOTARY_PASSWORD=hunter2xyz", mustNotSurvive: ["hunter2xyz"]),
        RuleFixture(rule: .secretAssignment, input: "tokens=5 passwordless: true", mustNotSurvive: []),
        RuleFixture(rule: .secretAssignment, input: "api_key=hunter2xyz", mustNotSurvive: ["hunter2xyz"]),
        RuleFixture(rule: .secretAssignment, input: "capital_key=hunter2xyz keyboard=us", mustNotSurvive: []),
        // appSpecificPassword (the default context needs a credential word)
        RuleFixture(rule: .appSpecificPassword, input: "app-specific password: abcd-efgh-ijkl-mnop", mustNotSurvive: ["abcd-efgh-ijkl-mnop"]),
        RuleFixture(rule: .appSpecificPassword, input: "some-test-case-name abcd-efgh-ijkl-mnop-qrst", mustNotSurvive: []),
        // uuid
        RuleFixture(rule: .uuid, input: "installation 6F9619FF-8B86-D011-B42D-00C04FC964FF registered", mustNotSurvive: ["6F9619FF"]),
        RuleFixture(rule: .uuid, input: "id 6f9619ff-8b86-d011-b42d-00c04fc964ff", mustNotSurvive: ["6f9619ff"]),
        RuleFixture(rule: .uuid, input: "6F9619FF-8B86-D011-B42D and 6F9619FF-8B86-D011-B42D-00C04FC964FF0", mustNotSurvive: []),
        // longHex
        RuleFixture(rule: .longHex, input: "key 0123456789abcdef0123456789abcdef0123 end", mustNotSurvive: ["0123456789abcdef0123456789abcdef"]),
        RuleFixture(rule: .longHex, input: "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", mustNotSurvive: ["e3b0c44298fc"]),
        RuleFixture(rule: .longHex, input: "commit 5cd503b1f0a2c9e8d7b6a5f4e3d2c1b0a9f8e7d6 and 0123456789abcdef", mustNotSurvive: []),
        // longBase64
        RuleFixture(rule: .longBase64, input: "blob QWxhZGRpbjpvcGVuIHNlc2FtZVRoaXNJc0Fsb25nQmFzZTY0U3RyaW5nMTIzNDU2 end", mustNotSurvive: ["QWxhZGRpbjpvcGVuIHNlc2FtZ"]),
        RuleFixture(rule: .longBase64, input: "slug the-morning-show-with-john-richards-2026-11-09-archive-copy and QWxhZGRpbjpvcGVu", mustNotSurvive: []),
        // email
        RuleFixture(rule: .email, input: "sign in as justin.purnell+beta@example.co.uk failed", mustNotSurvive: ["justin.purnell", "example.co.uk"]),
        RuleFixture(rule: .email, input: "write to @handle or a@b or user@localhost", mustNotSurvive: []),
        // homePath
        RuleFixture(rule: .homePath, input: "open /Users/jpurnell/Library/Caches/x.db", mustNotSurvive: ["jpurnell"]),
        RuleFixture(rule: .homePath, input: "open /home/alice/.config/app", mustNotSurvive: ["alice"]),
        RuleFixture(rule: .homePath, input: "open /var/mobile/Containers/Data/x.txt", mustNotSurvive: ["Containers"]),
        RuleFixture(rule: .homePath, input: "open /usr/local/bin/tool and /Library/Caches", mustNotSurvive: []),
        // musicID
        RuleFixture(rule: .musicID, input: "saved library song i.AbCdEf123456 to playlist", mustNotSurvive: ["i.AbCdEf123456"]),
        RuleFixture(rule: .musicID, input: "added to pl.u-8aAVxxJtEdpkDq9", mustNotSurvive: ["pl.u-8aAVxxJtEdpkDq9"]),
        RuleFixture(rule: .musicID, input: "playlist p.XyZ12345678", mustNotSurvive: ["p.XyZ12345678"]),
        RuleFixture(rule: .musicID, input: "x.AbCdEf123456 and i.short", mustNotSurvive: []),
        // ipv4
        RuleFixture(rule: .ipv4, input: "connected to 192.168.1.42:8080", mustNotSurvive: ["192.168.1.42"]),
        RuleFixture(rule: .ipv4, input: "peer 10.0.1.114 reset", mustNotSurvive: ["10.0.1.114"]),
        RuleFixture(rule: .ipv4, input: "version 3.4.0 and 999.1.1.1 and 1.2.3", mustNotSurvive: []),
        // ipv6
        RuleFixture(rule: .ipv6, input: "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 reset", mustNotSurvive: ["2001:0db8"]),
        RuleFixture(rule: .ipv6, input: "peer 2001:db8::8a2e:370:7334 reset", mustNotSurvive: ["2001:db8"]),
        RuleFixture(rule: .ipv6, input: "loopback ::1 up", mustNotSurvive: ["::1"]),
        RuleFixture(rule: .ipv6, input: "link fe80::1ff:fe23:4567:890a up", mustNotSurvive: ["fe80"]),
        RuleFixture(rule: .ipv6, input: "at 12:34:56 in Spinner::AudioEngine", mustNotSurvive: []),
    ]
}
