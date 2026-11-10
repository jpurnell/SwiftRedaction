import Foundation
import Testing
@testable import Redaction

/// The eleven tests of SwiftDiagnosticsHub's `LogScrubberTests`, ported with the same assertions (the scrubber is
/// `Redactor.appLog` here), followed by the behaviour this package adds.
@Suite("appLog policy: ported LogScrubberTests")
struct AppLogPortedTests {
    private let redactor = Redactor.appLog

    /// Whether redacting `line` leaves no trace of `secret`.
    private func removes(_ secret: String, from line: String) -> Bool {
        !redactor.redact(line).contains(secret)
    }

    @Test("A JWT is removed")
    func jwt() {
        let jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQ0QifQ.eyJpc3MiOiJURVNUMTIzIiwiaWF0IjoxNzAwMDAwMDAwfQ.MEUCIQDabcDEFghiJKLmnoPQRstuVWxyz"
        #expect(removes("eyJhbGci", from: "auth ok token=\(jwt) done"))
        #expect(removes("MEUCIQ", from: "auth ok token=\(jwt) done"))
    }

    @Test("A bearer credential is removed, keeping the surrounding words")
    func bearer() {
        let scrubbed = redactor.redact("request header Authorization: Bearer abc123XYZ.def-456_ghi sent")
        #expect(!scrubbed.contains("abc123XYZ"))
        #expect(scrubbed.hasPrefix("request header Authorization:"))
        #expect(scrubbed.hasSuffix("sent"))
    }

    @Test("Long hex runs and long base64 runs are removed")
    func longRuns() {
        #expect(removes("0123456789abcdef0123456789abcdef", from: "key 0123456789abcdef0123456789abcdef0123 end"))
        #expect(removes("QWxhZGRpbjpvcGVuIHNlc2FtZ", from: "blob QWxhZGRpbjpvcGVuIHNlc2FtZVRoaXNJc0Fsb25nQmFzZTY0U3RyaW5nMTIzNDU2 end"))
    }

    @Test("An email address is removed")
    func email() {
        #expect(removes("justin.purnell", from: "sign in as justin.purnell+beta@example.co.uk failed"))
        #expect(removes("example.co.uk", from: "sign in as justin.purnell+beta@example.co.uk failed"))
    }

    @Test("Home-folder paths lose the account name, and keep the rest of the line")
    func homePaths() {
        #expect(removes("jpurnell", from: "open /Users/jpurnell/Library/Caches/x.db"))
        #expect(removes("Containers", from: "open /var/mobile/Containers/Data/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Library/log.txt"))
        #expect(removes("alice", from: "open /home/alice/.config/app"))
        #expect(redactor.redact("open /Users/jpurnell/x").hasPrefix("open "))
    }

    @Test("Apple Music and MusicKit identifiers and user tokens are removed")
    func musicIdentifiers() {
        #expect(removes("AqWeRtYuIo", from: "Music-User-Token: AqWeRtYuIoPaSdFgHjKlZxCvBnM1234567890"))
        #expect(removes("short", from: "music-user-token=short"))
        #expect(removes("abc.def.ghi", from: "developer token = abc.def.ghi"))
        #expect(removes("i.AbCdEf123456", from: "saved library song i.AbCdEf123456 to playlist"))
        #expect(removes("pl.u-8aAVxxJtEdpkDq9", from: "added to pl.u-8aAVxxJtEdpkDq9"))
        #expect(removes("p.XyZ12345678", from: "playlist p.XyZ12345678"))
    }

    @Test("A UUID-looking installation ID is removed")
    func uuid() {
        #expect(removes("6F9619FF", from: "installation 6F9619FF-8B86-D011-B42D-00C04FC964FF registered"))
        #expect(removes("6f9619ff", from: "id 6f9619ff-8b86-d011-b42d-00c04fc964ff"))
    }

    @Test("IPv4 and IPv6 addresses are removed")
    func addresses() {
        #expect(removes("192.168.1.42", from: "connected to 192.168.1.42:8080"))
        #expect(removes("10.0.1.114", from: "peer 10.0.1.114 reset"))
        #expect(removes("2001:0db8", from: "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 reset"))
        #expect(removes("2001:db8", from: "peer 2001:db8::8a2e:370:7334 reset"))
        #expect(removes("::1", from: "loopback ::1 up"))
        #expect(removes("fe80", from: "link fe80::1ff:fe23:4567:890a up"))
    }

    @Test("Ordinary log lines are left exactly as they were")
    func ordinaryLinesSurvive() {
        let lines = [
            "2026-11-09T16:20:31.123Z [Playback] stream started",
            "12:34:56 [Archive] loaded show The Morning Show with John Richards",
            "[Network] GET https://kexp.org/archive/shows/The-Morning-Show-with-John-Richards-2026-11-09 -> 200",
            "[Intent] PlayLiveStreamIntent finished in 0.42s",
            "build 3.4.0 (57) on iOS 27.2 iPhone",
            "buffer underrun: 3 frames dropped, retrying in 2s",
            "Spinner::AudioEngine restart requested",
            "",
        ]
        for line in lines {
            #expect(redactor.redact(line) == line, "changed: \(line)")
        }
    }

    @Test("Scrubbing twice gives what scrubbing once did")
    func idempotent() {
        let line = "u /Users/jpurnell/x a@b.com 10.0.0.1 6F9619FF-8B86-D011-B42D-00C04FC964FF Bearer abcdef123456"
        let once = redactor.redact(line)
        #expect(redactor.redact(once) == once)
    }

    @Test("Every pattern compiles, so a typo cannot silently turn a category off")
    func patternsCompile() {
        let enabled = RedactionPolicy.appLog.rules.compactMap { RuleCatalogue.rule($0) }
        #expect(enabled.count == RedactionPolicy.appLog.rules.count)
        #expect(enabled.filter(\.isOperational).count == enabled.count)
    }

    @Test("A very long line is replaced, not passed through: it could hold anything and would be slow to search")
    func overlongLineFailsClosed() {
        let long = String(repeating: "a", count: RedactionPolicy.appLog.maxInputLength + 1) + " password hunter2"
        let scrubbed = redactor.redact(long)
        #expect(scrubbed == RedactionPolicy.appLog.overlongPlaceholder)
        #expect(scrubbed == "[line too long, removed]")
        #expect(!scrubbed.contains("hunter2"))
    }

    @Test("A line at the limit is still scrubbed normally")
    func lineAtLimit() {
        let padding = String(repeating: "x", count: RedactionPolicy.appLog.maxInputLength - 40)
        let scrubbed = redactor.redact("\(padding) mail bob@example.com")
        #expect(scrubbed.hasSuffix("mail [email]"))
    }

    @Test("An email's local part is bounded, which is what keeps the search linear")
    func emailLocalPartIsBounded() {
        let scrubbed = redactor.redact(String(repeating: "z", count: 65) + "@example.com")
        #expect(scrubbed == "z[email]")
    }
}

@Suite("appLog policy: added behaviour")
struct AppLogAddedBehaviourTests {
    private let redactor = Redactor.appLog

    @Test("typed replacements name what was removed",
          arguments: [
            ("peer 10.0.1.114 reset", "peer [ip] reset"),
            ("sign in as bob@example.com failed", "sign in as [email] failed"),
            ("id 6f9619ff-8b86-d011-b42d-00c04fc964ff", "id [uuid]"),
            ("open /Users/jpurnell/x", "open /Users/[user]/x"),
            ("open /home/alice/x", "open /home/[user]/x"),
            ("open /var/mobile/Containers/x", "open /var/mobile/[path]"),
            ("Music-User-Token: abc", "Music-User-Token=[token]"),
            ("Authorization: Bearer abc123", "Authorization: Bearer [token]"),
            ("saved i.AbCdEf123456", "saved [music-id]"),
            ("key 0123456789abcdef0123456789abcdef0123", "key [hex]"),
            ("loopback ::1 up", "loopback [ip] up"),
          ])
    func typedForms(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a key=value secret is removed from an app log, accepting that it also hits harmless text",
          arguments: [
            ("password=hunter2", "password=[secret]"),
            ("api_key: short and token=abc123", "api_key: short and token=[secret]"),
            ("secret: \"two words\"", "secret: \"[secret]\""),
            ("token: expired", "token: [secret]"),
          ])
    func keyValue(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a 40-digit git SHA survives, shorter and longer hex runs do not")
    func gitSHA() {
        let sha = "5cd503b1f0a2c9e8d7b6a5f4e3d2c1b0a9f8e7d6"
        #expect(sha.count == 40)
        #expect(redactor.redact("commit \(sha) built") == "commit \(sha) built")
        #expect(redactor.redact("key \(sha)a") == "key [hex]")
        #expect(redactor.redact("key \(String(sha.dropLast()))") == "key [hex]")
        #expect(redactor.redact("sha256 \(sha)\(sha.prefix(24))") == "sha256 [hex]")
        #expect(redactor.redact("md5 \(sha.prefix(32))") == "md5 [hex]")
    }

    @Test("the two policies provably differ on the identifiers line: buildTool keeps it, appLog removes the UUID and the home path")
    func policiesDiffer() {
        let text = "key ABC123DEFG issuer 69a6de80-1234-47e3-e053-5b8c7c11a4d1 file /Users/me/.appstoreconnect/private_keys/AuthKey_ABC123DEFG.p8 profile fleetwatch-notary team BNDA9Y6YV9"
        #expect(Redactor.buildTool.redact(text) == text)
        let scrubbed = Redactor.appLog.redact(text)
        #expect(!scrubbed.contains("69a6de80") && !scrubbed.contains("/Users/me"))
    }

    @Test("a log line expanding past the cap when redacted is replaced, so redacting twice cannot differ")
    func expansionFailsClosed() {
        let line = String(repeating: "a@b.cc ", count: 585)
        #expect(line.utf8.count <= RedactionPolicy.appLog.maxInputLength)
        let report = redactor.report(line)
        #expect(report.overlong)
        #expect(report.output == RedactionPolicy.appLog.overlongPlaceholder)
        #expect(redactor.redact(report.output) == report.output)
    }

    @Test("a PEM block is removed from an app log too")
    func pem() {
        #expect(!redactor.redact("-----BEGIN PRIVATE KEY-----\nAAAABBBB").contains("AAAABBBB"))
    }
}
