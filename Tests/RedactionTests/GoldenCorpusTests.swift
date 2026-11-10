import Foundation
import Testing
@testable import Redaction

/// Realistic ordinary lines that no shipped policy may change. A rule loosened until it eats these fails here.
@Suite("golden corpus: ordinary lines pass through unchanged")
struct GoldenCorpusTests {
    static let ordinaryLines = [
        // The eight lines of the old LogScrubber corpus.
        "2026-11-09T16:20:31.123Z [Playback] stream started",
        "12:34:56 [Archive] loaded show The Morning Show with John Richards",
        "[Network] GET https://kexp.org/archive/shows/The-Morning-Show-with-John-Richards-2026-11-09 -> 200",
        "[Intent] PlayLiveStreamIntent finished in 0.42s",
        "build 3.4.0 (57) on iOS 27.2 iPhone",
        "buffer underrun: 3 frames dropped, retrying in 2s",
        "Spinner::AudioEngine restart requested",
        "",
        // Build output.
        "Compiling Redaction Redactor.swift",
        "[19 / 28] RedactionTestSupport",
        "Build complete! (2.65 sec)",
        "Test run with 26 tests in 3 suites passed after 0.029 seconds.",
        "Executed 0 tests, with 0 failures (0 unexpected) in 0.000 (0.001) seconds",
        "warning: variable 'x' was never mutated; consider changing to 'let' constant",
        "/Library/Developer/CommandLineTools/usr/bin/swift-build --package-path /opt/work",
        // Test and case names, slugs, hyphenated words.
        "Test case 'RedactorTests.testSomeTestCaseName' passed (0.001 seconds)",
        "running some-test-case-name for the build-with-more-care run",
        "profile fleetwatch-notary uploaded",
        // Git.
        "commit 5cd503b1f0a2c9e8d7b6a5f4e3d2c1b0a9f8e7d6",
        "HEAD is now at 69ee7b8 Core engine, rule catalogue",
        // Swift identifiers and URLs.
        "Redactor.process(_:) returned in 3ms",
        "calling LiteralSecrets.redact with 2 literals",
        "GET https://api.example.com/v1/shows?limit=20&offset=40 200",
        "see https://github.com/jpurnell/SwiftRedaction/blob/main/README.md",
        // Words near the rules' keywords that are not credentials.
        "the tokens=5 counter and passwordless login flow",
        "user token count 3",
    ]

    @Test("a line a person would write is left alone by both policies", arguments: ordinaryLines)
    func survives(line: String) {
        #expect(Redactor.buildTool.redact(line) == line, "buildTool changed: \(line)")
        #expect(Redactor.appLog.redact(line) == line, "appLog changed: \(line)")
    }

    @Test("the stated trade-offs of appLog, pinned so they are decisions and not accidents")
    func tradeOffs() {
        // A word of the shape `x.AbCdEf123` after one of i, l, p is taken for a MusicKit id (known false positive).
        #expect(Redactor.appLog.redact("calling p.sharedInstance now") == "calling [music-id] now")
        // The word after `Bearer` is taken for the credential, whatever it is.
        #expect(Redactor.appLog.redact("Bearer of bad news") == "Bearer [token] bad news")
        // A long CamelCase identifier containing a digit is taken for base64.
        let mangled = "SwiftUIViewModifierContainerWithStateV2ForPlaybackScreen"
        #expect(Redactor.appLog.redact("type \(mangled)") == "type [token]")
    }
}
