# SwiftRedaction

One Foundation-only Swift package that removes secret-shaped and personal-looking text from strings. Named, individually
tested rules; two shipped policies; a report that counts what fired and never contains the secret; and a test-support
product that proves a secret reached no string, file, `Data` or error rendering.

**Status:** 0.1.1, released 2026-11-10 (0.1.0 on 2026-11-09). Not yet adopted by SwiftReleaseKit or SwiftDiagnosticsHub.
**Platforms:** iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1. The core is Foundation-only and intended to build on
Linux; **Linux is unverified** (no Linux host yet; the geo-audit host on fly.io is a candidate). Built and tested here on
macOS 27 with Swift 6.4.2 (the package declares tools-version 6.2). It has not been built for the iOS, watchOS, tvOS or
visionOS destinations.

## Read this first: defense in depth

A scrubber works by **shape**. It cannot remove a secret that has no recognisable shape, cannot know what is personal,
removes only what it recognises today, and is never the privacy control: that is not logging the secret, enforced by types
(in SwiftDiagnosticsHub, a log chunk is only accepted for TestFlight, events are schema-registered, and a free-text
field is refused on the same terms). A false positive is a cost, a false negative is a leak, and the defaults favour removal.
The DocC article `WhatRedactionCannotDo` states the five limits; read it before relying on this package.

## Use

```swift
import Redaction

let log = Redactor.appLog
log.redact("peer 10.0.1.114 reset")                    // "peer [ip] reset"
log.report("peer 10.0.1.114 mail a@b.com").fired       // [.ipv4: 1, .email: 1]  (counts only)

let build = try Redactor(.buildTool.adding(literalSecrets: [notaryPassword]))
build.redactArguments(["notarytool", "--password", notaryPassword])   // ["notarytool", "--password", "[REDACTED]"]
```

```swift
// In a test target (product RedactionTestSupport, which imports Testing):
let secret = Secret(label: "notary password", value: notaryPassword)
expectNoLeaks(of: [secret], in: [runLog, terminalOutput])
expectNoLeaks(of: [secret], inRenderingsOf: someError)
```

Add the package by git URL (the owner's convention between packages), once it has a remote:
`.package(url: "https://github.com/jpurnell/SwiftRedaction.git", from: "0.1.1")`. An app links `Redaction`; only test
targets link `RedactionTestSupport`.

## The rule catalogue

Rules run in this order; **the order is the algorithm**. A policy names a set of rules, never their order. This table is
checked against the catalogue by a test, so it cannot drift.

| Rule | `.buildTool` | `.appLog` | What it removes |
|---|---|---|---|
| `literalSecret` | yes | no | Strings the caller names (a password it holds, a token it just minted), removed wherever they appear. |
| `pemPrivateKey` | yes | yes | A PEM private-key block, whole or cut off before its END line. |
| `jwt` | yes | yes | A JSON Web Token, such as an App Store Connect API token. |
| `bearer` | yes | yes | An opaque Bearer credential. |
| `appleMusicToken` | no | yes | A labelled Apple Music user or developer token. |
| `secretFlag` | yes | no | A password, secret or token given as a command-line flag. |
| `secretAssignment` | yes | yes | A password, secret, token or API key (`api_key`, `api-key`, `apikey`, `x-api-key`) given as name=value, name: value or JSON. |
| `appSpecificPassword` | yes | no | An Apple app-specific password, xxxx-xxxx-xxxx-xxxx. |
| `uuid` | no | yes | A UUID, such as an installation ID. |
| `longHex` | no | yes | A long hexadecimal run (keys, digests), except a 40-digit git SHA. |
| `longBase64` | no | yes | A long mixed-case base64 run. |
| `email` | no | yes | An email address. |
| `homePath` | no | yes | A home-folder path: /Users, /home, /var/mobile. |
| `musicID` | no | yes | An Apple Music or MusicKit library, playlist or catalog identifier. |
| `ipv4` | no | yes | An IPv4 address. |
| `ipv6` | no | yes | An IPv6 address. |

Also not in either policy: nothing. Every rule above is in at least one policy. (The proposal's `apiKeyPrefix(prefix:)`
rule, a per-project prefix such as `bm_`, was not built in this release.)

## The two policies

| | `.buildTool` | `.appLog` |
|---|---|---|
| For | captured `xcodebuild` / `notarytool` output | app log lines before a TestFlight upload |
| Style | `[REDACTED]` | typed: `[token]`, `[ip]`, `[uuid]`, `[email]`... |
| Input cap | 8 MiB (a captured log) | 4,096 UTF-8 bytes (a line) |
| Over the cap | replaced by `[output too long, removed]` | replaced by `[line too long, removed]` |
| Keeps on purpose | key IDs, issuer UUIDs, team IDs, profile names, `.p8` **paths** | a 40-digit git SHA |
| `key=value` secrets | yes (and flags) | yes, accepting harmless hits such as `token: expired` |
| App-specific password | yes, with a credential word nearby (setting) | no |

## How it fails

- **Closed.** An input over the cap is replaced, never passed through; an output that grows past the cap is replaced too
  (4,096 bytes of `a@b.cc ` becomes longer as `[email]`), so redacting twice cannot differ from redacting once. A rule
  that did not compile makes the redactor replace every input rather than skip the rule; the catalogue test fails first.
- **Deterministic and idempotent.** The engine applies the rules in passes until a pass changes nothing, so the result is
  a fixed point: `redact(redact(x)) == redact(x)`. The policy initialiser also refuses a replacement token that its own
  rules would change. A text that has not settled after 8 passes is replaced whole (never seen in the property tests).
- **Report without leakage.** `report(x).output == redact(x)` (one code path); `fired` holds counts only, no text, no offsets.

## Choosing the engine: measurements

Swift Regex (owner decision 2) is the engine; each pattern is compiled once, behind an internal `PatternMatcher` protocol
so a rule can move to `NSRegularExpression` or a hand-written scanner. The same rule patterns were run on both engines,
each rule alone on pathological inputs of 16, 32, 64 and 128 KiB: a run of email characters with no `@`, random base64,
long hex runs with and without a near-miss suffix, `eyJ` repeated, a PEM header repeated with and without END,
`Bearer `, `--token `, `password=` and unterminated quotes repeated, runs of hyphens, colons and dots, and so on (34 inputs
per rule; the harness was a throwaway script outside the repository, and the same cases run as non-timed tests in
`AdversarialInputTests`). Best of 3 runs, `-O`, macOS 27 on arm64.

**The machine was heavily loaded while these were taken (load average 100 to 280), so absolute times are inflated several
fold. Read the growth, not the milliseconds.** The tests assert no time bound; the gate forbids wall-clock assertions.

| Rule | Swift Regex worst 64 KB (ms) | worst case | growth 64->128 KB | ICU worst 64 KB (ms) | worst case | growth 64->128 KB |
|---|---|---|---|---|---|---|
| `pemPrivateKey` | 30 | BEGIN PRIVATE KEY, no END | 8.7x | 7 | BEGIN PRIVATE KEY, no END | n/a (<20 ms) |
| `bearer` | 29 | Bearer x n | 2.7x | 7 | a@b.c.d.e.. dots | n/a (<20 ms) |
| `appleMusicToken` | 40 | a-a-a- x n | 3.6x | 6 | BEGIN PRIVATE KEY, no END | n/a (<20 ms) |
| `secretFlag` | 350 | -- + hyphens | 2.4x | 23 | -- + hyphens | 2.0x |
| `secretAssignment` | 65 | hex 16 x n | 4.5x | 8 | password=" unterminated x n | n/a (<20 ms) |
| `appSpecificPassword` | 503 | abcd-efgh-ijkl-mnop x n | 1.6x | 380 | abcd-efgh-ijkl-mnop x n | 2.0x |
| `uuid` | 18 | a@ x n | n/a (<20 ms) | 8 | hex run | n/a (<20 ms) |
| `longHex` | 28 | a@ x n | 2.9x | 10 | hex run + g | n/a (<20 ms) |
| `longBase64` | 41 | token + spaces | 3.1x | 10 | BEGIN PRIVATE KEY, no END | n/a (<20 ms) |
| `email` | 735 | a x n | 3.8x | 2391 | 1.1.1.1. x n | 4.2x |
| `homePath` | 69 | a x n | 2.4x | 6 | BEGIN PRIVATE KEY, no END | n/a (<20 ms) |
| `musicID` | 149 | colons | 4.6x | 6 | BEGIN PRIVATE KEY, no END | n/a (<20 ms) |
| `ipv4` | 73 | /Users/ x n | 7.6x | 8 | 1.1.1.1. x n | n/a (<20 ms) |
| `ipv6` | 156 | -- + hyphens | 8.2x | 79 | a@ x n | 4.9x |
| `jwt` (hand-written scanner, 0.1.1; the regex it replaced is described below) | 0.5 | eyJaaaaaa. x n | n/a (<20 ms) | same scanner on both | - | - |

(Growth is shown only where the 64 KiB run took at least 20 ms, so small-number noise is not reported as a trend; values
above 2.0x with large-sample noise were re-measured at 32 to 256 KiB with the best of 7 runs, and all came out between 1.2x
and 2.7x per doubling: **no rule is super-linear under Swift Regex**, except the one below, which was changed.)

What the measurement found and what was chosen because of it:

1. **`jwt` was quadratic under Swift Regex**, as unanchored `eyJ[A-Za-z0-9_-]{5,}...` on `eyJeyJeyJ...`: 16,384 bytes took
   3.9 s and 32,768 took 17 s. Bounding the first segment at 512 characters made it linear but 2.1 s for 64 KiB (about 200 ns
   per step). 0.1.0 therefore required the token to start a word (the preceding character consumed in a capture group; 64 KiB
   about 10 ms), which left a token glued to letters or digits (`mytokeneyJ...`, `id-eyJ...`) unrecognised: a leak. **0.1.1
   replaces the pattern with a hand-written scanner** (`JWTScanner`, behind the same `PatternMatcher` protocol) that finds the
   token wherever it starts. It makes one pass; after a failed attempt it skips the whole run of base64url characters it
   read (a start inside that run would fail the same way), and after a match it continues past the token, so no byte is read
   by two attempts. The test suite asserts that on the scanner's step count (at most three reads per byte, and doubling the
   input at most doubles the steps), which does not depend on the machine. Measured best-of-7, `-O`, with the same harness
   (`project/docs/technical/measure-engines.swift.txt`, 11 shapes of `eyJ` among them, on a machine with a load average of
   about 370, so read the growth): 32 / 64 / 128 / 256 KiB took 0.1 / 0.2 / 0.3 / 0.6 ms on the cheap shapes and, on the
   worst shape (`eyJaaaaaa.` repeated, which matches), 0.2 / 0.5 / 0.9 / 1.9 ms. Every shape roughly doubles per doubling.
   Observation only: no time bound is asserted.
2. **Swift Regex has no lookbehind** (`lookbehind is not currently supported`, measured on this toolchain). Every pattern that
   needed one (`longBase64`, the three IPv6 forms, `jwt`, the flag and 4-4-4-4 rules) consumes the character in front in
   group 1 and writes it back. This also makes those rules linear: a run is attempted once, from its start.
3. **The email rule is bounded** in every part (64, 63 x 9, 24), which the owner's earlier measurement showed is what keeps
   ICU linear (unbounded, 20,000 characters took 5.9 s). With the bound, Swift Regex is about 2 to 3 times *faster* than ICU on
   the worst email inputs here (470 ms against 1,275 ms at 128 KiB; both linear).
4. **Other rules: ICU is faster by a constant factor of roughly 3 to 40 on most** (for example 13 ms against 88 ms on a
   64 KiB PEM header run). Both are linear. The cost that matters is the one at the cap: with all of `.appLog`'s rules run on
   the 34 pathological inputs at 4,096 bytes, the worst took 70 ms (a run of `a-a-a-`; the next worst 25 ms) on the loaded
   machine, and an ordinary line takes microseconds. `.buildTool` takes 0.3 to 7 s per MiB on these inputs (the worst, repeated
   `abcd-efgh-ijkl-mnop `, 7 s before the credential-word check stopped allocating a string per match); its input is a captured
   log, not attacker-controlled, so 8 MiB is a ceiling and the numbers above are the worst case, not a typical log.
5. **Decision:** keep Swift Regex. No rule is super-linear, the length cap bounds the absolute cost, the engine is the one the owner
   prefers, and the protocol keeps ICU one `ICUMatcher` away (it exists in the test target for the comparison tests and the
   equivalence test). If a measured line budget is later tighter than about 70 ms per 4 KiB crafted line, move the PEM, flag and
   assignment rules first.

Not measured: Linux (no host), and iOS devices.

## The app-specific-password rule (4-4-4-4): measured false positives and the default

The rule's shape, four lowercase four-letter words joined by hyphens, is also what a test name or slug looks like
(`some-test-case-name`). The old `Redactor` removed every match. The context the rule needs is the policy setting
`RedactionPolicy.AppSpecificPasswordContext`: `.anywhere`, or `.requiresCredentialWord` (a word such as `password`,
`app-specific` or `sign in` on the same line, within 80 bytes).

Measured on 2026-11-09 with a throwaway script (the strict shape: not glued to more letters, digits or hyphens):

- **1,208,470,112 bytes of real build logs**: all 2,624 `.xcactivitylog` files in this machine's Xcode DerivedData (the
  captured output of the owner's own builds). **0 matches.**
- **4,599,714,562 bytes of text** in 135,940 files (`.md`, `.swift`, `.json`, `.yml`, `.log`, `.sh` and similar) across the owner's
  `Tools`, `KEXPPower` and `WineTaster 4` trees: 37 matches, **every one in this package's own fixtures and docs** (`abcd-efgh-ijkl-mnop`,
  `xxxx-xxxx-xxxx-xxxx`, `some-test-case-name`).
- No real `notarytool` output was available to test on, and an app-specific password was not found anywhere.

So the false-positive rate on real build logs is, on this evidence, approximately zero with either setting, and the measurement
does not by itself prefer one. **Default chosen: `.requiresCredentialWord` for `.buildTool`**, because it removes the known
false-positive class the owner listed (a test name or slug of four four-letter words) and the measured cost of the
trade is a bare password with no credential word within 80 bytes on its line passing through, which notarytool is believed to prompt
for rather than print (*unverified*). Callers who would rather fail closed set `.anywhere`; the numbers above say that would cost
nothing in the logs measured.

## Migration guide (not done in this release)

**SwiftReleaseKit** keeps a roughly ten-line wrapper so `RunDiagnostics`, `ReleasePipeline` and any caller do not change, and the
wrapper is removed in a later release:

```swift
public struct Redactor: Sendable, Equatable {
    // keep the old public constants (the replacement text) as they are
    private let inner: Redaction.Redactor
    public init(secrets: [String] = []) {
        // Cannot throw: if a rule failed to compile it would replace every input (fail closed), which a SwiftRedaction test rules out.
        inner = Redaction.Redactor(failClosed: .buildTool.adding(literalSecrets: secrets))
    }
    public func redact(_ text: String) -> String { inner.redact(text) }
    public func redactArguments(_ arguments: [String]) -> [String] { inner.redactArguments(arguments) }
}
```

(This repository does not touch SwiftReleaseKit.) Acceptance: its `RedactorTests` pass unchanged against the
wrapper; they are ported here as `BuildToolPortedTests`. Two things to handle: output over 8 MiB is replaced whole, so pass
`redact(lines:)` or split captured output; and `.buildTool` now also removes opaque `Bearer` tokens.

**SwiftDiagnosticsHub** keeps `public enum LogScrubber { static func scrub(_ line: String) -> String }` as a one-line forward to
`Redactor.appLog.redact`, so `DiagnosticsUploader` is unchanged, and removes the rules, compilation and the
`declaredRuleCount` / `compiledRuleCount` hooks (the catalogue test `everyPatternCompiles` replaces them). `maxLineLength` and
`overlongPlaceholder` become `RedactionPolicy.appLog.maxInputLength` and `.overlongPlaceholder`. Run `LogScrubberTests` against the
forward (ported here as `AppLogPortedTests`) and a golden comparison of old and new output on a fixed corpus before deleting
the old code; the intended differences are in the CHANGELOG.

## Documentation

DocC: `swift package generate-documentation --target Redaction`. Articles: `WhatRedactionCannotDo`, `ChoosingAPolicy`.
Design: `project/plans/proposals/SwiftRedaction.md` (decisions of 2026-11-09 win over its body). Plan: `project/master_plan.md`.
