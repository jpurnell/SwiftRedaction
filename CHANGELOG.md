# Changelog

All notable changes to SwiftRedaction are recorded here. The format follows Keep a Changelog; the package follows
semantic versioning, pre-1.0 (a minor version may break source).

## [Unreleased]

First release, 0.1.0. Nothing is tagged and there is no remote yet.

### Added

- `Redactor`, built from a `RedactionPolicy`: `redact(_:)`, `redact(lines:)` (carries a PEM block across lines),
  `redactArguments(_:)` and `report(_:)`, whose `RedactionReport` holds counts per `RuleID` and never the matched text.
  `redact(x) == report(x).output`.
- `RuleCatalogue`: sixteen named rules in a fixed order (the order is the algorithm), each with positive and negative
  fixtures in its documentation and in a test table: `literalSecret`, `pemPrivateKey`, `jwt`, `bearer`, `appleMusicToken`,
  `secretFlag`, `secretAssignment`, `appSpecificPassword`, `uuid`, `longHex`, `longBase64`, `email`, `homePath`, `musicID`,
  `ipv4`, `ipv6`.
- `RedactionPolicy` (rule set, `.uniform` or `.typed` style, `maxInputLength`, overlong handling, the app-specific-password
  context setting, literal secrets) and two shipped policies, `.buildTool` and `.appLog`. The initialiser throws on an
  unknown or duplicate rule, a non-positive cap, a placeholder that is empty or longer than the cap, and a replacement
  token that the policy itself would change.
- `RedactionTestSupport` (imports Testing; for test targets only): `Secret`, `Leak`, `findLeaks` and `expectNoLeaks` over
  strings, files, `Data` and every rendering of an error, searching each secret's base64, base64url, percent-encoded, hex
  and UTF-16 forms (and base64 at the three alignments a secret can have inside a longer blob). A failure names the
  fixture's label and the place, never the value.
- DocC articles `WhatRedactionCannotDo` and `ChoosingAPolicy`; a README rule table checked against the catalogue by a test.
- Fail-closed behaviour: an input over the cap, an output that grows past it, a rule that did not compile, or a text that
  does not settle in eight passes is replaced whole, never passed through.

### Intentional differences from the two existing implementations

The existing suites are ported as `BuildToolPortedTests` (from SwiftReleaseKit's `RedactorTests`) and `AppLogPortedTests` (from
SwiftDiagnosticsHub's `LogScrubberTests`) and pass with the same assertions. Behaviour that changed on purpose:

From `Redactor` (SwiftReleaseKit), now `.buildTool`:

- **Bearer:** an opaque `Bearer <token>` is removed (it only removed a JWT-shaped one). Same line only.
- **App-specific password:** `xxxx-xxxx-xxxx-xxxx` is removed only with a credential word on the same line within 80 bytes
  (setting `appSpecificPassword`, default `.requiresCredentialWord`; `.anywhere` is the old behaviour), and only when it
  stands alone, not glued to more letters, digits or hyphens. `some-test-case-name` now survives.
- **Quoted values with spaces** (`password: "hunter two"`, `--password "a b"`) are removed whole. The tail was leaked before.
  An unterminated quote runs to the end of the line. In a flag value the quotes go with it; in `name: "value"` they are kept.
- **Flags** must start a word (`some-token x` in prose is no longer read as `-token x`).
- **Keys** in `name=value` are matched by their ending (`password`, `passwd`, `secret`, `token`) without the old
  `\b[a-z_-]*` prefix, which was quadratic on `a-a-a-...`; a key such as `9token=` now matches too. The separator allows
  spaces and tabs, not a newline, before it.
- **Literal secrets** are found on bytes, overlapping ones merged and replaced in one pass (`["abc","abcdef"]` no longer leaves
  `def`), run first instead of last, and a literal that is a substring of a replacement token (`RED`) removes the real
  occurrences and leaves the tokens alone, so redaction stays idempotent.
- **Input cap:** 8 MiB (there was none). Over it, the output is `[output too long, removed]`.
- **PEM across lines:** `redact(lines:)` removes the body lines of a block begun on an earlier line (new).
- **API:** `Redactor(secrets:)` becomes `Redactor(.buildTool.adding(literalSecrets:))` (see the README migration guide).

From `LogScrubber` (SwiftDiagnosticsHub), now `.appLog`:

- **`key=value`:** `password=`, `token: x`, JSON and quoted values are removed (new). It also removes harmless text such
  as `token: expired`, which the owner accepted ("better to be safe").
- **Git SHA:** a 40-digit hex run is kept; 32 to 39 and 41 or more are still removed (it removed 32 or more).
- **JWT:** each of the second and third segments needs at least five characters, and the token must start a word (it matched
  `eyJ` followed by anything, anywhere). A token glued to letters is no longer matched by `jwt` alone.
- **Bearer:** the credential must be on the same line as the word (`\s+` crossed line breaks).
- **PEM private key blocks** are removed (the scrubber had no such rule).
- **Fixed point:** rules are applied in passes until nothing changes, so a replacement that puts a token next to text that
  then matches is handled in one call (a single pass was not idempotent on such input).
- **Output cap:** an output that grows past 4,096 bytes (4,096 bytes of `a@b.cc ` becomes longer as `[email]`) is replaced
  with `[line too long, removed]`, so a second call cannot differ from the first. The input cap, its unit (UTF-8 bytes)
  and the placeholder are unchanged.
- **API:** `LogScrubber.scrub` becomes `Redactor.appLog.redact`; `maxLineLength` and `overlongPlaceholder` become
  `RedactionPolicy.appLog.maxInputLength` and `.overlongPlaceholder`; `declaredRuleCount` and `compiledRuleCount` become the
  catalogue test `everyPatternCompiles`.
- **Unchanged on purpose:** `Music-User-Token: x` still becomes `Music-User-Token=[token]`; the MusicKit id rule keeps
  its known false positive (`p.sharedInstance`); a long CamelCase identifier containing a digit is still taken for base64.

### Measured

- Swift Regex has no lookbehind on Swift 6.4.2; patterns that needed one consume the preceding character instead.
- The `jwt` rule was quadratic under Swift Regex on `eyJeyJ...` (3.9 s at 16 KiB, 17 s at 32 KiB) and is now anchored to a word
  start (about 10 ms at 64 KiB). Every other rule grows linearly on the adversarial inputs tried. See the README for the
  engine comparison with ICU and the caveats (a loaded machine; no Linux).
- The 4-4-4-4 shape matched nothing in 1.2 GB of real xcodebuild logs; see the README for the default chosen.

### Known limitations

- Linux is unverified. iOS, watchOS, tvOS and visionOS destinations were not built.
- `apiKeyPrefix(prefix:)` from the proposal's catalogue is not built.
- The structural `RedactionPaths` module (access paths, URLs) is phase 2 and not started.

[Unreleased]: https://github.com/jpurnell/SwiftRedaction/compare/HEAD
