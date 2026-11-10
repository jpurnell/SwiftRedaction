# Session summary: SwiftRedaction phase 1, 2026-11-09

Built the package from `project/plans/proposals/SwiftRedaction.md` (owner decisions of 2026-11-09 applied), test-first, in
five local commits. No remote, no tag, no push. SwiftReleaseKit and SwiftDiagnosticsHub were read, not modified.

## State

- 84 tests (73 in `RedactionTests`, 11 in `RedactionTestSupportTests`), all passing; quality gate 0 errors, 0 warnings, no suppressions.
- Linux unverified; only macOS arm64 built.

## Decisions to review (the proposal was silent, or this departs from it)

1. **Truncate-then-redact not built.** The proposal's `OverlongInput.truncateThenRedact` was dropped: a cut can leave the start
   of a secret and cannot be made idempotent. One case, `.replaceWhole`.
2. **Swift Regex has no lookbehind** (measured). Patterns that needed one consume the preceding character in a capture group.
3. **`jwt` is anchored to a word start** after the unanchored form measured quadratic (17 s at 32 KiB) and the bounded form still 2 s at 64 KiB.
4. **Fixed-point passes** instead of one pass: needed for idempotence (found by the property test: a combining mark moved a word
   boundary; `/Users/` met a token). Costs a second pass on any line that changed.
5. **Hex rule:** a 40-digit SHA is kept; 32 to 39 and 41+ removed. The brief said "41+"; the old scrubber test uses a 36-digit run, so 32 to 39 stay removed.
6. **4-4-4-4 default** is `.requiresCredentialWord` for `.buildTool`, though the measurement (0 matches in 1.2 GB of build logs) would
   support `.anywhere` equally; the context default removes the listed test-name false positive.
7. **Literals run first**, on bytes, longest-first merged; tokens in the text are protected.
8. **Output over the cap is replaced** (expansion), for idempotence.
9. **`maxInputLength` unit** is UTF-8 bytes (the scrubber's), not characters (the proposal's). `.buildTool` cap is 8 MiB (new).
10. **`Redactor.init(failClosed:)`** is public so statics and wrappers need not throw.
11. **`apiKeyPrefix` not built.**

## Next

Owner review; Linux and device-destination builds; remote and tag; the two migrations in their own repositories.
