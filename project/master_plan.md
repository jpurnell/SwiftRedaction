# SwiftRedaction Master Plan

**Purpose:** Source of truth for project vision, architecture, and goals.

Approved design: `project/plans/proposals/SwiftRedaction.md` (its "Decisions by the owner, 2026-11-09" block wins over the body).

---

## Project Overview

### Mission
One Foundation-only Swift package that removes secret-shaped and personal-looking text from strings, so the two
scrubbers the owner's tools carry (`Redactor` in SwiftReleaseKit, `LogScrubber` in SwiftDiagnosticsHub) stop diverging,
and a fix or a new shape lands once.

### Target Users
- SwiftReleaseKit: captured `xcodebuild` and `notarytool` output before it reaches a run log (policy `.buildTool`).
- SwiftDiagnosticsHub: app log lines before a TestFlight upload, where lines are attacker-influenced (policy `.appLog`).
- Any later project that scrubs text, one at a time, each its own proposal.

### Key Differentiators
- **Named, individually tested rules** in a fixed order (the order is the algorithm), not an ad hoc regex list.
- **Fail closed:** an over-long input is replaced, never passed through; a rule that did not compile makes the redactor
  replace everything.
- **Deterministic and idempotent**, enforced when a policy is built and by property tests.
- **A report of counts only**: an audit can see which rules fired and never the secret.
- **A test-support product** that proves a secret reached no string, file, `Data` or error rendering, including in
  its base64, percent-encoded and hex forms.

---

## Architecture

### Technology Stack
- **Language:** Swift 6.2+ (tools-version 6.2), strict concurrency
- **Build System:** Swift Package Manager
- **Testing:** Swift Testing
- **Platforms:** iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1. Linux intended, **unverified** (no host yet).
- **Engine:** Swift Regex behind an internal `PatternMatcher` protocol, patterns compiled once. Measurements are in the README.
- **Dependencies:** none in `Redaction` (Foundation only). `RedactionTestSupport` imports `Testing`. swift-docc-plugin for docs.

### Module Structure

```
Sources/
├── Redaction/                 core: RuleID, Rule, RuleCatalogue, RedactionPolicy, Redactor, RedactionReport
│   ├── Rules/                 one file per rule family, fixtures in the doc comments
│   ├── Policies/              BuildToolPolicy, AppLogPolicy
│   └── Redaction.docc/        articles: what redaction cannot do, choosing a policy
└── RedactionTestSupport/      findLeaks / expectNoLeaks (test targets only; imports Testing)
Tests/
├── RedactionTests/            per rule, per policy, ported suites, golden corpus, idempotence, adversarial
└── RedactionTestSupportTests/ the helper detects a planted leak
```

### Key Types

| Type | Purpose |
|------|---------|
| `RuleID`, `Rule`, `RuleCatalogue` | named rules in a fixed order |
| `RedactionPolicy` | rule set, style, length cap, overlong handling, app-specific-password context, literal secrets |
| `Redactor` | applies a policy: `redact`, `redact(lines:)`, `redactArguments`, `report` |
| `RedactionReport` | output, per-rule counts, overlong flag; never the matched text |
| `Secret`, `Leak`, `findLeaks`, `expectNoLeaks` | test support |

### Data Flow

```
text -> length cap (replace whole when over) -> literal secrets (bytes, longest first)
     -> enabled rules in catalogue order -> length cap on the output -> text + counts
```

---

## Core Architectural Decisions

1. **Standalone shared package** (owner decision 1), not fixes in place in the two repositories.
2. **Swift Regex** (owner decision 2), with the length cap and measurement kept. Swift Regex has no lookbehind, so
   patterns that needed one consume the preceding character in a capture group instead. The matcher is a protocol so a
   rule can move engine.
3. **Defense in depth.** Types are the privacy line; the scrubber is the net.
4. **Fail closed**, and one overlong behaviour (replace whole). Truncate-then-redact from the proposal was not built: a cut can leave the start of a secret and cannot be made idempotent.
5. **`.appLog` has the key=value rule** (owner decision 3), accepting harmless hits such as `token: expired`.
6. **The 4-4-4-4 rule's context is a policy setting** (owner decision 4); default chosen from measurement (README).
7. **A 40-hex SHA is kept** (owner decision 7); other long hex runs are removed.
8. **Dependencies between the owner's packages by git URL** (owner decision 5).

---

## Current Status

### What's Working
- [x] Package skeleton, products `Redaction` and `RedactionTestSupport`
- [x] Rule catalogue, policy validation, `Redactor`, `report`, `.buildTool` policy with the RedactorTests ported
- [ ] `.appLog` policy with the LogScrubberTests ported
- [ ] Property tests, adversarial measurements
- [ ] Test support product
- [ ] Docs, migration guide

### What's Next
- [ ] See the checklist in `project/checklists/`.

---

## Quality Standards

### Code Quality
- All code follows `coding_rules.md`
- TDD: failing tests before implementation
- Documentation for all public APIs
- No warnings in build output
- Quality gate: 0 errors, 0 warnings before every commit

### Documentation Quality
- DocC comments for all public functions
- Usage examples in documentation
- Articles for complex topics

---

## Collaboration Principles

### AI as Sparring Partner, Not Oracle

AI proposes; the human interrogates. High AI confidence triggers harder questions, not faster acceptance.

- **Interrogate confident outputs.** When the AI states something with certainty, ask for the counterargument before accepting.
- **Demand counterarguments.** Before locking in an approach, require an explicit case for the strongest alternative.
- **Sit with discomfort.** Resist the pull to take the first plausible answer.

This principle is operationalized in the **Adversarial Review** step of `design_proposal.md`.

---

## Roadmap

### Phase 1: Core and two policies (this release, 0.1.0)
- [ ] Catalogue, policies, engine, test support, byte-compat suites, docs

### Phase 2: Structural helpers (not started)
- [ ] `RedactionPaths`: the access-path shape copied four times in the portfolio, and a URL helper
- [ ] Migrations of SwiftReleaseKit and SwiftDiagnosticsHub (separate reviewed changes in those repositories)

### Future
- A `swift-redact` CLI; rule hit counts into the corpus telemetry; a streaming `redact(into:)`; entropy detection as an opt-in rule.

---

**Last Updated:** 2026-11-09 (filled from the approved proposal; slice 1 built)
