# What redaction can never guarantee

A scrubber is a net under the type system. Read this page before you rely on one.

## Overview

Redaction here works by **shape**: a rule recognises text that looks like a JSON Web Token, a `Bearer` credential, a
password given as `name=value`, an email address, a home-folder path, and removes it. That is useful and it is bounded.
Five limits follow from it, and none can be engineered away.

### 1. It passes what has no recognisable shape

A short, human-chosen password in prose, a name, an address, a free-text note: none has a shape a rule can match. A
secret that has been transformed (split across two lines, interleaved with other text, URL-encoded, reversed) also
passes, because the rules read the text as it is written.

### 2. It cannot know what is personal

A show name is fine in a log; a diary entry typed into a text field is not, and no pattern tells them apart. The
rules remove *personal-looking* text (an email, a path under `/Users`), not personal text.

### 3. It removes what it recognises today

A new token format is invisible until a rule for it exists. That is what ``RedactionPolicy/adding(literalSecrets:)`` is
for: the caller that holds a secret is the only party who knows it, and can name it.

### 4. It is defense in depth, not the control

The privacy line must be enforced where the data is produced. In SwiftDiagnosticsHub that line is enforced by types: a
log chunk is accepted only for TestFlight builds, events are schema-registered, and a free-text field is refused on the
same terms. Redaction sits behind that line. A scrubber that is the *only* control is a design bug. Type-level
redaction (a type whose description is `<redacted>`), `os.Logger`'s `privacy: .private` and not logging the value at
all each come first.

### 5. A false positive is a cost; a false negative is a leak

The defaults favour removal. A commit SHA lost from a bug report, or `token: expired` turned into `token: [secret]`,
is the price. A policy may relax a rule, in code, where a reviewer can see it.

## What the engine does guarantee

- **Deterministic.** The same input and policy give the same output, on every host. The catalogue's order is the
  algorithm; a policy's list order is ignored.
- **Idempotent.** `redact(redact(x)) == redact(x)`, enforced when a policy is built and by a property test.
- **Fail closed.** An input longer than the policy's cap is *replaced*, never passed through, and a rule that did not
  compile makes the redactor replace every input rather than skip the rule.
- **Bounded.** A length cap runs before any pattern, and the measurements in the README show each rule's cost on the
  worst inputs tried.
- **Audit without leakage.** ``Redactor/report(_:)`` returns counts per rule, never the matched text.
