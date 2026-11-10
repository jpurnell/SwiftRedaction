# Choosing a policy

Pick the shipped policy that matches where the text goes, and derive a third from the rule catalogue when neither fits.

## Overview

A ``RedactionPolicy`` answers three questions: which rules apply, how a removal is written, and what happens to an
input that is too long. Two policies ship because two kinds of text need different answers.

### `.buildTool`: captured tool output

Use ``RedactionPolicy/buildTool`` for the output of `xcodebuild`, `notarytool` and similar before it reaches a run log,
`run.json` or the terminal. It removes PEM private keys (also one cut off before its END line), JWTs, opaque `Bearer`
credentials, a password, secret or token given as a flag, `name=value`, `name: value` or JSON, an app-specific password
when a credential word is nearby, and any literal secret you add. Every removal reads `[REDACTED]`.

It keeps, on purpose, the identifiers a build log needs: an App Store Connect key ID, an issuer UUID, a team ID, a notary
profile name, and the *path* of a `.p8` key file. Its input cap is 8 MiB, because the input is a captured log, not one line.

```swift
import Redaction

let notaryPassword = "example-password"
let redactor = try Redactor(.buildTool.adding(literalSecrets: [notaryPassword]))
let safe = redactor.redactArguments(["notarytool", "store-credentials", "--password", notaryPassword])
```

### `.appLog`: log lines that leave the device

Use ``RedactionPolicy/appLog`` for app log lines before a TestFlight upload, where a line may carry text a peer sent. It
removes everything above except the flag rule and the app-specific-password rule, and adds UUIDs, long hex runs (a 40-digit
git SHA is kept), long mixed-case base64 runs, email addresses, home-folder paths, MusicKit ids and IP addresses. Removals
are typed (`[ip]`, `[uuid]`, `[token]`) so a reader can tell what was there. The `key=value` rule is on and removes harmless
text such as `token: expired`: for text that leaves the device the cost of a false positive is lower than a leak. A line over
4,096 UTF-8 bytes is replaced whole.

### Deriving a third policy

Build it from the catalogue, not by copying a pattern:

```swift
import Redaction

let policy = try RedactionPolicy(
    rules: [.jwt, .bearer, .secretAssignment, .ipv4],
    style: .typed,
    maxInputLength: 2_048)
let custom = try Redactor(policy)
```

The policy names a *set* of rules; the engine applies them in the catalogue's order, so the order you list them in does
not matter. The initialiser refuses a rule that is unknown or listed twice, a cap that is not positive, and a placeholder
or replacement token that the policy itself would change (which would make redacting twice differ from redacting once).

### The app-specific-password setting

The shape `xxxx-xxxx-xxxx-xxxx` is also four ordinary hyphenated words, such as a test name. The
``RedactionPolicy/AppSpecificPasswordContext`` setting chooses: ``RedactionPolicy/AppSpecificPasswordContext/requiresCredentialWord``
(the default for `.buildTool`) removes the shape only with a credential word (`password`, `app-specific`, `sign in`) on the same line,
``RedactionPolicy/AppSpecificPasswordContext/anywhere`` removes every match.

## Reading a report

``Redactor/report(_:)`` returns the redacted text and a count per rule, never the matched text. Log it, store it, or send it
to telemetry: it is not a second copy of the secret.
