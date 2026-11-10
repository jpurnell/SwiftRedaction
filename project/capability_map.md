# SwiftRedaction Capability Map

**Purpose:** Scannable inventory of what this project can do: feature areas, key types, external interfaces, and application domains.

**Last reviewed:** 2026-11-09

> **Format reference:** See `development-guidelines/rules/capability_map.md` for field definitions,
> naming conventions, and maintenance rules.

---

## Removing secrets from text

**Key types:** `Redactor`, `RedactionPolicy`, `RuleCatalogue`, `Rule`, `RuleID`
**Interfaces:** internal only (a Swift library; no MCP tool, by design: sending text to a tool to be scrubbed defeats the point)
**Applications:** scrub captured build-tool output before it is logged; scrub app log lines before a TestFlight upload; remove literal secrets a caller holds.
**Dependencies:** Foundation only

## Auditing what was removed

**Key types:** `RedactionReport`
**Interfaces:** internal only
**Applications:** counts of which rules fired, for audits and telemetry, without a second copy of the secret.

## Proving a secret leaked nowhere

**Key types:** `Secret`, `Leak`, `findLeaks`, `expectNoLeaks` (product `RedactionTestSupport`)
**Interfaces:** internal only (test targets)
**Applications:** assert a secret fixture appears in no string, file, `Data` or rendering of an error, including its base64, percent-encoded and hex forms.
**Dependencies:** Testing
