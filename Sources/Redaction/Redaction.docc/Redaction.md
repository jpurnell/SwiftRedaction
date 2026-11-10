# ``Redaction``

Removes secret-shaped and personal-looking text from strings, with named rules, two shipped policies and a report that never contains the secret.

## Overview

A ``Redactor`` applies a ``RedactionPolicy``: a set of rules from the ``RuleCatalogue``, a style for the replacement
(`[REDACTED]` or `[token]`), and a length cap past which a line is replaced whole. Rules run in the catalogue's fixed
order, redaction is deterministic and idempotent, and ``Redactor/report(_:)`` says which rules fired without ever
returning the matched text.

Redaction is defense in depth. Start with <doc:WhatRedactionCannotDo>.

## Topics

### Essentials

- <doc:WhatRedactionCannotDo>
- ``Redactor``
- ``RedactionPolicy``
- ``RedactionReport``
- ``RedactionError``

### The rules

- ``RuleCatalogue``
- ``Rule``
- ``RuleID``
