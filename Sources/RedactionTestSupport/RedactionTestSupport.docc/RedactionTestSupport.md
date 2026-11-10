# ``RedactionTestSupport``

Assertions that a secret reached no string, file, `Data` or error rendering. For test targets only.

## Overview

Name each secret fixture with a ``Secret``, run the code under test, and hand its outputs to ``expectNoLeaks(of:in:sourceLocation:)-(_,[String],_)``
or its siblings. Each search also looks for the secret's base64, percent-encoded, hex and UTF-16 forms, because a secret
that was re-encoded before it was written is still a leak. A failure message names the fixture's label and where it was
found, never the value, so a failing privacy test does not write the secret into a CI log.

This product imports `Testing`. Link it from test targets only; an app must never depend on it.

## Topics

### Describing a secret

- ``Secret``
- ``Leak``

### Finding leaks

- ``findLeaks(of:in:)-(_,[String])``
- ``findLeaks(of:inFileAt:)``
- ``findLeaks(of:in:)-(_,Data)``
- ``findLeaks(of:inRenderingsOf:)``

### Asserting there are none

- ``expectNoLeaks(of:in:sourceLocation:)-(_,[String],_)``
- ``expectNoLeaks(of:inFileAt:sourceLocation:)``
- ``expectNoLeaks(of:in:sourceLocation:)-(_,Data,_)``
- ``expectNoLeaks(of:inRenderingsOf:sourceLocation:)``
