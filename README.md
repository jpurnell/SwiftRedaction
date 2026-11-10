# SwiftRedaction

One Foundation-only package that removes secret-shaped and personal-looking text from strings.

**Status:** 0.1.0, unreleased, work in progress. Not yet adopted by SwiftReleaseKit or SwiftDiagnosticsHub.

**Defense in depth.** A scrubber works by shape and can miss what has none; the control that matters is not logging the
secret, enforced by types. See `WhatRedactionCannotDo` in the DocC catalogue.
