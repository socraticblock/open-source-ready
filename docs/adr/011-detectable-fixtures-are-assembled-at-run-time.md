# ADR-011 — Detectable fixtures are assembled at run time, never written whole

**Date:** 2026-10-14  **Status:** accepted

## Context

A scanner test needs a value the scanner must find. Written as a literal, that value is
also a deny-list hit in the repository that contains the test — so the tool that exists
to make exports clean could not export itself. The previous answer was one
acknowledgement per affected file, which is the exception ADR-009 narrows and
`tests/test_self_clean.py` now forbids in this repository.

There is also a second reader to satisfy: the scanner checks a **whitespace-stripped**
copy of every file, because a value split by a newline is the same disclosure. A
fragment-assembled literal therefore has to leave its separator intact in *both* reads.
Found the hard way: a value whose separator sits inside the same string literal as the
secret name looks safe, and is not — the stripped copy joins the two fragments back into
a secret-named assignment with a literal value, and the gate refuses the commit that
contains the ADR describing it.

## Decision

Detectable values live in `tests/fixtures.py` and `acceptance/fixtures.py`, assembled
from fragments so that the runtime bytes are identical and the source text carries no
shape:

```python
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"          # AWS's published example, invalid
QUOTED_ASSIGNMENT = "api_" + "key" + " = " + '"' + "a" * 20 + '"'
CLIENT_SECRET_ASSIGNMENT = "client_" + "secret" + ": hunter2hunter2"
```

The key *name* is assembled too, not only the value: `api_key = "…"` in the source is a
clean-written-hit even when the value behind it is a variable.

`tests/test_self_clean.py` scans every tracked file with the tool's own deny-list and
fails if any shape appears, with a message saying what to do instead. Twelve
path-wide acknowledgements were deleted as a result.

## Consequences

* Two files (`tests/fixtures.py`, `acceptance/fixtures.py`) are the only place these
  values live, and each carries the reason in its docstring.
* A test that needs a *new* detectable value must assemble it the same way. The failure
  message from `test_self_clean` names the file and the check, so the fix is local.
* The scanner still detects every one of these values at run time — that is the point —
  and the acceptance rows that prove it (A04, A18, A20) are unchanged.
