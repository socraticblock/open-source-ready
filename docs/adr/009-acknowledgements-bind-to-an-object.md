# ADR-009 — An acknowledgement names the object it covers, not the path

**Date:** 2026-10-14  **Status:** accepted  **Supersedes:** the path-only entry form

## Context

`.openready-allow.json` carried twelve entries, and every one of them acknowledged a
**file**: `privacy.secret-shape` at `tests/test_hardening.py`, `candidate.host-path` at
`src/openready/scan.py`, and so on. `overrides.apply` matched on `(check_id, path)`, so
an entry suppressed *every* finding of that class at that path until it expired.

The entries existed for a real reason: the fixtures in this repository are
credential-shaped on purpose, and they were written as whole literals. But the
exception was far wider than the reason for it. A real credential committed into
`tests/test_hardening.py` on any day before 2027-01-13 would have been reported as
"acknowledged by the operator" — the fixture's exception would have covered it — and
`doctor` would have called it a human-owned item rather than a failure. The tool's own
existence argument is that a control must not be wider than the thing it excuses.

The same shape of problem appeared twice more on the same day:

* the acceptance record (`docs/ACCEPTANCE-STATE.{md,json}`) carries the sandbox paths
  the run happened in and quotes of the fixtures it measured, so the repository could
  not export itself — every run made the export worse;
* the history scan found 52 hits in the object store, and the only available
  acknowledgement was per path, which is the wide form again.

## Decision

A finding carries the id of the bytes it came from, and an entry may name it:

* `scan.content_object_id(data)` is `sha1("blob <size>\0" + content)[:12]` — git's own
  blob id. A working-tree file and the blob it was committed as therefore carry the
  **same** identifier, which is the property that makes one entry cover one decision
  in both places. `tests/test_scan.py` checks it against `git hash-object` rather than
  against our own arithmetic.
* `scan.scan_file(rel, data)` is `scan_content` plus that id, and is now used by the
  exporter, `doctor`'s tree scan and `verify`.
* An entry **with** `object` covers those bytes and nothing else. An entry
  **without** one keeps the old, wider meaning, so existing files keep working — and
  the result's `limitations` now say, in words, which of the two it was.

## Consequences

* The twelve path-only entries were replaced by 42 object-bound entries, one per
  historical blob. `tests/test_self_clean.py` fails if a path-only entry reappears in
  this repository.
* `doctor` on this repository went from 3 FAILED to **0 FAILED**, exit 2 (a required
  human decision) — and 42 of the 44 human items are now the acknowledged residue.
* Acknowledging a *new* leak now requires naming its blob, which means running the
  scan and reading the hit. That is slower than writing a path, and that friction is
  the point.
* `verify` and `candidate` share one matching rule (`overrides.entry_covers`). They
  had two implementations once, and they disagreed about the same frozen artifact.
