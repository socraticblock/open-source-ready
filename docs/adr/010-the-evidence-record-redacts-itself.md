# ADR-010 — The acceptance record redacts itself, and is not written if it cannot

**Date:** 2026-10-14  **Status:** accepted

## Context

`docs/ACCEPTANCE-STATE.md` and `.json` are the evidence the work order asks for: one
real subprocess per row, the command, the observed result, the sandbox path. They are
also **tracked files in this repository**, which means the tool's own exporter scans
them.

On 2026-10-13 the record for revision `688f0b6` held 99 absolute home paths in the JSON
and 97 in the markdown — the sandbox paths of that run — plus quotes of the
credential-shaped fixtures the rows had just measured. The result:

```
$ openready candidate --path . --out /tmp/or-self
  STOP candidate.host-path: 5 occurrence(s) in 5 file(s): docs/ACCEPTANCE-STATE.json; …
  STOP privacy.secret-shape: 7 occurrence(s) in 5 file(s): acceptance/tests_a01_a17.py x2; …
  STOP candidate.export: export refused: 12 blocking finding(s). No candidate was written.
```

The tool could not export the repository that contained its own acceptance record, and
**every run made it worse**: the harness rewrote the record after each measurement. The
row that asserts "Open-Ready's own tests pass and it is proposed for release" (A33)
failed on exactly this, while the completion report of the time claimed it passed.

## Decision

1. `scan.redact_for_evidence(data)` blanks host paths to `~` and credential shapes to
   `<redacted>`, in the raw text **and** in the whitespace-stripped copy the scanner
   also reads. A hit found only in the stripped copy is blanked by span in the
   original, because that is the only place it exists.
2. Every string the acceptance harness writes to its record goes through it —
   `Outcome.as_dict` for the JSON, and each rendered field in the markdown.
3. The runner scans the rendered record with the tool's own deny-list before writing.
   If it would be a hit, **nothing is written** and the run exits 1 (fail-closed). A
   record that poisons the export is worse than a run with no record, and a warning
   would be read as a note.

## Consequences

* The record is still evidence: what was found, where, and in what, all survive.
  `~` stands for the operator's home directory; the markdown says so at the top.
* A reader cannot copy a sandbox path out of the record and expect it to resolve
  without expanding `~`. That is the intended cost.
* Redaction is not permitted to become a way to hide a finding: it applies to the
  record, not to the scan. `tests/test_scan.py::TestEvidenceRedaction` and
  `tests/test_self_clean.py::TestTheRecordCannotPoisonTheExport` hold both halves.
