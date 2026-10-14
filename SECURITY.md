# Security policy

## Reporting a vulnerability

**There is no public repository yet**, so there is no intake channel that works: please do
not report a vulnerability in public anywhere. The moment a public destination exists, this
file will name it, and the tool already generates the intake templates:

```bash
PYTHONPATH=src python3 -m openready templates --to ./public-artifacts
```

That produces a `SECURITY.md` and a disclosure path with a private triage address and an
owner review step. Opening intake to the public is an owner act (recorded as acceptance row
A31, currently `NOT_TESTED` because there is nothing public to receive a report).

## What counts as a security issue here

This tool's whole claim is that it refuses to let private material leave without an owner's
decision. So the highest-severity class of bug is:

1. **A candidate is written that contains something the deny-list should have stopped** — a
   credential shape, a host path, a database, an `.env`, an object the scan could not read.
   A refusal that does not happen is worse than a false refusal, because a written candidate
   is a candidate that can ship.
2. **A finding is suppressed that should have been reported** — a forged or widened
   acknowledgement, an entry that covers content it never named, a `verify` that disagrees
   with the exporter about the same frozen artifact.
3. **A record that reports on a run becomes something the run would refuse** — this has
   happened once already; see `docs/adr/010-the-evidence-record-redacts-itself.md`.
4. **An approval is invented or reused** — any path by which a builder can make the tool
   treat an unapproved artifact as approved. The tool has no `publish` verb by design.

Bugs of the ordinary kind (a crash, a wrong message, an awkward interface) are not security
issues — the issue tracker is the right place for those.

## What this tool does not claim

- It does not contain network egress, and it cannot promise that private data is contained
  on a host where the agent has broad read access and unrestricted network.
- It does not detect arbitrary private *prose* by pattern scanning, and it says so
  (`NOT_RUN`, forever).
- It does not enforce that the publisher is a different principal from the builder unless the
  operator has separated the credentials; see `docs/PUBLISHING-CREDENTIALS.md`.
- It is not a secret scanner product. The deny-list is a set of patterns, and a credential
  in a shape none of them describes is not detected.

## Supported versions

Early (v0.1.x). Security fixes land on `main`; there are no maintained older branches yet.
