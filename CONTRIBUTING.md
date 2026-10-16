# Contributing

Thanks for looking. Two things to know before anything else: this project's only real
product is *evidence*, so a claim that has not been run is worse than an admission that it
has not; and `main` is owner-gated — work goes on a branch.

## Setup

Use CPython 3.12 or 3.13 on Linux, plus Git. The runtime has no third-party
dependencies. Engineering tools are separate and hash-locked:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python tools/check.py
python tools/distribution_check.py
```

The same gate runs on pull requests and before tagged releases: repository-wide
Ruff correctness lint, formatting for boundary modules and gate tools, strict mypy
for the four boundary modules, medium/high Bandit findings, branch coverage,
selected mutation checks, all 33 acceptance scenarios, and the release allowlist.
Coverage floors are 85% across the four modules, 85% each for boundaries/backup/
verify, and 80% for candidate. These are regression floors, not a correctness score.

CI also runs the unit suite with a scrubbed environment and verifies installed
wheel and sdist builds in fresh environments. Acceptance uses `--no-report`, so it
does not rewrite documents. NOT_TESTED and NOT_ENFORCED remain distinct from PASS.
Do not run generated evidence cleanup commands that could discard your edits.

Add new public source, tests and documentation to `release-paths.txt` in the same
change. Update the toolchain lock deliberately; every dependency version and hash
must be reviewed. The runtime must remain dependency-free unless an ADR changes it.

Branch protection must require both `quality (Python 3.12)` and
`quality (Python 3.13)`. Workflow files cannot configure GitHub branch protection or
PyPI's environment approval rules; an owner must verify those settings separately.
Release workflow dispatch validates only. Publication requires a matching version
tag and the existing owner-controlled `pypi` environment. Source revision and
artifact hashes accompany the build, with PyPI attestations enabled at publication.

## Before you open a pull request

Report the exact revision, commands, results and unverified environments. Run:

```bash
env -i PATH="$PATH" HOME="$(mktemp -d)" LANG=C.UTF-8 TMPDIR="$(mktemp -d)" \
    PYTHONPATH=src "$(command -v python)" -m unittest discover -s tests -q
```

Review [ADR 013](docs/adr/013-immutable-artifact-boundaries.md) for deliberate
compatibility changes. For security boundary changes, another reviewer should
reproduce the regression and mutation checks before merge.

## House rules

- **Every behaviour change ships with a test that fails against the old code.** Not a test
  that passes afterwards — one that was demonstrated failing first, with the assertion
  message carrying the reason. `0/0` tests and swallowed exit codes are never green.
- **Never weaken a test to make it pass.** If a test encodes a wrong requirement, fix the
  requirement in an ADR and say so in the commit.
- **Label evidence literally:** `VERIFIED` (you ran it) · `INSPECTED` (you read it) ·
  `INFERRED` · `UNVERIFIED`. An `INSPECTED` claim may not be promoted to `VERIFIED` later by
  copying it.
- **Report what you did not verify**, in the same place you report what you did. Every
  result that carries a limitation must be reachable from `limits`.
- **Write no shaped examples.** No host paths, no credential-shaped strings, no realistic
  tokens anywhere in the tree, including in comments, docs and test fixtures. The repository
  is scanned by the deny-list it ships, and a whole literal makes the tool unable to export
  itself. Assemble detectable test values at run time — see `tests/fixtures.py` — and
  `tests/test_self_clean.py` will tell you if one creeps back.
- **Describe the shape, never write one.** The same rule applies to prose about the scanner.
- **Do not touch `.openready-allow.json` entries by hand** unless you are removing one. An
  entry must name an object id; a path-only entry suppresses every finding at that path,
  including one committed there later. `tests/test_self_clean.py` enforces that here.
- **An exception wider than its reason is a bug.** If you need to acknowledge something,
  name exactly the bytes.

## Where notes go

Thinking, drafts, hunches, evidence and anything about the maintainer's own setup do **not** go
here; they go to the private notes repository, and a finished finding is promoted deliberately —
as an issue, a doc, or a release note — rather than published as it was written.

This is enforced, not asked for: `tools/release_tree_check.py` runs in CI and refuses both a path
that is not in `release-paths.txt` and any note-shaped path (nothing under `notes/`, `private/`,
`internal/`, `drafts/`). Adding a note to the list does not help — the second rule is independent
of the list, on purpose. If CI stops you with that message, the note belongs in the notes
repository, not in a different directory here.

## Commits and branches

- Branch from `main`, name it `work/<topic>`.
- Commit as yourself: the identity on your commits is yours, not a machine default. (The
  maintainer's own tooling commits under a single project identity; that is not a rule for
  contributors.)
- One logical change per commit, with the *why* in the message; `docs/adr/` for a decision
  that changes a rule.
- Do not commit to `main`, do not merge, and do not change repository visibility. All three
  are owner acts.

## What a review looks for

1. Does the new control hold when someone tries to defeat it — and is that attempt a test?
2. Is every claim in the diff reproducible by a command a reviewer can run?
3. Does anything new make the tool's own repository fail the tool's own gate?
4. Does the change widen an exception, a scan's blind spot, or a "not checked" that renders
   as "clean"?

## Security issues

Do not open a public issue. See `SECURITY.md`.
