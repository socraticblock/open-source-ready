# Contributing

Thanks for looking. Two things to know before anything else: this project's only real
product is *evidence*, so a claim that has not been run is worse than an admission that it
has not; and `main` is owner-gated — work goes on a branch.

## Setup

Python 3.12+ and `git`. Nothing else; there is no install step.

```bash
export PYTHONPATH="$PWD/src"
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Before you open a pull request

Run both of these, and paste the output in the PR description. The first is the suite; the
second is the same suite in the environment `verify` uses to run a candidate's tests, where
only `PATH`, a throwaway `HOME`, `LANG` and `TMPDIR` exist. It is not a formality — six tests
here once passed only because the developer's `~/.gitconfig` supplied an author identity.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests

env -i PATH=/usr/bin:/bin HOME=$(mktemp -d) LANG=C.UTF-8 TMPDIR=$(mktemp -d) \
    PYTHONPATH=src python3 -m unittest discover -s tests
```

If you changed anything the tool's own gate would notice:

```bash
PYTHONPATH=src python3 -m openready doctor --path .          # expect exit 2, FAILED 0
PYTHONPATH=src python3 -m acceptance.runner                  # 33 end-to-end rows (~45s)
PYTHONPATH=src python3 -m acceptance.gates                   # regenerate docs/P*-GATE.md
git checkout -- docs/                                        # those runs rewrite tracked docs
```

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
