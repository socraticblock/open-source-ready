# Open-Ready

**Private by default, and it refuses to publish your secrets.** Open-Ready keeps personal
software projects private, tests and backs them up, and — only when you ask — prepares a
release candidate that carries its own evidence and stays **unapproved** until you
authorise one exact artifact.

It is a working tool, not a manifesto. The interesting part is not what it does; it is what
it *won't* do. There is no `publish` command, no code path that changes a repository's
visibility, and no way for the agent using it to invent your approval. That absence is the
product.

**Who it's for.** People who let AI agents work inside their own private projects and want
a real boundary around what can leave. You should be comfortable with a terminal, `git` and
Python. It is opinionated — one owner, local-first, git-native — and it is not a hosted
service.

**Status:** v0.1.0-p0, early. Measured on Linux/WSL2 only, with a GitHub Actions workflow that
runs the checks on every push and every pull request (observed passing: run `38579119769` in
this repository — a contributor convenience, not a release gate). Read
[Verified limitations](#verified-limitations--do-not-treat-these-as-solved) before relying
on it.

## Quickstart

Requirements: Python 3.12+ and `git`. No install step, nothing to provision.

```bash
git clone https://github.com/socraticblock/open-source-ready && cd open-source-ready
export PYTHONPATH="$PWD/src"

# create a private project (scaffold, synthetic fixture, one local commit, no remote)
python3 -m openready new --path ~/projects/example

# what it found, and what it did not check
python3 -m openready doctor --path ~/projects/example

# prepare an UNAPPROVED release candidate, then verify it
python3 -m openready candidate --path ~/projects/example --out /tmp/candidate
python3 -m openready verify --candidate /tmp/candidate --packet /tmp/packet.json
```

Exit code `2` above is normal and correct: it means **a human decision is required**, not
that something broke. A release packet is always `REVIEW_REQUIRED`.

Two more worth knowing: `openready limits --path .` lists every control this build could
*not* verify, with what would verify it — one command, and the honest answer to "is this
thing actually safe?". And `openready precommit --path .` checks what a commit is about to
add, so the cheap moment catches it rather than the expensive one.

## Commands

| Command | What it does |
|---|---|
| `new --path P --project-id ID [--backup]` | **create a complete private project in one step**: scaffold, synthetic fixture, one local commit, private runtime data root outside the project, and a registration. Also installs an **advisory** commit-time control (`.githooks/pre-commit`) |
| `init --path P --project-id ID [--git] [--adopt] [--register]` | the bare scaffolding step on its own; **refuses to create a project inside an enclosing git working tree**, and `--adopt` never commits inside an existing tree |
| `doctor --path P [--json]` | findings, and what was not checked |
| `fixture --path P` | write the deterministic synthetic corpus |
| `ledger --path P [--write]` | dependency, asset and provenance inventory |
| `candidate --path P --out D [--history none\|squash\|preserve]` | export an **UNAPPROVED** candidate |
| `verify --candidate D [--packet FILE] [--no-build] [--expected-digest D]` | re-derive the digest; emit the release packet |
| `backup --path P \| --project ID [--out F] [--verify]` | private backup, verified restore, migration drill |
| `test --path P` | run the project's tests with a scrubbed environment |
| `worth --path P` | private recommendation memo |
| `update [--path P] --dry-run` | contract and policy drift; changes nothing |
| `capabilities [--path P]` | host and fleet detection, with no network call |
| `status [--path P \| --project ID]` | local metadata only; with neither, the **private project registry** |
| `limits [--path P]` | the one-command honesty view: every unverified control, why, and what would verify it |
| `precommit [--path P]` | check the **staged** content of a commit (the index blob, not the working file) and refuse a commit that would put a credential, host path, database or `.env` into history. **Advisory, not enforcement**: `git commit --no-verify` skips it |
| `acknowledge --path P [--write --reason "…" --by "…"] [--include-tree] [--expires DATE]` | adopting a repository that already has history: **propose** one acknowledgement per **blob** that still holds a cleaned-up shape, and write nothing until asked. It proposes nothing for a finding in the working tree, because that file can be edited |

### Adopting a repository that already exists

Cleaning the working tree is not enough. The object store still holds what was cleaned, and
the export refuses a candidate while any of it is unacknowledged. That is the first wall a
real user meets, and it is invisible from this repository, which has always been clean.

```
openready init --path . --adopt --project-id <id>   # scaffold into the tree, overwriting nothing
openready doctor --path .                            # what it found, and what it did not check
#   fix what is in the working tree -- those files are editable and get no proposal
openready acknowledge --path .                       # propose one entry per blob; writes nothing
openready acknowledge --path . --write --reason "…" --by "…"
openready candidate --path . --out ../candidate --history squash
openready verify --candidate ../candidate --packet packet.json
```

Two things this command will not do for you. An entry binds to the **blob** somebody looked
at, so content committed at the same path later is still a finding — an exception is never
allowed to grow wider than the reason for it. And the **reason** is yours: a placeholder is
refused, because a tool cannot tell a fixture from a credential and must not pretend to.
Measured on a real project (the engineering journal, 106 files, on a copy): 23 findings
across 12 blobs, 14 entries, then a candidate of 115 files — byte-identical to the same
operation with a hand-written acknowledgement file.

The registry (`registry.py`) is a **metadata-only index** — project id, path, risk tier,
creation date, whether a baseline commit exists — held in the private runtime data root,
outside every project and outside any git working tree. It is an index, not an authority:
the project's own contract wins, a disagreement is reported rather than resolved, and a
registry that cannot be read is never overwritten.

There is **no `publish` command**, and no code path that changes a repository's visibility.
Publication is an owner decision bound to an exact artifact digest, made through a principal
the builder cannot write to. To be straight about it: on a host where the agent's
credentials could also publish, that separation is *reported* as `NOT_ENFORCED` rather than
enforced — `docs/PUBLISHING-CREDENTIALS.md` is the recipe for making it real.

Some source modules and documents here cite the specification this tool was built from —
`docs/10-CLI-CONTRACT.md`, `02-ARCHITECTURE.md`, `06-ACCEPTANCE-TESTS.md`. Those belong to the
original brief and are **not** in this repository, so a citation of one is a provenance note,
not a link that resolves.

## Exit codes

`0` succeeded — *not* safe to publish. `1` a failure or `STOP`. `2` a required human
decision. `3` a required check was unavailable, unenforceable or not run. `64` usage error.

## Rules this build enforces in code rather than documenting

- **Exit 0 never means safe.** A required check that could not run forces exit 3.
- **A refused export writes nothing.** Every check whose failure severity is `STOP` blocks
  the write; the destination is left untouched — a candidate that is written and then
  criticised is a candidate that ships anyway. Included: an unreadable or only partly
  scanned object store, an empty allowlist, a destination that already holds unrelated data,
  and any unacknowledged history finding.
- **"Not checked" never renders as "clean".** A scan that could not run, could not be read,
  or hit its size bound is reported `NOT_RUN` and refuses the export, rather than reporting
  that it found nothing.
- **The digest covers content only.** `MANIFEST.json` and `CANDIDATE.json` describe the
  candidate and are not part of its identity, so a stranger can recompute the digest from the
  files alone. The two records must agree, and `verify` fails if they do not.
- **Acknowledgements cannot be silent, and they name exact bytes.** Naming a false positive
  requires a check id, an exact path, a real reason, who acknowledged it and when; entries
  expire; and every applied entry is re-reported on every run. An entry binds to the content
  id (git's blob id) of what was looked at, so it covers those bytes and nothing else — a
  fixture's exception cannot hide a credential committed into the same file later.
- **Rights are never reported as `PASS`.** Ownership cannot be established by a scan, so the
  packet always carries `rights: NOT_RUN` rather than inventing a fact. The same applies to
  dependency ecosystems this build does not parse: an unread `Cargo.toml` is `NOT_RUN`, never
  "no dependencies".
- **A dependency is a licence obligation.** Unknown licences and copyleft are human review
  items, not conclusions. This tool does not provide legal advice and does not determine
  compatibility.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests          # 357 tests, stdlib only
env -i PATH=/usr/bin:/bin HOME=$(mktemp -d) LANG=C.UTF-8 TMPDIR=$TMPDIR \
    PYTHONPATH=src python3 -m unittest discover -s tests      # same suite, scrubbed
```

Both must pass. The second is not a formality: `verify` runs a candidate's tests in an
environment with only `PATH`, a throwaway `HOME`, `LANG` and `TMPDIR`, and six tests in this
repository used to pass only because the developer's `~/.gitconfig` supplied an author
identity. A suite that needs the author's machine is not evidence about the tool.

Also in the repo: `acceptance/` measures 33 end-to-end requirements (A01–A33) by driving the
CLI as a subprocess, and `acceptance/gates.py` regenerates `docs/P0-GATE.md` …
`docs/P4-GATE.md` from real runs.

## Verified limitations — do not treat these as solved

- Every scanner here is a **deny-list**. It can prove it found something, never that nothing
  exists.
- Arbitrary private **prose** is undetectable by pattern scanning; that check is `NOT_RUN`
  forever.
- **Network egress is not contained.** A restricted build passing here is not evidence it
  works offline.
- **Publisher separation is `NOT_ENFORCED`** on a host where the builder's credential can
  also publish, so a release packet is always `REVIEW_REQUIRED`. See
  `docs/PUBLISHING-CREDENTIALS.md`.
- No secret-scanner binary is installed, so the deny-list is the whole check. It is a set of
  patterns: a credential in a shape none of them describes is not detected.
- **History scanning is bounded** at 4 MiB per object. Objects above the bound are not read,
  and the tool refuses to export rather than reporting a clean scan over them. It enumerates
  every ref in the object store, so a fetched branch counts.
- `doctor` makes no network call and therefore cannot tell you whether a remote repository is
  public.
- One operating system has been measured (linux-x86_64). No cross-platform claim is made.

## Design decisions

`docs/adr/` records them, each with its reason and its consequences — including the three
from the last pass: an acknowledgement binds to an object, the acceptance record redacts
itself and is not written if it cannot pass, and detectable test fixtures are assembled at
run time so the repository can pass the very gate it ships.

## Licence

MIT — see `LICENSE`.

Maintained by **Jeff Vandervelde** · [socraticblock.com](https://socraticblock.com) · also
known as `socraticblock`.
