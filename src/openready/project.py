"""Private project initialisation (OR-004).

Specification behaviour: create a private local project. No public repository, no
licence grant, no cloud call, no copying of personal data, and **existing
repositories are never modified**.

One control is added here beyond the inherited prototype, drawn from this fleet's
own measured failure: :func:`init` **refuses to create a project inside an
enclosing git working tree**. The fleet's working directory is a checkout of a
public repository, so a project created inside it silently inherits that
publication surface, and a per-directory guard file is not enforcement. Refusing
by default costs one directory and removes a whole failure class. The refusal is
overridable with an explicit reason, but never silently.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import POLICY_VERSION, __version__
from . import private as private_mod
from . import registry as registry_mod
from .capabilities import enclosing_checkout
from .contracts import validate_project_contract
from .status import (
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    Result,
    exit_code_for,
)

CONFIG_NAME = "openready.project.json"
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
TIERS = ("T0", "T1", "T2", "T3")

GITIGNORE = """# Never commit private data or credentials.
# This file is hygiene. It is NOT a confidentiality control: a guard can be
# bypassed with `git add -f`, and a rule is not a permission system.
.env
.env.*
!.env.example
private/
private-data/
secrets/
credentials/
personal/
userdata/
*.pem
*.key
*.p12
*.pfx
*.kdbx
*.sqlite
*.sqlite3
*.db
*.log
*.pyc
__pycache__/
.venv/
venv/
node_modules/
dist/
build/
.openready-private/
"""

AGENTS_MD = """# Instructions for coding agents

1. This project is PRIVATE. Do not create public repositories, publish packages,
   images or docs, or change repository visibility.
2. Work inside `src/`, `tests/`, `examples/` and `docs/`. Prefer synthetic test
   data. Real user data belongs in the private runtime data root, never here.
3. Never copy CVs, client data, journals, `.env` files, credentials, personal
   files or private corpora into source, fixtures, logs or prompts sent to any
   service without explicit owner approval.
4. Do not accept outside code, assets or contributions without recording the
   original source, licence and permission. Unknown provenance is `UNKNOWN`.
5. Do not submit external forms or send user data without explicit operator
   authorization and current platform terms.
6. Never approve a licence, waive a finding, or authorize publication. Those are
   owner decisions, made against an exact artifact digest.
7. Before proposing a release, run `openready doctor` and prepare a candidate for
   owner review. A passing check describes one check only.

**Warning: these are instructions, not filesystem or network enforcement.** A
rule an agent can read is not a boundary. Real containment requires host-level
permissions the operator must configure.
"""

README = """# {project_id}

Private work in progress. **Not licensed for public reuse.**

Initialised by Open-Ready {version} at risk tier {tier}. This project is
unlicensed and private by default: the licence decision is deliberately deferred
until a release is actually contemplated (ADR-005), and the irreversible moment
is the first outside contribution, not the first commit.

Run `openready doctor --path .` to see what has and has not been checked.
"""

ENV_EXAMPLE = """# Documented placeholder values only. Never put a real value in a tracked file.
# Copy to .env (gitignored) and fill in locally.
EXAMPLE_API_ENDPOINT=https://example.invalid/api
EXAMPLE_REGION=changeme
"""

HOOK_PATH = ".githooks/pre-commit"

#: The commit-time control, installed into every created project.
#:
#: It carries its own honesty in the file, because the file is the thing a future reader
#: finds -- not this module. It also degrades: where the tool is absent the commit is
#: allowed with a warning, since a missing lint tool must not make a repository
#: uncommittable.
HOOK_SCRIPT = """#!/bin/sh
# ADVISORY CONTROL -- NOT ENFORCEMENT.
#
# Asks Open-Ready whether the STAGED content would put private material into history:
# a credential shape, a host path, a database, or a staged .env. Run it by hand with
#   openready precommit --path .
#
# Saying "advisory" is the point, not a hedge:
#   * `git commit --no-verify` skips this hook entirely, and so does removing
#     core.hooksPath from .git/config;
#   * where the tool is not installed the commit is ALLOWED with a warning below,
#     because a missing lint tool must not make a repository uncommittable;
#   * the enforced control is the export -- `openready candidate` refuses to write a
#     candidate at all, and that one cannot be skipped with a flag.
if ! command -v openready >/dev/null 2>&1; then
  echo "openready: ADVISORY CHECK SKIPPED -- tool not on PATH on this machine; commit allowed" >&2
  exit 0
fi
openready precommit --path .
"""


def build_config(project_id: str, languages: Sequence[str], tier: str,
                 data_ref: Optional[str] = None) -> Dict:
    return {
        "schema_version": "1.0",
        "project_id": project_id,
        "visibility": "PRIVATE",
        "risk_tier": tier,
        "openready_version": __version__,
        "data_ref": data_ref or project_id,
        "languages": list(languages),
        "license_intent": "UNDECIDED",
        "checks_profile_version": POLICY_VERSION,
        "external_actions": [],
        "private_overlays": True,
    }


def _scaffold(config: Dict, project_id: str, tier: str) -> List[tuple]:
    """The files ``init`` creates, as (relative path, exact content).

    Held as data so the same list can be applied to an empty directory and, under
    ``--adopt``, to a directory that already holds a project.
    """
    return [
        (CONFIG_NAME, json.dumps(config, indent=2) + "\n"),
        (".gitignore", GITIGNORE),
        (".env.example", ENV_EXAMPLE),
        ("AGENTS.md", AGENTS_MD),
        ("README.md", README.format(project_id=project_id, version=__version__, tier=tier)),
        ("docs/README.md",
         "# Documentation\n\nTechnical and usage docs. No private project notes.\n"),
        ("docs/adr/000-template.md",
         "# ADR NNN -- <decision>\n\n"
         "**Status:** proposed | accepted | superseded\n"
         "**Date:**\n\n"
         "## Context\n\n## Decision\n\n## Consequence\n\n"
         "## Honest limitation\n\nWhat does this decision still not guarantee?\n"),
        (HOOK_PATH, HOOK_SCRIPT),
        ("examples/synthetic/README.md",
         "# Synthetic examples\n\nInvented data only. Never real personal records.\n"),
        ("src/README.md", "# Source\n\nProduct source goes here.\n"),
        ("tests/README.md",
         "# Tests\n\nAutomated tests go here. A passing test describes one behaviour.\n"),
    ]


def _preflight(root: Path, project_id: str, tier: str, force: bool,
               adopt: bool = False, register: bool = False) -> List[Result]:
    results: List[Result] = []
    env = "local"

    if not PROJECT_ID_RE.match(project_id):
        results.append(Result(
            "init.project-id", FAIL, STOP,
            f"{project_id!r} must match {PROJECT_ID_RE.pattern}", __version__, env,
        ))

    if tier not in TIERS:
        results.append(Result(
            "init.risk-tier", FAIL, STOP,
            f"risk tier must be one of {TIERS}, got {tier!r}", __version__, env,
        ))

    not_empty = root.exists() and (not root.is_dir() or any(root.iterdir()))
    if not_empty and not adopt:
        results.append(Result(
            "init.target-empty", FAIL, STOP,
            f"{root} exists and is not empty; refusing to overwrite", __version__, env,
            limitations=["An existing project is attached with `init --adopt`, which "
                         "creates only the files that are missing."],
        ))
    elif not_empty and adopt and (root / CONFIG_NAME).is_file() and not register:
        # Already a project: adopting it again would silently ignore --project-id and
        # leave the real project_id in place.
        results.append(Result(
            "init.already-project", FAIL, STOP,
            f"{root} already holds {CONFIG_NAME}; this is already an Open-Ready project "
            f"and nothing was changed", __version__, env,
            limitations=["Pass --register to record it in the private registry, which is "
                         "metadata only and changes nothing inside the project."],
        ))
    elif not_empty and adopt and (root / CONFIG_NAME).is_file() and register:
        results.append(Result(
            "init.already-project", NEEDS_HUMAN, REVIEW,
            f"{root} already holds {CONFIG_NAME}; this run only records it in the private "
            f"registry, and the project id its own contract declares is the one used",
            __version__, env, required=False,
        ))
    elif not_empty and adopt:
        results.append(Result(
            "init.adopt", NEEDS_HUMAN, REVIEW,
            (f"adopting the existing directory {root}: only files that are missing are "
             f"created, and no existing file is overwritten"),
            __version__, env, required=False,
            limitations=["Adoption records no inventory of what was already here. Run "
                         "`doctor` before treating this tree as reviewed."],
        ))

    encloser = enclosing_checkout(root)
    if encloser and not force:
        results.append(Result(
            "init.enclosing-checkout", FAIL, STOP,
            f"{root} would be created inside the git working tree at {encloser}; "
            f"the new project would inherit that repository's publication surface",
            __version__, env,
            limitations=[
                "Pass --allow-inside-checkout (with a reason in the audit log) to "
                "override. A guard file against the enclosing repository is not "
                "enforcement.",
            ],
        ))
    elif encloser:
        results.append(Result(
            "init.enclosing-checkout", NEEDS_HUMAN, REVIEW,
            f"overridden: inside the git working tree at {encloser}", __version__, env,
            required=False,
        ))
    return results


def init(root: Path, project_id: str, languages: Sequence[str] = ("python",),
         tier: str = "T1", git: bool = False, force: bool = False,
         adopt: bool = False, register: bool = False) -> List[Result]:
    """Create a private project skeleton. Returns results; caller maps to exit code.

    With ``adopt`` the skeleton is applied to a directory that already holds a project:
    every file that is already there is left exactly as it is, and only the missing
    ones are written. Without it the target must be empty, which is what a brand-new
    project looks like.

    ``register`` additionally records the project in the private registry (metadata only,
    outside the project). It is opt-in so that scaffolding never has a side effect the
    caller did not ask for; :func:`create` is the path that registers by default.
    """
    root = Path(root).absolute()
    results = _preflight(root, project_id, tier, force, adopt, register)
    if any(r.status == FAIL for r in results):
        return results

    config = build_config(project_id, languages, tier)
    schema_errors = validate_project_contract(config)
    if schema_errors:
        results.append(Result(
            "init.contract", FAIL, STOP,
            "refusing to write a config that fails the project contract: "
            + "; ".join(schema_errors[:3]),
            __version__, "local",
        ))
        return results

    root.mkdir(parents=True, exist_ok=True)
    for rel in ("src", "tests", "examples/synthetic", "docs", ".openready"):
        (root / rel).mkdir(parents=True, exist_ok=True)

    written: List[str] = []
    kept: List[str] = []
    for relative, content in _scaffold(config, project_id, tier):
        target = root / relative
        if target.exists():
            # Never overwrite. Under --adopt the file that is already there is the whole
            # reason the directory was adopted, and a scaffolder that replaces it
            # destroys the work it was invited to look after.
            kept.append(relative)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if relative == HOOK_PATH:
            # A hook that is not executable silently does nothing, which is the worst
            # available outcome: it looks installed.
            target.chmod(0o755)
        written.append(relative)
    # No LICENSE file: the licence decision is staged, not skipped (ADR-005).

    results.append(Result(
        "init.created", PASS, INFO,
        (f"private project scaffolded at {root} ({len(written)} file(s) written)"
         + (f", {len(kept)} already present and left untouched" if kept else "")),
        __version__, "local",
    ))
    if kept:
        results.append(Result(
            "init.kept", NEEDS_HUMAN, REVIEW,
            (f"{len(kept)} existing file(s) were left exactly as they are: "
             f"{', '.join(kept[:6])}"),
            __version__, "local", required=False,
            limitations=["These files were not written by this run and nothing here read "
                         "them. They are the operator's content, not scaffold."],
        ))

    if git:
        results.extend(_git_init(root))

    if register:
        results.extend(_register(root, project_id, tier))

    results.append(Result(
        "init.no-public-side-effect", PASS, INFO,
        "no repository was created, no visibility changed, no package published, "
        "no network call made",
        __version__, "local",
    ))
    return results


def _git_init(root: Path) -> List[Result]:
    env = "local"
    results: List[Result] = []
    try:
        done = subprocess.run(
            ["git", "-C", str(root), "init", "-q", "-b", "main"],
            capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        results.append(Result(
            "init.git", FAIL, REVIEW, f"git init failed: {exc}", __version__, env,
            required=False))
        return results
    if done.returncode != 0:
        results.append(Result(
            "init.git", FAIL, REVIEW, f"git init failed: {done.stderr.strip()}",
            __version__, env, required=False))
        return results
    results.append(Result(
        "init.git", PASS, INFO,
        "local git repository created with NO remote and no licence -- staged "
        "decision per ADR-005",
        __version__, env,
    ))

    hooks = subprocess.run(
        ["git", "-C", str(root), "config", "--local", "core.hooksPath", ".githooks"],
        capture_output=True, text=True, timeout=15, check=False)
    if hooks.returncode == 0:
        results.append(Result(
            "init.commit-control", PASS, INFO,
            f"advisory pre-commit control wired to {HOOK_PATH}: it refuses a commit whose "
            f"STAGED content would put a credential, host path, database or .env into history",
            __version__, env, required=False, enforcement=NOT_ENFORCED,
            limitations=[
                "Advisory, not enforcement: `git commit --no-verify` skips it, and so does "
                "removing core.hooksPath. The enforced control is the export, which refuses "
                "to write a candidate at all.",
                "Where the tool is not on PATH the hook allows the commit with a warning, "
                "rather than making a checkout uncommittable.",
            ],
        ))
    else:
        results.append(Result(
            "init.commit-control", NOT_RUN, REVIEW,
            f"`git config core.hooksPath` failed, so {HOOK_PATH} exists but is NOT wired "
            f"up: {hooks.stderr.strip()[:160]}",
            __version__, env, required=False, enforcement=NOT_ENFORCED,
            limitations=["The hook file is present but inert until it is wired up or "
                         "invoked as `openready precommit --path .`."],
        ))
    return results


COMMIT_MESSAGE = (
    "Initial commit: private project scaffold created by Open-Ready {version} "
    "(no remote, no licence, no publication)"
)


def _has_baseline_commit(root: Path) -> bool:
    """Whether the project's own repository has any commit yet."""
    try:
        done = subprocess.run(["git", "-C", str(root), "rev-list", "--all", "--count"],
                              capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0 and done.stdout.strip().isdigit() and int(done.stdout) > 0


def _register(root: Path, requested_id: str, requested_tier: str) -> List[Result]:
    """Record a project in the private registry, letting its own contract win.

    The registry is an index; the project contract is authoritative. So when a contract
    already exists, its ``project_id`` and ``risk_tier`` are the ones recorded, and a
    disagreement with what the caller asked for is reported rather than quietly obeyed.
    """
    results: List[Result] = []
    config_path = root / CONFIG_NAME
    effective_id, effective_tier = requested_id, requested_tier
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            return [Result(
                "init.register", FAIL, REVIEW,
                f"cannot register {root}: its contract could not be read ({exc})",
                __version__, "local", required=False,
            )]
        effective_id = str(config.get("project_id") or requested_id)
        effective_tier = str(config.get("risk_tier") or requested_tier)
        if effective_id != requested_id:
            results.append(Result(
                "init.register", NOT_RUN, REVIEW,
                f"registering under {effective_id!r} from the project's own contract, not "
                f"{requested_id!r} as asked: the contract is authoritative",
                __version__, "local", required=False,
            ))
    results.extend(registry_mod.record(effective_id, root, effective_tier,
                                       committed=_has_baseline_commit(root)))
    return results


def _private_root_preflight(root: Path, env: Optional[Dict[str, str]] = None) -> Optional[Result]:
    """Refuse before writing anything if the private data root would land in the project.

    Checked in preflight rather than reported afterwards on purpose: a STOP that arrives
    after a successful write is the defect this tool already shipped once.
    """
    home = private_mod.private_home(env)
    if home == root or root in home.parents:
        return Result(
            "create.private-root", FAIL, STOP,
            f"the private runtime data root resolves to {home}, which is inside {root}; "
            f"everything written there would be published by one `git add -A`",
            __version__, "local",
            limitations=["Point OPENREADY_PRIVATE_HOME at a location outside the project, "
                         "or clear it to use the platform default. Nothing was written."],
        )
    return None


def _configured_identity(root: Path) -> str:
    """The author email git would use for a commit in ``root``, or an empty string.

    `git config --get user.email` alone is too narrow. Git also takes its author and
    committer from `GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_EMAIL`, and that is how a CI machine
    -- and the scrubbed environment `verify` uses to run a candidate's tests -- normally
    supplies one. Found by running this repository's own suite under `verify`: `new`
    reported `NOT_RUN` for a missing identity that git would have used happily, and five
    tests failed for it.

    The lookup is scoped with `-C root`, so it reads the *project's* configuration. Asked
    from the caller's working directory it would silently inherit the configuration of
    whatever repository the operator happens to be standing in.
    """
    configured = subprocess.run(["git", "-C", str(root), "config", "--get", "user.email"],
                               capture_output=True, text=True, timeout=30, check=False)
    if configured.returncode == 0 and configured.stdout.strip():
        return configured.stdout.strip()
    return (os.environ.get("GIT_COMMITTER_EMAIL")
            or os.environ.get("GIT_AUTHOR_EMAIL") or "")


def _initial_commit(root: Path) -> Result:
    """Commit the created tree, so the project has a recoverable baseline.

    Deliberately does not invent an identity: a commit attributed to a fabricated author
    is worse than an honest NOT_RUN. An identity the environment supplies is not invented,
    so it is used; one the tool made up on the operator's behalf would be.
    """
    def git(*args: str):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, timeout=30, check=False)

    identity = _configured_identity(root)
    if not identity:
        return Result(
            "create.initial-commit", NOT_RUN, REVIEW,
            "git has no user.email configured and the environment supplies none, so no "
            "baseline commit was made: the project exists, but it has no recoverable "
            "revision yet",
            __version__, "local",
            limitations=["Set `git config --global user.email` and `user.name`, or export "
                         "`GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_EMAIL`, then commit the created "
                         "tree. Nothing is committed on the operator's behalf.",
                         "A NOT_RUN here describes one missing setting, not a broken project."],
        )

    staged = git("add", "-A")
    if staged.returncode != 0:
        return Result(
            "create.initial-commit", FAIL, REVIEW,
            f"`git add -A` failed in {root}: {staged.stderr.strip()[:200]}",
            __version__, "local", required=False,
            limitations=["The project was created but has no baseline commit."],
        )

    committed = git("commit", "-q", "-m", COMMIT_MESSAGE.format(version=__version__))
    if committed.returncode != 0:
        return Result(
            "create.initial-commit", FAIL, REVIEW,
            f"`git commit` failed in {root}: {(committed.stderr or committed.stdout).strip()[:200]}",
            __version__, "local", required=False,
            limitations=["The project was created but has no baseline commit."],
        )

    revision = git("rev-parse", "--short", "HEAD").stdout.strip() or "HEAD"
    return Result(
        "create.initial-commit", PASS, INFO,
        f"baseline commit {revision} recorded, so the created state is recoverable",
        __version__, "local",
        limitations=["A commit is a local revision, not a backup: it shares the disk with "
                     "the working tree."],
    )


def create(root: Path, project_id: str, languages: Sequence[str] = ("python",),
           tier: str = "T1", force: bool = False, backup: bool = False,
           env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Create a **complete** private project from one command (the stated goal).

    Composes what already exists rather than adding a second implementation: :func:`init`
    scaffolds, :mod:`private` owns the data-root boundary, :mod:`registry` records the
    project, :mod:`backup` makes the first recoverable copy.

    Order matters. The private-data-root placement is checked before anything is written;
    the baseline commit happens after the fixture so the commit captures the whole created
    state; the registry is written last, so a project is only named once it exists.
    """
    root = Path(root).absolute()
    blocked = _private_root_preflight(root, env)
    if blocked is not None:
        return [blocked]

    results = init(root, project_id, languages=languages, tier=tier, git=True, force=force)
    if any(r.status == FAIL for r in results):
        return results

    written = private_mod.synthetic_corpus(root)
    results.append(Result(
        "create.fixture", PASS, INFO,
        f"wrote {len(written)} deterministic synthetic file(s), so the project runs on a "
        f"machine that shares nothing with this one",
        __version__, "local",
        limitations=["Synthetic by construction: no operator content is copied into a fixture."],
    ))

    data_root = private_mod.private_home(env) / project_id
    try:
        data_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        results.append(Result(
            "create.private-root", FAIL, REVIEW,
            f"could not create the private runtime data root {data_root}: {exc}",
            __version__, "local", required=False,
        ))
    else:
        results.append(Result(
            "create.private-root", PASS, INFO,
            f"private runtime data root ready at {data_root}",
            __version__, "local",
        ))
    results.extend(private_mod.boundary_results(root, env))

    commit = _initial_commit(root)
    results.append(commit)

    results.extend(registry_mod.record(project_id, root, tier,
                                       committed=commit.status == PASS, env=env))

    if backup:
        from . import backup as backup_mod  # imported here: keeps module load order free
        backup_results, archive = backup_mod.create(root, None, env=env)
        results.extend(backup_results)
        if archive is not None:
            results.extend(backup_mod.verify_restore(archive)[0])
            # Carry the location, not just a sentence about it: an operator who is told a
            # backup exists but not where it went has to go looking for it.
            results.append(Result(
                "create.backup-archive", PASS, INFO,
                f"first backup written outside the project: {archive}",
                __version__, "local", evidence_path=str(archive),
            ))

    results.append(Result(
        "create.complete", PASS, INFO,
        f"complete private project at {root}: scaffold plus synthetic fixture, one local "
        f"repository with no remote and no licence, and a registration under {project_id!r}",
        __version__, "local",
        limitations=[
            "Not done here, and not implied by anything above: no licence was chosen, no "
            "backup was taken unless --backup was passed, and `doctor` has not been run.",
            "AGENTS.md in the project is an instruction file, not enforcement. Real "
            "containment needs host permissions this tool does not configure.",
            "Passing creation checks says the mechanical controls ran -- never that the "
            "project is safe to publish.",
        ],
    ))
    return results


def exit_code(results: List[Result]) -> int:
    return exit_code_for(results)
