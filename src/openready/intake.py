"""The OR-004 "new project appeared" proposal mechanism.

Why a proposal and not an automatic creator. A background watcher is a host
change: it would run on the operator's machine, persist between sessions and
consume state the operator has not approved. None of those are tool-shaped
questions, and the work order treats them as owner-gated. What *is* a tool is
the smaller, real question: given a directory that looks like a project, what
should an agent do about it? The honest answer is to surface the candidate and
the one command that would adopt it, never to silently adopt it, and never to
do so inside a directory that is itself inside an enclosing git checkout.

Three properties, each a check rather than a promise:

1. **Existing repositories are never modified without an opt-in.** Any candidate
   that sits inside an enclosing git working tree is blocked with the reason --
   proposing to adopt it would be proposing to commit inside somebody else's tree.
2. **Symlinks, private-data directories, and already-Open-Ready directories are
   not proposed.** A symlink would let a candidate point outside the proposed
   parent. A private-data directory is never a project. An existing
   Open-Ready project or one already in the registry is not "new".
3. **Proposing writes nothing anywhere.** The function returns the list, never
   a script, never an ad-hoc file, never a tracked change. The honest label for
   the automatic half is ``NOT_ENFORCED``: no watcher exists on this host, and
   the proposal mechanism is what an owner or an agent *runs* when they want to
   check.

Honest limits: the proposal is what an agent sees; an operator can still run
``openready init --adopt --allow-inside-checkout`` and override the refusal. The
refusal is a boundary, not a lock.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label, enclosing_checkout
from .private import private_home
from .registry import registry_file
from .status import FAIL, INFO, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

PROJECT_MARKERS = (
    "package.json", "pyproject.toml", "setup.py", "Cargo.toml", "go.mod",
    "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json",
    "*.csproj", "*.sln", "Makefile", "configure",
)
OPENREADY_MARKER = "openready.project.json"
SYMLINK_BLOCK_REASON = "candidate is a symlink, not a directory"
INTAKE_ENV = "OPENREADY_INTAKE_HOME"

LIMITATION = (
    "This is a proposal mechanism: an owner or an agent runs it explicitly. A background "
    "watcher would be a host change and is not implemented (the automatic half is reported "
    "NOT_ENFORCED by `intake.auto`); running this command does not adopt anything."
)


def _candidate_kind(directory: Path) -> Optional[str]:
    """Why the directory looks like a project, or None if it does not."""
    for name in PROJECT_MARKERS:
        if "*" in name:
            if any(directory.glob(name)):
                return name
            continue
        if (directory / name).is_file():
            return name
    return None


def candidates(parent: Path, env: Optional[Dict[str, str]] = None
               ) -> Tuple[List[Dict[str, Any]], List[Result]]:
    """One entry per child directory that looks like a project, with a reason for each block.

    A blocked candidate is still in the list, with ``blocked`` set to the reason -- the
    alternative ("silently drop it") is how an agent would adopt a directory that was
    never a candidate, and that is the failure this exists to prevent.
    """
    parent = Path(parent).resolve()
    out: List[Dict[str, Any]] = []
    notes: List[Result] = []

    if not parent.is_dir():
        return [], [Result(
            "intake.parent", FAIL, STOP, f"{parent} is not a directory",
            __version__, environment_label(),
        )]

    private = private_home(env).resolve()
    encloser = enclosing_checkout(parent)

    try:
        registry = json.loads(registry_file(env).read_text(encoding="utf-8")) \
            if registry_file(env).is_file() else {"projects": {}}
    except (ValueError, OSError):
        registry = {"projects": {}}
    registered_paths = {str(Path(entry.get("path", "")).resolve())
                        for entry in (registry.get("projects") or {}).values()
                        if isinstance(entry, dict)}

    for child in sorted(parent.iterdir(), key=lambda p: p.name):
        if child.is_symlink():
            out.append({"name": child.name, "path": str(child), "looks_like": "",
                        "blocked": SYMLINK_BLOCK_REASON, "registered": False})
            continue
        if not child.is_dir():
            continue
        resolved = child.resolve()
        if resolved == private or private in resolved.parents:
            out.append({"name": child.name, "path": str(resolved), "looks_like": "",
                        "blocked": f"{resolved} is inside the private runtime data root, "
                                   f"which is never a project", "registered": False})
            continue
        if (child / OPENREADY_MARKER).is_file():
            continue
        registered = str(resolved) in registered_paths
        if registered:
            continue
        marker = _candidate_kind(child)
        if marker is None:
            continue
        blocked: Optional[str] = None
        if encloser:
            blocked = (f"{child} is inside the enclosing checkout {encloser}; adopting it would "
                       f"commit inside somebody else's tree")
        if blocked is None:
            candidate_encloser = enclosing_checkout(child)
            if candidate_encloser and candidate_encloser != str(child.resolve()):
                blocked = (f"{child} is inside a git working tree at {candidate_encloser}; "
                           f"adopting it would commit inside that tree")
        out.append({"name": child.name, "path": str(resolved), "looks_like": marker,
                    "blocked": blocked, "registered": False})

    if not out:
        notes.append(Result(
            "intake.scan", PASS, INFO,
            f"no unadopted project candidates found under {parent}",
            __version__, environment_label(), limitations=[LIMITATION],
        ))
    return out, notes


def propose(parent: Path, env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Propose candidates -- never create, never commit, never adopt."""
    found, notes = candidates(parent, env)
    results: List[Result] = list(notes)

    for entry in found:
        if entry["blocked"]:
            results.append(Result(
                "intake.blocked", FAIL, REVIEW,
                f"NOT proposed: {entry['name']} -- {entry['blocked']}",
                __version__, environment_label(), limitations=[LIMITATION],
            ))
            continue
        command = (f"openready init --path '{entry['path']}' --adopt "
                   f"--allow-inside-checkout --register")
        results.append(Result(
            "intake.proposed", PASS, INFO,
            f"{entry['name']} looks like a project ({entry['looks_like']}); to adopt it: "
            f"{command}",
            __version__, environment_label(),
            evidence_path=entry["path"],
            limitations=[LIMITATION],
        ))

    if not any(r.status in (PASS, FAIL) for r in results) and not notes:
        results.append(Result(
            "intake.propose", PASS, INFO,
            f"0 candidate(s) under {parent}", __version__, environment_label(),
            limitations=[LIMITATION],
        ))

    return results


def auto_detection_results(env: Optional[Dict[str, str]] = None) -> List[Result]:
    """The honest label for the automatic half.

    The promise is: a daemon that watches the operator's filesystem is not installed by
    this tool and was not installed by anything on its behalf. The result is required,
    so a consumer cannot read a missing entry as "not enforced at all, fine".
    """
    return [Result(
        "intake.auto", NOT_ENFORCED, REVIEW,
        "automatic intake (a host watcher that creates projects without an explicit command) "
        "is not installed; this tool proposes only on demand. The `intake` command is the "
        "mechanism an owner or an agent runs to discover candidates.",
        __version__, environment_label(), required=True, enforcement=NOT_ENFORCED,
        evidence_path=str(registry_file(env)),
        limitations=[
            "A watcher would be a host change: it would persist between sessions, run on "
            "the operator's machine and consume state the operator has not approved. None of "
            "those are tool-shaped, and none are answered here.",
            "What would verify a true automatic intake: a host-managed watcher the owner "
            "registers outside this tool, whose events this command reads.",
        ],
    )]


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    from .status import EXIT_OK, EXIT_USAGE, exit_code_for

    parser = argparse.ArgumentParser(prog="openready-intake",
                                     description="Propose unadopted projects (never silently "
                                                 "adopts). Read-only.")
    sub = parser.add_subparsers(dest="verb", required=True)
    scan = sub.add_parser("scan", help="list candidates under a parent directory")
    scan.add_argument("--parent", required=True)
    scan.add_argument("--json", action="store_true")
    propose_cmd = sub.add_parser("propose", help="propose candidates (same data, "
                                                  "rendered as a one-line command each")
    propose_cmd.add_argument("--parent", required=True)
    propose_cmd.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    parent = Path(args.parent).expanduser().resolve()
    if args.verb == "scan":
        found, _ = candidates(parent)
        if args.json:
            print(json.dumps({"parent": str(parent), "candidates": found}, indent=2))
            return EXIT_OK
        if not found:
            print(f"  no candidates under {parent}")
        for entry in found:
            mark = "BLOCKED" if entry["blocked"] else entry["looks_like"]
            print(f"  {entry['name']:<32} {mark}")
            if entry["blocked"]:
                print(f"      blocked: {entry['blocked']}")
        return EXIT_OK
    results = propose(parent) + auto_detection_results()
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return exit_code_for(results)
    for result in results:
        print(f"  {result.message}")
    return exit_code_for(results)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
