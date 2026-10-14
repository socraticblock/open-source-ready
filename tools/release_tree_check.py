#!/usr/bin/env python3
"""The published tree is an allowlist, and a note cannot enter it.

Two rules, because they fail differently and each covers the other's hole.

1. **Every tracked path is listed in `release-paths.txt`.** A new file is a decision: the pull
   request that adds it edits the list in the same change, so a reviewer sees "a path is being
   added to the public tree" as a line in a diff rather than as an absence nobody notices.
2. **No tracked path is note-shaped** — nothing under `notes/`, `private/`, `internal/`,
   `drafts/`, and no `*.note.md`. This is the rule the allowlist cannot give you, because the
   failure it guards against is somebody adding an entry to the list to make the build pass.

What neither rule can do is recognise "this paragraph reads like a private note". Arbitrary
private prose is not mechanically detectable, and the project says so instead of pretending
otherwise — the tool's own `privacy.private-prose` check is recorded as not run for this reason.
What *is* mechanical is where a note lives, and that is what is enforced here. Thinking, drafts,
evidence and anything about the operator's own setup belong in the private notes repository:
https://github.com/socraticblock/open-source-ready-notes

Run locally with: `python3 tools/release_tree_check.py`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ALLOWLIST = Path("release-paths.txt")
NOTE_DIRECTORIES = {"notes", "private", "internal", "drafts"}
NOTE_SUFFIXES = (".note.md",)


def tracked_paths() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    return sorted(line for line in out.stdout.splitlines() if line.strip())


def listed_paths() -> list[str]:
    if not ALLOWLIST.is_file():
        print(f"FAIL: {ALLOWLIST} is missing. It is the list of what may be published.")
        raise SystemExit(1)
    return sorted(
        line.strip() for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )


def note_shaped(path: str) -> str:
    """Why this path looks like a note, or an empty string."""
    parts = path.split("/")
    for part in parts[:-1]:
        if part.lower() in NOTE_DIRECTORIES:
            return f"it lives under a '{part}/' directory"
    if parts[-1].lower().endswith(NOTE_SUFFIXES):
        return "its name ends in .note.md"
    return ""


def main() -> int:
    present = tracked_paths()
    listed = listed_paths()
    problems: list[str] = []

    for path in present:
        if path not in listed:
            problems.append(
                f"  unlisted path: {path}\n"
                f"      If this is code, documentation or a test, add it to {ALLOWLIST} in this\n"
                f"      same pull request -- a new path in the published tree is a decision, and\n"
                f"      the diff is where a reviewer gets to see it.\n"
                f"      If it is a note, thinking, a draft or evidence, it belongs in the private\n"
                f"      notes repository, not here."
            )
        why = note_shaped(path)
        if why:
            problems.append(
                f"  note-shaped path: {path} -- {why}.\n"
                f"      This path is refused even if it is listed in {ALLOWLIST}: the list can be\n"
                f"      edited, and this rule exists so that editing it cannot publish a note.\n"
                f"      Write it in https://github.com/socraticblock/open-source-ready-notes and\n"
                f"      promote the finished finding instead."
            )

    for path in listed:
        if path not in present:
            problems.append(
                f"  listed but absent: {path}\n"
                f"      Remove it from {ALLOWLIST} in the same pull request that removes the file,\n"
                f"      or the list stops describing the tree it is supposed to describe."
            )

    if problems:
        print("The published tree does not match its allowlist:\n")
        print("\n".join(problems))
        print(f"\n{len(present)} path(s) present, {len(listed)} listed.")
        return 1

    print(f"allowlist holds: {len(present)} path(s), none of them note-shaped, none unlisted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
