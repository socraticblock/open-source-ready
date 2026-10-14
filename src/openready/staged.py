"""The commit-time control: catch private material before it enters history.

Why this exists. Every other control in this tool runs at export time, when a mistake is
still cheap: the candidate is written, refused, fixed, re-exported. A commit is the one
moment where a mistake stops being cheap. The blob is in the object store, a `git reset`
does not reach it, and undoing it means rewriting history or rotating the credential.
This is the last point at which the cost is still one command.

What it scans is the **staged blob** (``git ls-files -s`` then ``git cat-file blob``),
never the working-tree file. A partial stage (``git add -p``) or an edit made after
staging leaves the two different, and the blob is what becomes history.

Honest limits, stated in every result and in the installed hook itself:

* a git hook is bypassed by ``git commit --no-verify``, and by removing
  ``core.hooksPath``. It is a convenience control, **not enforcement**. The enforced
  control remains the export path, which refuses to write a candidate at all;
* only material that means "private data would enter history" blocks a commit --
  a credential shape, a host path, a database, a staged ``.env``. Structural findings
  that only matter for a release (case-fold collisions, symlinks, LFS pointers) are
  reported and do not block;
* a file that could not be read or was too large to scan is reported as ``NOT_RUN``,
  never as clean, and does not block;
* where the tool is not installed the hook allows the commit with a warning, because a
  missing lint tool must not make a repository uncommittable.

**Exit contract**, because a hook is judged by its exit code and getting this wrong makes
every commit in every project fail: ``0`` means "nothing blocking was found", ``1`` means
"this commit would put private material into history". The advisory results are therefore
``required=False``: the tool's global rule turns a required ``NOT_ENFORCED`` or ``NOT_RUN``
check into exit ``3``, which for a hook would refuse every commit -- including a clean one
-- and a control that refuses everything is one an operator disables, which is strictly
worse than having none.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from . import overrides as overrides_mod
from . import scan as scan_mod
from .status import (
    ENFORCED,  # noqa: F401  (imported for symmetry with the other modules)
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    Result,
)

#: Check ids that mean private material would enter history. Only these block.
BLOCKING_CHECK_IDS = (
    "privacy.secret-shape",
    "candidate.host-path",
    "candidate.database-file",
    "candidate.env-file",
)

LIMITATION = (
    "Advisory, not enforcement: `git commit --no-verify` skips this hook entirely, and so "
    "does removing core.hooksPath. It is a convenience control that makes the cheap moment "
    "visible; the enforced control is the export, which refuses to write a candidate."
)


def _git_bytes(root: Path, *args: str, timeout: int = 60):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          timeout=timeout, check=False)


def _is_repository(root: Path) -> bool:
    done = _git_bytes(root, "rev-parse", "--git-dir")
    return done.returncode == 0


def staged_entries(root: Path) -> Tuple[List[Tuple[str, str, str]], List[Result]]:
    """(path, blob sha, stage) for every entry in the index, or a problem."""
    done = _git_bytes(root, "ls-files", "-s", "-z")
    if done.returncode != 0:
        return [], [Result(
            "precommit.index-unreadable", NOT_RUN, REVIEW,
            f"`git ls-files -s` failed, so nothing was scanned: "
            f"{done.stderr.decode('utf-8', 'replace').strip()[:160]}",
            __version__, "local", required=False,
            limitations=["An index that could not be read is reported unrun, never clean.",
                        LIMITATION],
        )]
    entries: List[Tuple[str, str, str]] = []
    for record in done.stdout.split(b"\0"):
        if not record.strip():
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
            mode, sha, stage = meta.split()
        except ValueError:
            continue
        entries.append((raw_path.decode("utf-8", "replace"), sha.decode("ascii"),
                        stage.decode("ascii")))
    return entries, []


def blob_bytes(root: Path, sha: str) -> Optional[bytes]:
    done = _git_bytes(root, "cat-file", "blob", sha)
    return done.stdout if done.returncode == 0 else None


def changed_entries(root: Path) -> Optional[set]:
    """Index entries this commit would ADD or MODIFY relative to HEAD.

    Returns ``None`` when there is no HEAD yet (the first commit adds everything).

    This is the scope rule, and it is the difference between a usable control and one an
    operator disables: scanning the whole index means a fixture committed months ago
    re-blocks every future commit, including one that only fixes a typo. Material already
    in history is not what a commit-time control can protect -- it is already there, and
    refusing the next commit does not remove it. What this control can do is stop the
    thing *entering*.
    """
    done = _git_bytes(root, "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
    if done.returncode != 0:
        return None
    return {path.decode("utf-8", "replace")
            for path in done.stdout.split(b"\0") if path.strip()}


def run(root: Path) -> List[Result]:
    """Scan the staged set. Blocks (FAIL/STOP -> exit 1) only on private material."""
    root = Path(root).resolve()
    if not _is_repository(root):
        return [Result(
            "precommit.repository", NOT_RUN, REVIEW,
            f"{root} is not a git working tree, so there is nothing to commit and nothing "
            f"was scanned", __version__, "local", required=False,
            limitations=[LIMITATION],
        )]

    entries, problems = staged_entries(root)
    if problems:
        return problems
    changed = changed_entries(root)
    staged = [(path, sha) for path, sha, stage in entries
              if stage == "0" and (changed is None or path in changed)]
    if not staged:
        return [Result(
            "precommit.scanned", PASS, INFO,
            "nothing is staged, so there is nothing to check in this commit",
            __version__, "local", required=False, enforcement=NOT_ENFORCED,
            limitations=[LIMITATION],
        )]

    findings: List = []
    findings.extend(scan_mod.scan_paths([path for path, _ in staged]))
    unreadable: List[str] = []
    for path, sha in staged:
        data = blob_bytes(root, sha)
        if data is None:
            unreadable.append(path)
            continue
        findings.extend(scan_mod.scan_content(path, data))

    remaining, override_results = overrides_mod.apply(root, findings, report_unused=False)
    blocking = [f for f in remaining if f.check_id in BLOCKING_CHECK_IDS]
    advisory = [f for f in remaining if f.check_id not in BLOCKING_CHECK_IDS]

    results: List[Result] = []
    if blocking:
        where: Dict[str, List[str]] = {}
        for finding in blocking:
            where.setdefault(finding.check_id, []).append(finding.path or "?")
        detail = "; ".join(
            f"{check_id}: {len(paths)} file(s) ({', '.join(sorted(set(paths))[:3])})"
            for check_id, paths in sorted(where.items())
        )
        results.append(Result(
            "precommit.blocked", FAIL, STOP,
            f"this commit would put private material into history -- {detail}. "
            f"Staging is untouched; nothing has been committed.",
            __version__, "local", enforcement=NOT_ENFORCED,
            limitations=[
                "Undoing this after a commit means rewriting history or rotating the "
                "credential, which is why it is refused here instead.",
                "Acknowledged findings do not block; only unacknowledged ones do.",
                LIMITATION,
            ],
        ))
    else:
        results.append(Result(
            "precommit.scanned", PASS, INFO,
            f"{len(staged)} staged file(s) scanned from the index; no unacknowledged "
            f"credential, host path, database or .env among them",
            __version__, "local", required=False, enforcement=NOT_ENFORCED,
            limitations=[
                "This describes the staged set only. A passing check means nothing matched, "
                "never that nothing is there.",
                LIMITATION,
            ],
        ))

    results.extend(override_results)

    if advisory:
        results.append(Result(
            "precommit.advisory-findings", NEEDS_HUMAN, REVIEW,
            f"{len(advisory)} finding(s) that only matter for a release are present and do "
            f"not block this commit: "
            + "; ".join(sorted({f.check_id for f in advisory})),
            __version__, "local", required=False, enforcement=NOT_ENFORCED,
            limitations=["These block an export, not a commit. Fixing them before the commit "
                        "is usually cheaper.", LIMITATION],
        ))

    if unreadable:
        results.append(Result(
            "precommit.unscanned", NOT_RUN, REVIEW,
            f"{len(unreadable)} staged file(s) could not be read and were NOT scanned: "
            f"{', '.join(unreadable[:3])}",
            __version__, "local", required=False, enforcement=NOT_ENFORCED,
            limitations=["Not checked is reported as not checked. Nothing here says those "
                         "files are clean.", LIMITATION],
        ))
    return results


def exit_code(results: List[Result]) -> int:
    from .status import exit_code_for
    return exit_code_for(results)
