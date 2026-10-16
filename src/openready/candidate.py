"""The allowlisted candidate exporter (OR-016) and the history choice.

This replaces the inherited prototype's ``do_candidate``. The prototype exported a
project's whole tree, wrote the operator's absolute home paths and private prose
into it, then printed "NO KNOWN BLOCKERS DETECTED". Four properties here are the
correction, and each is enforced rather than described:

1. **Allowlist, not exclude-list.** The candidate is the set of paths git tracks
   (or, with no repository, paths that survive the portability rules). A file the
   operator never added cannot reach the candidate by accident.
2. **Build-failing.** If any check reports a STOP, the export writes **nothing at
   all** and exits 1. A candidate that is written and then criticised is a
   candidate that gets shipped anyway.
3. **The digest is over content only.** ``MANIFEST.json`` and ``CANDIDATE.json``
   describe the candidate and are not part of its identity, so the digest can be
   recomputed by a stranger from the files alone and cannot be self-referential.
4. **Nothing here publishes.** This module never invokes ``gh``, never sets a
   remote and never changes visibility. The only artifact it can produce is an
   *unapproved* candidate and its evidence.

The history choice is explicit, because a clean tree does not imply a clean
history:

- ``none`` (default) -- export the file tree only. Nothing from history travels.
- ``squash`` -- create a single-commit repository in the candidate. This uses a
  placeholder identity and records a required owner decision, because the commit
  author would otherwise be the operator's real address.
- ``preserve`` -- clone with history, permitted only when the history scan found
  nothing. Otherwise the export fails: two commits do not remove an object.

Neither ``squash`` nor ``preserve`` is reachable from the public release workflow. Both
carry history into an artifact whose reader cannot tell an acknowledged finding from a
removed one: the same bytes are in it either way. A first public release therefore
supports ``none`` alone. ``export`` refuses the other two before it writes anything, and
only an internal caller that passes ``history_modes_allowed=True`` (the tests, and any
research into what a history-carrying release would require) can reach them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import PUBLICATION_STATUS, __version__
from . import boundaries
from .capabilities import environment_label
from .history import (
    HISTORY_LIMITATION,
    content_digest,
    findings as history_findings,
    is_repository as is_git_repository,
    results as history_results,
    scan as history_scan,
    scanned_completely as history_scanned_completely,
)
from .overrides import apply as apply_overrides
from .overrides import entry_covers
from .overrides import entry_key
from .overrides import finding_key
from .overrides import load as overrides_load
from .overrides import normalise_path as normalise_entry_path
from .private import BOUNDARY_LIMITATION
from .scan import (
    DENYLIST_LIMITATION,
    PROSE_LIMITATION,
    Finding,
    scan_file,
    scan_paths,
    scan_structure,
    safe_relative,
)
from .status import FAIL, INFO, NEEDS_HUMAN, PASS, REVIEW, STOP, Result

CANDIDATE_DIRNAME = ".openready-candidate"
MANIFEST_NAME = "MANIFEST.json"
CANDIDATE_NAME = "CANDIDATE.json"
TOOL_FILES = {MANIFEST_NAME, CANDIDATE_NAME}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    CANDIDATE_DIRNAME,
}

PLACEHOLDER_IDENTITY = "Open-Ready Candidate <candidate@openready.invalid>"

EXPORT_LIMITATION = (
    "An exported candidate is UNAPPROVED. Nothing in this tool authorises publication, "
    "and a passing scan on this machine is not evidence that the candidate is safe."
)

CANDIDATE_SCHEMA_VERSION = "1.0"


def _tracked(root: Path) -> Optional[List[str]]:
    probe = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0 or probe.stdout.strip() != b"true":
        return None
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
    )
    if listing.returncode != 0:
        raise boundaries.BoundaryError(
            "Git tracked-file enumeration failed; refusing a fallback walk"
        )
    return [p.decode("utf-8", "surrogateescape") for p in listing.stdout.split(b"\x00") if p]


def source_revision(root: Path) -> Optional[str]:
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, check=False
    )
    if head.returncode != 0:
        return None
    return head.stdout.decode("ascii", "replace").strip()


def _worktree_dirty(root: Path) -> bool:
    """True when the working tree differs from HEAD (untracked files count)."""
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"], capture_output=True, check=False
    )
    return status.returncode == 0 and bool(status.stdout.strip())


def plan(root: Path, project_id: str = "") -> Dict[str, Any]:
    """Decide what would be exported, and what is held back and why."""
    root = Path(root)
    included: List[str] = []
    excluded: List[Dict[str, str]] = []
    untracked: List[str] = []
    tracked = _tracked(root)
    allowlist = (
        "git-tracked files" if tracked is not None else "portability allowlist (no repository)"
    )

    candidates = tracked if tracked is not None else _walk(root)
    if tracked is not None:
        # The allowlist is the set of tracked files, so a file that exists here but is
        # not tracked appears in neither list and is silently missing from the
        # candidate. `doctor` scans it and the exporter does not, which is how two
        # surfaces came to disagree about the same file.
        listed = set(tracked)
        untracked = [rel for rel in _walk(root) if rel not in listed]
    for rel in candidates:
        rel = rel.replace("\\", "/")
        name = rel.rsplit("/", 1)[-1]
        if name in TOOL_FILES:
            excluded.append(
                {"path": rel, "reason": "tool metadata: describing a candidate is not part of it"}
            )
            continue
        if name.startswith(".openready-"):
            excluded.append(
                {"path": rel, "reason": "Open-Ready state file: private to this machine"}
            )
            continue
        try:
            safe_relative(rel)
        except ValueError as exc:
            excluded.append({"path": rel, "reason": str(exc)})
            continue
        if not (root / rel).is_file():
            excluded.append({"path": rel, "reason": "not a regular file here"})
            continue
        included.append(rel)

    return {
        "project_id": project_id,
        "allowlist": allowlist,
        "included": sorted(included),
        "excluded": sorted(excluded, key=lambda item: item["path"]),
        "untracked": sorted(untracked),
    }


def _walk(root: Path) -> List[str]:
    out: List[str] = []
    for where, dirs, names in os.walk(root, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            out.append((Path(where) / name).relative_to(root).as_posix())
    return out


def inspect(
    root: Path, paths: List[str], snapshot: Optional[Tuple[boundaries.FrozenFile, ...]] = None
) -> List[Finding]:
    """Content and path checks over the planned set, before anything is written."""
    root = Path(root)
    findings: List[Finding] = list(scan_structure(root))
    try:
        frozen = snapshot if snapshot is not None else boundaries.capture(root, paths)
    except (OSError, ValueError) as exc:
        return findings + [Finding("candidate.unreadable", str(exc), "")]
    for item in frozen:
        findings.extend(scan_file(item.path, item.data))
    findings.extend(scan_paths(paths))
    return findings


def _entry_key(check_id: str, path: str) -> Tuple[str, str]:
    try:
        return (check_id, normalise_entry_path(path))
    except ValueError:
        return (check_id, "")


def _acknowledged(findings: List[Finding], root: Path) -> List[Dict[str, Any]]:
    """The full acknowledgement entries that suppressed something.

    The whole entry travels -- reason, who, when, expiry, and the object id it names --
    because the verifier has to be able to judge whether the reason is credible and
    whether the entry has lapsed. Carrying only ``check_id`` and ``path`` let a frozen
    candidate assert "the operator acknowledged this" with no evidence behind it, and
    left the exception wider than the entry that recorded it.
    """
    remaining, _ = apply_overrides(root, findings)
    kept = {finding_key(f) for f in remaining}
    document, _ = overrides_load(root)
    entries = [
        entry for entry in (document or {}).get("entries", []) or [] if isinstance(entry, dict)
    ]
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for finding in findings:
        if finding_key(finding) in kept:
            continue
        entry = next(
            (
                item
                for item in entries
                if entry_covers(item, finding.check_id, finding.path, finding.object_id)
            ),
            None,
        )
        key = entry_key(entry) if entry else finding_key(finding)
        record: Dict[str, Any] = {"check_id": finding.check_id, "path": finding.path}
        # The object travels only when the *entry* names one. A path-only entry that
        # happened to suppress a blob finding must not read as a narrow exception.
        if entry and entry.get("object"):
            record["object"] = entry["object"]
        for field in ("reason", "acknowledged_by", "acknowledged_at", "expires"):
            if entry and entry.get(field):
                record[field] = entry[field]
        seen[key] = record
    return sorted(
        seen.values(), key=lambda item: (item["check_id"], item["path"], item.get("object", ""))
    )


def export(
    root: Path,
    out: Path,
    project_id: str = "",
    history_mode: str = "none",
    history_report: Optional[Dict[str, Any]] = None,
    history_modes_allowed: bool = False,
    acknowledged: Optional[List[Dict[str, str]]] = None,
    source_files: Optional[List[str]] = None,
) -> Tuple[List[Result], Optional[Dict[str, Any]]]:
    """Write the candidate. Returns (results, candidate_metadata-or-None).

    On any STOP the destination is left untouched: nothing is written, and any
    directory this call created is removed again.
    """
    root = Path(root).resolve()
    out = Path(os.path.abspath(out))
    try:
        results, paths = _preflight(root, out, project_id, source_files)
    except (OSError, ValueError) as exc:
        return [
            Result("candidate.preflight", FAIL, STOP, str(exc), __version__, environment_label())
        ], None
    if paths is None:
        return results, None
    try:
        snapshot = boundaries.capture(root, paths)
    except (OSError, ValueError) as exc:
        results.append(
            Result("candidate.snapshot", FAIL, STOP, str(exc), __version__, environment_label())
        )
        return results, None
    if any(item.data.startswith(LFS_POINTER_HEAD) for item in snapshot):
        return [
            Result(
                "candidate.lfs-pointer",
                FAIL,
                STOP,
                "snapshot contains an LFS pointer",
                __version__,
                environment_label(),
            )
        ], None
    decision_results, decision = _decide(
        root, paths, snapshot, history_mode, history_report, history_modes_allowed
    )
    results.extend(decision_results)
    if decision is None:
        return results, None
    destination = out
    # Keep the parent descriptor open across staging and promotion. A changed path
    # cannot redirect rename into an unrelated directory.
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with boundaries.directory(destination.parent) as parent_fd:
            parent_identity = os.fstat(parent_fd)
            with tempfile.TemporaryDirectory(
                prefix=".openready-stage-", dir=destination.parent
            ) as tmp:
                out = Path(tmp) / "artifact"
                out.mkdir(mode=0o700)
                records = _assemble_snapshot(out, snapshot)
                payload = [(item.path, item.data) for item in snapshot]
                meta = _finalize_artifact(
                    out,
                    root,
                    project_id,
                    decision.mode,
                    records,
                    payload,
                    decision.acknowledged,
                    decision.tree_acknowledged,
                    paths,
                )
                current = destination.parent.stat()
                if (current.st_dev, current.st_ino) != (
                    parent_identity.st_dev,
                    parent_identity.st_ino,
                ):
                    raise boundaries.BoundaryError("destination parent changed during export")
                # POSIX rename refuses to replace nonempty directories or symlinks
                # with a directory. Existing candidate artifacts stay untouched.
                os.rename(out, destination.name, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
    except (OSError, ValueError) as exc:
        results.append(
            Result(
                "candidate.export",
                FAIL,
                STOP,
                f"export refused: {exc}",
                __version__,
                environment_label(),
            )
        )
        return results, None

    digest = str(meta["candidate_digest"])
    results.append(
        Result(
            "candidate.export",
            PASS,
            INFO,
            f"wrote {len(snapshot)} file(s) with digest {digest}; status {PUBLICATION_STATUS}",
            __version__,
            environment_label(),
            candidate_digest=digest,
            limitations=[EXPORT_LIMITATION],
        )
    )
    return results, meta


@dataclass(frozen=True)
class ExportDecision:
    mode: str
    acknowledged: List[Dict[str, Any]]
    tree_acknowledged: List[Dict[str, Any]]


def _preflight(
    root: Path, out: Path, project_id: str, source_files: Optional[List[str]]
) -> Tuple[List[Result], Optional[List[str]]]:
    """Plan portable paths and reject unsafe destinations without writing."""
    results: List[Result] = []
    paths = source_files if source_files is not None else plan(root, project_id)["included"]

    inside_project = out == root or root in out.parents
    if inside_project and out != root / CANDIDATE_DIRNAME:
        results.append(
            Result(
                "candidate.destination",
                FAIL,
                STOP,
                (
                    f"{out} is inside the project; a candidate must be a separate tree, and the "
                    f"only in-project location permitted is {CANDIDATE_DIRNAME}/"
                ),
                __version__,
                environment_label(),
            )
        )
        return results, None

    # Immutable destinations make promotion one atomic rename and preserve old evidence.
    # Never merge into a previous artifact: even its metadata is untrusted input.
    if out.is_symlink() or (out.exists() and (not out.is_dir() or any(out.iterdir()))):
        results.append(
            Result(
                "candidate.destination",
                FAIL,
                STOP,
                "destination must be absent or an empty directory; use a new output path",
                __version__,
                environment_label(),
            )
        )
        return results, None

    planned = plan(root, project_id)
    paths = source_files if source_files is not None else planned["included"]
    try:
        for rel in paths:
            safe_relative(rel)
            if rel in TOOL_FILES:
                raise ValueError("source list contains reserved metadata")
    except (TypeError, ValueError) as exc:
        return [
            Result("candidate.source-path", FAIL, STOP, str(exc), __version__, environment_label())
        ], None
    # Files a path rule refuses are dropped from the candidate and mentioned nowhere
    # else, so the operator reads "wrote 10 file(s)" and never learns that
    # `data/records.db` was left out. The exclusion is deliberate and safe; its silence
    # is the same defect as a check that reports nothing. Reported, not blocking.
    refused_paths = [
        item
        for item in planned["excluded"]
        if "non-portable path component" in item.get("reason", "")
    ]
    if refused_paths:
        results.append(
            Result(
                "candidate.path-rules-excluded",
                NEEDS_HUMAN,
                REVIEW,
                (
                    f"{len(refused_paths)} file(s) are deliberately not in this candidate because "
                    f"a path rule refuses them: "
                    f"{', '.join(item['path'] for item in refused_paths[:4])}"
                ),
                __version__,
                environment_label(),
                required=False,
                limitations=[
                    "Excluded by rule, not by judgement: a database, key or device "
                    "file named here is held back on purpose and is not scanned."
                ],
            )
        )

    # Git can still list a tracked file after an unstaged working-tree deletion.
    # Omitting it from the artifact is safe, and may be deliberate, but should not
    # disappear from the machine-readable results of an otherwise successful export.
    unavailable = [
        item
        for item in planned["excluded"]
        if item.get("reason") == "not a regular file here"
    ]
    if unavailable:
        results.append(
            Result(
                "candidate.tracked-unavailable",
                NEEDS_HUMAN,
                REVIEW,
                (
                    f"{len(unavailable)} Git-tracked path(s) are unavailable in the working tree "
                    f"and absent from this candidate: "
                    f"{', '.join(item['path'] for item in unavailable[:4])}. "
                    "Confirm that omitting these tracked paths is intentional."
                ),
                __version__,
                environment_label(),
                required=False,
                limitations=[
                    "This reports tracked paths excluded from the current working tree. "
                    "Staged removals no longer appear in Git's tracked-file list; "
                    "artifact completeness still requires human review."
                ],
            )
        )

    # Hazard scan: a candidate is a *promise* about what is being released, so the
    # exporter refuses a tree that would carry a symlink (which can reach outside the
    # project at run time), a hardlink (which on most filesystems reuses the same
    # inode and cannot be cleanly extracted), a casefold collision that becomes a
    # silent overwrite on Windows, a reserved name (CON, NUL, ... on Windows), a
    # tracked LFS pointer (which is a 130-byte stub, not the asset) or a tracked
    # .gitmodules (a submodule -- the candidate does not carry it). Reporting the
    # hazard and writing the candidate anyway would be a fail-open design.
    #
    # Each hazard class is reported as its own ``candidate.<class>`` check row so
    # callers (the acceptance harness, the unit tests, the review packet) can
    # ask "is there a casefold-collision?" without parsing a message. The single
    # ``candidate.hazards`` roll-up is the summary; it carries the same FAIL/STOP
    # status as the per-class rows so the exit code is unchanged.
    _HAZARD_CLASS_TO_CHECK = {
        "symlink": "candidate.symlink",
        "hardlink": "candidate.hardlink",
        "casefold": "candidate.casefold-collision",
        "lfs-pointer": "candidate.lfs-pointer",
        "submodule": "candidate.submodule",
        "gitmodules": "candidate.submodule",
        "reserved": "candidate.reserved-name",
    }
    hazards = _scan_hazards(root, paths)
    if hazards:
        classes = sorted({h["class"] for h in hazards})
        sample = ", ".join(f"{h['path']} ({h['class']})" for h in hazards[:4])
        class_phrase = ", ".join(classes)
        # Per-class rows first: each one names the specific class so the packet
        # and the unit tests can find it by check_id.
        for hclass in classes:
            chk = _HAZARD_CLASS_TO_CHECK.get(hclass, f"candidate.hazard.{hclass}")
            members = [h for h in hazards if h["class"] == hclass]
            members_sample = ", ".join(m["path"] for m in members[:3])
            results.append(
                Result(
                    chk,
                    FAIL,
                    STOP,
                    (
                        f"{len(members)} tracked path(s) have class {hclass}: {members_sample}. "
                        f"The exporter refuses to write a candidate that carries this hazard."
                    ),
                    __version__,
                    environment_label(),
                    limitations=[
                        "The hazard scan is a path walk of the tracked tree. An "
                        "untracked hazard file is not detected; an untracked one "
                        "is also not in the candidate."
                    ],
                )
            )
        results.append(
            Result(
                "candidate.hazards",
                FAIL,
                STOP,
                (
                    f"{len(hazards)} export-hazard(s) found, classes {class_phrase}: {sample}. "
                    f"Submodules, LFS pointers, symlinks, hardlinks, reserved names, and "
                    f"casefold collisions are not safely portable; no candidate was written. "
                    f"Refusing the export is the safety property; `git clone --no-hardlinks` "
                    f"and the manifest do not see the hazard once it is checked in. To export, "
                    f"remove the hazard (untrack the symlink, delete the hardlink, rename the "
                    f"casefold-collision, remove the .gitmodules and the submodule, or move "
                    f"the LFS asset out of the tracked set) and run `candidate` again."
                ),
                __version__,
                environment_label(),
                limitations=[
                    "The hazard scan is a path walk of the tracked tree, not of "
                    "the working tree. An untracked hazard file is not detected; "
                    "an untracked one is also not in the candidate."
                ],
            )
        )
        return results, None
    # The allowlist is git-tracked files, so an uncommitted file is in neither the
    # included nor the excluded list: it is simply absent, and the operator who just
    # wrote a README is never told why their file is not in the release. Reported, not
    # blocking -- whether it should be committed is not this tool's decision.
    if planned["untracked"]:
        shown = ", ".join(planned["untracked"][:4])
        results.append(
            Result(
                "candidate.untracked-absent",
                NEEDS_HUMAN,
                REVIEW,
                (
                    f"{len(planned['untracked'])} file(s) exist here but are not tracked, so they "
                    f"are not in this candidate at all: {shown}"
                ),
                __version__,
                environment_label(),
                required=False,
                limitations=[
                    "The allowlist is the set of tracked files. An untracked file is "
                    "not scanned and not exported, and `doctor` does scan it, so the "
                    "two surfaces can disagree about the same file."
                ],
            )
        )

    # Completeness: an export is a *promise* that the project still builds. The
    # tool cannot run every project's tests, but it can name the things that
    # indicate the project is incomplete. A tracked .gitmodules is a submodule
    # (a vendor branch that the candidate will not carry); a tracked LFS
    # pointer is a 130-byte stub in place of the asset; a tracked lockfile
    # without the corresponding manifest means the candidate is exporting a
    # frozen set of versions that is not what the project ships. None of these
    # is a "stop" -- the operator may be exporting a snapshot on purpose --
    # but a `review` row names what is missing so the review packet is honest.
    tracked_set = set(paths)
    tracked_lfs_pointers = [p for p in paths if _is_lfs_pointer(root / p)]
    has_gitmodules = ".gitmodules" in tracked_set
    tracked_lockfiles = [
        p
        for p in paths
        if p.endswith("package-lock.json")
        or p.endswith("yarn.lock")
        or p.endswith("pnpm-lock.yaml")
        or p.endswith("Cargo.lock")
        or p.endswith("poetry.lock")
        or p.endswith("composer.lock")
    ]
    tracked_manifests = [
        p
        for p in paths
        if p.endswith("package.json")
        or p.endswith("pyproject.toml")
        or p.endswith("Cargo.toml")
        or p.endswith("composer.json")
        or p.endswith("go.mod")
    ]
    missing_lockfile = tracked_manifests and not tracked_lockfiles
    completeness_issues: List[str] = []
    if has_gitmodules:
        completeness_issues.append(
            ".gitmodules is tracked -- submodules are not carried in the candidate; "
            "the owner decides whether the project still builds without them"
        )
    if tracked_lfs_pointers:
        sample = ", ".join(tracked_lfs_pointers[:3])
        completeness_issues.append(
            f"tracked LFS pointer(s) at {sample} are stubs, not assets; the candidate "
            f"carries the pointer text only and the asset is missing"
        )
    if missing_lockfile:
        completeness_issues.append(
            f"manifests are tracked ({', '.join(tracked_manifests[:2])}) but no lockfile "
            f"is -- a candidate without a lockfile is not necessarily reproducible"
        )
    if completeness_issues:
        results.append(
            Result(
                "candidate.completeness",
                NEEDS_HUMAN,
                REVIEW,
                f"{len(completeness_issues)} completeness item(s) for the owner to confirm: "
                + "; ".join(completeness_issues),
                __version__,
                environment_label(),
                required=False,
                limitations=[
                    "The tool names what is missing. Whether the project still works "
                    "without it is a review item."
                ],
            )
        )
    if not paths:
        results.append(
            Result(
                "candidate.content",
                FAIL,
                STOP,
                (
                    "nothing to export: the allowlist is empty. An empty candidate would carry the "
                    "digest of empty input and verify as clean, which says nothing at all"
                ),
                __version__,
                environment_label(),
            )
        )
        return results, None
    missing_docs = not any(p.lower().startswith(("readme", "docs/readme")) for p in paths)
    if missing_docs:
        results.append(
            Result(
                "candidate.documented",
                NEEDS_HUMAN,
                REVIEW,
                "the candidate contains no README, so a stranger has no entry point",
                __version__,
                environment_label(),
                required=False,
            )
        )

    return results, paths


def _decide(
    root: Path,
    paths: List[str],
    snapshot: Tuple[boundaries.FrozenFile, ...],
    history_mode: str,
    history_report: Optional[Dict[str, Any]],
    history_modes_allowed: bool,
) -> Tuple[List[Result], Optional[ExportDecision]]:
    """Inspect captured bytes and resolve the explicit history/exception policy."""
    results: List[Result] = []
    findings = inspect(root, paths, snapshot)

    # Safe by default: never export out of a repository without having looked at its
    # object store. A caller who forgets to pass a report would otherwise get a
    # silent skip, which is the failure this tool exists to prevent.
    if history_report is None and is_git_repository(root):
        history_report = history_scan(root)

    # History hits go through the same acknowledgement path, so an acknowledged
    # positive control does not block once for the file and once for its blob.
    #
    # One pass over the union, not one pass per source. Two passes reported the same
    # entry twice in a single run: an acknowledgement that matched a blob but not the
    # working tree was announced as "matched nothing -- the finding is gone" by the
    # first pass and as "acknowledged (1 occurrence)" by the second.
    history_hits = history_findings(history_report)
    acknowledged = _acknowledged(findings + history_hits, root)
    # What *this* export decided on. With `--history none` nothing from the object store
    # travels, so an acknowledgement of a blob is not part of this artifact -- recording it
    # would publish the development history's file names, reasons and reviewer into a tree
    # that contains none of that. Found by exporting this tool for publication: the manifest
    # of a 72-file, single-commit release tree named the development repository's own
    # documents. `squash` and `preserve` still carry the whole list, because there the
    # residue is the reason for the mode.
    tree_acknowledged = _acknowledged(findings, root)
    remaining, override_results = apply_overrides(root, findings + history_hits)

    # The mode decides what stops the write, so the two sources must be separable
    # again: a tree finding is a STOP, a history finding is governed by --history.
    hit_ids = {id(item) for item in history_hits}
    findings = [item for item in remaining if id(item) not in hit_ids]
    history_unresolved = [item for item in remaining if id(item) in hit_ids]

    # The acknowledgement diagnostics belong to every outcome, including a refusal.
    # They used to be added after the refusal return, so an entry that was malformed,
    # expired, or matched nothing was invisible for as long as the export kept failing
    # -- and a mistyped acknowledgement path makes it fail forever. The operator's only
    # escape hatch reported nothing back.
    results.extend(override_results)

    blocking = [f for f in findings if f.status == FAIL]
    # An incomplete scan cannot support the history decision this export is about to
    # record. When rev-list fails, or blobs above the size bound were never read, the
    # tool did not check the object store -- and writing a file set to disk under a
    # verdict it never reached is the "written and then criticised" failure this tool
    # exists to prevent.
    if history_report is not None and is_git_repository(root):
        complete, why_not = history_scanned_completely(history_report)
        if not complete:
            results.append(
                Result(
                    "candidate.history-unscanned",
                    FAIL,
                    STOP,
                    (
                        f"no candidate was written: the object store was not fully scanned "
                        f"({why_not}). A clone of the source repository carries whatever was not "
                        f"read."
                    ),
                    __version__,
                    environment_label(),
                    limitations=[HISTORY_LIMITATION],
                )
            )
            return results, None
    by_check: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_check.setdefault(finding.check_id, []).append(finding)
    for check_id in sorted(by_check):
        group = by_check[check_id]
        worst = group[0]
        # Distinct paths, not the first four raw findings: four hits on one path used to
        # fill the message while the rest of the paths were never named, which is the
        # same "act on this, but we will not say on what" defect as the history message.
        per_path: Dict[str, int] = {}
        for item in group:
            per_path[item.path] = per_path.get(item.path, 0) + 1
        ordered_paths = sorted(per_path.items(), key=lambda kv: (-kv[1], kv[0]))
        rendered = "; ".join(
            (f"{path} x{count}" if count > 1 else path) for path, count in ordered_paths[:4]
        )
        more = f" (+{len(ordered_paths) - 4} more file(s))" if len(ordered_paths) > 4 else ""
        results.append(
            Result(
                check_id,
                FAIL,
                STOP,
                f"{len(group)} occurrence(s) in {len(ordered_paths)} file(s): {rendered}{more}",
                __version__,
                environment_label(),
                limitations=[worst.limitation] if worst.limitation else [],
            )
        )

    if blocking:
        results.append(
            Result(
                "candidate.export",
                FAIL,
                STOP,
                f"export refused: {len(blocking)} blocking finding(s). No candidate was written.",
                __version__,
                environment_label(),
                limitations=[EXPORT_LIMITATION],
            )
        )
        return results, None

    mode = history_mode
    if mode not in ("none", "squash", "preserve"):
        results.append(
            Result(
                "candidate.history-mode",
                FAIL,
                STOP,
                f"unknown history mode {mode!r}; expected none, squash or preserve",
                __version__,
                environment_label(),
            )
        )
        return results, None
    # The public release workflow has one history policy: none. An artifact that carries
    # history cannot be read as "the acknowledged finding was removed", because the same
    # bytes travel either way. So squash and preserve refuse here, before anything is
    # written, rather than being quietly converted to none: a silent conversion exports a
    # different artifact than the operator asked for and says nothing about it.
    if mode != "none" and not history_modes_allowed:
        results.append(
            Result(
                "candidate.history-mode",
                FAIL,
                STOP,
                (
                    f"history mode {mode!r} is not available: the public release workflow exports "
                    f"without Git history, because an artifact that carries history cannot show "
                    f"that an acknowledged finding was removed. No candidate was written. Use the "
                    f"default (--history none) and publish the file tree to a new repository."
                ),
                __version__,
                environment_label(),
                limitations=[HISTORY_LIMITATION],
            )
        )
        return results, None
    if mode == "preserve":
        report = history_report
        if report is None or not report.get("is_repository"):
            results.append(
                Result(
                    "candidate.history-mode",
                    FAIL,
                    STOP,
                    "preserve requires a history scan of a git repository",
                    __version__,
                    environment_label(),
                )
            )
            return results, None
        # The gate is the post-acknowledgement set, not the raw hit count: an
        # acknowledged positive control must not make preserve permanently impossible.
        if history_unresolved:
            results.append(
                Result(
                    "candidate.history-mode",
                    FAIL,
                    STOP,
                    f"preserve refused: {len(history_unresolved)} unresolved finding(s) remain in "
                    f"the object store, and a clone carries every one of them",
                    __version__,
                    environment_label(),
                    limitations=[HISTORY_LIMITATION],
                )
            )
            return results, None
        # A partial scan cannot support "the history is clean". Blobs above the size
        # bound were never read, so preserve could ship exactly what was skipped --
        # which is how a 4.5 MiB blob carrying a key reached a clone.
        complete, why_not = history_scanned_completely(report)
        if not complete:
            results.append(
                Result(
                    "candidate.history-mode",
                    FAIL,
                    STOP,
                    f"preserve refused: {why_not}. A clone carries whatever was not scanned.",
                    __version__,
                    environment_label(),
                    limitations=[HISTORY_LIMITATION],
                )
            )
            return results, None
        # A clone ships what HEAD contains, not what the working tree contains. With
        # uncommitted changes the manifest would describe a tree the candidate does
        # not hold, so the digest would be a lie.
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"], capture_output=True, check=False
        )
        if status.returncode != 0 or status.stdout.strip():
            results.append(
                Result(
                    "candidate.history-mode",
                    FAIL,
                    STOP,
                    (
                        "preserve refused: the working tree has uncommitted changes, so the clone "
                        "would not match the exported manifest"
                    ),
                    __version__,
                    environment_label(),
                )
            )
            return results, None
    elif history_modes_allowed and history_unresolved:
        # Reachable only from an internal caller. With the public workflow restricted to
        # none, a historical finding is not a precondition for anything: a none candidate
        # contains none of the history the finding is about. Requiring an acknowledgement
        # here made "export the file tree only" depend on signing off on bytes that do not
        # travel, which teaches the operator to acknowledge rather than to look.
        # A value that is still in the object store and has not been acknowledged is a
        # STOP that must stop the write. Reporting the STOP and writing the candidate
        # anyway is the exact "written and then criticised" failure this tool exists
        # to prevent. Acknowledged-but-present is handled separately below, as a
        # recorded human decision rather than a refusal.
        #
        # Grouped by (path, check_id), not truncated raw. Twenty hits on five distinct
        # pairs rendered as the first four raw hits -- four identical lines -- so the
        # message told the operator to "acknowledge each one explicitly" while naming
        # one of the five things they had to acknowledge.
        pairs: Dict[Tuple[str, str], int] = {}
        for item in history_unresolved:
            pairs[(item.path, item.check_id)] = pairs.get((item.path, item.check_id), 0) + 1
        ordered = sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0]))
        detail = "; ".join(
            (f"{path} ({check_id}) x{count}" if count > 1 else f"{path} ({check_id})")
            for (path, check_id), count in ordered[:6]
        )
        more = f" and {len(ordered) - 6} further pair(s)" if len(ordered) > 6 else ""
        results.append(
            Result(
                "candidate.history-unacknowledged",
                FAIL,
                STOP,
                (
                    f"{len(history_unresolved)} unacknowledged finding(s) across "
                    f"{len(ordered)} distinct path(s)/check(s) remain in the object store: "
                    f"{detail}{more}. No candidate was written. Acknowledge each pair "
                    f"explicitly, or start a fresh history."
                ),
                __version__,
                environment_label(),
                limitations=[HISTORY_LIMITATION],
            )
        )
        return results, None

    if history_report is not None:
        results.extend(
            history_results(
                history_report,
                unresolved=len(history_unresolved),
            )
        )
        # The object store describes HEAD; the manifest describes the working tree.
        # Those are the same only when the tree is clean, and saying so is cheap.
        if _worktree_dirty(root):
            results.append(
                Result(
                    "candidate.revision-matches-worktree",
                    NEEDS_HUMAN,
                    REVIEW,
                    (
                        "the working tree has uncommitted changes, so the history scan describes "
                        "HEAD while this candidate describes the working tree; the two are "
                        "different revisions"
                    ),
                    __version__,
                    environment_label(),
                    required=False,
                    limitations=[HISTORY_LIMITATION],
                )
            )
    return results, ExportDecision(history_mode, acknowledged, tree_acknowledged)


def _assemble_snapshot(
    out: Path, snapshot: Tuple[boundaries.FrozenFile, ...]
) -> List[Dict[str, Any]]:
    """Write only captured bytes into a private, previously empty staging tree."""
    records: List[Dict[str, Any]] = []
    for item in snapshot:
        target = out / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(item.data)
            handle.flush()
            os.fsync(handle.fileno())
        target.chmod(item.mode)
        records.append(item.record())
    return records


def _finalize_artifact(
    out: Path,
    root: Path,
    project_id: str,
    mode: str,
    records: List[Dict[str, Any]],
    payload: List[Tuple[str, bytes]],
    acknowledged: List[Dict[str, Any]],
    tree_acknowledged: List[Dict[str, Any]],
    paths: List[str],
) -> Dict[str, Any]:
    """Seal metadata after assembly; only the caller can promote this staging tree."""
    digest = content_digest(payload)

    if mode == "squash":
        _squash(out, project_id, paths)
    elif mode == "preserve":
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        clone = subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(root), str(out)],
            capture_output=True,
            check=False,
        )
        if clone.returncode != 0:
            raise boundaries.BoundaryError("history clone failed")
        actual = boundaries.capture(out, paths)
        if content_digest([(item.path, item.data) for item in actual]) != digest:
            raise boundaries.BoundaryError("cloned tree differs from scanned snapshot")

    manifest = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "digest": digest,
        "file_count": len(records),
        "total_bytes": sum(r["bytes"] for r in records),
        "files": records,
    }
    (out / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    meta: Dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "tool_version": __version__,
        "project_id": project_id,
        "candidate_digest": digest,
        "file_count": len(records),
        "history_mode": mode,
        "source_revision": source_revision(root),
        "publication_status": PUBLICATION_STATUS,
        "acknowledged_findings": sorted(
            acknowledged if mode != "none" else tree_acknowledged, key=lambda i: i.get("path", "")
        ),
        "required_owner_decisions": _owner_decisions(mode, project_id),
        "not_run_checks": [
            {"check_id": "privacy.private-prose", "reason": PROSE_LIMITATION},
            {"check_id": "privacy.secret-shape/deny-list", "reason": DENYLIST_LIMITATION},
            {"check_id": "private.boundary", "reason": BOUNDARY_LIMITATION},
        ],
        "limitations": [EXPORT_LIMITATION],
    }
    if mode == "squash":
        meta["squash_identity"] = PLACEHOLDER_IDENTITY
    (out / CANDIDATE_NAME).write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return meta


def _owner_decisions(mode: str, project_id: str) -> List[Dict[str, str]]:
    decisions = [
        {"decision": "license", "why": "no licence has been chosen; adding one is an owner act"},
        {
            "decision": "publication_scope",
            "why": "what may be published, and where, is an owner act",
        },
        {
            "decision": "rights",
            "why": "ownership and third-party rights cannot be verified automatically",
        },
    ]
    if mode == "squash":
        decisions.append(
            {
                "decision": "public_commit_identity",
                "why": (
                    f"the candidate history uses the placeholder {PLACEHOLDER_IDENTITY!r}; the "
                    f"owner must choose the identity that will be public"
                ),
            }
        )
    if project_id:
        decisions.append(
            {
                "decision": "destination",
                "why": "no destination has been proposed for this candidate",
            }
        )
    return decisions


RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
LFS_POINTER_HEAD = b"version https://git-lfs.github.com/spec/v1\n"


def _is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(LFS_POINTER_HEAD)) == LFS_POINTER_HEAD
    except OSError:
        return False


def _scan_hazards(root: Path, paths: List[str]) -> List[Dict[str, str]]:
    """Walk ``paths`` and surface every entry that an honest export must refuse.

    Five classes: symlink (escapes the project at run time), hardlink (shares
    an inode with another file and cannot be cleanly extracted), reserved
    (Windows device name like CON/NUL), casefold-collision (two tracked paths
    that differ only in case and overwrite each other on Windows), lfs-pointer
    (tracked 130-byte stub that is not the asset it points at).
    """
    root = Path(root)
    findings: List[Dict[str, str]] = []
    seen_inodes: Dict[Tuple[int, int], str] = {}
    seen_lower: Dict[str, str] = {}
    for rel in paths:
        full = root / rel
        if not full.exists():
            continue
        try:
            st = full.stat()
        except OSError:
            continue
        try:
            lst = full.lstat()
        except OSError:
            lst = st
        if lst.st_mode & 0o170000 == 0o120000:  # symlink
            findings.append({"path": rel, "class": "symlink"})
            continue
        if st.st_nlink > 1 and lst.st_mode & 0o170000 != 0o120000:
            key = (st.st_dev, st.st_ino)
            prior = seen_inodes.get(key)
            if prior is not None:
                findings.append(
                    {
                        "path": rel,
                        "class": "hardlink",
                        "alias_of": prior,
                    }
                )
            else:
                seen_inodes[key] = rel
        stem = full.name
        if stem.upper() in RESERVED_NAMES or (
            "." in stem and stem.split(".", 1)[0].upper() in RESERVED_NAMES
        ):
            findings.append({"path": rel, "class": "reserved"})
        low = (full.parent.as_posix() + "/" + stem).casefold()
        if low in seen_lower and seen_lower[low] != rel:
            findings.append(
                {
                    "path": rel,
                    "class": "casefold",
                    "alias_of": seen_lower[low],
                }
            )
        else:
            seen_lower[low] = rel
        if _is_lfs_pointer(full):
            findings.append({"path": rel, "class": "lfs-pointer"})
    if ".gitmodules" in paths:
        findings.append({"path": ".gitmodules", "class": "gitmodules"})
    return findings


def _unrecorded_files(out: Path) -> List[str]:
    """Files inside an existing candidate directory that its manifest does not record.

    The directory is about to be written into. Anything already there that the
    previous manifest did not describe is somebody else's file: it is not removed and
    it does not belong in a candidate.
    """
    manifest_path = out / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    recorded = {entry.get("path") for entry in manifest.get("files", []) if isinstance(entry, dict)}
    stray: List[str] = []
    for where, dirs, names in os.walk(out, topdown=True):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(names):
            rel = (Path(where) / name).relative_to(out).as_posix()
            if rel in TOOL_FILES or rel in recorded:
                continue
            stray.append(rel)
    return stray


def _squash(out: Path, project_id: str, paths: List[str]) -> None:
    """One commit, placeholder identity, staging *only* the planned paths.

    ``git add -A`` would commit whatever else happens to be sitting in the
    destination -- content that was never scanned, in a durable, distributable repo.
    """
    repo = out
    subprocess.run(
        ["git", "init", "--quiet", "-b", "main", str(repo)], capture_output=True, check=False
    )
    for key, value in (
        ("user.name", "Open-Ready Candidate"),
        ("user.email", "candidate@openready.invalid"),
        ("commit.gpgsign", "false"),
    ):
        subprocess.run(
            ["git", "-C", str(repo), "config", key, value], capture_output=True, check=False
        )
    # Only files that actually exist can be staged: ``git add`` aborts the entire
    # operation when a single pathspec matches nothing, which silently produced a
    # candidate repository with no commits at all.
    stage = sorted(
        p for p in (set(paths) | {MANIFEST_NAME, CANDIDATE_NAME}) if (repo / p).is_file()
    )
    if not stage:
        return
    subprocess.run(["git", "-C", str(repo), "add", "--", *stage], capture_output=True, check=False)
    subject = f"Candidate export{f' of {project_id}' if project_id else ''}".strip()
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "Open-Ready Candidate",
            "GIT_AUTHOR_EMAIL": "candidate@openready.invalid",
            "GIT_COMMITTER_NAME": "Open-Ready Candidate",
            "GIT_COMMITTER_EMAIL": "candidate@openready.invalid",
        }
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "commit",
            "--quiet",
            "-m",
            f"{subject}\n\nUnapproved release candidate. Not a release. Contains no history.",
        ],
        capture_output=True,
        check=False,
        env=env,
    )
