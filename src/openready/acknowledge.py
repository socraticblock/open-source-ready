"""The adoption path for a repository that already exists.

A repository that has been carrying code for a while cannot produce a candidate even
after its working tree is clean, because its **history** still holds what was cleaned.
Every blob that ever contained the shape is still in the object store, and the export
refuses to write a candidate while an unacknowledged hit is there. This is the first
wall a real user meets, and it is invisible from this tool's own repository, which has
always been clean.

Two different problems, and the tool must not answer them the same way:

* A finding in the **working tree** is fixable by editing the file. Acknowledging it
  would be an exception *wider than the reason for it* -- one path, every shape at that
  path, until it expires -- and an unnecessary one. So this command names those findings
  and proposes nothing for them. ``--include-tree`` exists for the case where the shape
  genuinely has to stay, and it says in the entry's own limitations that the exception is
  the wide kind.
* A finding in the **object store** cannot be fixed without rewriting history, which is
  the owner's decision and not this tool's. So one entry per **blob**: the exact bytes
  somebody looked at, not that path forever. Content committed at the same path later is
  still a finding.

Writing is a separate, explicit act (``--write --reason ... --by ...``). The tool cannot
know that a shape is a fixture; only a human can say so, so it will not say it for them.
Without ``--write`` this command prints what it would record and changes nothing.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .candidate import inspect as inspect_tree, plan as plan_candidate
from .history import (
    findings as history_findings,
    is_repository,
    scan as history_scan,
    scanned_completely,
)
from .overrides import (
    ALLOW_NAME,
    MIN_REASON_CHARS,
    OVERRIDABLE_CHECK_IDS,
    PLACEHOLDER_REASONS,
    apply as apply_overrides,
    load as load_allow,
)
from .status import (
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_RUN,
    PASS,
    REVIEW,
    Result,
)

def _environment_label() -> str:
    import os
    return f"{os.uname().sysname.lower()}-{os.uname().machine}"


def _result(check_id: str, status: str, message: str, *, severity: str = REVIEW,
            required: bool = False, limitations: Optional[List[str]] = None) -> Result:
    return Result(check_id, status, severity, message, __version__, _environment_label(),
                  required=required, limitations=limitations or [])


def _default_by() -> str:
    """Who is acknowledging, for the entry to carry as evidence.

    Built from ``os`` and ``getpass`` only. The standard-library calls that look this host
    up are tokens A01 scans this tool's own source for, and a label is not worth a hole in
    a check about not reaching the network -- the name comes from the uname structure.
    """
    import getpass
    import os
    try:
        who = getpass.getuser()
    except Exception:  # pragma: no cover - no passwd entry
        who = "unknown"
    host = (os.uname().nodename or "unknown-host").split(".")[0]
    return f"{who}@{host}"


def reason_errors(reason: str) -> List[str]:
    """Whether a reason is usable as somebody's statement about their own project."""
    text = str(reason or "").strip()
    if text.lower() in PLACEHOLDER_REASONS:
        return ["a reason is required: it is the operator's statement, not the tool's"]
    if len(text) < MIN_REASON_CHARS:
        return [f"the reason must be at least {MIN_REASON_CHARS} characters"]
    return []


def residue(root: Path) -> Tuple[List, Optional[str]]:
    """Unacknowledged object-store findings, or why they could not be judged.

    The second element is set when the scan did not complete: a partial scan must never
    be turned into "nothing to acknowledge", because that would acknowledge an
    unexamined history by omission.
    """
    root = Path(root)
    if not is_repository(root):
        return [], ""
    report = history_scan(root)
    complete, why = scanned_completely(report)
    if not complete:
        return [], why
    hits = history_findings(report)
    if not hits:
        return [], ""
    # Already-acknowledged blobs are not residue. Without this the command proposed an
    # entry for every hit it found, including the ones an earlier run had already
    # recorded, and re-running it grew the file with duplicates of its own output.
    remaining, _ = apply_overrides(root, hits)
    return remaining, ""


def tree_findings(root: Path) -> List:
    """Unacknowledged findings in the working tree, which the operator can just fix."""
    plan = plan_candidate(Path(root))
    paths = list(plan.get("included", [])) + list(plan.get("untracked", []))
    if not paths:
        return []
    remaining, _ = apply_overrides(Path(root), inspect_tree(Path(root), paths))
    return [item for item in remaining
            if getattr(item, "check_id", "") in OVERRIDABLE_CHECK_IDS]


def proposal(findings: Sequence, reason: str, by: str, expires: str = "",
             bind_objects: bool = True) -> List[Dict[str, Any]]:
    """One entry per finding, object-bound when the finding came from the object store."""
    seen: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for finding in findings:
        check_id = str(getattr(finding, "check_id", ""))
        path = str(getattr(finding, "path", ""))
        if check_id not in OVERRIDABLE_CHECK_IDS or not path:
            continue
        obj = str(getattr(finding, "object_id", "") or "") if bind_objects else ""
        entry: Dict[str, Any] = {
            "check_id": check_id,
            "path": path,
            "reason": reason,
            "acknowledged_by": by,
            "acknowledged_at": date.today().isoformat(),
        }
        if obj:
            entry["object"] = obj
        if expires:
            entry["expires"] = expires
        seen[(check_id, path, obj)] = entry
    return [seen[key] for key in sorted(seen)]


def existing_entries(root: Path) -> List[Dict[str, Any]]:
    document, _ = load_allow(Path(root))
    entries = (document or {}).get("entries", []) if document else []
    return [entry for entry in entries or [] if isinstance(entry, dict)]


def write(root: Path, entries: Sequence[Dict[str, Any]]) -> Path:
    """Merge entries into the acknowledgement file, keeping the existing ones.

    Rewriting the file from the proposal alone would silently delete every earlier
    acknowledgement, which is the sort of quiet data loss an evidence tool cannot afford.
    """
    import json
    root = Path(root)
    path = root / ALLOW_NAME
    document, _ = load_allow(root)
    document = document or {}
    kept = [entry for entry in document.get("entries", []) or [] if isinstance(entry, dict)]
    keyed = {(str(e.get("check_id", "")), str(e.get("path", "")), str(e.get("object", "") or "")): e
             for e in kept}
    for entry in entries:
        keyed[(str(entry["check_id"]), str(entry["path"]), str(entry.get("object", "") or ""))] = entry
    merged = [keyed[key] for key in sorted(keyed)]
    document["entries"] = merged
    path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def run(root: Path, *, reason: str = "", by: str = "", expires: str = "", write_it: bool = False,
        include_tree: bool = False) -> Tuple[List[Result], Dict[str, Any]]:
    """Propose, or record, the acknowledgements that adoption needs."""
    root = Path(root)
    results: List[Result] = []
    payload: Dict[str, Any] = {}

    stored, why = residue(root)
    tree = tree_findings(root) if include_tree else []
    fixable = [] if include_tree else tree_findings(root)

    payload["object_residue"] = len(stored)
    payload["tree_findings"] = len(fixable) + len(tree)

    if why:
        results.append(_result(
            "acknowledge.scan-incomplete", NOT_RUN,
            f"the object store could not be scanned completely, so no acknowledgement is "
            f"proposed: {why}",
            severity=REVIEW, required=True,
            limitations=[
                "A partial scan is not a clean one. Acknowledging here would exempt the "
                "part that was never read.",
                "Raise the blob limit or run the scan where the object store is fully "
                "readable, then propose again.",
            ],
        ))
        return results, payload

    if not stored and not tree:
        results.append(_result(
            "acknowledge.nothing", PASS,
            "nothing to acknowledge: no unacknowledged finding in the object store or the "
            "working tree is of an overridable kind",
            severity=INFO,
            limitations=[
                "This says nothing about findings that are not overridable. Those are "
                "reported by doctor and candidate and need a human decision, not an "
                "acknowledgement.",
            ],
        ))
        return results, payload

    proposed = proposal(stored, reason or "<your reason here>", by or _default_by(), expires)
    if tree:
        proposed += proposal(tree, reason or "<your reason here>", by or _default_by(), expires,
                             bind_objects=False)

    objects = {str(getattr(item, "object_id", "") or "") for item in stored}
    objects.discard("")
    payload["proposal"] = proposed
    payload["would_write"] = ALLOW_NAME

    if stored:
        results.append(_result(
            "acknowledge.object-residue", NEEDS_HUMAN,
            f"{len(stored)} unacknowledged finding(s) in {len(objects)} object(s) in the "
            f"store, from commits that predate this cleanup -- your history, not your "
            f"working tree",
            severity=REVIEW, required=True,
            limitations=[
                "One entry per blob covers the exact bytes somebody looked at. Content "
                "committed at the same path later is still reported.",
                "These are in history. Fixing them means rewriting history, which is the "
                "owner's decision, not this tool's.",
            ],
        ))
    if fixable:
        results.append(_result(
            "acknowledge.tree-findings", NEEDS_HUMAN,
            f"{len(fixable)} finding(s) are in the working tree, where you can fix them: "
            + "; ".join(sorted({f"{item.path} ({item.check_id})" for item in fixable})[:6]),
            severity=REVIEW, required=True,
            limitations=[
                "No acknowledgement is proposed for these. An exception at a path is "
                "wider than the reason for it, and editing the file costs less.",
                "Pass --include-tree to acknowledge them anyway, if the shape has to stay.",
            ],
        ))
    if tree and include_tree:
        results.append(_result(
            "acknowledge.tree-acknowledged", NEEDS_HUMAN,
            f"{len(tree)} working-tree finding(s) are included in the proposal as "
            f"path-bound entries",
            severity=REVIEW, required=True,
            limitations=[
                "A path-bound entry covers every shape at that path until it expires, "
                "including a real credential committed there later.",
            ],
        ))

    if not write_it:
        results.append(_result(
            "acknowledge.nothing-written", PASS,
            "nothing was written. This command proposes; recording is a separate act "
            "(add --write --reason \"...\" --by \"...\")",
            severity=INFO, required=False,
        ))
        return results, payload

    problems = reason_errors(reason)
    if not proposed:
        problems.append("no entry was proposed to write")
    if problems:
        results.append(_result(
            "acknowledge.refused", FAIL,
            "nothing was written: " + "; ".join(problems),
            severity="STOP", required=True,
            limitations=[
                "The reason is the operator's own statement about their project. The tool "
                "cannot tell a fixture from a credential, so it will not write one for you.",
            ],
        ))
        return results, payload

    path = write(root, proposed)
    # The residue result described the state *before* the write. Leaving it in place made
    # a successful run report the findings it had just acknowledged as unacknowledged.
    results = [item for item in results if item.check_id != "acknowledge.object-residue"]
    results.append(_result(
        "acknowledge.written", PASS,
        f"recorded {len(proposed)} entr(y/ies) in {path.name}, covering {len(stored)} "
        f"finding(s) in {len(objects)} object(s); the findings they name are now "
        f"acknowledged, and nothing else is",
        severity=INFO,
        limitations=[
            "An acknowledgement says 'I know about this one'. It says nothing about "
            "whether this project may be published.",
            "Entries that name a blob cover that blob. Re-run candidate with "
            "--history squash to export a tree that carries none of it.",
        ],
    ))
    return results, payload
