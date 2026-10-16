"""Git-history scanning and the history choice (OR-017).

A working tree can be clean while the history is not. Removing a secret in a later
commit leaves it in the object store for anyone who clones, and squashing is the
only thing that removes it. So a candidate that *ships history* carries a risk the
tree scan cannot see.

This module answers two questions and refuses to blur them:

1. **What did the deny-list find in the object store?** Reported with counts, and
   with ``truncated`` set when a bound stopped the scan -- a partial scan is never
   presented as a complete one.
2. **Should this candidate ship history at all?** The recommendation is
   ``SQUASH_REQUIRED`` when anything was found; otherwise ``HISTORY_CLEAN_SCAN``.
   Note the wording: a clean *scan*, never a clean history. A deny-list can prove
   it found something and can never prove absence, so for a first public release
   the conservative option -- a single squashed commit -- is always available and
   always cheap.
"""

from __future__ import annotations

import subprocess
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .overrides import validate_entry
from .scan import Finding, MAX_SCAN_BYTES, scan_content
from .status import FAIL, INFO, NEEDS_HUMAN, NOT_RUN, NOT_ENFORCED, PASS, REVIEW, Result

DEFAULT_BLOB_LIMIT = 20000
BATCH_CHUNK = 500

HISTORY_LIMITATION = (
    "Deny-list scan of the object store. It cannot prove a history is free of "
    "secrets, and it does not see content inside commits' binary blobs beyond the "
    "size bound."
)

SQUASH_REQUIRED = "SQUASH_REQUIRED"
HISTORY_CLEAN_SCAN = "HISTORY_CLEAN_SCAN"
HISTORY_UNKNOWN = "HISTORY_UNKNOWN"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, check=False,
    )


def is_repository(root: Path) -> bool:
    probe = _git(Path(root), "rev-parse", "--is-inside-work-tree")
    return probe.returncode == 0 and probe.stdout.strip() == b"true"


def _blob_index(root: Path) -> Tuple[Dict[str, str], bool]:
    """Map blob sha -> a path it appeared under. First path wins, for reporting only.

    Returns ``(index, ok)``. ``ok`` is False when ``git rev-list`` failed, which is
    how an unreadable object store used to be reported as "nothing found".
    """
    listing = _git(root, "rev-list", "--objects", "--all")
    if listing.returncode != 0:
        return {}, False
    index: Dict[str, str] = {}
    for line in listing.stdout.split(b"\n"):
        parts = line.split(b" ", 1)
        if len(parts) != 2:
            continue  # a commit or tag line has no path
        sha = parts[0].decode("ascii", "replace")
        path = parts[1].decode("utf-8", "replace")
        index.setdefault(sha, path)
    return index, True


def _iter_blobs(root: Path, shas: List[str]):
    """Yield (sha, declared_type, size, body-iterator) using one long-lived git call."""
    for start in range(0, len(shas), BATCH_CHUNK):
        chunk = shas[start:start + BATCH_CHUNK]
        proc = subprocess.run(
            ["git", "-C", str(root), "cat-file", "--batch"],
            input=("\n".join(chunk) + "\n").encode("ascii"),
            capture_output=True, check=False,
        )
        if proc.returncode != 0:
            return
        stream = proc.stdout
        offset = 0
        while offset < len(stream):
            newline = stream.find(b"\n", offset)
            if newline == -1:
                return
            header = stream[offset:newline].decode("utf-8", "replace").split()
            offset = newline + 1
            if len(header) < 3 or header[1] == "missing":
                continue
            sha, declared_type, size_text = header[0], header[1], header[2]
            try:
                size = int(size_text)
            except ValueError:
                return
            body = stream[offset:offset + size]
            offset += size + 1  # trailing newline
            yield sha, declared_type, size, body


def scan(root: Path, limit: int = DEFAULT_BLOB_LIMIT) -> Dict[str, Any]:
    """Scan the object store. Bounded, and honest about the bound and about failure."""
    root = Path(root)
    # A directory with no object store is not a repository, and saying otherwise made
    # every caller that trusted this field describe a candidate with no history as one
    # whose object store "could not be read" -- a different, alarming claim. The
    # intended honest branch (``not report["is_repository"]``) was unreachable while
    # this function reported True unconditionally.
    if not is_repository(root):
        return {
            "is_repository": False,
            "blob_count": 0,
            "blobs_scanned": 0,
            "blob_limit": limit,
            "truncated": False,
            "scan_failed": False,
            "oversized_skipped": 0,
            "oversized_paths": [],
            "unreadable": [],
            "hit_count": 0,
            "hits": [],
        }
    index, index_ok = _blob_index(root)
    has_commits = _git(root, "rev-parse", "--verify", "HEAD").returncode == 0
    # A repository with commits but no readable objects is a FAILED scan, not an
    # empty one. Reporting "matched nothing" there is the tool rendering "we did not
    # check" as "this is clean".
    scan_failed = (not index_ok) or (has_commits and not index)
    shas = sorted(index)
    truncated = len(shas) > limit
    if truncated:
        shas = shas[:limit]

    hits: List[Dict[str, str]] = []
    blobs_scanned = 0
    oversized: List[str] = []
    unreadable: List[str] = []
    for sha, declared_type, size, body in _iter_blobs(root, shas):
        if declared_type != "blob":
            continue
        rel = index.get(sha, sha)
        if size > MAX_SCAN_BYTES:
            oversized.append(rel)
            continue
        blobs_scanned += 1
        for finding in scan_content(rel, bytes(body)):
            hits.append({
                "object": sha[:12],
                "path": rel,
                "check_id": finding.check_id,
                "message": finding.message,
            })
    return {
        "is_repository": True,
        "blob_count": len(index),
        "blobs_scanned": blobs_scanned,
        "blob_limit": limit,
        "truncated": truncated,
        "scan_failed": scan_failed,
        "oversized_skipped": len(oversized),
        "oversized_paths": oversized[:10],
        "unreadable": unreadable,
        "hit_count": len(hits),
        "hits": hits,
    }


def scanned_completely(report: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """``(complete, why_not)``. Any gap means the scan cannot support a decision."""
    if not report or not report.get("is_repository"):
        return False, "there is no git repository, so there is no object store to scan"
    if report.get("scan_failed"):
        return False, "the object store could not be read (git rev-list failed or returned nothing)"
    if report.get("truncated"):
        return False, (f"only {report.get('blobs_scanned')} of {report.get('blob_count')} "
                       f"objects were scanned")
    if report.get("oversized_skipped"):
        return False, (f"{report['oversized_skipped']} object(s) exceed the "
                       f"{MAX_SCAN_BYTES // (1024 * 1024)} MiB scan bound and were NOT scanned: "
                       + ", ".join(report.get("oversized_paths", [])))
    return True, ""


def history_choice(report: Dict[str, Any]) -> Dict[str, str]:
    """The OR-016 history decision: ship history, or squash."""
    if not report.get("is_repository"):
        return {"choice": HISTORY_UNKNOWN,
                "reason": "no git repository, so there is no history to ship"}
    complete, why_not = scanned_completely(report)
    if not complete:
        return {"choice": HISTORY_UNKNOWN,
                "reason": f"the object store was not fully scanned, so no history decision "
                          f"can be made: {why_not}"}
    if report.get("hit_count"):
        return {"choice": SQUASH_REQUIRED,
                "reason": (f"{report['hit_count']} deny-list hit(s) remain in the object store; "
                           f"a later commit does not remove them")}
    return {"choice": HISTORY_CLEAN_SCAN,
            "reason": ("the deny-list matched nothing in the scanned objects; this is a clean "
                       "scan, not a clean history")}


def findings(report: Optional[Dict[str, Any]]) -> List[Finding]:
    """History hits as ordinary findings, so one acknowledgement path covers both.

    Without this the acknowledgement file is useless for any committed file: the
    same bytes are found in the object store and reported again, so an acknowledged
    positive control still blocks.
    """
    if not report or not report.get("is_repository"):
        return []
    out: List[Finding] = []
    for hit in report.get("hits", []):
        out.append(Finding(
            hit["check_id"],
            f"still present in the object store at {hit['path']} ({hit['object']})",
            hit["path"],
            HISTORY_LIMITATION,
            object_id=str(hit.get("object", "")),
        ))
    return out


def results(report: Optional[Dict[str, Any]], choice: Optional[Dict[str, str]] = None,
            unresolved: Optional[int] = None,
            acknowledged: Optional[List[Dict[str, Any]]] = None) -> List[Result]:
    """Scan evidence plus the history decision.

    ``unresolved`` is the post-acknowledgement count. Passing it keeps one source of
    truth: the exporter decides what is resolved, and this reports the scan honestly
    rather than failing a second time for the same bytes.

    ``acknowledged`` re-derives that count from the entries in a frozen candidate, so
    a verifier who holds only the candidate does not contradict the exporter.
    """
    if report is None or not report.get("is_repository"):
        return [Result(
            "privacy.full-history", NOT_RUN, REVIEW,
            "no git repository here, so no object store was scanned",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[HISTORY_LIMITATION],
        )]

    if acknowledged is not None:
        narrow = set()
        wide = set()
        for entry in acknowledged:
            if validate_entry(entry):
                continue  # reported separately as verify.acknowledgement-invalid
            if entry.get("object"):
                narrow.add((entry.get("check_id"), entry.get("path"), entry.get("object")))
            else:
                wide.add((entry.get("check_id"), entry.get("path")))
        hits = report.get("hits", [])

        def covered(hit: Dict[str, Any]) -> bool:
            """The same rule the exporter applies: narrow first, then the wide form."""
            if (hit.get("check_id"), hit.get("path"), hit.get("object")) in narrow:
                return True
            return (hit.get("check_id"), hit.get("path")) in wide

        unresolved = len([h for h in hits if not covered(h)])

    hit_count = report.get("hit_count", 0)
    remaining = hit_count if unresolved is None else unresolved
    complete, why_not = scanned_completely(report)
    out: List[Result] = []
    if not complete:
        out.append(Result(
            "privacy.full-history", NOT_RUN, REVIEW,
            f"the object store was not fully scanned: {why_not}",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[HISTORY_LIMITATION],
        ))
    elif remaining:
        out.append(Result(
            "privacy.full-history", FAIL, "STOP",
            f"{remaining} deny-list hit(s) in {report['blobs_scanned']} scanned object(s): " + "; ".join(
                f"{h['object']}:{h['path']} ({h['check_id']})" for h in report["hits"][:4]),
            __version__, environment_label(), limitations=[HISTORY_LIMITATION],
        ))
    elif hit_count:
        out.append(Result(
            "privacy.full-history", PASS, INFO,
            f"{hit_count} hit(s) in the object store, every one acknowledged by the operator",
            __version__, environment_label(), limitations=[HISTORY_LIMITATION],
        ))
    else:
        out.append(Result(
            "privacy.full-history", PASS, INFO,
            f"deny-list matched nothing in {report['blobs_scanned']} object(s)",
            __version__, environment_label(), limitations=[HISTORY_LIMITATION],
        ))
    if choice is None:
        choice = history_choice(report)
    acknowledged_but_present = bool(hit_count) and not remaining
    if acknowledged_but_present:
        label = "SQUASH_RECOMMENDED"
        why = (f"all {hit_count} object-store hit(s) are acknowledged, so nothing blocks -- but "
               f"the string is still in the object store and any public scanner will flag it "
               f"forever. A squashed single-commit history removes it.")
    elif remaining:
        # The advice and the gate have to agree. `--history squash` is refused while
        # these strings are still in this object store, so recommending it here pointed
        # the operator at a command that would refuse them -- the export gate below
        # says "acknowledge each one explicitly, or start a fresh history", and that is
        # what this has to say too.
        label = "HISTORY_ROTATION_REQUIRED"
        why = (f"{remaining} object-store hit(s) are unresolved. A candidate carrying this "
               f"history would publish them, and `--history squash` is refused while they "
               f"remain in this object store: acknowledge each one by exact path, or start "
               f"a fresh history in a new directory and export from there.")
    else:
        label = choice["choice"]
        why = choice["reason"]
    blocking = choice["choice"] == SQUASH_REQUIRED or acknowledged_but_present
    out.append(Result(
        "candidate.history-choice",
        NEEDS_HUMAN if blocking else PASS,
        REVIEW if blocking else INFO,
        f"{label}: {why}",
        __version__, environment_label(),
        limitations=[
            "A squashed single-commit history is the conservative option for a first "
            "public release: it removes whatever a deny-list cannot see.",
        ],
    ))
    return out


def content_digest(paths_and_bytes) -> str:
    """A stable digest over a set of (relative path, bytes) pairs."""
    digest = sha256()
    for rel, data in sorted(paths_and_bytes, key=lambda item: item[0]):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(sha256(data).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest()
