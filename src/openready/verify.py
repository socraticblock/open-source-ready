"""Frozen-candidate verification and the unapproved release packet (OR-017/019/020).

``verify`` answers a narrower question than people expect: *is this frozen
candidate the one the evidence describes, and what does it still need?* It cannot
authorise a release and has no code path that does.

The check that matters most here is the digest. A manifest that lists hashes is
decoration unless somebody recomputes them, so ``verify`` re-derives the digest
from the candidate's own bytes and compares. It also looks for the two failures a
hash list cannot see on its own: a file present in the candidate but absent from
the manifest (added after export) and a manifest entry with no file behind it.

The packet this module emits is the specification's ``release-packet`` contract:
``schema_version`` ``1.0``, a ``sha256:`` digest, and a status of exactly
``REVIEW_REQUIRED``. There is no "approved" variant of that contract, which is the
point of it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .candidate import CANDIDATE_NAME, MANIFEST_NAME, TOOL_FILES
from .capabilities import environment_label
from .history import content_digest
from .history import results as rescan_history
from .history import scan as history_scan
from .history import HISTORY_LIMITATION
from .ledger import build as build_ledger
from .ledger import results as ledger_results
from .overrides import entry_covers
from .overrides import validate_entry
from .private import BOUNDARY_LIMITATION
from .scan import DENYLIST_LIMITATION, PROSE_LIMITATION, Finding, scan_file, scan_paths
from .status import (
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    NOT_TESTED,
    PASS,
    REVIEW,
    STOP,
    Result,
)

PACKET_SCHEMA_VERSION = "1.0"
PACKET_STATUS = "REVIEW_REQUIRED"
PACKET_KINDS = ("rights", "privacy", "security", "build", "external_platforms",
                "license", "support", "publication_scope")
BUILD_TIMEOUT_SECONDS = 600

VERIFY_LIMITATION = (
    "Verification describes this frozen candidate on this machine. It authorises "
    "nothing and does not establish that publication is lawful or safe."
)
NETWORK_LIMITATION = (
    "Network egress was NOT contained during the restricted build. A build that "
    "passes here is not evidence that it works without network access."
)
ANCHOR_LIMITATION = (
    "Without an out-of-band digest this verification proves only that the candidate is "
    "self-consistent. It cannot tell the artifact the owner reviewed from a forgery "
    "that regenerated MANIFEST.json and CANDIDATE.json together, so bind a review to "
    "an exact artifact with --expected-digest."
)

# A module that is not installed is a fact about this machine, not about the candidate.
# The restricted build installs nothing on purpose, so this has to be separated from a
# candidate whose own tests genuinely fail.
_MISSING_DEPENDENCY = re.compile(
    r"(?:ModuleNotFoundError|ImportError): No module named '?([\w.\-]+)'?"
    r"|Cannot find module '([^']+)'"
    r"|Module not found: Error: Can't resolve '([^']+)'"
    r"|command not found")
_MISSING_DEPENDENCY_LIMITATION = (
    "A missing-dependency message is matched by pattern, so a candidate that raises the "
    "same error from its own code is also reported NOT_RUN rather than FAIL. The error "
    "text is included so the operator can tell the two apart."
)


def _missing_dependency_error(*blobs: str) -> Optional[str]:
    for blob in blobs:
        match = _MISSING_DEPENDENCY.search(blob or "")
        if match:
            module = next((group for group in match.groups() if group), None)
            return (f"a required module is not installed here ({module})"
                    if module else "the command could not be started")
    return None


class CandidateError(Exception):
    """The candidate could not be read at all."""


def load_candidate(path: Path) -> Tuple[Dict[str, Any], Dict[str, Any], Path]:
    path = Path(path)
    if not path.is_dir():
        raise CandidateError(f"{path} is not a directory")
    manifest_path = path / MANIFEST_NAME
    meta_path = path / CANDIDATE_NAME
    if not manifest_path.is_file():
        raise CandidateError(f"{MANIFEST_NAME} is missing; this is not a candidate export")
    if not meta_path.is_file():
        raise CandidateError(f"{CANDIDATE_NAME} is missing; this is not a candidate export")
    try:
        return (json.loads(manifest_path.read_text(encoding="utf-8")),
                json.loads(meta_path.read_text(encoding="utf-8")), path)
    except (ValueError, OSError) as exc:
        raise CandidateError(f"candidate metadata is unreadable: {exc}") from exc


def _present_files(root: Path) -> List[str]:
    import os as _os

    out: List[str] = []
    for where, dirs, names in _os.walk(root, topdown=True):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(names):
            rel = (Path(where) / name).relative_to(root).as_posix()
            if rel in TOOL_FILES:
                continue
            out.append(rel)
    return out


def digest_check(root: Path, manifest: Dict[str, Any],
                 meta: Optional[Dict[str, Any]] = None) -> Tuple[List[Result], List[str]]:
    """Recompute the digest and reconcile the manifest against the actual bytes."""
    results: List[Result] = []
    recorded = {entry["path"]: entry for entry in manifest.get("files", [])}
    present = set(_present_files(root))

    import hashlib

    payload: List[Tuple[str, bytes]] = []
    mismatched: List[str] = []
    missing: List[str] = []
    unreadable: List[str] = []
    for rel, entry in sorted(recorded.items()):
        target = root / rel
        if not target.is_file():
            missing.append(rel)
            continue
        try:
            data = target.read_bytes()
        except OSError as exc:
            # An unreadable file is a finding, not a traceback. Crashing told the
            # verifier nothing and skipped the file's bytes entirely.
            unreadable.append(f"{rel} ({exc.__class__.__name__})")
            continue
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            mismatched.append(rel)
            continue
        if len(data) != entry.get("bytes"):
            mismatched.append(rel)
            continue
        payload.append((rel, data))

    extra = sorted(present - set(recorded))

    if unreadable:
        results.append(Result(
            "verify.file-unreadable", FAIL, STOP,
            f"{len(unreadable)} file(s) could not be read, so their bytes were not checked: "
            f"{', '.join(unreadable[:4])}",
            __version__, environment_label(),
        ))

    if missing:
        results.append(Result(
            "verify.manifest-complete", FAIL, STOP,
            f"{len(missing)} manifest entr(ies) have no file: {', '.join(missing[:4])}",
            __version__, environment_label(),
        ))
    elif extra:
        results.append(Result(
            "verify.manifest-complete", FAIL, "STOP",
            f"{len(extra)} file(s) are present but absent from the manifest: {', '.join(extra[:4])}",
            __version__, environment_label(),
        ))
    else:
        results.append(Result(
            "verify.manifest-complete", PASS, INFO,
            f"every one of the {len(recorded)} manifest entr(ies) has a file, and nothing extra "
            f"is present",
            __version__, environment_label(),
        ))

    if mismatched:
        results.append(Result(
            "verify.file-integrity", FAIL, "STOP",
            f"{len(mismatched)} file(s) do not match their recorded hash: "
            f"{', '.join(mismatched[:4])}",
            __version__, environment_label(),
        ))
    else:
        results.append(Result(
            "verify.file-integrity", PASS, INFO,
            "every file matches its recorded sha256 and length",
            __version__, environment_label(),
        ))

    recomputed = content_digest(payload)
    declared = manifest.get("digest")
    # A candidate carries its digest twice: in MANIFEST.json and in CANDIDATE.json.
    # Comparing only the manifest meant the two identity records could disagree while
    # the run reported a consistent candidate, and a reader trusting CANDIDATE.json
    # would be reading an unvalidated number.
    declared_meta = (meta or {}).get("candidate_digest")
    if declared_meta is not None and declared_meta != declared:
        results.append(Result(
            "verify.digest", FAIL, STOP,
            (f"CANDIDATE.json declares {declared_meta} but MANIFEST.json declares "
             f"{declared}; the candidate's two identity records disagree"),
            __version__, environment_label(), candidate_digest=recomputed,
        ))
    elif recomputed != declared:
        results.append(Result(
            "verify.digest", FAIL, "STOP",
            f"recomputed digest {recomputed} does not match the manifest's {declared}",
            __version__, environment_label(), candidate_digest=recomputed,
        ))
    else:
        results.append(Result(
            "verify.digest", PASS, INFO,
            f"recomputed digest matches the manifest: {declared}",
            __version__, environment_label(), candidate_digest=recomputed,
        ))
    return results, [rel for rel, _ in payload]


def rescan(root: Path, paths: List[str],
           acknowledged: Optional[List[Dict[str, Any]]] = None) -> List[Result]:
    """Re-run the deny-list over the frozen candidate, for whoever receives it.

    An acknowledged finding is downgraded to ``NEEDS_HUMAN``, never to a pass: the
    string really is in the candidate, and a verifier who did not take part in the
    acknowledgement has to judge whether the stated reason is credible. Reporting a
    hard ``FAIL`` here would contradict the exporter; reporting nothing would hide a
    real string. Both are wrong, so it is surfaced and escalated instead.
    """
    entries: List[Dict[str, Any]] = []
    invalid: List[str] = []
    for entry in (acknowledged or []):
        problems = validate_entry(entry)
        if problems:
            invalid.append(
                f"{entry.get('check_id')}:{entry.get('path')} ({'; '.join(problems)})")
            continue
        entries.append(entry)
    findings = scan_paths(paths)
    for rel in paths:
        try:
            findings.extend(scan_file(rel, (root / rel).read_bytes()))
        except OSError as exc:
            findings.append(Finding(
                "verify.file-unreadable",
                f"{rel} could not be read, so its bytes were never checked "
                f"({exc.__class__.__name__})",
                rel,
            ))
    grouped: Dict[str, List[Any]] = {}
    for finding in findings:
        grouped.setdefault(finding.check_id, []).append(finding)
    results: List[Result] = []
    if invalid:
        results.append(Result(
            "verify.acknowledgement-invalid", FAIL, STOP,
            ("acknowledgement(s) in this candidate are not valid and suppress nothing: "
             + "; ".join(invalid[:4])),
            __version__, environment_label(),
            limitations=["An acknowledgement is a named, reasoned, expiring decision. An entry "
                         "missing its reason, author, date, or a valid unexpired date is not "
                         "one, and a candidate's own metadata cannot make it one."],
        ))
    for check_id in sorted(grouped):
        group = grouped[check_id]
        known = [f for f in group
                 if any(entry_covers(entry, f.check_id, f.path, f.object_id)
                        for entry in entries)]
        unknown = [f for f in group
                   if not any(entry_covers(entry, f.check_id, f.path, f.object_id)
                              for entry in entries)]
        if unknown:
            results.append(Result(
                check_id, FAIL, STOP,
                f"{len(unknown)} occurrence(s): " + "; ".join(
                    f"{f.path}: {f.message}" for f in unknown[:4]),
                __version__, environment_label(),
                limitations=[unknown[0].limitation] if unknown[0].limitation
                else [DENYLIST_LIMITATION],
            ))
        if known:
            results.append(Result(
                f"{check_id}.acknowledged", NEEDS_HUMAN, REVIEW,
                (f"{len(known)} occurrence(s) declared in this candidate's metadata as "
                 f"acknowledged, not removed: "
                 + "; ".join(f"{f.path}" for f in known[:4])),
                __version__, environment_label(), required=False,
                limitations=[
                    "The acknowledgement records the exporter's awareness, not a fact about "
                    "the content. A verifier must judge whether the stated reason is credible.",
                    DENYLIST_LIMITATION,
                ],
            ))
    results.append(Result(
        "verify.private-prose", NOT_RUN, REVIEW,
        "no scan can establish that a document is free of private content",
        __version__, environment_label(), enforcement=NOT_ENFORCED,
        limitations=[PROSE_LIMITATION, BOUNDARY_LIMITATION],
    ))
    return results


# --- restricted build (OR-019, partial) ---------------------------------------

def detect_test_command(root: Path) -> Optional[List[str]]:
    if (root / "package.json").is_file():
        try:
            manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))
        except (ValueError, OSError):
            manifest = {}
        if (manifest.get("scripts") or {}).get("test"):
            return ["npm", "test", "--silent"]
    if (root / "tests").is_dir() or (root / "src").is_dir():
        if list((root / "tests").glob("test_*.py")) or list((root / "tests").glob("*.test.ts")):
            return ["python3", "-m", "unittest", "discover", "-s", "tests"]
    return None


def restricted_build(root: Path) -> List[Result]:
    """Run the candidate's own tests in a copy, with a scrubbed environment.

    The environment is reduced to PATH plus a throwaway HOME, so a credential in
    the operator's shell cannot be read by the candidate's code. Network egress is
    not contained, and that is reported rather than glossed.
    """
    root = Path(root)
    command = detect_test_command(root)
    if command is None:
        return [Result(
            "build.restricted-run", NOT_RUN, REVIEW,
            "no test command could be determined for this candidate",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[VERIFY_LIMITATION],
        )]
    if shutil.which(command[0]) is None:
        return [Result(
            "build.restricted-run", NOT_RUN, REVIEW,
            f"{command[0]} is not available on this machine",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[VERIFY_LIMITATION],
        )]

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "candidate"
        shutil.copytree(root, work, symlinks=False,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
        home = Path(tmp) / "home"
        home.mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
               "LANG": "C.UTF-8", "TMPDIR": tmp}
        try:
            proc = subprocess.run(command, cwd=str(work), capture_output=True,
                                  env=env, timeout=BUILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return [Result(
                "build.restricted-run", FAIL, STOP,
                f"the test command exceeded {BUILD_TIMEOUT_SECONDS}s",
                __version__, environment_label(),
            )]
        except OSError as exc:
            return [Result(
                "build.restricted-run", NOT_RUN, REVIEW,
                f"could not run the test command: {exc}", __version__,
                environment_label(), enforcement=NOT_ENFORCED,
            )]

    passed = proc.returncode == 0
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    if not passed:
        missing = _missing_dependency_error(stdout, stderr)
        if missing:
            # Nothing was installed, by design, so this is NOT_RUN: the check could not
            # be performed here. Reporting it as FAIL/STOP made a missing PyYAML look
            # like a defect in the candidate and forced exit 1.
            return [Result(
                "build.restricted-run", NOT_RUN, REVIEW,
                (f"`{' '.join(command)}` could not run in the scrubbed environment: {missing}. "
                 f"No dependency install was attempted, so this describes this machine, not "
                 f"the candidate."),
                __version__, environment_label(), enforcement=NOT_ENFORCED,
                limitations=[NETWORK_LIMITATION, "No dependency install was attempted.",
                             _MISSING_DEPENDENCY_LIMITATION],
            )]
    # `unittest` and most test runners write their diagnosis to stderr, so reporting
    # only the stdout tail produced "exited 1: " with no reason at all.
    combined = "\n".join(part.strip() for part in (stdout, stderr) if part.strip())
    tail = (combined.splitlines() or [""])[-3:]
    return [Result(
        "build.restricted-run", PASS if passed else FAIL, INFO if passed else STOP,
        (f"`{' '.join(command)}` passed in a scrubbed environment"
         if passed else f"`{' '.join(command)}` exited {proc.returncode}: {' / '.join(tail)}"),
        __version__, environment_label(),
        limitations=[NETWORK_LIMITATION, "No dependency install was attempted."],
    )]


# --- release packet (OR-020) --------------------------------------------------

_KIND_FOR_CHECK = (
    # Most specific first: a privacy check named "verify.*" is still a privacy item.
    ("private-prose", "privacy"),
    ("full-history", "privacy"),
    ("secret-shape", "privacy"),
    ("ledger.", "license"),
    ("rights.", "rights"),
    ("release.", "rights"),
    ("privacy.", "privacy"),
    ("candidate.", "publication_scope"),
    ("private.", "privacy"),
    ("verify.", "publication_scope"),
    ("build.", "build"),
    ("egress.", "security"),
    ("trust.", "security"),
    ("host.", "security"),
    ("git.", "publication_scope"),
    ("config.", "publication_scope"),
    ("structure.", "support"),
    ("override.", "publication_scope"),
)

# Kinds a release packet must always address. Omitting a kind that was never
# assessed reads as "nothing to review here", which is the opposite of the truth;
# the honest status for an unassessed kind is NOT_RUN.
#
# ``rights`` is deliberately in this list and deliberately has no automated check
# mapping to it: ownership and third-party rights cannot be established by any
# scan, so a packet that reported them as PASS would be inventing a fact.
ALWAYS_REVIEWED = ("rights", "privacy", "license", "publication_scope", "security", "support")


def kind_for(check_id: str) -> str:
    for prefix, kind in _KIND_FOR_CHECK:
        if check_id.startswith(prefix):
            return kind
    return "support"


def _project_config(root: Path) -> Optional[Dict[str, Any]]:
    """The project contract if the candidate carries one, else None."""
    for name in ("openready.project.json",):
        if not name:
            continue
        path = Path(root) / name
        if path.is_file():
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if isinstance(document, dict):
                return document
    return None


# Checks this build genuinely cannot perform. They belong in the packet as review
# items: a packet that names no ``security`` item reads as "security was fine", when
# the truth is that no egress, isolation or publisher-separation check ran at all.
#
# ``host.isolation`` is NOT_TESTED, not NOT_ENFORCED: nothing was exercised, which is
# a different admission from a control that was measured and found absent. ``doctor``
# has always said NOT_TESTED, and the two surfaces must not disagree about the same
# check.
_UNPERFORMED = (
    ("trust.publisher-separation", STOP, NOT_ENFORCED,
     "no publisher principal separate from the builder exists (ADR-002)",
     "Publication must remain a manual owner action."),
    ("egress.containment", STOP, NOT_ENFORCED,
     "outbound private-data flow is not contained or measured",
     "Broad builder read access plus unrestricted network is incompatible with a "
     "technical promise of private-data containment."),
    ("host.isolation", STOP, NOT_TESTED,
     "no isolation facility was exercised; untrusted code must not be run here",
     "A present sandbox binary is not evidence that it denies anything."),
    ("release.rights", REVIEW, NOT_ENFORCED,
     "ownership, licences and third-party rights are unresolved",
     "Rights cannot be established by any automated check."),
)


def limitation_results(config: Optional[Dict[str, Any]] = None) -> List[Result]:
    """The unperformed checks, so they appear in every packet rather than only in doctor."""
    del config  # reserved: risk tier may narrow this list later
    return [
        Result(check_id, NOT_RUN, severity, message, __version__, environment_label(),
               enforcement=enforcement, limitations=[limitation])
        for check_id, severity, enforcement, message, limitation in _UNPERFORMED
    ]


def history_results(report: Optional[Dict[str, Any]],
                    acknowledged: Optional[List[Dict[str, Any]]] = None) -> List[Result]:
    """Scan the candidate's own object store, when it carries one.

    ``verify`` used to ignore the candidate's ``.git`` entirely, so a ``preserve``
    export whose history held a key verified as clean: the verifier checked the bytes
    it could see and never the objects that travel with them.

    The candidate's own acknowledgement entries are applied here, because a verifier
    must not report a bare failure for a string the exporter already recorded as a
    named, reasoned, known finding.
    """
    if not report or not report.get("is_repository"):
        return [Result(
            "privacy.full-history", NOT_RUN, REVIEW,
            "the candidate carries no git object store; its history was not scanned",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[HISTORY_LIMITATION],
        )]
    return rescan_history(report, acknowledged=acknowledged)


def build_packet(results: List[Result], candidate_digest: str,
                 proposed_destination: Optional[str] = None,
                 proposed_license: Optional[str] = None) -> Dict[str, Any]:
    """One review item per kind, at the worst status seen for that kind.

    A kind that nothing assessed is emitted as ``NOT_RUN``, never omitted: an absent
    item reads as "nothing to review", which is how a packet overstates readiness.
    """
    worst: Dict[str, str] = {}
    rank = {FAIL: 4, NEEDS_HUMAN: 3, NOT_RUN: 2, PASS: 1, "NOT_APPLICABLE": 0}
    for result in results:
        kind = kind_for(result.check_id)
        current = worst.get(kind)
        if current is None or rank.get(result.status, 0) > rank.get(current, 0):
            worst[kind] = result.status
    for kind in ALWAYS_REVIEWED:
        worst.setdefault(kind, NOT_RUN)
    items = [{"kind": kind, "status": worst[kind], "evidence_path": None}
             for kind in PACKET_KINDS if kind in worst]
    # Per-result rows carry the specific check ids and their status. The
    # review_items above is a roll-up; the rows below make every check visible
    # in the packet so a reviewer (and the acceptance harness) can see, for
    # example, ``verify.private-prose`` and ``candidate.lfs-pointer`` by name
    # rather than only as "rights: NOT_RUN" or "structural: PASS".
    result_rows = [{
        "check_id": r.check_id,
        "kind": kind_for(r.check_id),
        "status": r.status,
        "severity": r.severity,
        "enforcement": r.enforcement or None,
        "limitations": list(r.limitations),
    } for r in results if kind_for(r.check_id) in worst]
    packet: Dict[str, Any] = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "candidate_digest": candidate_digest,
        "creation_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": PACKET_STATUS,
        # The packet is the *only* place an operator reads whether publication
        # is allowed. ``decision`` is the unambiguous answer -- "NOT APPROVED"
        # -- so the file cannot be misread as a green light. ``status`` names
        # the workflow state ("REVIEW_REQUIRED"); ``decision`` names the
        # answer. They are different and they say different things on purpose.
        "decision": "NOT APPROVED",
        "unapproved_reason": (
            "an exported candidate has not been authorised for publication by "
            "the independent publisher; this packet is the local evidence, the "
            "owner-side review is the only thing that can change the decision"),
    }
    if proposed_destination is not None:
        packet["proposed_destination"] = proposed_destination
    if proposed_license is not None:
        packet["proposed_license"] = proposed_license
    packet["review_items"] = items
    packet["results"] = result_rows
    return packet


def write_packet(packet: Dict[str, Any], destination: Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _anchor_check(declared: str, expected: Optional[str]) -> List[Result]:
    """Compare the candidate's identity against a digest supplied out of band.

    Everything else in this module is self-consistency: the manifest, the metadata and
    the bytes all arrive from the same hand, so a forgery that regenerates all three
    together verifies cleanly while containing something the owner never reviewed. An
    owner who wants to prove the artifact is the one they looked at has to supply the
    digest from somewhere the forger does not control.
    """
    if expected is None:
        return [Result(
            "verify.digest-anchor", NOT_RUN, REVIEW,
            "no expected digest was supplied, so this run proves the candidate is "
            "self-consistent and nothing more",
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[ANCHOR_LIMITATION],
        )]
    normalised = expected.strip()
    if normalised and not normalised.startswith("sha256:"):
        normalised = f"sha256:{normalised}"
    if normalised != declared:
        return [Result(
            "verify.digest-anchor", FAIL, STOP,
            (f"this candidate digests to {declared} but the expected artifact is "
             f"{normalised}; this is not the candidate that was reviewed"),
            __version__, environment_label(), candidate_digest=declared,
        )]
    return [Result(
        "verify.digest-anchor", PASS, INFO,
        f"the candidate matches the digest supplied out of band: {declared}",
        __version__, environment_label(), candidate_digest=declared,
    )]


def verify(candidate_path: Path, packet_path: Optional[Path] = None,
           proposed_destination: Optional[str] = None,
           proposed_license: Optional[str] = None,
           run_build: bool = True,
           expected_digest: Optional[str] = None
           ) -> Tuple[List[Result], Optional[Dict[str, Any]]]:
    try:
        manifest, meta, root = load_candidate(candidate_path)
    except CandidateError as exc:
        return [Result("verify.readable", FAIL, STOP, str(exc), __version__,
                       environment_label())], None

    results, paths = digest_check(root, manifest, meta)
    # The candidate's own identity records are checked above; the anchor is the only
    # check here that does not take the candidate's word for its own identity.
    results.extend(_anchor_check(manifest.get("digest", ""), expected_digest))
    results.extend(rescan(root, paths, meta.get("acknowledged_findings")))
    # Obligation review runs against the candidate, not the project: the packet
    # must describe what would actually be published.
    ledger_document = build_ledger(root, str(meta.get("project_id", "")))
    results.extend(ledger_results(ledger_document))
    # The checks this build cannot perform belong in the packet as review items.
    # Without them the packet omitted the whole ``security`` kind, so "we did not
    # check egress or publisher separation" was invisible to whoever read it.
    results.extend(limitation_results(_project_config(root)))
    results.extend(history_results(history_scan(root),
                                   meta.get("acknowledged_findings")))
    results.extend(restricted_build(root) if run_build else [Result(
        "build.restricted-run", NOT_RUN, REVIEW, "the restricted build was not requested",
        __version__, environment_label(), enforcement=NOT_ENFORCED,
    )])

    digest = manifest.get("digest", "")
    # A packet describes an artifact. If the candidate is not the artifact the owner
    # named, or its own two identity records disagree, there is nothing to describe.
    mismatched_digest = any(
        r.check_id in ("verify.digest", "verify.digest-anchor") and r.status == FAIL
        for r in results
    )
    packet = None
    if not mismatched_digest:
        packet = build_packet(results, digest, proposed_destination, proposed_license)
        if packet_path is not None:
            write_packet(packet, packet_path)
    results.append(Result(
        "release.packet", NEEDS_HUMAN if packet else NOT_RUN, REVIEW,
        (f"packet status {PACKET_STATUS}; the candidate is NOT APPROVED -- "
         f"it has not been authorised for publication"
         if packet else "no packet was emitted because the candidate digest did not verify"),
        __version__, environment_label(), required=False,
        limitations=[VERIFY_LIMITATION],
    ))
    return results, packet
