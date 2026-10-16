"""The independent-publisher seam (work order D-5, OR-022).

This is the *read-only* half of ADR-002: a publisher principal that is separate
from the builder. It exists to answer exactly one question, and to answer it
without any ability to act on the answer:

    Does an owner approval exist, bound to this exact candidate's content digest,
    this destination and this licence?

Three properties are the whole point, and each is enforced rather than described:

1. **Approval is bound to an exact artifact.** The digest is re-derived here from
   the *frozen candidate's own bytes* -- the same digest function the exporter and
   verifier use -- never read from the candidate's metadata. A candidate that
   changed by one byte is a different artifact and its approval does not apply.

2. **The approval lives outside the builder's write authority.** It is stored in
   ``$OPENREADY_APPROVAL_HOME`` or ``<private-home>/approvals/approvals.json``,
   not inside the project and not inside the candidate. A builder that edits the
   candidate's own ``CANDIDATE.json`` to add ``"approved": true`` therefore
   changes nothing: that field is IGNORED by construction, because an approval is
   a record the builder never writes and cannot write.

3. **Nothing here publishes.** :func:`main` exposes three verbs and no more:
   ``check`` and ``verify-log`` read, and ``record`` is the *owner's* act of
   binding an approval to an exact (digest, destination, licence) triple -- it
   refuses any actor other than ``owner`` and writes nothing else. There is no
   publish, push, visibility or upload path, and the owner-held publisher
   credential is referenced only by *file path*
   (``OPENREADY_PUBLISHER_TOKEN_FILE``); its value is never read, printed or
   stored here. Publication remains a manual owner action outside this tool.

   ``--actor`` is a **string, not an authenticated identity**. The separation the
   specification asks for is a credential the builder does not possess, and no such
   credential custody exists on this host (``openready capabilities`` reports
   ``trust.publisher-separation`` as ``NOT_ENFORCED``). What is enforced here is the
   weaker but real property: the approval lives outside the project, the artifact
   cannot authorise itself, and the builder-side CLI has no verb that records one.

If a check cannot be performed, or the approval file is unreadable, the honest
answer is a refusal -- never a pass. A corrupt ``approvals.json`` is never
silently replaced, for the same reason a registry is not: "repair a JSON file" is
a smaller problem than "silently lose every other approval".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from . import boundaries
from .candidate import CANDIDATE_NAME, MANIFEST_NAME, TOOL_FILES
from .capabilities import environment_label
from .history import content_digest
from .private import private_home
from .status import (
    EXIT_OK,
    EXIT_USAGE,
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    Result,
    exit_code_for,
    summarize,
)

APPROVAL_ENV = "OPENREADY_APPROVAL_HOME"
APPROVAL_NAME = "approvals.json"
PUBLISHER_TOKEN_ENV = "OPENREADY_PUBLISHER_TOKEN_FILE"
APPROVAL_SCHEMA_VERSION = "1.0"

#: The one field a candidate is *allowed* to carry that a naive reader might trust.
SELF_ASSERTED_FIELDS = ("approved", "approved_by", "approved_by_role", "owner_approved")

APPROVAL_LIMITATION = (
    "An approval record proves only that this exact (digest, destination, licence) "
    "was recorded by the owner. It does not establish that the content is safe, "
    "lawful or free of private data, and it authorises nothing by itself."
)
INTEGRITY_LIMITATION = (
    "A record's own digest detects an edit made to the approval file after it was "
    "written. It is not a signature: anyone who can write the file can rewrite the "
    "record and its digest together, so the file must live where only the owner "
    "writes."
)
TOKEN_LIMITATION = (
    "The publisher credential is read as a FILE PATH only. Its value is never read, "
    "printed, logged or stored by this module."
)
SELF_ASSERTED_LIMITATION = (
    "A field named 'approved' inside the candidate's own metadata is written by "
    "whoever produced the candidate. It is not an approval and is ignored here."
)


# --- locations ----------------------------------------------------------------


def approval_dir(env: Optional[Dict[str, str]] = None) -> Path:
    """Where owner approvals live: ``$OPENREADY_APPROVAL_HOME`` or ``<private>/approvals``."""
    source = os.environ if env is None else env
    raw = source.get(APPROVAL_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (private_home(env) / "approvals").resolve()


def approval_file(env: Optional[Dict[str, str]] = None) -> Path:
    return approval_dir(env) / APPROVAL_NAME


def publisher_token_path(env: Optional[Dict[str, str]] = None) -> Optional[Path]:
    """The owner-held publisher credential, as a *path*, or None.

    Deliberately reads a path from ``OPENREADY_PUBLISHER_TOKEN_FILE`` and never a
    token value from an environment variable. Nothing here opens the file.
    """
    source = os.environ if env is None else env
    raw = source.get(PUBLISHER_TOKEN_ENV, "").strip()
    return Path(raw).expanduser() if raw else None


# --- the approval's own integrity ---------------------------------------------


def _approval_digest(candidate_digest: str, destination: str, licence: str, actor: str) -> str:
    """The digest of an approval, over the four fields that define it.

    Canonical JSON (sorted keys, no insignificant whitespace) so the same fields
    produce the same digest on every machine. This is what makes a later edit of
    the stored file detectable.
    """
    canonical = json.dumps(
        {
            "candidate_digest": candidate_digest,
            "destination": destination,
            "licence": licence,
            "actor": actor,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _record_digest_ok(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    stored = record.get("approval_digest")
    expected = _approval_digest(
        str(record.get("candidate_digest", "")),
        str(record.get("destination", "")),
        str(record.get("licence", "")),
        str(record.get("actor", "")),
    )
    return stored == expected


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --- persistence --------------------------------------------------------------


def load(env: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, Any], List[Result]]:
    """Read the approval file. Returns (document, problems); problems block any write.

    Never silently replaces an unreadable file: the problems make every caller
    refuse to write, because replacing it would take the other approvals with it.
    """
    path = approval_file(env)
    empty: Dict[str, Any] = {"schema_version": APPROVAL_SCHEMA_VERSION, "approvals": []}
    if not path.is_file():
        return empty, []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return empty, [Result(
            "publisher.approval-unreadable", FAIL, REVIEW,
            f"{path} exists but could not be read ({exc}); nothing was overwritten and no "
            f"approval was recorded",
            __version__, environment_label(), required=False,
            limitations=[
                "Repair or remove that file, then run the command again. It is never "
                "replaced automatically, because the other approvals would go with it.",
                APPROVAL_LIMITATION,
            ],
        )]
    if not isinstance(document, dict) or not isinstance(document.get("approvals"), list):
        return empty, [Result(
            "publisher.approval-malformed", FAIL, REVIEW,
            f"{path} does not hold an approval document with an 'approvals' list; nothing "
            f"was overwritten",
            __version__, environment_label(), required=False,
            limitations=[APPROVAL_LIMITATION],
        )]
    document.setdefault("schema_version", APPROVAL_SCHEMA_VERSION)
    return document, []


def save(document: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Path:
    """Write the approval file atomically, so a crash cannot leave it half-written."""
    path = approval_file(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)
    return path


def verify_store(env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Read-only integrity audit of the approval store itself.

    Every record carries a digest over its own (candidate_digest, destination,
    licence, actor) fields. Recomputing it catches an edited record -- someone
    widening a destination or swapping a licence in the file after the fact -- which
    is the one tamper an approval file is otherwise open to.
    """
    document, problems = load(env)
    if problems:
        return problems
    records = [r for r in document.get("approvals", []) if isinstance(r, dict)]
    if not records:
        return [Result(
            "publisher.store-empty", NOT_RUN, REVIEW,
            f"no approvals are recorded in {approval_file(env)}; this reports nothing about "
            f"whether any candidate is approved", __version__, environment_label(),
            limitations=[APPROVAL_LIMITATION],
        )]

    tampered: List[str] = []
    for record in records:
        if not _record_digest_ok(record):
            tampered.append(f"{str(record.get('candidate_digest'))[:16]}… -> "
                            f"{record.get('destination')!r}")
    if tampered:
        return [Result(
            "publisher.store-tampered", FAIL, STOP,
            f"{len(tampered)} approval record(s) do not match their own digest and are therefore "
            f"not usable: {'; '.join(sorted(tampered))}", __version__, environment_label(),
            evidence_path=str(approval_file(env)),
            limitations=["A tampered record is reported, never repaired: the whole store is left "
                         "untouched so a human can inspect it.", APPROVAL_LIMITATION],
        )]
    return [Result(
        "publisher.store-intact", PASS, INFO,
        f"{len(records)} approval record(s) match their own digests; the store is "
        f"{approval_file(env)} (outside every project by construction)",
        __version__, environment_label(), evidence_path=str(approval_file(env)),
        limitations=[APPROVAL_LIMITATION, INTEGRITY_LIMITATION],
    )]


def record_approval(candidate_digest: str, destination: str, licence: str, actor: str,
                    note: str = "", env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Record an owner approval bound to (digest, destination, licence).

    ``actor`` must be exactly ``'owner'``. Any other actor -- ``'builder'``,
    ``'agent'``, ``'verifier'``, anything -- is refused with FAIL/STOP and nothing
    is written. An empty digest, destination or licence is refused too, because an
    approval that binds nothing authorises everything.

    The record carries the digest of the approval itself (see
    :func:`_approval_digest`) so a later edit of the file is detectable.
    """
    if actor != "owner":
        return [Result(
            "publisher.approval-actor", FAIL, STOP,
            f"refusing to record an approval for actor {actor!r}: only the owner records an "
            f"approval. A builder, agent or verifier cannot approve its own artifact.",
            __version__, environment_label(),
            limitations=[
                "The publisher principal is separate from the builder for this reason: an "
                "approval a builder can write is not an approval.",
                APPROVAL_LIMITATION,
            ],
        )]
    digest = (candidate_digest or "").strip()
    if not digest:
        return [Result(
            "publisher.approval-digest", FAIL, STOP,
            "refusing to record an approval with no candidate digest: an approval that binds "
            "no artifact authorises everything",
            __version__, environment_label(), limitations=[APPROVAL_LIMITATION],
        )]
    want_destination = (destination or "").strip()
    if not want_destination:
        return [Result(
            "publisher.approval-destination", FAIL, STOP,
            "refusing to record an approval with no destination: where a candidate may go is "
            "part of what is approved",
            __version__, environment_label(), limitations=[APPROVAL_LIMITATION],
        )]
    want_licence = (licence or "").strip()
    if not want_licence:
        return [Result(
            "publisher.approval-licence", FAIL, STOP,
            "refusing to record an approval with no licence: the licence is part of what is "
            "approved",
            __version__, environment_label(), limitations=[APPROVAL_LIMITATION],
        )]

    document, problems = load(env)
    if problems:
        return problems

    record: Dict[str, Any] = {
        "candidate_digest": digest,
        "destination": want_destination,
        "licence": want_licence,
        "actor": "owner",
        "recorded_at": _now(),
    }
    if note.strip():
        record["note"] = note.strip()
    record["approval_digest"] = _approval_digest(digest, want_destination, want_licence, "owner")

    document["approvals"].append(record)
    path = save(document, env)
    return [Result(
        "publisher.approval-recorded", PASS, INFO,
        f"recorded owner approval for digest {digest}, destination {want_destination!r}, "
        f"licence {want_licence!r} in {path}",
        __version__, environment_label(), candidate_digest=digest,
        evidence_path=str(path),
        limitations=[APPROVAL_LIMITATION, INTEGRITY_LIMITATION],
    )]


# --- reading the frozen candidate ---------------------------------------------


def _candidate_files(root: Path) -> List[str]:
    out: List[str] = []
    def onerror(exc: OSError) -> None:
        raise exc
    for where, dirs, names in os.walk(root, topdown=True, onerror=onerror):
        if any((Path(where) / name).is_symlink() for name in dirs):
            raise boundaries.BoundaryError("candidate contains a directory symlink")
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(names):
            rel = (Path(where) / name).relative_to(root).as_posix()
            if rel in TOOL_FILES:
                continue
            out.append(rel)
    return out


def _candidate_content_digest(root: Path) -> str:
    """Re-derive the content digest from the frozen candidate's own bytes.

    Uses the same digest function the exporter and verifier use, over the same set
    of files (everything but the two tool metadata files), so the number means the
    same thing in all three places.
    """
    if (root / ".git").exists() or (root / ".git").is_symlink():
        raise boundaries.BoundaryError("history-bearing artifacts are not publishable")
    snapshot = boundaries.capture(root, _candidate_files(root))
    return content_digest([(item.path, item.data) for item in snapshot])


def _candidate_self_approval(root: Path) -> List[str]:
    """Names of self-asserted approval fields found in the candidate's own metadata.

    Read only so they can be *named* as ignored. Nothing in this module ever treats
    one as an approval.
    """
    found: List[str] = []
    for name in (CANDIDATE_NAME, MANIFEST_NAME):
        path = root / name
        if not path.is_file():
            continue
        try:
            with boundaries.directory(root) as fd:
                document = boundaries.decode_object(boundaries.read_file(fd, name, boundaries.MAX_METADATA_BYTES).data)
        except (ValueError, OSError):
            continue
        if isinstance(document, dict):
            found.extend(f"{name}:{key}" for key in SELF_ASSERTED_FIELDS if key in document)
    return found


# --- the read-only check ------------------------------------------------------


def verify_approval(candidate: Path, destination: str, licence: str,
                    env: Optional[Dict[str, str]] = None) -> List[Result]:
    """The read-only check a separate publisher runs. One Result per step."""
    candidate = Path(candidate)
    if not candidate.is_dir():
        return [Result(
            "publisher.candidate-readable", FAIL, STOP,
            f"{candidate} is not a directory, so no candidate digest could be derived",
            __version__, environment_label(),
            limitations=["The digest is derived from the frozen candidate's own bytes; there "
                         "are none to read here."],
        )]

    manifest_path = candidate / MANIFEST_NAME
    meta_path = candidate / CANDIDATE_NAME
    if not manifest_path.is_file() or not meta_path.is_file():
        missing = [n for n in (MANIFEST_NAME, CANDIDATE_NAME) if not (candidate / n).is_file()]
        return [Result(
            "publisher.candidate-readable", FAIL, STOP,
            f"{candidate} is missing {', '.join(missing)}; this is not a candidate export",
            __version__, environment_label(),
        )]

    # 1. Re-derive the digest from the frozen candidate's bytes. This is the artifact
    #    identity; the candidate's own CANDIDATE.json is never trusted for it.
    try:
        digest = _candidate_content_digest(candidate)
    except (OSError, ValueError) as exc:
        return [Result(
            "publisher.candidate-digest", FAIL, STOP,
            f"could not read the candidate's bytes to derive its digest ({exc})",
            __version__, environment_label(),
        )]

    results: List[Result] = [Result(
        "publisher.candidate-digest", PASS, INFO,
        f"re-derived content digest from the frozen candidate's bytes: {digest}",
        __version__, environment_label(), candidate_digest=digest,
        limitations=["The digest is over the candidate's content files only; the two tool "
                     "metadata files describe the candidate and are not part of its identity."],
    )]

    want_destination = (destination or "").strip()
    want_licence = (licence or "").strip()

    # 4. The candidate's own 'approved' field is named and ignored, always, so a
    #    reader can see the rule rather than infer it.
    self_asserted = _candidate_self_approval(candidate)
    if self_asserted:
        results.append(Result(
            "publisher.self-asserted-approval", NEEDS_HUMAN, REVIEW,
            f"the candidate's own metadata carries {', '.join(self_asserted)}; this is "
            f"IGNORED. Only an owner approval record bound to ({digest}, {want_destination!r}, "
            f"{want_licence!r}) authorises anything.",
            __version__, environment_label(), required=False,
            candidate_digest=digest,
            limitations=[SELF_ASSERTED_LIMITATION, APPROVAL_LIMITATION],
        ))
    else:
        results.append(Result(
            "publisher.self-asserted-approval", PASS, INFO,
            "any field named 'approved' in the candidate's own metadata is IGNORED; approval "
            "exists only as an owner record bound to (digest, destination, licence)",
            __version__, environment_label(), required=False,
            candidate_digest=digest, limitations=[SELF_ASSERTED_LIMITATION],
        ))

    document, problems = load(env)
    if problems:
        results.extend(problems)
        results.append(Result(
            "publisher.approval-record", FAIL, STOP,
            f"no approval could be read from {approval_file(env)}, so this candidate is not "
            f"approved",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[APPROVAL_LIMITATION],
        ))
        return results

    records = [r for r in document.get("approvals", []) if isinstance(r, dict)]

    # 3. The approval file's own integrity: a record whose stored digest does not match
    #    its contents was edited after it was written and grants nothing.
    valid: List[Dict[str, Any]] = []
    corrupt: List[str] = []
    for record in records:
        if _record_digest_ok(record):
            valid.append(record)
        else:
            corrupt.append(str(record.get("candidate_digest", "<no digest>")))
    if corrupt:
        results.append(Result(
            "publisher.approval-integrity", FAIL, STOP,
            f"{len(corrupt)} approval record(s) do not match their own integrity digest and "
            f"grant nothing: {', '.join(corrupt[:3])}",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[INTEGRITY_LIMITATION, APPROVAL_LIMITATION],
        ))
    else:
        results.append(Result(
            "publisher.approval-integrity", PASS, INFO,
            f"all {len(valid)} approval record(s) match their own integrity digest",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[INTEGRITY_LIMITATION],
        ))

    # 2. Require a valid record for exactly this digest AND destination AND licence.
    by_digest = [r for r in valid if str(r.get("candidate_digest", "")) == digest]
    if not by_digest:
        others = sorted({str(r.get("candidate_digest", "")) for r in valid})
        detail = (f"; records exist for other digest(s): {', '.join(others[:3])}"
                  if others else "; the approval file holds no record at all")
        results.append(Result(
            "publisher.approval-record", FAIL, STOP,
            f"no owner approval matches this candidate: the frozen bytes digest to {digest} "
            f"but there is no approval for that digest{detail}. A candidate that changed by "
            f"one byte is a different artifact and its approval does not apply.",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[APPROVAL_LIMITATION],
        ))
        return results

    by_destination = [r for r in by_digest if str(r.get("destination", "")) == want_destination]
    if not by_destination:
        available = sorted({str(r.get("destination", "")) for r in by_digest})
        results.append(Result(
            "publisher.approval-record", FAIL, STOP,
            f"an owner approval exists for digest {digest} but not for destination "
            f"{want_destination!r} (approved destination(s): {', '.join(available) or 'none'})",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[APPROVAL_LIMITATION],
        ))
        return results

    by_licence = [r for r in by_destination if str(r.get("licence", "")) == want_licence]
    if not by_licence:
        available = sorted({str(r.get("licence", "")) for r in by_destination})
        results.append(Result(
            "publisher.approval-record", FAIL, STOP,
            f"an owner approval exists for digest {digest} at {want_destination!r} but not for "
            f"licence {want_licence!r} (approved licence(s): {', '.join(available) or 'none'})",
            __version__, environment_label(), candidate_digest=digest,
            evidence_path=str(approval_file(env)),
            limitations=[APPROVAL_LIMITATION],
        ))
        return results

    matched = by_licence[0]
    results.append(Result(
        "publisher.approval-record", PASS, INFO,
        f"owner approval found for digest {digest}, destination {want_destination!r}, "
        f"licence {want_licence!r} (recorded {matched.get('recorded_at', 'unknown')})",
        __version__, environment_label(), candidate_digest=digest,
        evidence_path=str(approval_file(env)),
        limitations=[APPROVAL_LIMITATION],
    ))
    results.append(Result(
        "publisher.read-only", NOT_RUN, INFO,
        "this check authorises the *next* step; it performs none. Publication, push, "
        "visibility and upload remain a manual owner action outside this tool.",
        __version__, environment_label(), required=False,
        limitations=[APPROVAL_LIMITATION, TOKEN_LIMITATION],
    ))
    return results


# --- read-only entry point ----------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openready-publisher",
        description=(
            "Independent publisher check. Read-only: this tool has no publish, push, "
            "visibility or upload verb and must not gain one."
        ),
    )
    parser.add_argument("--version", action="version", version=f"openready-publisher {__version__}")
    sub = parser.add_subparsers(dest="verb", required=True)
    check = sub.add_parser("check", help="read-only: does an owner approval cover this artifact?")
    check.add_argument("--candidate", required=True)
    check.add_argument("--destination", required=True)
    check.add_argument("--licence", required=True)
    check.add_argument("--json", action="store_true")

    record = sub.add_parser(
        "record",
        help="the OWNER's act: bind an approval to an exact (digest, destination, licence). "
             "Refused for any actor other than 'owner'.",
    )
    record.add_argument("--candidate", required=True,
                        help="the frozen candidate directory; its digest is re-derived here, "
                             "never read from the candidate's own metadata")
    record.add_argument("--destination", required=True)
    record.add_argument("--licence", required=True)
    record.add_argument("--actor", required=True,
                        help="must be exactly 'owner' -- a string, not an authenticated identity")
    record.add_argument("--note", default="")
    record.add_argument("--json", action="store_true")

    log = sub.add_parser("verify-log", help="read-only integrity check of the approval store")
    log.add_argument("--json", action="store_true")
    return parser


def _emit(results: List[Result], as_json: bool) -> int:
    code = exit_code_for(results)
    if as_json:
        print(json.dumps({
            "tool_version": __version__,
            "command": "check",
            "exit_code": code,
            "summary": summarize(results),
            "approval_file": str(approval_file()),
            "publisher_token_file": (str(publisher_token_path())
                                     if publisher_token_path() else None),
            "results": [r.to_dict() for r in results],
        }, indent=2, default=str))
    else:
        counts = summarize(results)
        for result in results:
            tag = "ok  " if result.status == PASS else {
                FAIL: "STOP", NEEDS_HUMAN: "HUMAN", NOT_RUN: "UNRUN",
            }.get(result.status, "PROB")
            print(f"  {tag} {result.check_id}: {result.message}")
            for limitation in result.limitations:
                print(f"        limitation: {limitation}")
        print(f"  -> exit {code} (failed {counts[FAIL]}, human {counts['NEEDS_HUMAN']}, "
              f"unrun {counts[NOT_RUN]})")
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """The publisher entry point.

    ``python3 -m openready.publisher check --candidate PATH --destination D --licence L``
    answers whether an owner approval covers this exact artifact.

    ``python3 -m openready.publisher record --candidate PATH --destination D --licence L
    --actor owner`` is the owner's act of binding that approval. It is refused for any
    other actor, and the digest it binds is re-derived from the candidate's bytes.

    ``python3 -m openready.publisher verify-log`` audits the approval store's integrity.

    There is no verb that changes anything anywhere -- no publish, no push, no
    visibility change, no upload -- and an unknown verb is a usage error.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 for a usage error; the CLI contract reserves 2 for
        # "a required human review blocks release", so the two must not be confused.
        code = exc.code
        if code in (2, None):
            return EXIT_USAGE if code == 2 else EXIT_OK
        return int(code)

    if args.verb == "verify-log":
        return _emit(verify_store(), args.json)

    if args.verb == "record":
        candidate = Path(args.candidate)
        if not candidate.is_dir():
            return _emit([Result(
                "publisher.candidate-missing", FAIL, STOP,
                f"{candidate} is not a directory, so no digest can be derived and nothing was "
                f"recorded", __version__, environment_label(),
                limitations=[APPROVAL_LIMITATION],
            )], args.json)
        results = record_approval(
            _candidate_content_digest(candidate), args.destination, args.licence,
            args.actor, note=args.note,
        )
        return _emit(results, args.json)

    if args.verb == "check":
        results = verify_approval(Path(args.candidate), args.destination, args.licence)
        return _emit(results, args.json)

    print("usage error: unknown verb", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
