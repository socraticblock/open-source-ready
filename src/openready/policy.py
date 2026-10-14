"""Scoped owner approvals for external services and recurring expenses (OR-011).

Acceptance tests A10 and A12 ask two questions the rest of this tool cannot answer
by inspection:

* **A10** -- a daily build wants to upload the journal to a cloud destination.
  Is that *permitted*?
* **A12** -- a new paid API subscription is proposed. Was it authorised by the
  owner *before* money was spent?

Both are answered the same way: by a small, private, owner-authored policy that
grants one ``(destination, data_class)`` pair at a time, for a bounded time, with
the ability to revoke. Nothing here is a blanket approval of a host, a vendor or a
budget line -- the scope is the pair, and it expires.

The honest limit, stated here and in every result rather than in a footnote:

    This module makes **no network call**, and it cannot *block* one either. It can
    only **refuse to authorise** an outbound flow, and say so. A caller that ignores
    this answer has not been stopped by it. This is a policy and an honest label,
    not egress containment -- ``capabilities.py`` already reports egress containment
    as ``NOT_ENFORCED`` for exactly this reason. No fake PASS, and no claim of a
    protection that is not there.

Three properties make this a *scoped approval* rather than a setting, and each is
enforced in code, not prose:

1. **The scope is the pair.** ``api.example.invalid`` approved for ``public-metadata``
   says nothing about ``private-notes`` sent to the same host.
2. **It expires.** A grant carries an ISO-8601 expiry; past it the approval lapses
   and a check on the pair FAILs, it does not quietly continue.
3. **It is revocable, and history survives.** Revoking records the revocation and
   keeps the grant, so a check FAILs and the listing still shows what was once
   approved.

Two further rules:

* **Only the owner can grant or revoke.** ``actor`` must be exactly ``owner``.
  ``builder``, ``agent`` and everything else is refused, and nothing is written.
* **No note is ever stored.** Notes record *why* an approval exists and may hold
  private prose, so only a sha256 of the note is kept. The body is not written to
  the file and never appears in a listing.

The policy file lives in the private runtime data root, outside every project and
every git working tree, so a careless ``git add -A`` in any project cannot publish
it. A policy that cannot be read is reported and **never** silently replaced:
rewriting a file a human edited would discard the very record the tool exists to
keep.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from . import private as private_mod
from .capabilities import environment_label
from .status import (
    EXIT_OK,
    EXIT_USAGE,
    FAIL,
    INFO,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    Result,
    exit_code_for,
)

#: Environment variable that relocates the policy root (used by the acceptance
#: harness and by tests; the default is the private runtime data root).
POLICY_ENV = "OPENREADY_POLICY_HOME"
POLICY_NAME = "external-services.json"
SCHEMA_VERSION = "1.0"

#: The only actor permitted to author or revoke an approval.
OWNER = "owner"

#: An approval may not run longer than this, so a grant is always revisited.
MAX_EXPIRY_DAYS = 366

# --- limitations --------------------------------------------------------------

GRANT_LIMITATION = (
    "A grant is a scoped owner authorisation recorded on this host, not a network "
    "control: nothing here stops a call that ignores this policy. A principal with "
    "filesystem write access to the policy file could edit it; the per-record digest "
    "makes that detectable, not impossible."
)
CHECK_LIMITATION = (
    "This tool makes no network call and cannot block one: it can only refuse to "
    "authorise an outbound flow. A caller must honour that decision; it is not egress "
    "containment."
)
REDACTION_LIMITATION = (
    "A note is never stored -- only its sha256 digest is kept, because notes may "
    "contain private prose or a credential written down by mistake."
)
ABSENT_LIMITATION = (
    "Absence of a policy is not permission: with no file, every outbound flow is "
    "unauthorised, and this tool can only say so."
)
LOCATION_LIMITATION = (
    "The private location is a filesystem convention, not a control: nothing prevents "
    "an operator from copying the policy into a project by hand."
)


# --- location -----------------------------------------------------------------


def policy_home(env: Optional[Dict[str, str]] = None) -> Path:
    """The directory holding the policy. Defaults to the private runtime data root.

    ``OPENREADY_POLICY_HOME`` overrides it, exactly as ``OPENREADY_PRIVATE_HOME``
    overrides the private root in :mod:`openready.private`. The default is that
    private root, which is outside every project and every git working tree by
    construction.
    """
    source = os.environ if env is None else env
    raw = source.get(POLICY_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return private_mod.private_home(source)


def policy_file(env: Optional[Dict[str, str]] = None) -> Path:
    """Absolute path of the policy file. Nothing is created by reading this."""
    return policy_home(env) / POLICY_NAME


# --- time helpers -------------------------------------------------------------


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_dt().replace(microsecond=0).isoformat()


def _parse_expiry(raw: Any) -> datetime:
    """Parse an ISO-8601 date (``YYYY-MM-DD``) or datetime into an aware UTC instant.

    A date-only expiry is valid through the end of that day, which is what an
    operator writing ``2030-01-01`` means.
    """
    text = str(raw).strip()
    if not text:
        raise ValueError("empty expiry")
    if "T" in text or " " in text:
        moment = datetime.fromisoformat(text)
    else:
        day = date.fromisoformat(text)
        moment = datetime.combine(day, time(23, 59, 59, 999999))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def is_expired(record: Any, now: Optional[datetime] = None) -> bool:
    """True when a record's approval has lapsed. Fails closed on an unreadable expiry.

    ``record`` is a grant mapping (or a raw expiry string). An expiry this module
    cannot parse is treated as *not active*, because an approval whose end date
    cannot be established is not an approval a caller may rely on.
    """
    raw = record.get("expires") if isinstance(record, dict) else record
    try:
        expiry = _parse_expiry(raw)
    except (ValueError, TypeError):
        return True
    moment = now or _now_dt()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return expiry < moment.astimezone(timezone.utc)


def _revoked(record: Dict[str, Any]) -> bool:
    return bool(str(record.get("revoked_at", "")).strip())


# --- digests ------------------------------------------------------------------


def _note_digest(note: str) -> Optional[str]:
    text = str(note or "")
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def approval_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """The approval fields a grant's digest covers.

    Deliberately excludes the digest itself and the revocation fields: revoking an
    approval is a legitimate recorded act, and must not look like tampering. Any
    edit to the *scope* -- the service id, destination, data class, expiry, actor or
    grant time -- changes the digest and is detectable.
    """
    return {
        "service_id": str(record.get("service_id", "")),
        "destination": str(record.get("destination", "")),
        "data_class": str(record.get("data_class", "")),
        "expires": str(record.get("expires", "")),
        "actor": str(record.get("actor", "")),
        "granted_at": str(record.get("granted_at", "")),
        "note_digest": record.get("note_digest"),
    }


def record_digest(record: Dict[str, Any]) -> str:
    """sha256 of a grant's approval fields, so a later edit is detectable."""
    blob = json.dumps(approval_view(record), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _is_tampered(record: Dict[str, Any]) -> bool:
    digest = str(record.get("digest", "")).strip()
    return bool(digest) and digest != record_digest(record)


# --- matching -----------------------------------------------------------------


def _norm(text: Any) -> str:
    """Normalise a destination or data class for comparison.

    Whitespace is stripped and case is folded: a hostname and a data-class label
    are conventionally lower-case, and ``API.example.invalid`` is the same
    destination as ``api.example.invalid``. Everything else must match exactly --
    this is not a prefix or suffix match.
    """
    return str(text or "").strip().casefold()


# --- load / save --------------------------------------------------------------


def _empty() -> Dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "policy": "external-services", "grants": {}}


def load(env: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, Any], List[Result]]:
    """Read the policy. Returns ``(document, problems)``.

    * An **absent** file is not an error and not a permission: it yields an empty
      policy plus a ``NOT_RUN`` result that says nothing is authorised yet.
    * A file that **cannot be read** yields a ``FAIL`` result and an empty policy.
      It is never replaced from here -- callers that write refuse to proceed.
    """
    path = policy_file(env)
    if not path.is_file():
        return _empty(), [Result(
            "policy.absent", NOT_RUN, REVIEW,
            f"no external-services policy exists at {path}: nothing is authorised "
            f"yet and this tool cannot actually block a network call it does not "
            f"make -- it can only refuse to authorise one",
            __version__, environment_label(), required=True,
            enforcement=NOT_ENFORCED, evidence_path=str(path),
            limitations=[ABSENT_LIMITATION, LOCATION_LIMITATION, CHECK_LIMITATION],
        )]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return _empty(), [Result(
            "policy.unreadable", FAIL, STOP,
            f"{path} exists but could not be read ({exc}); nothing was overwritten "
            f"and no approval is in force",
            __version__, environment_label(), required=True,
            evidence_path=str(path),
            limitations=[
                "Repair or remove that file by hand, then run the command again. It is "
                "never replaced automatically, because the other approvals would go "
                "with it.",
                LOCATION_LIMITATION,
            ],
        )]
    if not isinstance(document, dict) or not isinstance(document.get("grants"), dict):
        return _empty(), [Result(
            "policy.malformed", FAIL, STOP,
            f"{path} does not hold an external-services policy with a 'grants' map; "
            f"nothing was overwritten",
            __version__, environment_label(), required=True,
            evidence_path=str(path),
            limitations=[LOCATION_LIMITATION],
        )]
    document.setdefault("schema_version", SCHEMA_VERSION)
    return document, []


def save(document: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Path:
    """Write the policy atomically, so a crash cannot leave it half-written.

    Only ever called after a clean :func:`load`: a policy that could not be read is
    never the thing that gets overwritten.
    """
    path = policy_file(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)
    return path


def _fatal(problems: List[Result]) -> List[Result]:
    """The subset of load problems that must block a write."""
    return [r for r in problems if r.status in (FAIL, "NEEDS_HUMAN")]


# --- grant / revoke -----------------------------------------------------------


def grant(service_id: str, destination: str, data_class: str, expires: str, actor: str,
          note: str = '', env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Scope ONE ``(destination, data_class)`` pair to one service, until ``expires``.

    Refused, writing nothing, when:

    * ``actor`` is not exactly ``owner``;
    * any of ``service_id``/``destination``/``data_class``/``expires`` is blank;
    * the expiry cannot be parsed, is in the past, or is more than 366 days out;
    * an existing policy file cannot be read (it is never overwritten).

    On success one ``PASS`` result is returned naming the scope and the expiry, and
    the record is written with a digest of its own approval fields.
    """
    if actor != OWNER:
        return [Result(
            "policy.grant-refused", FAIL, STOP,
            f"actor {actor!r} may not grant an external-service approval; only "
            f"{OWNER!r} may, and nothing was written",
            __version__, environment_label(), required=True,
            limitations=[
                "The actor check is a convention enforced by this writer, not a "
                "credential: anyone able to edit the private file directly could "
                "bypass it. The per-record digest makes such an edit detectable.",
                GRANT_LIMITATION,
            ],
        )]

    blanks = [name for name, value in (
        ("service_id", service_id), ("destination", destination),
        ("data_class", data_class), ("expires", expires),
    ) if not str(value or "").strip()]
    if blanks:
        return [Result(
            "policy.grant-invalid", FAIL, STOP,
            f"cannot grant: blank field(s) {', '.join(blanks)}; nothing was written",
            __version__, environment_label(), required=True,
            limitations=[GRANT_LIMITATION],
        )]

    try:
        instant = _parse_expiry(expires)
    except (ValueError, TypeError) as exc:
        return [Result(
            "policy.grant-invalid", FAIL, STOP,
            f"cannot grant: expiry {expires!r} is not an ISO-8601 date or datetime "
            f"({exc}); nothing was written",
            __version__, environment_label(), required=True,
            limitations=[GRANT_LIMITATION],
        )]

    now = _now_dt()
    if instant <= now:
        return [Result(
            "policy.grant-invalid", FAIL, STOP,
            f"cannot grant: expiry {expires} is in the past; an approval that starts "
            f"expired authorises nothing, and nothing was written",
            __version__, environment_label(), required=True,
            limitations=[GRANT_LIMITATION],
        )]
    if instant - now > timedelta(days=MAX_EXPIRY_DAYS):
        return [Result(
            "policy.grant-invalid", FAIL, STOP,
            f"cannot grant: expiry {expires} is more than {MAX_EXPIRY_DAYS} days out; "
            f"a grant must be revisited, not handed over indefinitely, and nothing "
            f"was written",
            __version__, environment_label(), required=True,
            limitations=[GRANT_LIMITATION],
        )]

    document, problems = load(env)
    fatal = _fatal(problems)
    if fatal:
        return fatal

    record: Dict[str, Any] = {
        "service_id": str(service_id).strip(),
        "destination": str(destination).strip(),
        "data_class": str(data_class).strip(),
        "expires": str(expires).strip(),
        "actor": OWNER,
        "granted_at": _now_iso(),
        "note_digest": _note_digest(note),
    }
    record["digest"] = record_digest(record)
    document["grants"][record["service_id"]] = record
    save(document, env)

    return [Result(
        "policy.granted", PASS, INFO,
        f"granted {OWNER} approval for service {record['service_id']!r}: send "
        f"{record['data_class']!r} to {record['destination']!r} until "
        f"{record['expires']} (record digest {record['digest'][:12]}...)",
        __version__, environment_label(), evidence_path=str(policy_file(env)),
        limitations=[GRANT_LIMITATION, REDACTION_LIMITATION],
    )]


def revoke(service_id: str, actor: str,
           env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Revoke a service's approval, recording the revocation and keeping the grant.

    Refused, writing nothing, when ``actor`` is not exactly ``owner``, when
    ``service_id`` is blank, or when an existing policy cannot be read. An unknown
    service id is a FAIL. Re-revoking an already-revoked service changes nothing and
    is reported as such.
    """
    if actor != OWNER:
        return [Result(
            "policy.revoke-refused", FAIL, STOP,
            f"actor {actor!r} may not revoke an external-service approval; only "
            f"{OWNER!r} may, and nothing was written",
            __version__, environment_label(), required=True,
            limitations=[
                "The actor check is a convention enforced by this writer, not a "
                "credential.",
                GRANT_LIMITATION,
            ],
        )]
    if not str(service_id or "").strip():
        return [Result(
            "policy.revoke-invalid", FAIL, STOP,
            "cannot revoke: a service id is required; nothing was written",
            __version__, environment_label(), required=True,
            limitations=[GRANT_LIMITATION],
        )]

    document, problems = load(env)
    fatal = _fatal(problems)
    if fatal:
        return fatal

    key = str(service_id).strip()
    record = document["grants"].get(key)
    if not isinstance(record, dict):
        return [Result(
            "policy.unknown-service", FAIL, STOP,
            f"no approval is recorded for service {key!r} in {policy_file(env)}; "
            f"nothing was written",
            __version__, environment_label(),
            limitations=[GRANT_LIMITATION],
        )]

    if _revoked(record):
        return [Result(
            "policy.already-revoked", PASS, INFO,
            f"service {key!r} was already revoked at {record.get('revoked_at')}; the "
            f"historical record is unchanged",
            __version__, environment_label(), evidence_path=str(policy_file(env)),
            limitations=[GRANT_LIMITATION],
        )]

    record["revoked_at"] = _now_iso()
    record["revoked_by"] = OWNER
    save(document, env)
    return [Result(
        "policy.revoked", PASS, INFO,
        f"revoked the approval for service {key!r}; the grant is kept as history so a "
        f"check on {record.get('destination')!r} now FAILs",
        __version__, environment_label(), evidence_path=str(policy_file(env)),
        limitations=[GRANT_LIMITATION],
    )]


# --- the enforcement question -------------------------------------------------


def check(destination: str, data_class: str,
          env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Is this exact outbound flow authorised right now? Asked before any call.

    * ``PASS``/``INFO`` only for an exact ``(destination, data_class)`` match that is
      unexpired and unrevoked, naming the service id and the expiry;
    * ``FAIL``/``STOP`` for a match that exists but is expired or revoked -- a scoped
      approval is not a blanket one;
    * ``FAIL``/``STOP`` for a destination approved only for a *different* data class
      -- the scope is the pair, never the host;
    * ``NOT_RUN``/``NOT_ENFORCED`` and ``required`` whenever no policy file exists or
      no match does, so the caller's exit code is 3 and never 0, because this tool
      cannot actually block a network call it does not make -- it can only refuse to
      authorise one.
    """
    if not str(destination or "").strip() or not str(data_class or "").strip():
        return [Result(
            "policy.check-usage", FAIL, STOP,
            "check needs both a destination and a data_class; an empty field cannot "
            "be authorised",
            __version__, environment_label(), required=True,
            limitations=[CHECK_LIMITATION],
        )]

    document, problems = load(env)
    if any(r.status == FAIL for r in problems):
        return problems

    want_dest = _norm(destination)
    want_class = _norm(data_class)
    grants = [g for g in document.get("grants", {}).values() if isinstance(g, dict)]
    same_dest = [g for g in grants if _norm(g.get("destination")) == want_dest]
    exact = [g for g in same_dest if _norm(g.get("data_class")) == want_class]
    active = [g for g in exact if not _revoked(g) and not is_expired(g)]

    if active:
        record = sorted(active, key=lambda g: str(g.get("service_id", "")))[0]
        if _is_tampered(record):
            return [Result(
                "policy.tampered", FAIL, STOP,
                f"the grant for service {record.get('service_id')!r} has a digest that "
                f"does not match its content: the approval record was edited after it "
                f"was written, so it cannot be trusted",
                __version__, environment_label(), required=True,
                evidence_path=str(policy_file(env)),
                limitations=[GRANT_LIMITATION, CHECK_LIMITATION],
            )]
        return [Result(
            "policy.authorised", PASS, INFO,
            f"{data_class!r} to {destination!r} is authorised by {OWNER} approval "
            f"{record.get('service_id')!r} until {record.get('expires')}",
            __version__, environment_label(), enforcement="ADVISORY",
            evidence_path=str(policy_file(env)),
            limitations=[CHECK_LIMITATION],
        )]

    if exact:
        record = sorted(exact, key=lambda g: str(g.get("service_id", "")))[0]
        state = "revoked" if _revoked(record) else "expired"
        return [Result(
            "policy.approval-lapsed", FAIL, STOP,
            f"an approval exists for {destination!r} / {data_class!r} but it is "
            f"{state} ({record.get('service_id')!r}); a scoped approval is not a "
            f"blanket one, so the flow is not authorised",
            __version__, environment_label(), required=True,
            evidence_path=str(policy_file(env)),
            limitations=[CHECK_LIMITATION],
        )]

    if same_dest:
        classes = sorted({str(g.get("data_class", "")) for g in same_dest})
        return [Result(
            "policy.data-class-mismatch", FAIL, STOP,
            f"{destination!r} is approved only for data class(es) {classes}, not "
            f"{data_class!r}: the scope is the (destination, data_class) pair, never "
            f"the host",
            __version__, environment_label(), required=True,
            evidence_path=str(policy_file(env)),
            limitations=[CHECK_LIMITATION],
        )]

    return [Result(
        "policy.unapproved", NOT_RUN, REVIEW,
        f"no owner approval covers {data_class!r} to {destination!r}: this tool cannot "
        f"actually block a network call it does not make -- it can only refuse to "
        f"authorise one, so the flow must be treated as UNAUTHORISED",
        __version__, environment_label(), required=True,
        enforcement=NOT_ENFORCED, evidence_path=str(policy_file(env)),
        limitations=[ABSENT_LIMITATION, CHECK_LIMITATION],
    )]


# --- redacted listing ---------------------------------------------------------


def rows(env: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """A redacted listing of every approval. Never a note body.

    Each note is stored as a sha256 digest, so the row carries ``note_digest`` and a
    fixed statement that the body is not held -- private prose written into a note
    must not become readable by running a listing command.
    """
    document, _ = load(env)
    out: List[Dict[str, Any]] = []
    for record in document.get("grants", {}).values():
        if not isinstance(record, dict):
            continue
        if _revoked(record):
            state = "revoked"
        elif is_expired(record):
            state = "expired"
        else:
            state = "active"
        out.append({
            "service_id": record.get("service_id"),
            "destination": record.get("destination"),
            "data_class": record.get("data_class"),
            "expires": record.get("expires"),
            "state": state,
            "digest": record.get("digest"),
            "note_digest": record.get("note_digest"),
            "note": "note body not stored; sha256 digest only" if record.get("note_digest") else "",
            "revoked_at": record.get("revoked_at", ""),
        })
    return sorted(out, key=lambda r: str(r.get("service_id", "")))


def summary_results(env: Optional[Dict[str, str]] = None) -> List[Result]:
    """What ``policy list`` reports: a single line whose status is PASS when at
    least one scoped approval exists, and ``NOT_RUN`` (not PASS, never green by
    silence) when no approval has been recorded. ``NEEDS_HUMAN`` when the policy
    file is unreadable. Corrupt files are never silently replaced."""
    document, problems = load(env)
    if problems:
        return problems
    rows_present = document.get("grants", [])
    if not rows_present:
        return [Result(
            "policy.list", NOT_RUN, REVIEW,
            f"no scoped approvals are recorded in {policy_file(env)}; this is not evidence "
            f"that no flow needs one",
            __version__, environment_label(), required=False,
            limitations=["An empty policy is a list of nothing -- not a list of allowed things. "
                         "Every flow is checked against the actual grants at the moment it is "
                         "proposed."],
        )]
    return [Result(
        "policy.list", PASS, INFO,
        f"{len(rows_present)} scoped approval(s) recorded in {policy_file(env)}",
        __version__, environment_label(), required=False,
        limitations=["Listing is a record. It does not authorise a flow.", "Each row's "
                     "state (active/expired/revoked) is computed at the moment it is read."],
    )]


# --- CLI ----------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openready.policy",
        description=(
            "Scoped owner approvals for external services and outbound flows "
            "(OR-011). No network call is made."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list approvals (redacted; never a note body)")
    p_list.add_argument("--json", action="store_true")

    p_check = sub.add_parser("check", help="is this exact outbound flow authorised?")
    p_check.add_argument("--destination", required=True)
    p_check.add_argument("--data-class", dest="data_class", required=True)
    p_check.add_argument("--json", action="store_true")

    p_grant = sub.add_parser("grant", help="grant one (destination, data_class) pair "
                                          "(owner only)")
    p_grant.add_argument("--service-id", dest="service_id", required=True)
    p_grant.add_argument("--destination", required=True)
    p_grant.add_argument("--data-class", dest="data_class", required=True)
    p_grant.add_argument("--expires", required=True,
                         help="ISO-8601 date or datetime")
    p_grant.add_argument("--actor", required=True)
    p_grant.add_argument("--note", default="")
    p_grant.add_argument("--json", action="store_true")

    p_revoke = sub.add_parser("revoke", help="revoke a service's approval (owner only)")
    p_revoke.add_argument("--service-id", dest="service_id", required=True)
    p_revoke.add_argument("--actor", required=True)
    p_revoke.add_argument("--json", action="store_true")

    return parser


def _emit(results: List[Result], as_json: bool) -> int:
    code = exit_code_for(results)
    if as_json:
        print(json.dumps({
            "tool_version": __version__,
            "command": "policy",
            "exit_code": code,
            "results": [r.to_dict() for r in results],
        }, indent=2, default=str))
    else:
        for result in results:
            tag = "ok  " if result.status == PASS else result.status
            print(f"  {tag} {result.check_id}: {result.message}")
            for limitation in result.limitations:
                print(f"        limitation: {limitation}")
        print(f"  -> exit {code}")
    return code


def _list(as_json: bool) -> int:
    document, problems = load()
    listing = rows()
    code = exit_code_for(problems) if problems else EXIT_OK
    if as_json:
        print(json.dumps({
            "tool_version": __version__,
            "command": "policy list",
            "exit_code": code,
            "policy_file": str(policy_file()),
            "approvals": listing,
            "problems": [r.to_dict() for r in problems],
        }, indent=2, default=str))
        return code
    if problems:
        return _emit(problems, False)
    print(f"OPEN-READY EXTERNAL SERVICES  (private policy, no note bodies stored)")
    print(f"  policy file: {policy_file()}")
    if not listing:
        print("  no approvals recorded -- nothing is authorised")
        return code
    for row in listing:
        print(f"  {str(row['service_id']):<24} {str(row['state']):<8} "
              f"{str(row['destination']):<28} {str(row['data_class']):<20} "
              f"expires {row['expires']}")
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Read-only by default; ``grant``/``revoke`` require ``--actor owner``.

    Exit codes follow ``docs/10-CLI-CONTRACT.md``: 0 ok, 1 failure, 3 a required
    check was unenforceable or unrun, 64 usage error.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (2, None):
            return EXIT_USAGE if code == 2 else EXIT_OK
        return int(code)

    if args.command == "list":
        return _list(args.json)
    if args.command == "check":
        return _emit(check(args.destination, args.data_class), args.json)
    if args.command == "grant":
        return _emit(grant(args.service_id, args.destination, args.data_class,
                           args.expires, args.actor, args.note), args.json)
    if args.command == "revoke":
        return _emit(revoke(args.service_id, args.actor), args.json)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
