"""Private, redacted audit trail of agent actions (OR-009, ``decisions.json`` Q20).

The work order asks for "a **private, redacted** record of agent actions, checks
and approvals in the private runtime data root: what was run, when, against which
revision, result, and *no* private content."

Everything about this module follows from one design rule, and every function here
is an attempt to keep it:

    **This log must never become a second copy of the private data.**

So the record deliberately stores far less than it is handed. Per result it keeps
only ``check_id``, ``status``, ``severity`` and ``enforcement`` -- never a result's
``message`` text, which is exactly where a secret or a host path would sit. It
never stores file contents. It never stores a secret value. It never stores an
absolute host path: an absolute path is reduced to its basename, an over-long
argument to ``<long-arg>``, and a credential-shaped value to ``<redacted>``. An
``extra`` mapping has any key matching ``secret``/``token``/``password``/``key``/
``authorization``/``credential`` dropped, and the dropped names are recorded so the
omission is visible rather than silent.

Two honest limits are stated here rather than discovered later:

* The chain below makes an **edit or a deletion in the middle** detectable, because
  each line commits to the previous line's hash. It cannot detect a rewrite of the
  *whole file* from line 1 by a writer who recomputes every hash: without an
  external anchor a local log is tamper-*evident*, never tamper-*proof*.
* Redaction is a **deny-list**. It removes the credential shapes this tool already
  detects (:data:`openready.scan.SECRET_SIGNATURES` -- reused, not re-invented) and
  every absolute path. It cannot prove a line is free of confidential *prose*.

Chain scheme, stated once so a verifier can re-derive it:

* The first line's ``prev`` is :data:`GENESIS_PREV`.
* Each later line's ``prev`` is the previous line's ``chain``.
* ``chain`` is ``sha256(canonical_json(body) + prev)`` where ``body`` is the line's
  redacted entry -- everything the line stores *except* ``prev`` and ``chain``
  themselves (so the hash is not circular).

Append-only by construction: :func:`record` opens the file with ``O_APPEND`` and
never rewrites an existing byte. The file and its parent directory are created
``0o600`` / ``0o700``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from . import private as private_mod
from . import scan
from .capabilities import environment_label
from .status import (
    ADVISORY,
    FAIL,
    INFO,
    NOT_RUN,
    NOT_TESTED,
    PASS,
    REVIEW,
    STOP,
    Result,
    now_iso,
    summarize,
)

# --- location -----------------------------------------------------------------

AUDIT_ENV = "OPENREADY_AUDIT_HOME"  # test isolation hook; default private_home()
AUDIT_NAME = "audit.jsonl"

# --- redaction vocabulary -----------------------------------------------------

GENESIS_PREV = "0" * 64
REDACTED = "<redacted>"
PATH_TOKEN = "<path>"
LONG_ARG = "<long-arg>"
MAX_FIELD_LEN = 120

# The allowed shape of a stored entry. Anything else is a field redact_entry()
# would not have produced, and record() refuses to write it.
ALLOWED_ENTRY_KEYS = frozenset({
    "timestamp", "command", "project_id", "revision", "results", "counts",
    "argv", "extra", "dropped_keys",
})
ALLOWED_RESULT_KEYS = frozenset({"check_id", "status", "severity", "enforcement"})

# Keys whose *name* marks an extra as sensitive enough to drop. Case-insensitive
# substring match, per the interface spec.
SECRET_KEY_PATTERNS = (
    "secret", "token", "password", "key", "authorization", "credential",
)

# An absolute path is one of: a POSIX path, a drive-qualified Windows path, or a
# UNC path. This is used to redact a value and to detect one, so the two agree.
_ABSOLUTE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)")
_SEPARATORS = re.compile(r"[\\/]")

LOCATION_LIMITATION = (
    "The log lives in the private runtime data root, outside every project and "
    "every git working tree, and is created 0o700 (directory) / 0o600 (file)."
)
REDACTION_LIMITATION = (
    "Redaction is a deny-list: it removes the credential shapes this tool already "
    "detects and every absolute path, and stores per result only check_id, status, "
    "severity and enforcement -- never a result message, file content or secret "
    "value. It cannot prove a line is free of confidential prose."
)
CHAIN_LIMITATION = (
    "The hash chain makes an edit or a deletion in the middle detectable. It cannot "
    "detect a rewrite of the whole file by a writer who recomputes every hash: "
    "without an external anchor this is tamper-evident, not tamper-proof."
)


# --- location resolution ------------------------------------------------------

def audit_file(env: Optional[Dict[str, str]] = None) -> Path:
    """The audit log's path.

    ``AUDIT_ENV`` (when set) names the directory to use instead of the private
    runtime data root; this is the isolation hook tests point into scratch. The
    default is :func:`openready.private.private_home`, which is outside every
    project and every git working tree by construction.
    """
    source = os.environ if env is None else env
    raw = source.get(AUDIT_ENV, "").strip()
    if raw:
        return Path(raw).expanduser() / AUDIT_NAME
    return private_mod.private_home(source) / AUDIT_NAME


# --- redaction ----------------------------------------------------------------

def _is_absolute(value: str) -> bool:
    return bool(_ABSOLUTE.match(value))


def _matches_secret(value: str) -> bool:
    """True when the value carries a credential shape this tool already detects.

    Reuses :data:`openready.scan.SECRET_SIGNATURES`; there is deliberately no
    second deny-list here.
    """
    data = value.encode("utf-8", "replace")
    return any(pattern.search(data) for _description, pattern in scan.SECRET_SIGNATURES)


def _scrub_str(value: Any) -> str:
    """Neutralise one string: secret shape, then absolute path, then length.

    Order matters. A credential-shaped value is replaced before the path and length
    rules, so a secret that also happens to be long is reported as ``<redacted>``
    and never echoed.
    """
    text = value if isinstance(value, str) else str(value)
    if _matches_secret(text):
        return REDACTED
    if _is_absolute(text):
        base = _SEPARATORS.split(text.rstrip("/\\"))[-1]
        return base if base else PATH_TOKEN
    if len(text) > MAX_FIELD_LEN:
        return LONG_ARG
    return text


def _maybe_scrub(value: Optional[str]) -> Optional[str]:
    return None if value is None else _scrub_str(value)


def _scrub_value(value: Any) -> Any:
    """Scrub a value that may be a string, a list or a mapping used by ``extra``."""
    if isinstance(value, str):
        return _scrub_str(value)
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, dict):
        return {_scrub_str(k): _scrub_value(v) for k, v in value.items()}
    return value


def _is_secret_key(key: str) -> bool:
    low = str(key).lower()
    return any(pattern in low for pattern in SECRET_KEY_PATTERNS)


def _result_record(result: Result) -> Dict[str, Any]:
    """Only the four fields the interface allows -- never the message."""
    return {
        "check_id": result.check_id,
        "status": result.status,
        "severity": result.severity,
        "enforcement": result.enforcement,
    }


def redact_entry(*, command: str, results: List[Result], argv: Optional[Sequence[str]] = None,
                 project_id: Optional[str] = None, revision: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None,
                 extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a redacted record. See the module docstring for what is and is not kept.

    ``env`` is accepted for interface symmetry with :func:`record`; redaction itself
    reads no environment.
    """
    entry: Dict[str, Any] = {
        "timestamp": now_iso(),
        "command": _scrub_str(command),
        "project_id": _maybe_scrub(project_id),
        "revision": _maybe_scrub(revision),
        "results": [_result_record(r) for r in results],
        "counts": _counts(results),
    }
    if argv is not None:
        entry["argv"] = [_scrub_str(item) for item in argv]
    if extra:
        kept: Dict[str, Any] = {}
        dropped: List[str] = []
        for key, value in extra.items():
            if _is_secret_key(key):
                dropped.append(str(key))
            else:
                kept[_scrub_str(key)] = _scrub_value(value)
        if kept:
            entry["extra"] = kept
        if dropped:
            entry["dropped_keys"] = sorted(dropped)
    return entry


def _counts(results: List[Result]) -> Dict[str, int]:
    counts = summarize(results)
    counts["total"] = len(results)
    return counts


# --- the anti-leak gate -------------------------------------------------------

def _string_problems(value: str, location: str) -> List[str]:
    problems: List[str] = []
    if _matches_secret(value):
        problems.append(f"{location} carries a credential-shaped value")
    if _is_absolute(value):
        problems.append(f"{location} is an absolute path")
    if len(value) > MAX_FIELD_LEN:
        problems.append(f"{location} is longer than {MAX_FIELD_LEN} characters")
    return problems


def _scan_values(obj: Any, location: str = "entry") -> List[str]:
    problems: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            problems.extend(_scan_values(value, f"{location}.{key}"))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            problems.extend(_scan_values(value, f"{location}[{index}]"))
    elif isinstance(obj, str):
        problems.extend(_string_problems(obj, location))
    return problems


def _leaks(entry: Any) -> List[str]:
    """Everything :func:`redact_entry` would have removed from an entry.

    :func:`record` refuses to write while this list is non-empty, and the check is
    not vacuous: an entry passed in directly with a raw ``message``, a result with a
    disallowed field, an absolute path, a credential-shaped value or a secret-named
    ``extra`` key all produce at least one problem.
    """
    if not isinstance(entry, dict):
        return ["the entry is not an object"]
    problems: List[str] = []
    for key in entry:
        if key not in ALLOWED_ENTRY_KEYS:
            problems.append(f"field {key!r} is not permitted")
    results = entry.get("results")
    if results is not None:
        if not isinstance(results, list):
            problems.append("results is not a list")
        else:
            for index, result in enumerate(results):
                if not isinstance(result, dict):
                    problems.append(f"results[{index}] is not an object")
                    continue
                for key in result:
                    if key not in ALLOWED_RESULT_KEYS:
                        problems.append(
                            f"results[{index}] field {key!r} is not permitted "
                            f"(a result message must never be recorded)"
                        )
    extra = entry.get("extra")
    if isinstance(extra, dict):
        for key in extra:
            if _is_secret_key(key):
                problems.append(f"extra key {key!r} names a secret and must be dropped")
    problems.extend(_scan_values(entry))
    return problems


# --- chain --------------------------------------------------------------------

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _chain(body: Dict[str, Any], prev: str) -> str:
    """``sha256(canonical_json(body) + prev)`` -- see the module docstring."""
    return hashlib.sha256((_canonical_json(body) + prev).encode("utf-8")).hexdigest()


def _body_of(line: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in line.items() if k not in ("prev", "chain")}


def _last_chain(path: Path) -> Optional[str]:
    """The previous line's ``chain``, or :data:`GENESIS_PREV`.

    Returns ``None`` when the file exists and is non-empty but its last line cannot
    be read, so :func:`record` refuses rather than chain onto a corrupt log.
    """
    if not path.is_file():
        return GENESIS_PREV
    data = path.read_bytes()
    if not data.strip():
        return GENESIS_PREV
    last = data.rstrip(b"\n").split(b"\n")[-1]
    try:
        obj = json.loads(last.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    chain = obj.get("chain") if isinstance(obj, dict) else None
    return chain if isinstance(chain, str) else None


def _write_line(path: Path, line: Dict[str, Any]) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    _chmod(parent, 0o700)
    payload = (_canonical_json(line) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    _chmod(path, 0o600)


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        # A filesystem without POSIX modes (or a Windows mount) cannot hold this;
        # the write still succeeds and verify() reports the chain, not the mode.
        pass


# --- record -------------------------------------------------------------------

def record(entry: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Append one redacted JSON line, or refuse and write nothing.

    The entry is expected to come from :func:`redact_entry`; if it still contains
    anything :func:`redact_entry` would have removed, nothing is written.
    """
    leaks = _leaks(entry)
    if leaks:
        return [Result(
            "audit.unredacted", FAIL, STOP,
            "refused to append: the entry still carries content redact_entry() would "
            "remove -- " + "; ".join(leaks[:4]),
            __version__, environment_label(),
            limitations=[REDACTION_LIMITATION, LOCATION_LIMITATION],
        )]

    path = audit_file(env)
    prev = _last_chain(path)
    if prev is None:
        return [Result(
            "audit.unreadable", FAIL, STOP,
            f"refused to append: the log exists at {path.name} but its last line "
            f"cannot be read, so a new line cannot be chained onto it",
            __version__, environment_label(),
            limitations=[CHAIN_LIMITATION, LOCATION_LIMITATION],
        )]

    line = dict(entry)
    line["prev"] = prev
    line["chain"] = _chain(_body_of(line), prev)
    _write_line(path, line)

    return [Result(
        "audit.recorded", PASS, INFO,
        f"recorded {_scrub_str(entry.get('command', ''))!r} "
        f"({len(entry.get('results', []) or [])} result(s)) in the private audit log "
        f"({path.name})",
        __version__, environment_label(), enforcement=ADVISORY,
        limitations=[REDACTION_LIMITATION, CHAIN_LIMITATION, LOCATION_LIMITATION],
    )]


# --- read ---------------------------------------------------------------------

def read(env: Optional[Dict[str, str]] = None,
         limit: Optional[int] = None) -> Tuple[List[Dict[str, Any]], List[Result]]:
    """Read the log. Returns ``(records, problems)``.

    ``limit`` returns the **most recent** ``limit`` records (a tail), which is the
    useful end of an append-only log; the interface spec did not fix the direction.
    A line that will not parse is reported as a problem and skipped, never silently
    dropped.
    """
    path = audit_file(env)
    records: List[Dict[str, Any]] = []
    problems: List[Result] = []
    if not path.is_file():
        return records, problems
    for number, raw in enumerate(path.read_bytes().split(b"\n"), start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            problems.append(Result(
                "audit.unreadable-line", FAIL, REVIEW,
                f"line {number} is not valid JSON ({exc})", __version__,
                environment_label(), required=False,
                limitations=[CHAIN_LIMITATION],
            ))
            continue
        if not isinstance(obj, dict):
            problems.append(Result(
                "audit.unreadable-line", FAIL, REVIEW,
                f"line {number} is not a record object", __version__,
                environment_label(), required=False,
                limitations=[CHAIN_LIMITATION],
            ))
            continue
        records.append(obj)
    if limit is not None and limit >= 0:
        records = records[-limit:] if limit else []
    return records, problems


# --- verify -------------------------------------------------------------------

def _line_problems(obj: Dict[str, Any], number: int, prev_chain: str,
                   raw: bytes) -> Tuple[List[str], str]:
    """Chain and redaction problems for one parsed line. Returns (problems, chain)."""
    problems: List[str] = []
    body = _body_of(obj)
    stored_chain = obj.get("chain")
    stored_prev = obj.get("prev")

    if not isinstance(stored_prev, str):
        problems.append(f"line {number}: 'prev' is missing or not a string")
    else:
        if stored_prev != prev_chain:
            problems.append(
                f"line {number}: 'prev' does not match the previous line's chain -- "
                f"a line was removed or reordered"
            )
        if not isinstance(stored_chain, str):
            problems.append(f"line {number}: 'chain' is missing or not a string")
        elif _chain(body, stored_prev) != stored_chain:
            problems.append(
                f"line {number}: 'chain' does not match its content -- the line was edited"
            )

    # Redaction audit: reuse scan's own patterns and the general absolute-path test.
    for _description, pattern in scan.SECRET_SIGNATURES:
        if pattern.search(raw):
            problems.append(f"line {number}: contains a credential-shaped value")
            break
    for _description, pattern in scan.HOST_PATH_PATTERNS:
        if pattern.search(raw):
            problems.append(f"line {number}: contains an absolute host path")
            break
    problems.extend(_line_value_problems(obj, number))

    next_chain = stored_chain if isinstance(stored_chain, str) else prev_chain
    return problems, next_chain


def _line_value_problems(obj: Dict[str, Any], number: int) -> List[str]:
    problems: List[str] = []
    # A top-level 'message', or a 'message' inside a result, means the log holds
    # result text it must never hold.
    for key in obj:
        if str(key).lower() == "message":
            problems.append(f"line {number}: records a top-level result message")
    results = obj.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict) and any(str(k).lower() == "message" for k in result):
                problems.append(f"line {number}: records a result message")
    for location, value in obj.items():
        problems.extend(_scan_values(value, f"line {number}.{location}"))
    return problems


def verify(env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Read-only integrity and redaction audit of the whole log.

    Chain continuity is checked from line 1, and every line is scanned for an
    absolute host path, a credential-shaped value and a result message. Reports
    ``NOT_RUN`` -- never ``PASS`` -- when the log does not exist, because an absent
    log is not a clean one.
    """
    path = audit_file(env)
    if not path.is_file():
        return [Result(
            "audit.integrity", NOT_RUN, REVIEW,
            f"no audit log at {path.name}; an absent log is not a clean one, it is an "
            f"absent one", __version__, environment_label(),
            enforcement=NOT_TESTED,
            limitations=[REDACTION_LIMITATION, CHAIN_LIMITATION, LOCATION_LIMITATION],
        )]

    lines = [raw for raw in path.read_bytes().split(b"\n") if raw.strip()]
    chain_problems: List[str] = []
    redaction_problems: List[str] = []
    prev_chain = GENESIS_PREV
    for number, raw in enumerate(lines, start=1):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            chain_problems.append(f"line {number}: not valid JSON ({exc})")
            continue
        if not isinstance(obj, dict):
            chain_problems.append(f"line {number}: not a record object")
            continue
        problems, prev_chain = _line_problems(obj, number, prev_chain, raw)
        for problem in problems:
            if "chain" in problem or "'prev'" in problem:
                chain_problems.append(problem)
            else:
                redaction_problems.append(problem)

    if not lines:
        return [Result(
            "audit.integrity", NOT_RUN, REVIEW,
            f"the audit log at {path.name} exists but is empty; an empty log is not a "
            f"clean one", __version__, environment_label(),
            enforcement=NOT_TESTED,
            limitations=[REDACTION_LIMITATION, CHAIN_LIMITATION, LOCATION_LIMITATION],
        )]

    results: List[Result] = []
    results.append(Result(
        "audit.chain",
        FAIL if chain_problems else PASS,
        STOP if chain_problems else INFO,
        (f"{len(chain_problems)} chain problem(s) in {len(lines)} record(s): "
         + "; ".join(chain_problems[:4]))
        if chain_problems else
        f"{len(lines)} record(s) chained end to end",
        __version__, environment_label(), enforcement=ADVISORY,
        limitations=[CHAIN_LIMITATION],
    ))
    results.append(Result(
        "audit.redaction",
        FAIL if redaction_problems else PASS,
        STOP if redaction_problems else INFO,
        (f"{len(redaction_problems)} redaction problem(s): "
         + "; ".join(redaction_problems[:4]))
        if redaction_problems else
        f"no absolute host path, credential-shaped value or result message in "
        f"{len(lines)} record(s)",
        __version__, environment_label(),
        limitations=[REDACTION_LIMITATION],
    ))
    return results
