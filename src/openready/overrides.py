"""Acknowledged false positives (acceptance test A05).

Specification requirement, verbatim from ``docs/06-ACCEPTANCE-TESTS.md``:

    A05 | Intentional false-positive secret pattern | Human override path
    documented, no exposure or silent skip | P0

Three properties make this an *acknowledgement* and not a bypass, and all three
are enforced here rather than documented:

1. **Named, not global.** An entry must name one ``check_id`` and one exact path.
   There is no wildcard, no directory scope and no "disable this check" switch.
2. **Reasoned.** A blank or placeholder reason is rejected. An approval without a
   recorded reason is not a record.
3. **Visible.** An applied override is reported as a ``NEEDS_HUMAN`` result, so it
   appears in the doctor output and in the counts. Nothing is silently skipped.

Two further limits:

- **Only pattern-based findings may be acknowledged.** ``candidate.host-path`` and
  ``privacy.secret-shape`` can be false positives. Structural findings (symlinks,
  hardlinks, collisions) and responsibility-bearing checks (rights, publication,
  egress) are not overridable, because there is no sense in which they are a
  false positive.
- **An expired acknowledgement lapses.** Past its ``expires`` date an entry stops
  applying and is reported as a ``NEEDS_HUMAN`` check that the operator must
  revisit, rather than quietly continuing to suppress.

**This file is not authorization for anything.** Acknowledging a finding says "I
know about this one"; it says nothing about whether a project may be published.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .status import NEEDS_HUMAN, REVIEW, Result

ALLOW_NAME = ".openready-allow.json"
OVERRIDABLE_CHECK_IDS = frozenset({"candidate.host-path", "privacy.secret-shape"})
REQUIRED_ENTRY_FIELDS = ("check_id", "path", "reason", "acknowledged_by", "acknowledged_at")
PLACEHOLDER_REASONS = {"", "-", "n/a", "na", "todo", "tbd", "because", "false positive", "fp"}
MIN_REASON_CHARS = 12
OBJECT_ID_RE = re.compile(r"[0-9a-f]{4,64}")


def _environment_label() -> str:
    import os
    return f"{os.uname().sysname.lower()}-{os.uname().machine}"


def validate_entry(entry: Dict, today: Optional[date] = None) -> List[str]:
    """Public wrapper over ``_entry_errors``, for consumers holding a frozen entry.

    ``verify`` must apply this to every acknowledgement it reads out of
    ``CANDIDATE.json``: without it, anyone holding a candidate could rewrite a real
    credential finding as "the operator acknowledged this" using an entry the
    exporter's own validator rejects.
    """
    return _entry_errors(entry, today or date.today())


def load(root: Path) -> Tuple[Optional[Dict], List[Result]]:
    """Load the acknowledgement file. Returns (document, structural results)."""
    path = Path(root) / ALLOW_NAME
    if not path.is_file():
        return None, []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return None, [Result(
            "override.readable", NEEDS_HUMAN, REVIEW,
            f"{ALLOW_NAME} exists but cannot be read: {exc}", __version__,
            _environment_label(), required=False,
        )]
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        return None, [Result(
            "override.readable", NEEDS_HUMAN, REVIEW,
            f"{ALLOW_NAME} must be an object with an 'entries' array", __version__,
            _environment_label(), required=False,
        )]
    return document, []


def _entry_errors(entry: Dict, today: date) -> List[str]:
    errors: List[str] = []
    if not isinstance(entry, dict):
        return ["entry is not an object"]
    for field in REQUIRED_ENTRY_FIELDS:
        if not str(entry.get(field, "")).strip():
            errors.append(f"missing or blank {field!r}")
    if errors:
        return errors
    check_id = str(entry["check_id"])
    if check_id not in OVERRIDABLE_CHECK_IDS:
        errors.append(
            f"check_id {check_id!r} is not overridable; only "
            f"{sorted(OVERRIDABLE_CHECK_IDS)} may be acknowledged"
        )
    reason = str(entry["reason"]).strip()
    if reason.lower() in PLACEHOLDER_REASONS or len(reason) < MIN_REASON_CHARS:
        errors.append(
            f"reason must be a real explanation of at least {MIN_REASON_CHARS} characters"
        )
    expires = entry.get("expires")
    if expires:
        try:
            if date.fromisoformat(str(expires)) < today:
                errors.append(f"acknowledgement expired on {expires}")
        except ValueError:
            errors.append(f"expires {expires!r} is not an ISO date (YYYY-MM-DD)")
    if entry.get("object") is not None:
        obj = str(entry.get("object", "")).strip()
        if not OBJECT_ID_RE.fullmatch(obj):
            errors.append(f"object {obj!r} is not a lowercase hex object id (4-64 characters)")
    return errors


def apply(root: Path, findings: Sequence, report_unused: bool = True) -> Tuple[List, List[Result]]:
    """Split findings into still-reportable ones and override results.

    ``report_unused=False`` suppresses the "matched nothing, remove it" advice for
    entries this pass could not have matched. The commit-time control scans the *staged
    set* only, so every entry that names an object in the object store reports itself as
    unused there and the advice would be wrong 42 times over on this repository. `doctor`
    and `candidate` run the full scan, and they still report a genuinely stale entry.

    Returns ``(remaining_findings, override_results)``. An entry that fails
    validation does **not** suppress anything: its finding stays, and the problem
    with the entry is reported separately.
    """
    document, results = load(root)
    if document is None:
        return list(findings), results

    today = date.today()
    narrow: Dict[Tuple[str, str, str], Dict] = {}
    wide: Dict[Tuple[str, str], Dict] = {}
    for index, entry in enumerate(document.get("entries", [])):
        errors = _entry_errors(entry, today)
        if errors:
            results.append(Result(
                f"override.entry-{index}.invalid", NEEDS_HUMAN, REVIEW,
                f"{ALLOW_NAME} entry {index} rejected: " + "; ".join(errors),
                __version__, _environment_label(), required=False,
                limitations=[
                    "A malformed or expired acknowledgement suppresses nothing. The "
                    "finding it named is still reported.",
                ],
            ))
            continue
        key = entry_key(entry)
        if key[2]:
            narrow[key] = entry
        else:
            wide[key[:2]] = entry

    remaining: List = []
    used: Dict[Tuple, int] = {}
    for finding in findings:
        key = finding_key(finding)
        entry = narrow.get(key) if key[2] else None
        used_key: Tuple = key
        if entry is None:
            # An entry with no object id is the older, wider form: it covers every
            # shape at that path. Kept for acknowledgement files written before the
            # narrow form existed; this repository binds to objects.
            entry = wide.get(key[:2])
            used_key = key[:2]
        if entry is None:
            remaining.append(finding)
            continue
        used[used_key] = used.get(used_key, 0) + 1

    for key, entry in sorted({**narrow, **wide}.items()):
        count = used.get(key, 0)
        path = key[1]
        object_id = key[2] if len(key) > 2 else ""
        where = f"{path} ({object_id})" if object_id else path
        if count == 0:
            if report_unused:
                results.append(Result(
                    "override.unused", NEEDS_HUMAN, REVIEW,
                    f"acknowledgement for {key[0]} at {where} matched nothing -- the "
                    f"finding is gone, so the entry should be removed",
                    __version__, _environment_label(), required=False,
                ))
            continue
        results.append(Result(
            "override.applied", NEEDS_HUMAN, REVIEW,
            f"acknowledged {key[0]} at {where} ({count} occurrence(s)): "
            f"{entry['reason']} -- acknowledged_by {entry['acknowledged_by']}",
            __version__, _environment_label(), required=False,
            limitations=[
                "An acknowledgement records awareness of one finding. It is not a "
                "release approval and it is not evidence that the project is safe "
                "to publish.",
            ] + ([
                "This entry names one object id, so it covers those exact bytes and "
                "nothing else: any other content at this path is still reported.",
            ] if object_id else [
                "This entry names a path and no object id, so it covers every shape "
                "found at that path, including any committed there later.",
            ]),
        ))
    return remaining, results


def entry_key(entry: Dict) -> Tuple[str, str, str]:
    """What an acknowledgement entry covers: (check id, path, object id).

    The object is what makes an exception narrow. An entry without one covers *every*
    shape at that path -- including a real credential committed there later, and
    including one that a fixture's exception was never meant to cover. Entries in this
    repository bind to an object; the rest of the tool stays backwards compatible.
    """
    return (str(entry.get("check_id", "")), _normalise(str(entry.get("path", ""))),
            str(entry.get("object", "") or ""))


def finding_key(finding) -> Tuple[str, str, str]:
    """What a finding is, for matching: (check id, path, object id)."""
    return (str(getattr(finding, "check_id", "")), _normalise(str(getattr(finding, "path", ""))),
            str(getattr(finding, "object_id", "") or ""))


def entry_covers(entry: Dict, check_id: str, path: str, object_id: str = "") -> bool:
    """Whether one acknowledgement entry covers one finding.

    One rule, used by the exporter and by the verifier, because two implementations of
    "is this acknowledged" is how `candidate` and `verify` came to disagree about the
    same frozen artifact.

    * An entry **with** an object id covers only that blob -- the exact bytes the
      operator looked at. Content added at the same path later is not covered.
    * An entry **without** one covers every shape at that path. That is the older form,
      kept so existing acknowledgement files keep working; it is also the wider
      exception, and the tool says so in the result's limitations.
    """
    if str(entry.get("check_id", "")) != str(check_id):
        return False
    if _normalise(str(entry.get("path", ""))) != _normalise(str(path)):
        return False
    obj = str(entry.get("object", "") or "")
    if not obj:
        return True
    return obj == str(object_id or "")


def normalise_path(raw: str) -> str:
    """Canonicalise an entry path. Rejects traversal and absolute forms outright.

    ``lstrip("./")`` (the previous behaviour) strips any leading mix of dots and
    slashes, so ``../src/leak.txt`` normalised to ``src/leak.txt`` and suppressed a
    finding for a path the entry never named.
    """
    text = str(raw).replace("\\", "/").strip()
    if text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or ":" in text.split("/", 1)[0]:
        raise ValueError(f"absolute path not allowed: {raw!r}")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe path traversal: {raw!r}")
    return text


def _normalise(path: str) -> str:
    try:
        return normalise_path(path)
    except ValueError:
        # An unusable path can never match a real finding, so it suppresses nothing.
        return ""
