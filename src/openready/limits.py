"""The one-command honesty view (work order F4 / T3): every unverified control.

The question this module answers, in one command, is the one the handoff keeps
returning to: *what is not verified, why not, and what would verify it?*  Every
other surface in this tool reports on the work it did.  This one reports on the
work nobody has done -- the controls that exist only as a promise, an ADR, or an
acceptance test that has never run on a second machine.

Three shape rules, taken from the specification and the house conventions:

1. **One row per unverified control, in one view.**  :func:`rows` aggregates the
   four places an unverified control can be hiding: the host capabilities this
   build detected, the ``doctor`` findings, the policy dry run, and the table of
   declared limits in :func:`declared_rows`.  A ``PASS`` result is never a row.
2. **A row says why it is unverified and what would verify it.**  ``reason`` is
   the honest statement of what was not done; ``verified_by`` names a *concrete*
   thing (a second machine, a separate principal, a sandboxed runner), never
   "review" or "later".
3. **Nothing here is a safety claim.**  The view never reports green.  A row
   status of ``NOT_RUN``/``NOT_ENFORCED`` is the whole point: it records the
   absence of a check, and an empty view is itself reported as ``NOT_RUN``,
   never as a clean bill of health.

:func:`source_scan` is the anti-omission guard for the table itself.  It reads
the source, finds every place a result is *emitted* with ``NOT_ENFORCED`` or
``NOT_TESTED``, and reports any check id that the limits view cannot reach -- so
a new emission cannot quietly stay outside the one view that is supposed to list
it.  It is deliberately conservative: an emission it cannot attribute to a check
id is reported as uncovered, not skipped.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import __version__
from . import advisory as advisory_mod
from . import doctor as doctor_mod
from .capabilities import detect as detect_capabilities
from .capabilities import environment_label
from .status import (
    ENFORCEMENTS,
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_APPLICABLE,
    NOT_ENFORCED,
    NOT_RUN,
    NOT_TESTED,
    PASS,
    REVIEW,
    Result,
)

# --- exported interface constants -------------------------------------------

#: Requirement-id prefixes this view understands. ``OR-`` is a backlog/risk item,
#: ``A`` an acceptance test. A declared row whose id starts with anything else is
#: a bookkeeping error and is refused loudly rather than rendered as a bare row.
REQUIREMENT_PREFIXES = ("OR-", "A")

#: Optional environment override: a path to a JSON file of extra declared rows.
#: It exists so a test (or an operator) can inject a row without editing this
#: file. The file holds either a list of rows or ``{"rows": [...]}``.
ENV_LIMITS = "OPENREADY_LIMITS_JSON"

#: The status vocabulary of this view. It deliberately reuses the two enforcement
#: tokens as statuses: ``NOT_ENFORCED`` says the control was measured and is
#: absent, ``NOT_TESTED`` says nothing was exercised, ``NOT_RUN`` says the check
#: did not run, ``NEEDS_HUMAN`` says only a person can resolve it.
ROW_STATUSES = (NOT_RUN, NOT_TESTED, NOT_ENFORCED, NEEDS_HUMAN)

#: Where a row came from. The source is part of the row so a reader can tell a
#: detected fact (``capability``) from a standing promise (``declared``).
ROW_SOURCES = ("capability", "doctor", "policy", "declared")

LIMITATION = (
    "This view lists controls that are NOT verified. It is not a checklist that "
    "was completed, and an empty or short list is not evidence that nothing is "
    "wrong -- only that nothing reachable from here was found unverified."
)

ROW_LIMITATION = (
    "A row records that this control is unverified and why. It is not evidence "
    "that the control is absent or present in any particular artifact."
)


# --- declared limits ----------------------------------------------------------
#
# Controls that NO command emits a result for. They exist as an ADR, a promise or
# an acceptance test that has never run, so no aggregator can discover them and
# they must be written down by hand. Each is keyed to the requirement id that
# would retire it. ``verified_by`` must name a concrete, external act: the whole
# value of the row is that it says what a human would have to do.


def _row(requirement_id: str, check_id: str, status: str, enforcement: Optional[str],
         reason: str, verified_by: str) -> Dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "check_id": check_id,
        "status": status,
        "enforcement": enforcement,
        "reason": reason,
        "verified_by": verified_by,
        "source": "declared",
    }


_DECLARED: List[Dict[str, Any]] = [
    _row(
        "A10", "acceptance.egress-containment", NOT_ENFORCED, NOT_ENFORCED,
        "egress containment has never been measured. This tool deliberately makes "
        "no network call, so it cannot observe the outbound traffic it would need "
        "to contain -- the confidentiality claim rests on an unmeasured property.",
        "a network monitor or an egress-logging proxy on the builder host during a "
        "full `openready` pass, showing no private data leaving the host (A10)",
    ),
    _row(
        "A11", "acceptance.publisher-separation", NOT_ENFORCED, NOT_ENFORCED,
        "no publisher principal distinct from the builder exists (ADR-002). The "
        "process that builds a candidate also holds every credential a publisher "
        "would use, so build and publish are separated by convention, not by "
        "capability.",
        "a separate publisher principal holding credentials the builder does not "
        "have, publishing a candidate the builder only exported (OR-022/A11)",
    ),
    _row(
        "A12", "acceptance.paid-service-authorisation", NOT_ENFORCED, NOT_ENFORCED,
        "no check can see whether a paid API, model or service was used. Usage and "
        "spend are invisible from the repository, so authorisation of a cost cannot "
        "be confirmed here.",
        "the owner's dated authorisation for each paid service used, reconciled "
        "against the provider's billing statement for the period (A12)",
    ),
    _row(
        "A23", "acceptance.clean-room", NOT_TESTED, NOT_TESTED,
        "no second machine has run docs/CLEAN-ROOM.md. Every observation in this "
        "repository comes from one host, so portability and isolation are untested.",
        "one human run of docs/CLEAN-ROOM.md on a second machine (A23)",
    ),
    _row(
        "A25", "acceptance.independent-publisher-first", NEEDS_HUMAN, NOT_ENFORCED,
        "no first independent-publisher rehearsal has happened. A builder rehearsing "
        "their own candidate does not test whether the packet is sufficient for "
        "anyone else.",
        "a first independent publisher, given only the exported candidate and its "
        "packet, reproducing the publish without help from the builder (A25)",
    ),
    _row(
        "A26", "acceptance.independent-publisher-second", NEEDS_HUMAN, NOT_ENFORCED,
        "no second independent-publisher rehearsal, on a second machine, has "
        "happened. One rehearsal cannot distinguish a good packet from one that "
        "happened to match one environment.",
        "a second independent publisher, on a second machine, reproducing the "
        "publish from the candidate alone (A26)",
    ),
    _row(
        "A27", "acceptance.independent-publisher-third", NEEDS_HUMAN, NOT_ENFORCED,
        "no third independent-publisher rehearsal has happened, so the packet's "
        "sufficiency across people and environments is still a claim rather than an "
        "observation.",
        "a third independent publisher, again from the candidate alone, confirming "
        "the packet is not accidentally coupled to one person's environment (A27)",
    ),
    _row(
        "A28", "acceptance.sandboxed-pr-ci", NOT_TESTED, NOT_TESTED,
        "no pull-request CI has run inside a sandbox. The checks run only where a "
        "human starts them, with the operator's own credentials present, which is "
        "the opposite of an untrusted contribution.",
        "a sandboxed CI runner that cannot read a token, running the checks on an "
        "untrusted pull request (OR-025/A28)",
    ),
    _row(
        "A29", "acceptance.second-patch-private-core", NOT_ENFORCED, NOT_ENFORCED,
        "no second patch has been produced against a private core by someone other "
        "than its author, so the public/private split is untested in practice.",
        "a second, independent patch applied to a private core, with the resulting "
        "public change reviewed apart from the core (A29)",
    ),
    _row(
        "A31", "acceptance.vulnerability-disclosure", NOT_ENFORCED, NOT_ENFORCED,
        "no vulnerability-disclosure path has been exercised. Nothing in this tool "
        "receives, tracks or answers a security report, so the response time and "
        "the process are both unproven.",
        "a test report filed through the documented private disclosure channel, "
        "with the response time and outcome recorded (A31)",
    ),
    _row(
        "A32", "acceptance.os-variance", NOT_TESTED, NOT_TESTED,
        "every check in this repository has run on one operating system. "
        "OS-specific behaviour -- file permissions, path handling, sandbox "
        "facilities -- is untested elsewhere.",
        "a second OS runner executing the full check suite and reporting its own "
        "result (A32)",
    ),
    _row(
        "A33", "acceptance.final-owner-authorisation", NEEDS_HUMAN, NOT_ENFORCED,
        "final authorisation is an owner act. No command can perform it, and no "
        "command can record it as done, so it cannot be closed from inside this "
        "tool.",
        "the owner's dated authorisation naming the exact candidate digest, "
        "recorded outside this tool (A33)",
    ),
    _row(
        "OR-025", "acceptance.community-ci", NOT_ENFORCED, NOT_ENFORCED,
        "no community-facing CI runs the checks on a contributor's pull request, so "
        "a contribution is merged without the checks having run anywhere the "
        "contributor does not control.",
        "a CI workflow on the public mirror that runs `openready doctor` on an "
        "untrusted pull request and blocks the merge on failure (OR-025)",
    ),
]


def _validate_declared() -> None:
    for row in _DECLARED:
        requirement = str(row["requirement_id"])
        if not requirement.startswith(REQUIREMENT_PREFIXES):
            raise ValueError(
                f"declared limits row {row['check_id']!r} has requirement id "
                f"{requirement!r}, which does not start with one of "
                f"{REQUIREMENT_PREFIXES}"
            )
        if not str(row["reason"]).strip() or not str(row["verified_by"]).strip():
            raise ValueError(
                f"declared limits row {row['check_id']!r} must state a reason and "
                f"the concrete thing that would verify it"
            )


_validate_declared()


# Reasonable fallbacks. An injected row that omits them still gets a truthful
# sentence rather than an empty string that would read as "nothing to say".
_VERIFIED_BY_FALLBACK: Dict[str, str] = {
    "capability": (
        "a re-detection of this capability on a host where it is actually "
        "exercised, not merely present (A32)"
    ),
    "doctor": (
        "a human review of this check with a concrete artefact; the check itself "
        "reports only that it did not run here"
    ),
    "policy": (
        "a project whose recorded policy version matches this build, re-run after "
        "`openready update`"
    ),
    "declared": "a named external act; see the row's requirement id",
}

# Check ids whose requirement id the source itself names.
_REQUIREMENT_BY_CHECK: Dict[str, str] = {
    "egress.containment": "A10",
    "trust.publisher-separation": "A11",
    "host.isolation": "A23",
    "host.isolation-tools": "A23",
}

# The requirement a *source* answers to when the check id itself is not mapped.
# Each value is the task id the module states for itself in its own docstring.
_REQUIREMENT_BY_SOURCE: Dict[str, str] = {
    "capability": "OR-002",
    "doctor": "OR-006",
    "policy": "OR-013",
    "declared": "",
}

# Concrete verification acts for the aggregated check ids. A missing entry falls
# back to the source's sentence above rather than to an invented one.
_VERIFIED_BY: Dict[str, str] = {
    "egress.containment": (
        "a network monitor or egress-logging proxy on the builder host during a "
        "full `openready` pass, showing no private data leaving the host (A10)"
    ),
    "trust.publisher-separation": (
        "a separate publisher principal holding credentials the builder does not "
        "have (OR-022/A11)"
    ),
    "host.isolation": "one human run of docs/CLEAN-ROOM.md on a second machine (A23)",
    "host.isolation-tools": (
        "one human run of docs/CLEAN-ROOM.md on a second machine (A23)"
    ),
    "host.user-namespaces": (
        "a demonstrated unprivileged user-namespace creation on this exact host (A23)"
    ),
    "fleet.profiles": (
        "a re-run of `openready limits` on a host that holds at least one Hermes "
        "profile (A32)"
    ),
    "privacy.private-prose": (
        "a human reading of the exported candidate for private prose; no scan can "
        "establish its absence"
    ),
    "privacy.full-history": (
        "a full object-store scan completing over the repository with zero unread "
        "blobs and zero remaining deny-list hits"
    ),
    "git.visibility": (
        "a hosting-API query from a network-enabled session, confirming the "
        "remote's visibility before any public act"
    ),
    "release.rights": (
        "the owner's licence and third-party-rights decision, recorded outside "
        "this tool (A33)"
    ),
    "update.policy-version": (
        "a project whose recorded policy version matches this build, re-run after "
        "`openready update`"
    ),
}

# --- enforcement/status mapping ----------------------------------------------

#: The status a result gets when a row is turned into a Result. Every unverified
#: token collapses onto NOT_RUN so ``exit_code_for`` treats it as a required check
#: that did not run, which is exactly what it is.
_STATUS_TO_RESULT: Dict[str, str] = {
    NOT_RUN: NOT_RUN,
    NOT_ENFORCED: NOT_RUN,
    NOT_TESTED: NOT_RUN,
    NEEDS_HUMAN: NEEDS_HUMAN,
    NOT_APPLICABLE: NOT_APPLICABLE,
}

_CAPABILITY_UNKNOWN = "UNKNOWN"


# --- injected rows (testing seam) --------------------------------------------


def _normalise_row(raw: Dict[str, Any], default_source: str = "declared") -> Dict[str, Any]:
    """Coerce a row from the environment file into the row shape.

    Missing fields are filled with something truthful and non-empty rather than
    dropped: an injected row that forgets a reason should still appear, said so
    plainly, not vanish.
    """
    source = str(raw.get("source") or default_source)
    if source not in ROW_SOURCES:
        source = default_source
    status = str(raw.get("status") or NOT_RUN)
    if status not in ROW_STATUSES:
        status = NOT_RUN
    enforcement = raw.get("enforcement")
    if enforcement not in ENFORCEMENTS:
        enforcement = None
    return {
        "requirement_id": str(raw.get("requirement_id") or "").strip(),
        "check_id": str(raw.get("check_id") or "").strip() or "declared.unnamed",
        "status": status,
        "enforcement": enforcement,
        "reason": str(raw.get("reason") or "").strip()
        or "(no reason was recorded in the injected row)",
        "verified_by": str(raw.get("verified_by") or "").strip()
        or _VERIFIED_BY_FALLBACK.get(source, _VERIFIED_BY_FALLBACK["declared"]),
        "source": source,
    }


def _injected_rows() -> List[Dict[str, Any]]:
    raw_path = os.environ.get(ENV_LIMITS, "").strip()
    if not raw_path:
        return []
    try:
        document = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(document, dict):
        document = document.get("rows", [])
    rows: List[Dict[str, Any]] = []
    for item in document or []:
        if isinstance(item, dict):
            rows.append(_normalise_row(item, default_source="declared"))
    return rows


def declared_rows() -> List[Dict[str, Any]]:
    """Substantive limits that NO command emits, each keyed to a requirement id.

    See the module docstring: these are controls with no runtime detector, so
    they are written down here and re-read on every run rather than re-derived.
    Rows injected through :data:`ENV_LIMITS` are appended, for testing.
    """
    return [dict(row) for row in _DECLARED] + _injected_rows()


# --- aggregation --------------------------------------------------------------


def _result_status(row_status: str) -> str:
    return _STATUS_TO_RESULT.get(row_status, NOT_RUN)


def _capability_status(enforcement: str) -> str:
    if enforcement in (NOT_ENFORCED, NOT_TESTED):
        return enforcement
    # A capability the detector could not classify proves nothing was enforced.
    return NOT_RUN


def _row_status_from_result(source_status: str, enforcement: Optional[str]) -> str:
    """Never let a PASS leak into the view.

    A PASS that still carries a NOT_ENFORCED/NOT_TESTED label is reported by the
    label, because the label is the honest statement about enforcement.
    """
    if source_status == NOT_RUN:
        return NOT_RUN
    if source_status == NEEDS_HUMAN:
        return NEEDS_HUMAN
    if enforcement in (NOT_ENFORCED, NOT_TESTED):
        return enforcement
    return NOT_RUN


def _verified_by(check_id: str, source: str) -> str:
    return _VERIFIED_BY.get(check_id) or _VERIFIED_BY_FALLBACK.get(
        source, _VERIFIED_BY_FALLBACK["declared"]
    )


def _requirement_for(check_id: str, source: str) -> str:
    return _REQUIREMENT_BY_CHECK.get(check_id, _REQUIREMENT_BY_SOURCE.get(source, ""))


def _capability_rows(root: Optional[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        report = detect_capabilities(root)
    except (OSError, ValueError):
        return rows
    for capability in report.capabilities:
        enforcement = str(capability.enforcement)
        if enforcement not in (NOT_ENFORCED, NOT_TESTED, _CAPABILITY_UNKNOWN):
            continue
        reason = capability.note or capability.evidence
        label = f"{capability.capability_id}: {reason}"
        rows.append({
            "requirement_id": _requirement_for(capability.capability_id, "capability"),
            "check_id": capability.capability_id,
            "status": _capability_status(enforcement),
            "enforcement": enforcement if enforcement in ENFORCEMENTS else None,
            "reason": label,
            "verified_by": _verified_by(capability.capability_id, "capability"),
            "source": "capability",
        })
    return rows


def _doctor_rows(root: Path) -> List[Dict[str, Any]]:
    """Run doctor's checks, capturing stdout, exactly as ``cli.doctor_results_for`` does."""
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            doctor_mod.run(root, json_output=True)
    except (NotADirectoryError, OSError, ValueError):
        return []
    try:
        payload = json.loads(buffer.getvalue())
    except ValueError:
        return []

    rows: List[Dict[str, Any]] = []
    for record in payload.get("results", []):
        source_status = str(record.get("status", ""))
        enforcement = record.get("enforcement")
        if source_status != NOT_RUN and enforcement not in (NOT_ENFORCED, NOT_TESTED):
            continue
        check_id = str(record.get("check_id", ""))
        reason = str(record.get("message", ""))
        limitations = [str(item) for item in (record.get("limitations") or [])]
        if limitations:
            reason = f"{reason} | limitations: {' '.join(limitations)}"
        rows.append({
            "requirement_id": _requirement_for(check_id, "doctor"),
            "check_id": check_id,
            "status": _row_status_from_result(source_status, enforcement),
            "enforcement": enforcement if enforcement in ENFORCEMENTS else None,
            "reason": reason,
            "verified_by": _verified_by(check_id, "doctor"),
            "source": "doctor",
        })
    return rows


def _policy_rows(root: Path) -> List[Dict[str, Any]]:
    try:
        results = advisory_mod.update_dry_run(root)
    except (OSError, ValueError):
        return []
    rows: List[Dict[str, Any]] = []
    for result in results:
        if result.status != NOT_RUN and result.enforcement not in (NOT_ENFORCED, NOT_TESTED):
            continue
        reason = result.message
        if result.limitations:
            reason = f"{reason} | limitations: {' '.join(result.limitations)}"
        rows.append({
            "requirement_id": _requirement_for(result.check_id, "policy"),
            "check_id": result.check_id,
            "status": _row_status_from_result(result.status, result.enforcement),
            "enforcement": result.enforcement if result.enforcement in ENFORCEMENTS else None,
            "reason": reason,
            "verified_by": _verified_by(result.check_id, "policy"),
            "source": "policy",
        })
    return rows


def rows(project_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Every unverified control reachable in ONE view.

    Aggregates host capabilities whose enforcement is ``NOT_ENFORCED`` /
    ``NOT_TESTED`` / ``UNKNOWN``, ``doctor`` results that did not run or are not
    enforced, the policy dry run, and the declared table.  ``PASS`` results are
    never rows.  ``project_root=None`` still works: it returns the declared table
    plus the host capabilities, and simply cannot reach the per-project checks.

    Duplicate check ids from different sources are kept: they are different
    surfaces looking at the same control, and each carries its own evidence.
    """
    found: List[Dict[str, Any]] = []
    root = Path(project_root) if project_root is not None else None

    found.extend(_capability_rows(root if root is not None else None))
    if root is not None and root.is_dir():
        found.extend(_doctor_rows(root))
        found.extend(_policy_rows(root))
    found.extend(declared_rows())
    return found


def _sources_reachable(project_root: Optional[Path]) -> List[str]:
    reachable = ["declared", "capability"]
    if project_root is not None and Path(project_root).is_dir():
        reachable.extend(["doctor", "policy"])
    return reachable


def _unreachable_note(project_root: Optional[Path]) -> str:
    if project_root is None:
        return (
            "no project root was given, so the doctor and policy checks were not "
            "run and only the declared table and this host's capabilities were "
            "consulted"
        )
    if not Path(project_root).is_dir():
        return (
            f"the given project root {project_root} is not a directory, so the "
            f"doctor and policy checks were not run and only the declared table "
            f"and this host's capabilities were consulted"
        )
    return (
        "doctor, the policy dry run and this host's capabilities were all "
        "consulted and produced no unverified row; this describes this host and "
        "this project only"
    )


def collect(project_root: Optional[Path] = None) -> List[Result]:
    """The same data as :class:`Result` objects, so the CLI can emit it once.

    One ``limits.unverified-count`` result (never ``PASS`` -- a count of
    unverified controls is not a safety claim) plus one result per row.  Never
    returns ``[]``: when nothing is reachable, the count result itself says so.
    """
    view = rows(project_root)
    if view:
        count_message = (
            f"{len(view)} unverified control(s) reachable from here across "
            f"{len(sorted({row['source'] for row in view}))} source(s); each row "
            f"states why it is unverified and what would verify it"
        )
    else:
        count_message = (
            "0 unverified control(s) reachable from here -- this is not evidence "
            "that none exist: " + _unreachable_note(project_root)
        )

    results: List[Result] = [Result(
        "limits.unverified-count", NOT_RUN, INFO, count_message,
        __version__, environment_label(), required=False, limitations=[LIMITATION],
    )]
    for row in view:
        enforcement = row["enforcement"] if row["enforcement"] in ENFORCEMENTS else None
        results.append(Result(
            f"limits.{row['check_id']}",
            _result_status(row["status"]),
            REVIEW,
            f"{row['reason']} | what would verify it: {row['verified_by']}",
            __version__, environment_label(), required=True,
            enforcement=enforcement, limitations=[ROW_LIMITATION],
        ))
    return results


# --- static coverage of the table --------------------------------------------

#: The modules whose results the limits view aggregates at runtime. An emission
#: inside one of these is reachable: the view surfaces that module's results
#: wholesale, whether or not the check id can be read statically.
_VIEW_MODULES = frozenset({
    "capabilities.py",
    "doctor.py",
    "advisory.py",
    "history.py",
    "scan.py",
    "overrides.py",
    "contracts.py",
})

#: Files whose NOT_ENFORCED/NOT_TESTED emissions are intentionally NOT surfaced
#: by the limits view. Every entry must state a reason. These are command-scoped
#: findings: they describe one invocation (one commit, one candidate, one
#: archive, one ledger) and are surfaced by that command's own output at the
#: moment they matter, not as a standing property of the project.
EXEMPTIONS: Dict[str, str] = {
    "staged.py": (
        "precommit.* emissions describe ONE staged commit and are surfaced by "
        "`openready precommit` (and the wired git hook) at the moment they block "
        "or allow that commit; they are per-invocation findings, not a standing "
        "project control."
    ),
    "verify.py": (
        "verify.*, verify.digest-anchor and build.restricted-run are the "
        "per-candidate output of `openready verify` / `openready test`: the "
        "candidate does not exist until it is exported, and the finding is about "
        "that one artifact. (verify.py also re-states trust.publisher-separation, "
        "egress.containment, host.isolation and release.rights, which the limits "
        "view surfaces from doctor, capabilities and the declared table.)"
    ),
    "backup.py": (
        "backup.restore-readable and migration.untransacted-hazard are produced by "
        "`openready backup --verify` against one archive; they are a property of "
        "that archive, not a standing control of the project."
    ),
    "ledger.py": (
        "ledger.dependency-licenses and ledger.assets are produced by `openready "
        "ledger` from the project's own manifests; an unreadable or unparsed "
        "manifest is reported there, when the ledger is built."
    ),
    "project.py": (
        "init.commit-control is produced by `openready new` / `openready init` when "
        "it wires the advisory pre-commit hook. It describes one created checkout, "
        "and the hook's own limitation (`git commit --no-verify` skips it) travels "
        "with that emission."
    ),
    "policy.py": (
        "policy.absent / policy.unapproved are emitted by `openready policy check` "
        "*exactly when* no owner approval covers a (destination, data_class) pair. "
        "A declared row would have to assert 'nothing is authorised' "
        "unconditionally, which is false the moment a grant exists, so this view "
        "leaves the evaluation to the command that can read the actual grants at "
        "the moment a flow is proposed. The standing limit behind both -- the tool "
        "can refuse to authorise an outbound flow but cannot block one -- is A10 in "
        "the declared table."
    ),
    "audit.py": (
        "audit.integrity is emitted by `openready audit verify` only when the "
        "private audit log is absent or empty. That is a property of the log's "
        "current state, not a standing control of the project, and the log lives "
        "in the private runtime root that this view does not read."
    ),
    "feature.py": (
        "feature.check-unparsed is emitted by a tiered feature/test run when an "
        "inner check printed something that is not JSON -- a diagnostic about one "
        "malformed sub-process, not a standing property of the project. feature.py "
        "otherwise forwards the inner checks' own results, which are surfaced by "
        "those checks themselves."
    ),
    "intake.py": (
        "intake.* are emitted by `openready intake propose` only when it scans a "
        "parent directory; the proposal is a one-off discovery, and the auto/"
        "background half is reported as a standing limit by the declared table."
    ),
    "providers.py": (
        "provider.* are emitted by `openready providers preflight` for one target; "
        "the network-free read of the local gh hosts file is a property of that "
        "target, not a standing project control."
    ),
    "external.py": (
        "external.* are emitted by `openready external --profile NAME` for one "
        "profile; the platform-authority and human-only lines are statements about "
        "the profile, surfaced when a job-submission flow is considered."
    ),
    "promote.py": (
        "promote.* are emitted by `openready promote` / `openready rollback` for one "
        "promotion; a stage or a code rollback is a property of that run, not a "
        "standing control of the project."
    ),
    "migrate.py": (
        "migrate.proposal.regresses / migrate.applied are emitted by `openready "
        "migrate --migrate --policy FILE` for one proposal; the regression gate is "
        "a property of that proposal, not a standing control of the project."
    ),
    "templates.py": (
        "templates.* are emitted by `openready templates --to PATH` for one "
        "generation; the on-demand rule is a property of that one write."
    ),
    "cli.py": (
        "history.scan is emitted by `openready history --path PATH` for a single "
        "repository as a per-invocation finding about that one history; the "
        "standing limit behind the scan (no scrubbed history equals a clean "
        "history) is the global `history.bounded` line carried in the declared "
        "table."
    ),
}

_CHECK_ID_RE = re.compile(r"^[a-z0-9]+(?:[.\-][a-z0-9]+)+$")

# Uncovered entries that could not be attributed to a check id are reported under
# this prefix rather than being skipped.
_UNATTRIBUTED = "unattributed"


def _enforcement_tokens(node: ast.AST) -> Set[str]:
    """The NOT_ENFORCED / NOT_TESTED tokens an expression literally names.

    Catches both forms the specification names -- the imported name
    (``NOT_ENFORCED``) and the literal string value (``"NOT_ENFORCED"``).
    """
    found: Set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in (NOT_ENFORCED, NOT_TESTED):
            found.add(sub.id)
        elif (isinstance(sub, ast.Constant) and isinstance(sub.value, str)
              and sub.value in (NOT_ENFORCED, NOT_TESTED)):
            found.add(sub.value)
    return found


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _literal_check_id(call: ast.Call) -> Optional[str]:
    """The check id a call states as a literal, or None when it cannot be read."""
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value if _CHECK_ID_RE.match(first.value) else None
        # An f-string, a variable or a call: the id is not statically readable.
        return None
    for keyword in call.keywords:
        if keyword.arg == "check_id" and isinstance(keyword.value, ast.Constant) \
                and isinstance(keyword.value.value, str):
            return keyword.value.value
    return None


def _emission(node: ast.AST) -> Optional[Tuple[Optional[str], Set[str]]]:
    """A ``Result(...)``/``Capability(...)`` call that emits an unenforced status.

    Only the arguments that carry enforcement are inspected, so a limitation
    string that merely mentions the word is not mistaken for an emission. The
    check id is read from the call's first positional argument when it is a
    literal; otherwise it is reported as unattributable.
    """
    if not isinstance(node, ast.Call):
        return None
    name = _call_name(node)
    if name not in ("Result", "Capability"):
        return None
    tokens: Set[str] = set()
    for keyword in node.keywords:
        if keyword.arg == "enforcement":
            tokens |= _enforcement_tokens(keyword.value)
    if name == "Capability" and len(node.args) >= 4:
        tokens |= _enforcement_tokens(node.args[3])
    if not tokens:
        return None
    return _literal_check_id(node), tokens


def _module_check_ids(directory: Path) -> Set[str]:
    """Every check id the limits view can surface from the view modules here."""
    ids: Set[str] = set()
    for filename in sorted(_VIEW_MODULES):
        path = directory / filename
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in ("Result", "Capability"):
                check_id = _literal_check_id(node)
                if check_id:
                    ids.add(check_id)
    return ids


def source_scan(root: Optional[Path] = None) -> List[Result]:
    """Static coverage: is every NOT_ENFORCED/NOT_TESTED emission in the view?

    Reads ``root`` (default: this package) for ``*.py``, finds every emission,
    extracts the check id it states, and reports each emitting check id that the
    limits view cannot reach.  Conservative by design: an emission whose check id
    cannot be read statically is reported as uncovered rather than skipped, and a
    failure to parse a source file is reported as "not scanned", never as clean.

    Exempt files (:data:`EXEMPTIONS`) are skipped with their stated reason; the
    count of exemptions is reported so the size of the escape hatch is visible.
    """
    default_dir = Path(__file__).resolve().parent
    scan_dir = Path(root).expanduser().resolve() if root is not None else default_dir

    view_ids: Set[str] = {row["check_id"] for row in declared_rows()}
    for directory in ([scan_dir, default_dir] if scan_dir != default_dir else [scan_dir]):
        view_ids |= _module_check_ids(directory)

    uncovered: Dict[str, List[str]] = {}
    unscanned: List[str] = []
    exempted: List[str] = []
    scanned = 0

    for path in sorted(scan_dir.glob("*.py")):
        if path.name in EXEMPTIONS:
            exempted.append(path.name)
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            unscanned.append(f"{path.name} ({exc.__class__.__name__})")
            continue
        scanned += 1
        if path.name in _VIEW_MODULES:
            # The view surfaces this module's results wholesale.
            continue
        for node in ast.walk(tree):
            emission = _emission(node)
            if emission is None:
                continue
            check_id, _tokens = emission
            if check_id is not None and check_id in view_ids:
                continue
            key = check_id if check_id is not None else (
                f"<{_UNATTRIBUTED}:{path.name}:{getattr(node, 'lineno', 0)}>"
            )
            uncovered.setdefault(key, []).append(f"{path.name}:{getattr(node, 'lineno', 0)}")

    limitations = [
        LIMITATION,
        "The scan reads the emission statements it can parse. A check id built at "
        "run time, inside a table literal or behind a helper, is reported as "
        "unattributed rather than assumed to be covered.",
        "Exempt files are skipped by decision, not by accident: "
        + "; ".join(f"{name} -- {EXEMPTIONS[name]}" for name in sorted(exempted))
        if exempted else "No file was exempted on this pass.",
    ]
    if unscanned:
        limitations.append(
            "Not scanned (parse failure): " + ", ".join(sorted(unscanned))
        )

    if scanned == 0 and not uncovered:
        summary_status, summary_severity = NOT_RUN, REVIEW
        summary = (
            f"no Python source was scanned under {scan_dir}; this reports nothing "
            f"about whether any emission is covered"
        )
    else:
        clean = not uncovered
        summary_status, summary_severity = (PASS, INFO) if clean else (FAIL, REVIEW)
        summary = (
            f"{scanned} source file(s) scanned under {scan_dir}; "
            f"{len(exempted)} exempt; "
            f"{len(uncovered)} emitting check id(s) not reachable from the limits view"
        )

    results: List[Result] = [Result(
        "limits.source-covered", summary_status, summary_severity, summary,
        __version__, environment_label(), required=False, limitations=limitations,
    )]
    if uncovered:
        listed = ", ".join(sorted(uncovered))
        results.append(Result(
            "limits.source-uncovered", FAIL, REVIEW,
            "these emitting check id(s) are NOT reachable from the limits view: "
            + listed,
            __version__, environment_label(), required=True,
            limitations=[
                "An uncovered emission means a control is reported with "
                "NOT_ENFORCED or NOT_TESTED somewhere that the one-command view "
                "does not reach. Add a declared row for it, or record an explicit "
                "reason in EXEMPTIONS -- never widen the view silently.",
                LIMITATION,
            ],
        ))
    return results
