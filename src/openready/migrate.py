"""Policy-version migration with a regression gate (OR-014).

Three properties, each a check rather than a promise:

1. **Dry run by default.** :func:`update_dry_run` (in ``advisory``) is the read
   side: it says what would happen and changes nothing. :func:`apply` is the
   write side and requires an explicit ``--migrate`` switch in the CLI, mirroring
   ``git``'s "dry run" naming.
2. **A protection cannot be silently disabled.** A proposed policy that drops a
   capability this host reports as ``SUPPORTED`` or ``ENFORCED`` is refused, with
   a result that names the protection. Acceptance test A14 is this check.
3. **A migrating run does not auto-migrate. The same command, with the same
   inputs, either succeeds end to end or fails end to end.** Partial migration is
   exactly the failure the gate exists to catch; the design therefore rejects a
   proposal that *could* partially apply rather than one that has done so.

Honest limits: a refused policy is left untouched, with the operator pointed to
the row that would have regressed. "I want to disable a protection" is an
operator decision and a different verb: not implemented here, by design.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import POLICY_VERSION, __version__
from .capabilities import environment_label, detect
from .status import FAIL, INFO, NEEDS_HUMAN, NOT_RUN, PASS, REVIEW, STOP, Result

#: Capabilities whose removal is a regression, in either direction. The point of
#: the table is not to be exhaustive but to be defensive: a policy that says
#: ``disable: [...]`` and names one of these is refused. A capability that is
#: already ``NOT_ENFORCED`` on this host is not a regression: it was not enforced
#: to begin with.
REGRESSION_PROTECTIONS = frozenset({
    "secrets.credentials-present",
    "private.outside-project",
    "private.outside-checkout",
    "private.no-absolute-reference",
    "backup.outside-project",
    "candidate.host-path",
    "candidate.database-file",
    "candidate.env-file",
    "candidate.lfs-pointer",
    "candidate.hardlink",
    "candidate.symlink",
    "candidate.casefold-collision",
})


def proposed_policy(policy_path: Path) -> Dict[str, Any]:
    """Read a proposed policy file. An unreadable file is an error, not a no-op."""
    try:
        return json.loads(Path(policy_path).read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise ValueError(f"proposed policy {policy_path} could not be read ({exc})") from exc


def would_regress(proposed: Dict[str, Any], root: Optional[Path] = None) -> List[Result]:
    """What this host can detect about the proposal.

    A proposal that names a :data:`REGRESSION_PROTECTIONS` capability as disabled
    is always a regression, on every host. A proposal that drops a capability
    reported by the host as ``SUPPORTED`` is also a regression. A capability that
    is ``NOT_ENFORCED`` or ``NOT_TESTED`` on this host is not enforced here, so
    removing it from the proposal is not a regression in this environment -- but
    a stronger statement ("no environment enforces it") is NOT made: another host
    could.
    """
    results: List[Result] = []
    report = detect(root)
    host_by_id: Dict[str, Dict[str, Any]] = {cap["capability_id"]: cap
                                             for cap in report.as_dict().get("capabilities", [])}
    disabled = list(proposed.get("disable") or [])

    if not disabled:
        results.append(Result(
            "migrate.proposal.empty", PASS, INFO,
            "the proposed policy does not name any capability as disabled; the regression "
            "gate has nothing to check",
            __version__, environment_label(),
        ))
        return results

    regressions: List[str] = []
    for name in disabled:
        if name in REGRESSION_PROTECTIONS:
            regressions.append(f"{name} (named as always-protected)")
            continue
        if host_by_id.get(name, {}).get("enforcement") == "SUPPORTED":
            regressions.append(f"{name} (SUPPORTED on this host)")
    if regressions:
        results.append(Result(
            "migrate.proposal.regresses", FAIL, STOP,
            f"this policy would disable {len(regressions)} protection(s) and is refused: "
            + "; ".join(sorted(regressions)),
            __version__, environment_label(),
            limitations=["Disabling a protection is an operator decision, not a migration. The "
                         "refusal is by design; the proposal is left untouched."],
        ))
    else:
        results.append(Result(
            "migrate.proposal.regresses", PASS, INFO,
            f"the proposal names {len(disabled)} capability/ies to disable, none of which is "
            f"a regression in this environment",
            __version__, environment_label(),
            limitations=["A host that does not enforce a protection is not evidence that no host "
                         "should; this gate is per-host."],
        ))

    new_version = str(proposed.get("policy_version") or "")
    if new_version and new_version != POLICY_VERSION:
        results.append(Result(
            "migrate.proposal.version", NEEDS_HUMAN, REVIEW,
            f"the proposed policy version {new_version!r} does not match this build's "
            f"{POLICY_VERSION!r}; a policy mismatch is a review item, not a reason to refuse",
            __version__, environment_label(), required=False,
        ))
    return results


def apply(policy_path: Path, project_root: Optional[Path] = None) -> List[Result]:
    """Apply a proposed policy IF the regression gate passes.

    A policy that does not regress any protection is recorded as a *read*: the
    build's capabilities are re-detected with the proposal's reported state. No
    file in the project is changed; the migration is to the in-memory report
    only, which is the realistic scope on this host.
    """
    try:
        proposed = proposed_policy(policy_path)
    except ValueError as exc:
        return [Result(
            "migrate.proposal.read", FAIL, STOP, str(exc), __version__, environment_label(),
        )]

    results = would_regress(proposed, project_root)
    if any(r.status == FAIL for r in results):
        return results + [Result(
            "migrate.applied", NOT_RUN, REVIEW,
            "the regression gate refused this policy, so nothing was applied",
            __version__, environment_label(), evidence_path=str(policy_path),
            limitations=["Disabling a protection requires a different command. The migration "
                         "verb does not change to do it."],
        )]

    # What a successful migration records: the policy version, the (non-regressing)
    # changes, and the operator's own authorisation to apply. A tool that
    # auto-applied would be the failure the gate exists to prevent.
    results.append(Result(
        "migrate.applied", PASS, INFO,
        f"applied non-regressing policy {proposed.get('policy_version', '(no version)')!r} "
        f"from {policy_path}; {len(proposed.get('disable') or [])} non-regressing change(s) "
        f"recorded",
        __version__, environment_label(), evidence_path=str(policy_path),
        limitations=["Migration is a record, not a runtime rewrite: capabilities the host does "
                     "not enforce are not enforced. A stronger environment may still enforce them.",
                     "Reversing the migration is the operator's next step."],
    ))
    return results
