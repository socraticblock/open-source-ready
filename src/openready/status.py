"""Open-Ready status, severity and exit-code vocabulary.

Normative sources (do not extend without a new owner decision):

- ``docs/10-CLI-CONTRACT.md`` in the definitive agent handoff for the exit codes
  and the rule that exit ``0`` never means safe to publish.
- ``contracts/result.schema.json`` for the exact shape of a check result.

The set of statuses is deliberately small and closed. If a new situation seems to
need a new status, it almost always means the check is trying to say two things at
once -- split it into two checks instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"

# --- statuses -----------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
NEEDS_HUMAN = "NEEDS_HUMAN"
NOT_RUN = "NOT_RUN"
NOT_APPLICABLE = "NOT_APPLICABLE"
STATUSES = (PASS, FAIL, NEEDS_HUMAN, NOT_RUN, NOT_APPLICABLE)

# --- severities ---------------------------------------------------------------
STOP = "STOP"
REVIEW = "REVIEW"
INFO = "INFO"
SEVERITIES = (STOP, REVIEW, INFO)

# --- enforcement --------------------------------------------------------------
ENFORCED = "ENFORCED"
ADVISORY = "ADVISORY"
NOT_ENFORCED = "NOT_ENFORCED"
NOT_TESTED = "NOT_TESTED"
ENFORCEMENTS = (ENFORCED, ADVISORY, NOT_ENFORCED, NOT_TESTED)

# --- exit codes (CLI contract) ------------------------------------------------
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_NEEDS_HUMAN = 2
EXIT_NOT_RUN = 3
EXIT_USAGE = 64

# Statuses that block release readiness when the check is required.
BLOCKING_STATUSES = (FAIL, NEEDS_HUMAN, NOT_RUN)


@dataclass
class Result:
    """One check result.

    ``required`` is NOT emitted: ``contracts/result.schema.json`` sets
    ``additionalProperties: false``. It is engine-side bookkeeping that decides
    whether an unrun check forces exit 3.
    """

    check_id: str
    status: str
    severity: str
    message: str
    tool_version: str
    environment: str
    required: bool = True
    timestamp: Optional[str] = None
    source_revision: Optional[str] = None
    candidate_digest: Optional[str] = None
    evidence_path: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    enforcement: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown status: {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")
        if self.enforcement is not None and self.enforcement not in ENFORCEMENTS:
            raise ValueError(f"unknown enforcement: {self.enforcement!r}")
        if self.timestamp is None:
            self.timestamp = now_iso()

    def to_dict(self) -> Dict[str, Any]:
        """Exactly the fields in result.schema.json -- nothing extra."""
        out: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "check_id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "tool_version": self.tool_version,
            "timestamp": self.timestamp,
            "environment": self.environment,
            "source_revision": self.source_revision,
            "candidate_digest": self.candidate_digest,
            "evidence_path": self.evidence_path,
            "limitations": list(self.limitations),
        }
        if self.enforcement is not None:
            out["enforcement"] = self.enforcement
        return out


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def exit_code_for(results: List[Result]) -> int:
    """Map results to the CLI contract's exit codes.

    Precedence, per the contract: an actionable failure (1) outranks a required
    human review (2), which outranks a required check that could not run (3).
    Never returns 0 for a run that contains a required unrun or unenforced check.
    """
    if any(r.status == FAIL for r in results):
        return EXIT_FAIL
    if any(r.status == NEEDS_HUMAN and r.required for r in results):
        return EXIT_NEEDS_HUMAN
    unrun = [r for r in results if r.status == NOT_RUN and r.required]
    unenforced = [
        r for r in results
        if r.enforcement in (NOT_ENFORCED, NOT_TESTED) and r.required
    ]
    if unrun or unenforced:
        return EXIT_NOT_RUN
    return EXIT_OK


def summarize(results: List[Result]) -> Dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for r in results:
        counts[r.status] += 1
    return counts


def is_release_ready(results: List[Result]) -> bool:
    """No universal certified-safe state: this answers one narrow question.

    ``True`` means only that no *check this run performed* blocks readiness. It is
    never evidence that unrun checks would pass and must never be surfaced to a
    human as a safe-to-publish claim.
    """
    return not any(r.status in BLOCKING_STATUSES for r in results)
