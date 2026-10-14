"""``doctor`` -- findings, checkpoint policy and privacy guardrails (OR-006).

The inherited prototype printed ``NO KNOWN BLOCKERS DETECTED`` immediately after
exporting a document that contained the owner's home path and a personal
sentence. The fix is structural, not cosmetic:

- :data:`~openready.scan.PROSE_LIMITATION` is emitted as a ``NOT_RUN`` check, so
  "we could not check this" can never render as "this is clean".
- Every scanner result carries its own limitation string.
- The headline reports counts of failures, human reviews and unrun checks, and
  never a safe-to-publish claim.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from . import POLICY_VERSION, __version__
from . import history as history_mod
from .capabilities import detect as detect_capabilities
from .capabilities import enclosing_checkout
from .contracts import validate_project_contract
from .history import findings as history_findings
from .overrides import apply as apply_overrides
from .overrides import load as overrides_load
from .scan import DENYLIST_LIMITATION, PROSE_LIMITATION, scan_tree
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
    exit_code_for,
    summarize,
)

CONFIG_NAME = "openready.project.json"
ENVIRONMENT_LABEL = "local"


def _environment_label() -> str:
    return f"{os.uname().sysname.lower()}-{os.uname().machine}"


def _check_config(root: Path) -> List[Result]:
    path = root / CONFIG_NAME
    results: List[Result] = []
    if not path.is_file():
        results.append(Result(
            "config.present", FAIL, STOP,
            f"missing {CONFIG_NAME}; this is not an Open-Ready project",
            __version__, _environment_label(),
        ))
        return results
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        results.append(Result(
            "config.present", FAIL, STOP, f"cannot read {CONFIG_NAME}: {exc}",
            __version__, _environment_label(),
        ))
        return results
    errors = validate_project_contract(config)
    if errors:
        results.append(Result(
            "config.valid", FAIL, STOP,
            f"{CONFIG_NAME} does not satisfy contracts/project.schema.json: "
            + "; ".join(errors[:4]),
            __version__, _environment_label(),
        ))
    else:
        results.append(Result(
            "config.valid", PASS, INFO,
            f"{CONFIG_NAME} satisfies the versioned project contract",
            __version__, _environment_label(),
        ))
    return results


def _findings_to_results(findings, root: Path) -> List[Result]:
    """Group findings by check_id so each contract check reports once."""
    grouped: Dict[str, List] = {}
    for finding in findings:
        grouped.setdefault(f"{finding.check_id}", []).append(finding)
    results: List[Result] = []
    for check_id, items in sorted(grouped.items()):
        worst = items[0]
        for candidate in items:
            if candidate.status == FAIL:
                worst = candidate
                break
        paths = sorted({i.path for i in items if i.path})
        shown = ", ".join(paths[:3]) or "-"
        more = f" (+{len(paths) - 3} more)" if len(paths) > 3 else ""
        results.append(Result(
            check_id, worst.status, worst.severity,
            f"{len(items)} occurrence(s): {shown}{more}",
            __version__, _environment_label(),
            required=True,
            limitations=[worst.limitation] if worst.limitation else [],
            enforcement=NOT_ENFORCED if worst.status == NOT_RUN else None,
        ))
    return results


def _structure_checks(root: Path) -> List[Result]:
    """Advisory structural expectations. Not required: they never force exit 3.

    A missing directory is reported as ``NOT_RUN`` rather than a failure: its
    meaning is "nothing here was verified", which is exactly what NOT_RUN says.
    """
    results: List[Result] = []
    for label, rel in (("tests", "tests"), ("examples", "examples")):
        present = (root / rel).is_dir()
        results.append(Result(
            f"structure.{label}", PASS if present else NOT_RUN, INFO,
            f"{rel}/ {'present' if present else 'absent -- nothing in it was verified'}",
            __version__, _environment_label(), required=False,
            enforcement=None if present else NOT_ENFORCED,
        ))
    gitignore = root / ".gitignore"
    results.append(Result(
        "structure.gitignore", PASS if gitignore.is_file() else NOT_RUN, INFO,
        ".gitignore present" if gitignore.is_file() else ".gitignore missing",
        __version__, _environment_label(), required=False,
        enforcement=None if gitignore.is_file() else NOT_ENFORCED,
        limitations=["A .gitignore is hygiene, never a confidentiality control."],
    ))
    return results


def _git_checks(root: Path) -> List[Result]:
    results: List[Result] = []
    encloser = enclosing_checkout(root)
    if encloser:
        results.append(Result(
            "git.enclosing-checkout", FAIL, STOP,
            f"project root sits inside the git working tree at {encloser}; it "
            f"inherits that repository's publication surface",
            __version__, _environment_label(),
            limitations=[
                "A gitignore guard against the enclosing repository is not "
                "enforcement: `git add -f`, a deleted guard file, or a blanket "
                "`git add -A` each bypass it.",
            ],
        ))
    else:
        results.append(Result(
            "git.enclosing-checkout", PASS, INFO,
            "project root is not inside another git working tree",
            __version__, _environment_label(),
        ))

    if (root / ".git").exists():
        remote = _git_output(["git", "-C", str(root), "remote", "get-url", "origin"])
        results.append(Result(
            "git.remote", NEEDS_HUMAN if remote else PASS, REVIEW,
            f"origin = {remote}" if remote else "no origin remote (private local only)",
            __version__, _environment_label(),
            required=bool(remote),
        ))
        results.append(Result(
            "git.visibility", NOT_RUN, REVIEW,
            "repository visibility cannot be read offline; only the hosting API knows",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED,
            limitations=[
                "This command makes no network call, so it cannot confirm whether a "
                "remote repository is public. Verify with the hosting API before "
                "any public act.",
            ],
        ))
    else:
        results.append(Result(
            "git.remote", PASS, INFO, "no local git repository", __version__,
            _environment_label(), required=False,
        ))
    return results


def _git_output(args: List[str]) -> Optional[str]:
    import subprocess
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


def _history_checks(root: Path, report: Optional[Dict] = None) -> List[Result]:
    """The object-store scan, run rather than described as unimplemented.

    ``doctor`` hardcoded ``privacy.full-history`` as NOT_RUN reading "no git history
    scan is implemented" while ``history.scan`` existed and the exporter enforced it.
    One repository was therefore reported here as unscannable and refused there with
    twenty findings the doctor never mentioned -- the two surfaces disagreed about the
    same object store, and the doctor's claim about itself was simply false.
    """
    if report is None:
        report = history_mod.scan(root) if history_mod.is_repository(root) else None
    if not report or not report.get("is_repository"):
        return [Result(
            "privacy.full-history", NOT_RUN, REVIEW,
            "no git repository here, so no object store was scanned",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED, limitations=[history_mod.HISTORY_LIMITATION],
        )]
    document, _ = overrides_load(root)
    acknowledged = [entry for entry in (document or {}).get("entries", []) or []
                    if isinstance(entry, dict)]
    return history_mod.results(report, acknowledged=acknowledged)


def _unimplemented_checks(config: Optional[Dict]) -> List[Result]:
    """Checks the specification requires that this build genuinely cannot do.

    Each is ``NOT_RUN`` and *required*, so exit 3 -- never green. This list is the
    honest measure of distance to the P0 exit gate, and should shrink, never grow
    silently.
    """
    tier = (config or {}).get("risk_tier", "unknown")
    return [
        Result(
            "privacy.private-prose", NOT_RUN, REVIEW,
            "no scan can establish that a document is free of private content",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED, limitations=[PROSE_LIMITATION],
        ),
        Result(
            "trust.publisher-separation", NOT_RUN, STOP,
            "no publisher principal separate from the builder exists (ADR-002)",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED,
            limitations=["Publication must remain a manual owner action."],
        ),
        Result(
            "egress.containment", NOT_RUN, STOP,
            "outbound private-data flow is not contained or measured",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED,
            limitations=[
                "Broad builder read access plus unrestricted network is incompatible "
                "with a technical promise of private-data containment.",
            ],
        ),
        Result(
            "host.isolation", NOT_RUN, STOP,
            "no isolation facility was exercised; untrusted code must not be run here",
            __version__, _environment_label(),
            enforcement=NOT_TESTED,
            limitations=["A present sandbox binary is not evidence it denies anything."],
        ),
        Result(
            "release.rights", NOT_RUN, REVIEW,
            f"ownership, licences and third-party rights for a {tier} project are "
            "unresolved",
            __version__, _environment_label(),
            enforcement=NOT_ENFORCED,
            limitations=["Rights cannot be established by any automated check."],
        ),
    ]


def run(root: Path, json_output: bool = False) -> int:
    """Run every ``doctor`` check. Returns the CLI exit code."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    config: Optional[Dict] = None
    config_path = root / CONFIG_NAME
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            config = None

    report = scan_tree(root)
    # The object-store scan runs before the acknowledgement pass, so an entry that
    # matches a blob is reported as applied rather than as "matched nothing -- the
    # finding is gone". An operator following that advice deletes an entry that the
    # export gate still requires, and the export refuses again for a reason the doctor
    # told them was gone.
    history_report = history_mod.scan(root) if history_mod.is_repository(root) else None
    history_hits = history_findings(history_report)
    findings, override_results = apply_overrides(root, list(report.findings) + history_hits)

    results: List[Result] = []
    results.extend(_check_config(root))
    results.extend(_structure_checks(root))
    results.extend(_git_checks(root))
    results.extend(_findings_to_results(findings, root))
    results.extend(override_results)
    results.extend(_history_checks(root, history_report))
    results.extend(_unimplemented_checks(config))

    if not any(f.check_id == "privacy.secret-shape" for f in findings):
        results.append(Result(
            "privacy.secret-shape", PASS, INFO,
            "no secret-shaped value matched the deny-list in the scanned tree",
            __version__, _environment_label(),
            limitations=[DENYLIST_LIMITATION],
        ))

    caps = detect_capabilities(root)
    code = exit_code_for(results)

    if json_output:
        print(json.dumps({
            "tool_version": __version__,
            "policy_version": POLICY_VERSION,
            "project_root": str(root),
            "project_id": (config or {}).get("project_id"),
            "risk_tier": (config or {}).get("risk_tier"),
            "exit_code": code,
            "summary": summarize(results),
            "results": [r.to_dict() for r in results],
            "capabilities": caps.as_dict()["capabilities"],
            "publication_status": "NOT_APPROVED",
        }, indent=2, sort_keys=False))
        return code

    counts = summarize(results)
    print(f"OPEN-READY DOCTOR  |  {root.name}  |  policy {POLICY_VERSION}  |  tool {__version__}")
    print(f"  risk tier      : {(config or {}).get('risk_tier', 'unknown')}")
    print(f"  files scanned  : {len(report.files)}")
    print(f"  FAILED         : {counts[FAIL]}")
    print(f"  need a human   : {counts[NEEDS_HUMAN]}")
    print(f"  NOT RUN        : {counts[NOT_RUN]}   (never green)")
    print(f"  passed         : {counts[PASS]}")
    acknowledged = [r for r in results if r.check_id == "override.applied"]
    if acknowledged:
        print(f"  acknowledged   : {len(acknowledged)}   (findings the operator owns)")
    print()

    for result in results:
        if result.status == PASS:
            continue
        marker = {FAIL: "STOP ", NEEDS_HUMAN: "HUMAN", NOT_RUN: "UNRUN", REVIEW: "NOTE "}.get(
            result.status, "     ")
        enf = f" [{result.enforcement}]" if result.enforcement else ""
        print(f"  {marker} {result.check_id}: {result.message}{enf}")
        for limitation in result.limitations:
            print(f"        limitation: {limitation}")

    print()
    print("  passed checks:")
    for result in results:
        if result.status == PASS:
            print(f"    ok   {result.check_id}: {result.message}")
    print()
    print(f"  effective_actor : builder    (this process has no publisher credentials)")
    print(f"  network_policy  : unknown    (not probed; probing would itself be egress)")
    publisher = caps.get("trust.publisher-separation")
    print(f"  publisher split : {publisher.enforcement if publisher else 'UNKNOWN'}")
    print()
    print("PUBLICATION STATUS: NOT APPROVED -- requires separate owner review of the exact candidate.")
    print("A passing check describes that one check only. There is no certified-safe state.")
    return code
