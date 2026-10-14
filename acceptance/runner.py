"""T1 acceptance harness entry point.

Runs every test in :mod:`acceptance.harness` against a real, fresh subprocess
invocation of the tool, captures the real exit code and the real output, and
writes the full evidence table to ``docs/ACCEPTANCE-STATE.md`` (overwriting the
prior accepted draft).

Usage::

    cd ~/projects/openready
    PYTHONPATH=src python3 -m acceptance.runner [--only A01,A02] [--no-report]

Exit codes follow the project's contract: the runner exits 0 only when every
acceptance row has a *measured* result (PASS or one of the honest
``NOT_RUN``/``NOT_TESTED``/``NOT_ENFORCED``/``NEEDS_HUMAN`` states). A row that
the runner could not even reach raises and is recorded as an error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import openready  # noqa: E402
from openready import scan  # noqa: E402

from acceptance import harness  # noqa: E402
from acceptance import tests_a01_a17  # noqa: E402,F401  (import to register tests)
from acceptance import tests_a18_a33  # noqa: E402,F401


def _run_one(test_id: str, stage: str, title: str, runner) -> harness.Outcome:
    sandbox = harness.Sandbox(test_id)
    try:
        outcome = runner(sandbox)
    except Exception as exc:  # noqa: BLE001 - every measured failure is recorded
        tb = traceback.format_exc(limit=8)
        return harness.outcome(test_id, stage, title, sandbox, harness.FAIL,
                                f"the test itself raised {exc.__class__.__name__}: {exc}; "
                                f"traceback was:\n{tb}",
                                limitations=["This is a defect in the acceptance test, not in "
                                             "the tool. The same condition on a different day "
                                             "would have to fail the same way to be ignored."])
    finally:
        sandbox.cleanup()
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="", help="comma-separated ids; default: all")
    parser.add_argument("--no-report", action="store_true",
                        help="run the tests but do not write ACCEPTANCE-STATE.md")
    parser.add_argument("--keep", action="store_true",
                        help="keep the per-test sandboxes (default: clean up after each test)")
    args = parser.parse_args()

    only = {item.strip() for item in args.only.split(",") if item.strip()}

    revision = openready.__version__
    head_sha = _git_head_sha()
    started = time.time()
    outcomes: List[harness.Outcome] = []

    if not args.keep:
        if harness.SCRATCH_ROOT.exists():
            shutil.rmtree(harness.SCRATCH_ROOT, ignore_errors=True)
        harness.SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)

    for test_id, stage, title, runner in harness.TESTS:
        if only and test_id not in only:
            continue
        outcome = _run_one(test_id, stage, title, runner)
        outcomes.append(outcome)
        sys.stdout.write(f"  {test_id} {outcome.result:<12} {outcome.observed[:80]}\n")
        sys.stdout.flush()

    elapsed = time.time() - started
    counts: Dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.result] = counts.get(outcome.result, 0) + 1

    print(f"\nAcceptance harness: {len(outcomes)} rows in {elapsed:.1f}s")
    for status, count in sorted(counts.items()):
        print(f"  {status:<16} {count}")

    if not args.no_report:
        report = REPO / "docs" / "ACCEPTANCE-STATE.md"
        json_path = REPO / "docs" / "ACCEPTANCE-STATE.json"
        json_text = json.dumps([o.as_dict(head_sha) for o in outcomes], indent=2) + "\n"
        markdown_text = _render_report(outcomes, counts, head_sha, revision, elapsed)
        blockers = _record_findings({
            "ACCEPTANCE-STATE.md": markdown_text,
            "ACCEPTANCE-STATE.json": json_text,
        })
        if blockers:
            print("\nthe record would not pass the tool's own deny-list, so nothing was"
                  " written (fail-closed):")
            for line in blockers:
                print(f"  - {line}")
            return 1
        report.write_text(markdown_text, encoding="utf-8")
        json_path.write_text(json_text, encoding="utf-8")
        print(f"\nReport: {report}\nJSON:   {json_path}")

    return 0 if all(o.result != harness.FAIL for o in outcomes) else 1


def _record_findings(sources: Dict[str, str]) -> List[str]:
    """What the tool's own deny-list finds in the record about to be written.

    The record is part of this repository, so it is scanned by the same deny-list as
    everything else -- and a hit in it would make this repository unexportable by its
    own gate. Fail-closed rather than write-and-warn: a record that poisons the export
    is worse than a run with no record, and a warning would be read as a note.
    """
    findings: List[str] = []
    for name, text in sources.items():
        for hit in scan.scan_content(f"docs/{name}", text.encode("utf-8")):
            findings.append(f"docs/{name}: {hit.check_id}: {hit.message}")
    return findings


def _render_report(outcomes: List[harness.Outcome], counts: Dict[str, int],
                   head_sha: str, tool_version: str, elapsed: float) -> str:
    lines: List[str] = []
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# Open-Ready — acceptance state (A01–A33)\n")
    lines.append(f"**Written:** {today}.  ")
    lines.append(f"**Tool version:** {tool_version} (this build).  ")
    lines.append(f"**Source revision:** {head_sha}.  ")
    lines.append(f"**Runner:** one real subprocess per row, in a fresh disposable "
                  "sandbox under the session scratch directory; the tool is invoked "
                  "exactly as a stranger would (`python3 -m openready …`).\n")

    lines.append("## How to read this table\n")
    lines.append("Every row is a measurement. A row marked `PASS` is a measurement of "
                  "the tool against the requirement. A row marked `NOT_RUN`, `NOT_TESTED` "
                  "or `NOT_ENFORCED` is a measurement that the requirement could not be "
                  "satisfied on this host and names what would verify it. `NEEDS_HUMAN` "
                  "is a measurement that the requirement deliberately ends at the owner. "
                  "`FAIL` is a measurement that the tool does not satisfy the requirement. "
                  "No row reads `PASS` on the strength of having read the code.\n")
    lines.append("**Every path in this file is redacted.** `~` stands for the operator's home "
                  "directory and a credential shape is written as `<redacted>`. The record is "
                  "scanned by the tool's own deny-list before it is written: a record carrying a "
                  "home path or a credential shape would make this repository unexportable by "
                  "its own gate, so if it would not pass, it is not written at all.\n")

    lines.append("## Summary\n")
    for status, count in sorted(counts.items()):
        lines.append(f"- **{status}:** {count}")
    lines.append(f"- **Total:** {len(outcomes)}")
    lines.append("")

    lines.append("## A01–A33\n")
    lines.append("| ID | Stage | Result | Requirement | Evidence path |")
    lines.append("|----|-------|--------|-------------|---------------|")
    for outcome in sorted(outcomes, key=lambda o: o.id):
        lines.append(f"| {outcome.id} | {outcome.stage} | {outcome.result} | "
                      f"{harness.redact(outcome.title)} | `{harness.redact(outcome.sandbox)}` |")
    lines.append("")

    lines.append("## Detail\n")
    for outcome in sorted(outcomes, key=lambda o: o.id):
        lines.append(f"### {outcome.id} — {harness.redact(outcome.title)}\n")
        lines.append(f"- **Result:** `{outcome.result}`")
        lines.append(f"- **Stage:** {outcome.stage}")
        if outcome.task_id:
            lines.append(f"- **Backlog task:** {outcome.task_id}")
        lines.append(f"- **Sandbox:** `{harness.redact(outcome.sandbox)}`")
        lines.append(f"- **Observed:** {harness.redact(outcome.observed)}")
        if outcome.command.strip():
            preview = harness.redact(outcome.command.strip().splitlines()[-1][:200])
            lines.append(f"- **Last command in the sandbox:** `{preview}`")
        if outcome.limitations:
            lines.append("- **Limitations:**")
            for limitation in outcome.limitations:
                lines.append(f"  - {harness.redact(limitation)}")
        lines.append("")

    lines.append("## Honest limits of this measurement\n")
    lines.append("- The harness is a one-pass measurement on this host. Where a row "
                  "ends `NOT_TESTED`, no second machine or sandbox exists on this host "
                  "to make it testable. ")
    lines.append("- Acceptance tests A23, A28, A30, A32 and A33 have at least one row "
                  "each that ends in `NOT_TESTED` or `NEEDS_HUMAN` by design: the "
                  "specification names these as the cases where tool-shaped control ends "
                  "and owner/external/platform authority begins.")
    lines.append("- The harness writes no file to the project under test: every sandbox "
                  "lives in the session scratch directory and is deleted at the end of "
                  "the row, unless `--keep` is passed.")
    return "\n".join(lines) + "\n"


def _git_head_sha() -> str:
    import subprocess
    try:
        done = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "0000000000000000000000000000000000000000"
    return done.stdout.strip() or "0000000000000000000000000000000000000000"


if __name__ == "__main__":
    raise SystemExit(main())
