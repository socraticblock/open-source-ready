"""Private advice and policy-version checks (OR-013, OR-014).

Two small, deliberately unglamorous jobs:

- ``worth`` writes a private recommendation memo: given what the checks found, is
  this project close to being shareable, and what is the cheapest next step? It
  recommends and never decides -- the licence and the launch are owner acts.
- ``update`` answers "would a policy change break this project?" without changing
  anything. Drift between the project's recorded policy version and this build's is
  reported, and so is the regression that matters most: that the vendored contracts
  still load and that the validator still *refuses* a contract using a keyword it
  does not implement. A validator that silently accepts everything is worse than no
  validator, because it reports success.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import POLICY_VERSION, __version__
from .capabilities import environment_label
from .contracts import contract_paths, load_schema, tool_root, unsupported_keywords
from .private import private_home
from .status import FAIL, INFO, NEEDS_HUMAN, NOT_RUN, PASS, REVIEW, STOP, Result

MEMO_DIRNAME = "memos"


def worth(project_root: Path, results: List[Result],
          ledger_document: Optional[Dict[str, Any]] = None,
          write: bool = True) -> Tuple[List[Result], str]:
    """A private memo. Recommends; never decides, and never launches anything."""
    project_root = Path(project_root)
    failures = [r for r in results if r.status == FAIL]
    unrun = [r for r in results if r.status == NOT_RUN]
    human = [r for r in results if r.status == NEEDS_HUMAN]
    dependencies = (ledger_document or {}).get("dependency_count")
    assets = (ledger_document or {}).get("asset_count")

    if failures:
        verdict = "NOT CLOSE"
        next_step = (f"resolve {len(failures)} blocking finding(s) first: "
                     f"{', '.join(r.check_id for r in failures[:3])}")
    elif unrun:
        verdict = "CLOSE, WITH UNCHECKED AREAS"
        next_step = (f"{len(unrun)} check(s) could not run here, so \"close\" means \"nothing "
                     f"failed\", not \"nothing is wrong\": "
                     f"{', '.join(r.check_id for r in unrun[:3])}")
    else:
        verdict = "CLOSE"
        next_step = "the remaining steps are owner decisions (licence, scope, destination)"

    lines = [
        f"# Worth-sharing memo -- {project_root.name}",
        "",
        f"Written {datetime.now(timezone.utc).strftime('%Y-%m-%d')} by openready {__version__}.",
        "This memo is private. It is not a publication decision and it is not legal advice.",
        "",
        "## Verdict",
        "",
        f"{verdict}. {next_step}",
        "",
        "## What the checks found",
        "",
        f"- blocking failures: {len(failures)}",
        f"- needs a human: {len(human)}",
        f"- not run here: {len(unrun)}",
    ]
    if dependencies is not None:
        lines.append(f"- declared dependencies: {dependencies}"
                     + (" (nothing third-party is imported)" if dependencies == 0 else ""))
    if assets is not None:
        lines.append(f"- binary assets: {assets}")
    lines += [
        "",
        "## Cheapest next step",
        "",
        "1. Nothing in this list is expensive once the product is worth sharing. Licence, "
        "documentation, contributor terms and CI are all addable in one commit each.",
        "2. The one thing that is expensive later is accepting a contribution before the "
        "contribution terms exist. Decide those before the repository is public, not after.",
        "3. Anything this tool reported as NOT_RUN will not become true by waiting.",
        "",
    ]
    memo = "\n".join(lines)

    written: Optional[Path] = None
    if write:
        directory = private_home() / MEMO_DIRNAME
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        written = directory / f"{project_root.name}-{stamp}.md"
        written.write_text(memo, encoding="utf-8")

    return [Result(
        "worth.recommendation", NEEDS_HUMAN if (failures or unrun) else PASS,
        REVIEW if (failures or unrun) else INFO,
        f"{verdict}: {next_step}", __version__, environment_label(), required=False,
        evidence_path=str(written) if written else None,
        limitations=[
            "A recommendation about effort, not a decision about publishing. Licence, scope "
            "and destination remain owner decisions.",
        ],
    )], memo


def update_dry_run(project_root: Optional[Path] = None) -> List[Result]:
    """Would a policy or contract change break this project? Changes nothing."""
    results: List[Result] = []
    root = Path(project_root) if project_root else None

    problems: List[str] = []
    loaded: List[str] = []
    for name, path in sorted(contract_paths(tool_root()).items()):
        try:
            schema = load_schema(path)
        except Exception as exc:
            problems.append(f"{name}: {exc}")
            continue
        keywords = unsupported_keywords(schema)
        if keywords:
            problems.append(f"{name}: uses unimplemented keyword(s) {sorted(keywords)}")
            continue
        loaded.append(f"{name}@{schema.get('$id', 'no-$id').rsplit('/', 1)[-1]}")
    if problems:
        results.append(Result(
            "update.contracts-load", FAIL, STOP,
            "; ".join(problems), __version__, environment_label(),
            limitations=["A contract this build cannot fully validate is not re-validated as "
                         "passing; it is reported and left alone."],
        ))
    else:
        results.append(Result(
            "update.contracts-load", PASS, INFO,
            f"{len(loaded)} contract(s) load and use only implemented keywords: "
            f"{', '.join(loaded)}",
            __version__, environment_label(),
        ))

    # A live probe, not an assertion about the validator. The previous version was an
    # unconditional PASS with a note that the test suite had covered it, so it could
    # not fail and told the operator nothing.
    probe = {"type": "object",
             "properties": {"x": {"type": "string", "refuses_to_be_ignored": True}}}
    try:
        caught = unsupported_keywords(probe)
        failed = "refuses_to_be_ignored" not in (caught or set())
        detail = f"keywords reported unsupported: {sorted(caught or set())}"
    except Exception as exc:  # noqa: BLE001 - the probe failing is itself a finding
        failed = True
        detail = f"the probe raised {exc.__class__.__name__}: {exc}"
    results.append(Result(
        "update.validator-refuses-unknown-keywords", FAIL if failed else PASS,
        STOP if failed else INFO,
        ("the validator accepted a contract keyword it does not implement, so a contract "
         "could validate while being only partly checked"
         if failed else
         f"the validator reports an unimplemented keyword instead of ignoring it ({detail})"),
        __version__, environment_label(),
    ))

    if root is not None:
        config_path = root / "openready.project.json"
        if not config_path.is_file():
            results.append(Result(
                "update.policy-version", NOT_RUN, REVIEW,
                "no project config here, so policy drift cannot be assessed",
                __version__, environment_label(), required=False,
            ))
        else:
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except (ValueError, OSError) as exc:
                config = {}
                results.append(Result(
                    "update.policy-version", FAIL, STOP, f"config unreadable: {exc}",
                    __version__, environment_label(),
                ))
            recorded = str(config.get("checks_profile_version", ""))
            same = recorded == POLICY_VERSION
            results.append(Result(
                "update.policy-version", PASS if same else NEEDS_HUMAN, INFO if same else REVIEW,
                (f"project policy version {recorded} matches this build ({POLICY_VERSION})"
                 if same else
                 f"project records policy {recorded or '(none)'} but this build is "
                 f"{POLICY_VERSION}; re-run doctor and review the difference before relying on it"),
                __version__, environment_label(), required=not same,
            ))

    results.append(Result(
        "update.destructive-action", PASS, INFO,
        "dry run: no migration was applied and no file was changed",
        __version__, environment_label(),
    ))
    return results
