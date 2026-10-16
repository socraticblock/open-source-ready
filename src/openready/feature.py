"""Feature worktrees and risk-tiered test runs (OR-007).

Why a worktree rather than a branch in place. The failure this control exists to
prevent is specific: an agent changing code that is currently being served. A branch
in the same working tree does not prevent it -- ``git checkout`` moves the live tree,
and a half-finished edit is visible to whatever is running from that directory. A
linked worktree gives the change its own directory and its own ``HEAD``, so the
serving checkout is not on the path of the change at all.

Three properties, each a check rather than a promise:

1. **The serving checkout is untouched.** :func:`start` records ``HEAD`` before and
   after and reports both; a worktree operation that moved the live revision is a
   failure, not a warning.
2. **Worktrees live outside the project**, under the private runtime data root. A
   worktree inside the project would be committed, exported or backed up with it.
3. **The test run is risk-tiered.** The project's contract carries a tier, and the
   tier decides how much is run -- but the project's own suite always runs. A tier
   reduces how much *else* is checked; it never turns the suite off.

Honest limits: a worktree shares the object store, so it is isolation of the working
tree, not of the repository. Nothing here stops an agent editing files in the serving
checkout by hand -- this removes the reason to, it does not prevent it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from . import doctor as doctor_mod
from . import ledger as ledger_mod
from . import verify as verify_mod
from .capabilities import environment_label
from .private import private_home
from .status import FAIL, INFO, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

WORKTREES_DIRNAME = "worktrees"
CONFIG_NAME = "openready.project.json"

#: Which additional checks each tier runs, in order. The project's own test suite
#: runs at every tier -- a tier that skipped it would be a tier that proves nothing.
TIER_CHECKS: Dict[str, Tuple[str, ...]] = {
    "T0": (),
    "T1": ("doctor",),
    "T2": ("doctor", "ledger"),
    "T3": ("doctor", "ledger", "candidate-plan"),
}
TIERS = tuple(TIER_CHECKS)

LIMITATION = (
    "A linked worktree isolates the working tree, not the repository: it shares the "
    "object store, and nothing here prevents an operator editing the serving checkout "
    "directly."
)


def _git(root: Path, *args: str, timeout: int = 60) -> Tuple[int, str]:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          text=True, timeout=timeout, check=False)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def _is_repository(root: Path) -> bool:
    code, _ = _git(root, "rev-parse", "--git-dir")
    return code == 0


def _revision(root: Path) -> str:
    code, out = _git(root, "rev-parse", "HEAD")
    return out.strip() if code == 0 else ""


def project_config(root: Path) -> Dict[str, object]:
    path = Path(root) / CONFIG_NAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def worktree_root(project_id: str, env: Optional[Dict[str, str]] = None) -> Path:
    """Where a project's feature worktrees live: outside the project, by construction."""
    return private_home(env) / WORKTREES_DIRNAME / (project_id or "project")


def worktree_path(project_root: Path, name: str,
                  env: Optional[Dict[str, str]] = None) -> Path:
    project_id = str(project_config(Path(project_root)).get("project_id") or
                     Path(project_root).name)
    return worktree_root(project_id, env) / name


def safe_name(name: str) -> Optional[str]:
    """A feature name is a path component. Reject anything that is not one.

    ``../../etc`` as a feature name would create a worktree outside the private root,
    which is exactly the traversal the exporter refuses; refusing it here keeps the
    two ends consistent rather than trusting the caller.
    """
    raw = (name or "").strip()
    if not raw or raw in {".", ".."}:
        return None
    if "/" in raw or "\\" in raw or raw.startswith("-") or ".." in raw:
        return None
    if not all(character.isalnum() or character in "-_. " for character in raw):
        return None
    return raw.replace(" ", "-")


def start(project_root: Path, name: str, base: Optional[str] = None,
          env: Optional[Dict[str, str]] = None) -> Tuple[List[Result], Optional[Path]]:
    """Create a linked worktree for a feature, leaving the serving checkout alone."""
    project_root = Path(project_root).resolve()
    clean = safe_name(name)
    if clean is None:
        return [Result(
            "feature.name", FAIL, STOP,
            f"refusing feature name {name!r}: it would become a path component outside the "
            f"private worktree root", __version__, environment_label(),
        )], None

    if not _is_repository(project_root):
        return [Result(
            "feature.repository", FAIL, STOP,
            f"{project_root} is not a git working tree, so a worktree cannot be linked "
            f"(a project without git has no revision to branch from)",
            __version__, environment_label(),
        )], None

    before = _revision(project_root)
    if not before:
        return [Result(
            "feature.baseline", FAIL, STOP,
            f"{project_root} has no commit yet, so there is no revision to branch from",
            __version__, environment_label(),
        )], None

    target = worktree_path(project_root, clean, env)
    if target.exists():
        return [Result(
            "feature.already-exists", FAIL, STOP,
            f"{target} already exists; refusing to reuse or overwrite a worktree",
            __version__, environment_label(), limitations=[LIMITATION],
        )], None

    private = private_home(env).resolve()
    if project_root == private or private in project_root.parents or \
            project_root == target or project_root in target.parents:
        return [Result(
            "feature.outside-project", FAIL, STOP,
            f"refusing to place a worktree at {target}: it must be outside the project "
            f"({project_root}) so it is never committed, exported or backed up with it",
            __version__, environment_label(), limitations=[LIMITATION],
        )], None

    target.parent.mkdir(parents=True, exist_ok=True)
    branch = f"feature/{clean}"
    code, out = _git(project_root, "worktree", "add", "-b", branch, str(target),
                     base or before)
    if code != 0:
        return [Result(
            "feature.worktree", FAIL, STOP,
            f"`git worktree add -b {branch}` failed: {out.strip()[:200]}",
            __version__, environment_label(), limitations=[LIMITATION],
        )], None

    after = _revision(project_root)
    results: List[Result] = []
    if after != before:
        # The whole reason for a worktree, stated as a check rather than a promise.
        results.append(Result(
            "feature.serving-checkout", FAIL, STOP,
            f"the serving checkout's HEAD moved from {before[:12]} to {after[:12]} while "
            f"starting a feature worktree", __version__, environment_label(),
            limitations=[LIMITATION],
        ))
    else:
        results.append(Result(
            "feature.serving-checkout", PASS, INFO,
            f"the serving checkout is still at {before[:12]}; the change has its own "
            f"directory and its own HEAD", __version__, environment_label(),
            limitations=[LIMITATION],
        ))
    results.append(Result(
        "feature.started", PASS, INFO,
        f"{branch} checked out at {target} (outside the project, under the private data "
        f"root)", __version__, environment_label(), evidence_path=str(target),
        limitations=[
            "The worktree shares the project's object store, so this isolates the working "
            "tree only.", LIMITATION,
        ],
    ))
    return results, target


def test(project_root: Path, name: str, tier: Optional[str] = None,
         env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Run the risk-tiered check set in the feature worktree."""
    project_root = Path(project_root).resolve()
    clean = safe_name(name)
    if clean is None:
        return [Result(
            "feature.name", FAIL, STOP, f"refusing feature name {name!r}",
            __version__, environment_label(),
        )]
    target = worktree_path(project_root, clean, env)
    if not target.is_dir():
        return [Result(
            "feature.worktree-missing", FAIL, STOP,
            f"no worktree at {target}; start one with `openready feature start`",
            __version__, environment_label(),
        )]

    config = project_config(project_root)
    tier = tier or str(config.get("risk_tier") or "T1")
    if tier not in TIER_CHECKS:
        return [Result(
            "feature.tier", FAIL, STOP,
            f"unknown risk tier {tier!r}; expected one of {TIERS}",
            __version__, environment_label(),
        )]

    results: List[Result] = []

    # The project's own suite, in a scrubbed environment, always.
    suite = verify_mod.restricted_build(target)
    failing = [r for r in suite if r.status == FAIL]
    if failing:
        results.append(Result(
            "feature.tests", FAIL, STOP,
            f"the project's own suite does not pass in {target}: {failing[0].message[:160]}",
            __version__, environment_label(), evidence_path=str(target),
            limitations=[LIMITATION],
        ))
    else:
        results.extend(suite)
        results.append(Result(
            "feature.tests", PASS, INFO,
            f"the project's own suite ran in the scrubbed environment of {target}",
            __version__, environment_label(), evidence_path=str(target),
            limitations=[LIMITATION],
        ))

    for check in TIER_CHECKS[tier]:
        if check == "doctor":
            results.extend(_captured(doctor_mod.run, target, json_output=True))
        elif check == "ledger":
            document = ledger_mod.build(target)
            results.extend(ledger_mod.results(document))
        elif check == "candidate-plan":
            from . import candidate as candidate_mod

            plan = candidate_mod.plan(target, str(config.get("project_id") or ""))
            results.append(Result(
                "feature.candidate-plan", PASS if plan["included"] else NOT_RUN, INFO,
                f"tier {tier} would export {len(plan['included'])} of "
                f"{len(plan['included']) + len(plan['excluded'])} file(s) from this worktree "
                f"(plan only -- nothing was written)",
                __version__, environment_label(),
                limitations=[
                    "A plan is not an export: no candidate was written and no STOP was "
                    "evaluated.", LIMITATION,
                ],
            ))

    results.append(Result(
        "feature.tier", PASS, INFO,
        f"risk tier {tier} ran the project suite plus {list(TIER_CHECKS[tier]) or ['nothing else']}",
        __version__, environment_label(), required=False,
        limitations=["A tier changes how much *else* is checked. It never turns the project's "
                     "own suite off.", LIMITATION],
    ))
    return results


def _captured(func, *args, **kwargs) -> List[Result]:
    """Run a command that prints, and keep its results rather than its output.

    Used so that a tier can compose existing checks without a second implementation of
    them -- the alternative is a copy that drifts.
    """
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        func(*args, **kwargs)
    text = buffer.getvalue()
    try:
        payload = json.loads(text)
    except ValueError:
        return [Result(
            "feature.check-unparsed", NOT_RUN, REVIEW,
            f"an inner check ({getattr(func, '__module__', '?')}) printed something that is not "
            f"JSON, so its results are unrun rather than assumed", __version__,
            environment_label(), required=False, enforcement=NOT_ENFORCED,
        )]
    return [_result_from(record) for record in payload.get("results", [])]


def _result_from(record: Dict[str, object]) -> Result:
    from .status import NOT_RUN as _NOT_RUN

    return Result(
        str(record["check_id"]), str(record["status"]), str(record["severity"]),
        str(record["message"]), str(record.get("tool_version") or __version__),
        str(record.get("environment") or environment_label()),
        required=str(record["status"]) != _NOT_RUN,
        enforcement=record.get("enforcement"),  # type: ignore[arg-type]
        limitations=list(record.get("limitations", [])),  # type: ignore[arg-type]
    )
