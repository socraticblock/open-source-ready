"""Private project registry (OR-013, the index half).

Why this exists: the CLI contract says ``status`` reads "local private registry
metadata", and several commands take ``--project ID``. Neither was possible, because
nothing recorded the projects that had been created -- so every command took a path,
and a project had no name you could use.

Two rules this module holds to:

1. **Metadata only.** A project id, its path, its risk tier, when it was created and
   whether it has a baseline commit. No project contents, no private data, no
   documents. The registry lives in the private runtime data root, outside every
   project and outside any git working tree.
2. **An index is not an authority.** The project's own ``openready.project.json`` is
   authoritative. The registry is a convenience that can be deleted and rebuilt; when
   the two disagree the disagreement is reported (:func:`resolve`), never resolved by
   silently preferring one.

A registry that cannot be read is never silently replaced: :func:`record` refuses to
write, because "repair a JSON file" is a smaller problem than "silently lose every
other project's entry".
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from . import private as private_mod
from .status import FAIL, INFO, NOT_RUN, PASS, REVIEW, STOP, Result

REGISTRY_NAME = "registry.json"
SCHEMA_VERSION = "1.0"

LIMITATION = (
    "The registry holds metadata only -- never project contents, never private data. "
    "It is an index, not an authority: the project's own project contract remains "
    "authoritative, and deleting this file loses convenience, not projects."
)


def registry_file(env: Optional[Dict[str, str]] = None) -> Path:
    return private_mod.private_home(env) / REGISTRY_NAME


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load(env: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, Any], List[Result]]:
    """Read the registry. Returns (document, problems); problems block any write."""
    path = registry_file(env)
    empty: Dict[str, Any] = {"schema_version": SCHEMA_VERSION, "projects": {}}
    if not path.is_file():
        return empty, []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return empty, [Result(
            "registry.unreadable", FAIL, REVIEW,
            f"{path} exists but could not be read ({exc}); nothing was overwritten and no "
            f"project was registered", __version__, "local", required=False,
            limitations=["Repair or remove that file, then run the command again. It is "
                         "never replaced automatically, because the other entries would go "
                         "with it.", LIMITATION],
        )]
    if not isinstance(document, dict) or not isinstance(document.get("projects"), dict):
        return empty, [Result(
            "registry.malformed", FAIL, REVIEW,
            f"{path} does not hold a registry object with a 'projects' map; nothing was "
            f"overwritten", __version__, "local", required=False,
            limitations=[LIMITATION],
        )]
    document.setdefault("schema_version", SCHEMA_VERSION)
    return document, []


def save(document: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Path:
    """Write the registry atomically, so a crash cannot leave it half-written."""
    path = registry_file(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)
    return path


def entry_for(project_id: str, path: Path, risk_tier: str, committed: bool,
              version: str = __version__) -> Dict[str, Any]:
    return {
        "project_id": project_id,
        "path": str(Path(path).resolve()),
        "risk_tier": risk_tier,
        "created_at": _now(),
        "openready_version": version,
        "baseline_commit": bool(committed),
    }


def record(project_id: str, path: Path, risk_tier: str, committed: bool,
           env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Add or update one entry. Refuses to write a registry it could not read."""
    document, problems = load(env)
    if problems:
        return problems
    document["projects"][project_id] = entry_for(project_id, path, risk_tier, committed)
    save(document, env)
    return [Result(
        "registry.recorded", PASS, INFO,
        f"recorded {project_id} -> {Path(path).resolve()} in {registry_file(env)}",
        __version__, "local", limitations=[LIMITATION],
    )]


def find(project_id: str, env: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    document, _ = load(env)
    found = document["projects"].get(project_id)
    return found if isinstance(found, dict) else None


def entries(env: Optional[Dict[str, str]] = None) -> Tuple[List[Dict[str, Any]], List[Result]]:
    document, problems = load(env)
    if problems:
        return [], problems
    rows = [e for e in document["projects"].values() if isinstance(e, dict)]
    return sorted(rows, key=lambda e: str(e.get("project_id", ""))), []


def summary_results(env: Optional[Dict[str, str]] = None) -> List[Result]:
    """What ``status`` reports when asked for the portfolio rather than one project."""
    rows, problems = entries(env)
    if problems:
        return problems
    if not rows:
        return [Result(
            "registry.empty", NOT_RUN, REVIEW,
            f"no projects are registered in {registry_file(env)}; this reports nothing "
            f"about whether any project exists", __version__, "local",
            limitations=[LIMITATION],
        )]
    return [Result(
        "registry.projects", PASS, INFO,
        f"{len(rows)} registered project(s) at {registry_file(env)}", __version__, "local",
        limitations=[LIMITATION],
    )]


def resolve(project_id: str, env: Optional[Dict[str, str]] = None) -> Tuple[Optional[Path], List[Result]]:
    """Turn a registered project id into a path, reporting every disagreement found."""
    found = find(project_id, env)
    if found is None:
        return None, [Result(
            "registry.unknown-project", FAIL, STOP,
            f"no project with id {project_id!r} is registered in {registry_file(env)}; "
            f"registration happens when a project is created with `openready new` or "
            f"adopted with `openready init --adopt`", __version__, "local",
            limitations=[LIMITATION],
        )]

    path = Path(str(found.get("path", "")))
    results: List[Result] = []
    if not path.is_dir() or not (path / "openready.project.json").is_file():
        return None, [Result(
            "registry.path-missing", FAIL, STOP,
            f"{project_id!r} is registered at {path}, which no longer holds a project",
            __version__, "local",
            limitations=["The registry is an index and was not updated: a project that moved "
                         "is re-registered by running `openready init --adopt` at its new "
                         "location, which the registry records rather than repairs.",
                         LIMITATION],
        )]

    try:
        config = json.loads((path / "openready.project.json").read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return None, [Result(
            "registry.config-unreadable", FAIL, STOP,
            f"{path}/openready.project.json could not be read ({exc})", __version__, "local",
        )]

    declared = str(config.get("project_id", ""))
    if declared != project_id:
        results.append(Result(
            "registry.id-mismatch", FAIL, REVIEW,
            f"{path} declares project id {declared!r} but is registered as {project_id!r}; "
            f"the project contract is authoritative and the registry entry is stale",
            __version__, "local", required=False,
            limitations=[LIMITATION],
        ))
    tier = config.get("risk_tier")
    if tier and found.get("risk_tier") and tier != found.get("risk_tier"):
        results.append(Result(
            "registry.tier-drift", NOT_RUN, REVIEW,
            f"{project_id!r} is registered at tier {found.get('risk_tier')} but its contract "
            f"says {tier}; the contract wins", __version__, "local", required=False,
            limitations=[LIMITATION],
        ))
    results.append(Result(
        "registry.resolved", PASS, INFO,
        f"{project_id!r} resolves to {path}", __version__, "local", limitations=[LIMITATION],
    ))
    return path, results
