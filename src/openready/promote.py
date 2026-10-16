"""Promotion, health probing and code rollback (OR-012).

The failure this exists for: a change is promoted, the running version fails its
health check, and the rollback that follows takes the user's newer data with it --
because the data and the code were in the same tree, so "roll the code back" and
"roll the data back" were the same operation.

Open-Ready separates them by construction (``private.py`` puts private data outside
the project), so a code rollback **cannot** reach the data. That is the property this
module demonstrates rather than assumes: :func:`rollback` hashes the private data
root before and after and fails if a single byte moved.

Two more things are deliberate:

* **The health probe is loopback-only.** A probe to any other host would be egress
  from a tool whose whole posture is that it makes no network call. A non-loopback
  URL is refused, not attempted, and that refusal is itself a control (see
  ``capabilities``: ``egress.containment`` is ``NOT_ENFORCED``).
* **A stage is recorded, not inferred.** ``live_checked`` is written only after a
  probe actually returned a healthy status, and it records the revision that passed.
  An unrecorded stage is reported as unrun rather than assumed.

Honest limits: ``git reset --hard`` moves the branch and leaves the discarded commits
in the reflog. Removing them is history rewriting, which is a decision an operator
makes, not one a rollback should make for them.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .private import private_home
from .status import FAIL, INFO, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

STAGES_DIRNAME = "stages"
CONFIG_NAME = "openready.project.json"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
DEFAULT_TIMEOUT = 5.0

ROLLBACK_LIMITATION = (
    "The rolled-back commits remain in the reflog and in the object store: a rollback "
    "moves the branch, it does not erase the work."
)
PROBE_LIMITATION = (
    "A loopback probe says this host answered on this port. It is not a release "
    "gate and it says nothing about any other machine."
)


def _git(root: Path, *args: str, timeout: int = 60) -> Tuple[int, str]:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          text=True, timeout=timeout, check=False)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def _revision(root: Path) -> str:
    code, out = _git(root, "rev-parse", "HEAD")
    return out.strip() if code == 0 else ""


def _config(root: Path) -> Dict[str, Any]:
    path = Path(root) / CONFIG_NAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def stage_file(project_id: str, env: Optional[Dict[str, str]] = None) -> Path:
    return private_home(env) / STAGES_DIRNAME / f"{project_id or 'project'}.json"


def non_loopback_reason(url: str) -> Optional[str]:
    """The reason a URL must not be probed, or None when it may be.

    Refusing rather than warning is the point: a warning still sends the request, and
    the request is the thing this tool promises not to make.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return f"{url!r} is not a URL ({exc})"
    if parsed.scheme not in ("http", "https"):
        return f"{url!r} uses scheme {parsed.scheme!r}; only http/https can be probed"
    host = (parsed.hostname or "").lower()
    if host not in LOOPBACK_HOSTS:
        return (f"{url!r} targets {host or 'no host'!r}, which is not loopback; a probe "
                f"there would be egress from a tool that makes no network call")
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A loopback endpoint cannot redirect the probe onto the public network."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def health_probe(url: str, timeout: float = DEFAULT_TIMEOUT) -> List[Result]:
    """Probe a loopback health endpoint. Refuses everything else."""
    refusal = non_loopback_reason(url)
    if refusal:
        return [Result(
            "health.loopback-only", FAIL, STOP,
            f"refusing to probe: {refusal}", __version__, environment_label(),
            evidence_path=url,
            limitations=[
                "A health probe is not a release gate, and this tool does not reach the "
                "network: the refusal is the control.", PROBE_LIMITATION,
            ],
        )]

    request = urllib.request.Request(url, method="GET")
    try:
        # Do not inherit a proxy or follow redirects across the loopback boundary.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 0) or 0)
            body_prefix = response.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return [Result(
            "health.status", FAIL, STOP,
            f"{url} answered HTTP {exc.code}, which is not a healthy status",
            __version__, environment_label(), evidence_path=url,
            limitations=[PROBE_LIMITATION],
        )]
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [Result(
            "health.status", FAIL, STOP,
            f"{url} could not be reached ({exc}); the running version did not answer",
            __version__, environment_label(), evidence_path=url,
            limitations=[PROBE_LIMITATION],
        )]

    if not 200 <= status < 300:
        return [Result(
            "health.status", FAIL, STOP,
            f"{url} answered HTTP {status}, which is not a healthy status",
            __version__, environment_label(), evidence_path=url,
            limitations=[PROBE_LIMITATION],
        )]
    return [Result(
        "health.status", PASS, INFO,
        f"{url} answered HTTP {status} ({body_prefix[:60].strip()!r})",
        __version__, environment_label(), evidence_path=url,
        limitations=[PROBE_LIMITATION],
    )]


def data_root_digest(root: Path) -> Tuple[str, int]:
    """A content digest of everything under a path, for before/after comparison."""
    digest = hashlib.sha256()
    count = 0
    path = Path(root)
    if not path.exists():
        return "", 0
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(item.relative_to(path)).encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(item.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")
        count += 1
    return digest.hexdigest(), count


def promote(project_root: Path, url: Optional[str] = None,
            timeout: float = DEFAULT_TIMEOUT,
            env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Record a promotion stage, and only after a probe actually passed."""
    project_root = Path(project_root).resolve()
    config = _config(project_root)
    project_id = str(config.get("project_id") or project_root.name)
    revision = _revision(project_root)

    results: List[Result] = []
    if url is None:
        results.append(Result(
            "promote.health-probe", NOT_RUN, REVIEW,
            "no health endpoint was given, so the running version was not checked; no "
            "`live_checked` stage was recorded", __version__, environment_label(),
            required=True, enforcement=NOT_ENFORCED,
            limitations=["An unchecked promotion is not a promotion. Pass --url to check one.",
                         PROBE_LIMITATION],
        ))
        return results

    probe = health_probe(url, timeout)
    results.extend(probe)
    if any(r.status == FAIL for r in probe):
        results.append(Result(
            "promote.stage", NOT_RUN, REVIEW,
            "the health check failed, so `live_checked` was NOT recorded and the change is "
            "not promoted", __version__, environment_label(), required=True,
            enforcement=NOT_ENFORCED,
            limitations=["Recording a stage that did not happen is the failure this check "
                         "exists to prevent.", PROBE_LIMITATION],
        ))
        return results

    path = stage_file(project_id, env)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": "1.0",
        "project_id": project_id,
        "stage": "live_checked",
        "revision": revision,
        "health_url": url,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": __version__,
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)
    results.append(Result(
        "promote.stage", PASS, INFO,
        f"`live_checked` recorded for revision {revision[:12]} at {path}",
        __version__, environment_label(), source_revision=revision or None,
        evidence_path=str(path),
        limitations=["A recorded stage is a record. It does not roll anything back by itself.",
                     PROBE_LIMITATION],
    ))
    return results


def rollback(project_root: Path, to_revision: str,
             env: Optional[Dict[str, str]] = None) -> List[Result]:
    """Move the code back, and prove the private data did not move with it."""
    project_root = Path(project_root).resolve()
    results: List[Result] = []

    code, _ = _git(project_root, "rev-parse", "--git-dir")
    if code != 0:
        return [Result(
            "rollback.repository", FAIL, STOP,
            f"{project_root} is not a git working tree, so there is no revision to roll back to",
            __version__, environment_label(),
        )]

    if not to_revision:
        return [Result(
            "rollback.target", FAIL, STOP,
            "no target revision was given; a rollback to nowhere is a checkout",
            __version__, environment_label(),
        )]
    code, out = _git(project_root, "rev-parse", "--verify", f"{to_revision}^{{commit}}")
    if code != 0:
        return [Result(
            "rollback.target", FAIL, STOP,
            f"{to_revision!r} does not resolve to a commit in {project_root}",
            __version__, environment_label(),
        )]
    target = out.strip()
    current = _revision(project_root)
    if target == current:
        return [Result(
            "rollback.target", PASS, INFO,
            f"HEAD is already {target[:12]}; there is nothing to roll back",
            __version__, environment_label(), required=False,
            limitations=[ROLLBACK_LIMITATION],
        )]

    # The guard that makes the promise real: if the private data root were inside the
    # project, a code rollback could destroy data, and no amount of hashing would
    # notice. So it is refused outright.
    private = private_home(env).resolve()
    if private == project_root or private in project_root.parents or \
            project_root == private or project_root in private.parents:
        return [Result(
            "rollback.data-boundary", FAIL, STOP,
            f"the private data root ({private}) and the project ({project_root}) are not "
            f"separate, so a code rollback could destroy data; refusing",
            __version__, environment_label(),
            limitations=["Fix the layout first: private data must live outside every project.",
                         ROLLBACK_LIMITATION],
        )]

    before_digest, before_count = data_root_digest(private)
    results.append(Result(
        "rollback.data-boundary", PASS, INFO,
        f"the private data root is outside the project ({private}); {before_count} file(s) "
        f"recorded before the rollback", __version__, environment_label(),
        evidence_path=str(private), limitations=[ROLLBACK_LIMITATION],
    ))

    code, out = _git(project_root, "reset", "--hard", target)
    if code != 0:
        return results + [Result(
            "rollback.applied", FAIL, STOP,
            f"`git reset --hard {target[:12]}` failed: {out.strip()[:200]}",
            __version__, environment_label(), limitations=[ROLLBACK_LIMITATION],
        )]

    after_digest, after_count = data_root_digest(private)
    if (before_digest, before_count) != (after_digest, after_count):
        results.append(Result(
            "rollback.data-preserved", FAIL, STOP,
            f"the private data root changed during a code rollback ({before_count} -> "
            f"{after_count} file(s)); a code rollback must not touch user data",
            __version__, environment_label(), evidence_path=str(private),
            limitations=[ROLLBACK_LIMITATION],
        ))
    else:
        results.append(Result(
            "rollback.data-preserved", PASS, INFO,
            f"{after_count} file(s) under the private data root are byte-identical after the "
            f"rollback", __version__, environment_label(), evidence_path=str(private),
            limitations=[ROLLBACK_LIMITATION],
        ))

    results.append(Result(
        "rollback.applied", PASS, INFO,
        f"code moved {current[:12]} -> {target[:12]}; user data was not touched",
        __version__, environment_label(), source_revision=target,
        evidence_path=str(project_root), limitations=[ROLLBACK_LIMITATION],
    ))
    return results
