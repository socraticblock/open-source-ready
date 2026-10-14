"""Execution harness for acceptance tests A01-A33.

Why this exists
---------------

The project's work order lists thirty-three acceptance tests. At the time it was written,
most of their rows read ``INSPECTED`` -- a
reading of the source, not an executed test -- and T1 exists to replace every one
of those readings with a measurement.

So this module does the two things a reading cannot:

* it **runs** the tool as a real command (``python3 -m openready``) in a
  **disposable repository** it built itself, and records the real exit code and
  the real output rather than a claim about them;
* it **labels honestly**. ``NOT_RUN``, ``NOT_TESTED`` and ``NOT_ENFORCED`` are
  first-class results here, not failures to be smoothed over. A row may only be
  ``PASS`` because a command actually returned what the requirement asked for.

Nothing in this harness touches a real project, a real credential or a real
repository. Every sandbox lives under the session scratch directory, which is
pruned; every environment root the tool reads is redirected into that sandbox by
an explicit ``OPENREADY_*`` variable, so a test cannot read or write the operator's
private data root even by accident.

The harness never makes a network call. ``A11`` measures the builder's credential
by reading the local ``gh`` configuration file rather than asking GitHub, because
asking GitHub would itself be egress.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from openready import __version__  # noqa: E402
from openready import scan  # noqa: E402
from openready.capabilities import environment_label  # noqa: E402


def redact(text: str) -> str:
    """Everything this suite writes to its record goes through here first.

    The record contains the sandbox paths the run happened in and quotes of
    deliberately credential-shaped fixtures. Written verbatim it would be a deny-list
    hit in this repository's own object store, which would make the tool unable to
    export itself -- the tool's own gate refuses the very file that reports its
    results. `~` therefore stands for this machine's home directory in every path
    this module writes, and a credential shape is written as `<redacted>`.

    This is redaction, not removal: what was found, where, and what it was found *in*
    all survive.
    """
    return scan.redact_for_evidence(text.encode("utf-8")).decode("utf-8", "replace")

# --- result vocabulary --------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
NEEDS_HUMAN = "NEEDS_HUMAN"
NOT_RUN = "NOT_RUN"
NOT_TESTED = "NOT_TESTED"
NOT_ENFORCED = "NOT_ENFORCED"
NOT_APPLICABLE = "NOT_APPLICABLE"
ROW_RESULTS = (PASS, FAIL, NEEDS_HUMAN, NOT_RUN, NOT_TESTED, NOT_ENFORCED,
               NOT_APPLICABLE)

#: Rows that are not green and are not a defect either -- they are the honest
#: recorded limits. Kept separate so a report can never blur them into a PASS.
UNVERIFIED_RESULTS = (NOT_RUN, NOT_TESTED, NOT_ENFORCED, NEEDS_HUMAN)

SCRATCH_ROOT = Path(os.environ.get(
    "OPENREADY_ACCEPTANCE_SCRATCH",
    Path.home() / ".cache" / "openready-acceptance",
)) / "acceptance"


@dataclass
class Outcome:
    """One acceptance test's measured result."""

    id: str
    title: str
    stage: str
    result: str
    command: str
    observed: str
    task_id: str = ""
    limitations: List[str] = field(default_factory=list)
    requirement: str = ""
    evidence_path: str = ""
    candidate_digest: str = ""
    sandbox: str = ""

    def as_dict(self, source_revision: str) -> Dict[str, Any]:
        """Exactly the evidence fields the specification's §"Required evidence
        fields" asks for, plus the ones a reader needs to re-run it.

        Every string goes through :func:`redact`: this record is scanned by the tool's
        own deny-list and, in the normal case, exported as part of this repository.
        """
        return {
            "id": self.id,
            "task_id": self.task_id,
            "title": redact(self.title),
            "stage": self.stage,
            "requirement": redact(self.requirement),
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "runner_os": environment_label(),
            "tool_version": __version__,
            "source_revision": source_revision,
            "candidate_digest": self.candidate_digest or None,
            "command": redact(self.command),
            "result": self.result,
            "observed_denial_or_outcome": redact(self.observed),
            "limitations": [redact(item) for item in self.limitations],
            "evidence_path": redact(self.evidence_path),
            "sandbox": redact(self.sandbox),
        }


class Sandbox:
    """A disposable environment: its own project, its own private data roots.

    Every ``OPENREADY_*`` variable the tool reads is redirected here. ``HOME`` is
    deliberately left alone: git needs the operator's identity, and rewriting
    ``HOME`` would change which git configuration the tool sees, which would make
    the measurement about the harness rather than about the tool.
    """

    def __init__(self, test_id: str, root: Optional[Path] = None) -> None:
        self.test_id = test_id
        self.root = Path(root) if root else SCRATCH_ROOT / f"{test_id}-{uuid.uuid4().hex[:8]}"
        self.private = self.root / "private"
        self.bin = self.root / "bin"
        for path in (self.root, self.private, self.bin):
            path.mkdir(parents=True, exist_ok=True)
        self.commands: List[str] = []

    # -- environment -----------------------------------------------------------

    def env(self, **extra: str) -> Dict[str, str]:
        env = dict(os.environ)
        env.update({
            "PYTHONPATH": str(SRC),
            "OPENREADY_PRIVATE_HOME": str(self.private),
            "OPENREADY_POLICY_HOME": str(self.private),
            "OPENREADY_AUDIT_HOME": str(self.private),
            "OPENREADY_APPROVAL_HOME": str(self.private / "approvals"),
            "OPENREADY_LIMITS_SCRATCH": str(self.private),
            # git must not inherit a global template that installs hooks; and the
            # sandbox must never be pushed anywhere.
            "GIT_CONFIG_NOSYSTEM": "1",
        })
        env.pop("OPENREADY_ACCEPTANCE_SCRATCH", None)
        env.update({k: v for k, v in extra.items() if v is not None})
        return env

    # -- commands --------------------------------------------------------------

    def run(self, argv: Sequence[str], cwd: Optional[Path] = None,
            env_extra: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        """Run a real command. Returns (exit code, combined output)."""
        shown = " ".join(argv)
        self.commands.append(shown)
        done = subprocess.run(
            list(argv), cwd=str(cwd or self.root), env=self.env(**(env_extra or {})),
            capture_output=True, text=True, timeout=180, check=False,
        )
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    def cli(self, *args: str, cwd: Optional[Path] = None,
            env_extra: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        """The tool as a stranger would invoke it: a real subprocess, no shim."""
        return self.run([sys.executable, "-m", "openready", *args], cwd=cwd,
                        env_extra=env_extra)

    def cli_json(self, *args: str) -> Tuple[int, Dict[str, Any]]:
        code, out = self.cli(*args, "--json")
        try:
            return code, json.loads(out)
        except ValueError:
            return code, {}

    def git(self, *args: str, cwd: Optional[Path] = None) -> Tuple[int, str]:
        return self.run(["git", *args], cwd=cwd)

    def publisher(self, *args: str) -> Tuple[int, str]:
        return self.run([sys.executable, "-m", "openready.publisher", *args])

    def capabilities_json(self, path: Optional[Path] = None) -> Tuple[int, Dict[str, Any]]:
        args = ["capabilities"]
        if path is not None:
            args += ["--path", str(path)]
        return self.cli_json(*args)

    def python_snippet(self, code: str, *args: str) -> Tuple[int, str]:
        """Run a snippet against the tool's own modules inside this sandbox's environment.

        Used where the *owner* side of an owner act is exercised (recording an
        approval, for instance): the tool exposes no CLI verb for it, and it should
        not, because a builder-side verb that granted approval would defeat the
        control it exists to provide.
        """
        return self.run([sys.executable, "-c", code, *args])

    # -- repository helpers ----------------------------------------------------

    def repo(self, name: str = "outer", files: Optional[Dict[str, str]] = None,
             commit: bool = True) -> Path:
        """A real repository that already has content -- the house rule (§7.1) is
        that a control is proven in a repo that is not empty."""
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main", cwd=path)
        self.git("config", "user.email", "socraticblock@gmail.com", cwd=path)
        self.git("config", "user.name", "Open-Ready Acceptance", cwd=path)
        for rel, body in (files or {"README.md": "# existing content\n"}).items():
            target = path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        self.git("add", "-A", cwd=path)
        if commit:
            self.git("commit", "-qm", "pre-existing content", cwd=path)
        return path

    def new_project(self, name: str = "proj", *extra: str) -> Tuple[Path, int, str]:
        path = self.root / name
        code, out = self.cli("new", "--path", str(path), *extra)
        return path, code, out

    def project_rev(self, path: Path) -> str:
        code, out = self.git("rev-parse", "HEAD", cwd=path)
        return out.strip() if code == 0 else ""

    def head_unchanged(self, path: Path, sentinel: str) -> bool:
        return self.project_rev(path) == sentinel and bool(sentinel)

    def write(self, path: Path, rel: str, body: str) -> Path:
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return target

    def tree_hashes(self, path: Path) -> Dict[str, str]:
        """Hash every file under a path, ignoring ``.git`` (linked worktrees write
        a ``.git`` file at the project root; that is bookkeeping, not a change)."""
        import hashlib

        out: Dict[str, str] = {}
        for where, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in (".git", "__pycache__"))
            for name in sorted(names):
                if name == ".git":
                    continue
                target = Path(where) / name
                try:
                    out[str(target.relative_to(path))] = hashlib.sha256(
                        target.read_bytes()).hexdigest()
                except OSError:
                    out[str(target.relative_to(path))] = "<unreadable>"
        return out

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


# --- registry of acceptance tests --------------------------------------------

#: A01..A33, in the order the specification lists them. Each entry is
#: (id, stage, one-line requirement, callable). The callable receives a Sandbox
#: and returns an Outcome.
TESTS: List[Tuple[str, str, str, Callable[[Sandbox], Outcome]]] = []


def acceptance(test_id: str, stage: str, requirement: str):
    def register(func: Callable[[Sandbox], Outcome]):
        TESTS.append((test_id, stage, requirement, func))
        return func
    return register


def outcome(test_id: str, stage: str, requirement: str, sandbox: Sandbox,
            result: str, observed: str, *, task_id: str = "",
            limitations: Optional[List[str]] = None,
            candidate_digest: str = "") -> Outcome:
    if result not in ROW_RESULTS:
        raise ValueError(f"{test_id}: {result!r} is not an acceptance result")
    if result == PASS and not observed.strip():
        raise ValueError(f"{test_id}: a PASS must state what was observed")
    return Outcome(
        id=test_id, title=requirement, stage=stage, result=result,
        command="\n".join(sandbox.commands), observed=observed, task_id=task_id,
        limitations=limitations or [], requirement=requirement,
        evidence_path=str(sandbox.root), candidate_digest=candidate_digest,
        sandbox=str(sandbox.root),
    )


# --- assertions that make a row honest ---------------------------------------

class AcceptanceFailure(AssertionError):
    """A measured contradiction with the requirement -- never a reason for NOT_RUN.

    The distinction matters: ``NOT_RUN`` means "this was not measured", while a
    raised ``AcceptanceFailure`` means "this was measured and it did not hold".
    Collapsing the two is how a suite goes green while the product does not.
    """


def require(condition: Any, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def section(text: str) -> str:
    """Extract the block for one check id from the tool's human output."""
    lines = text.splitlines()
    out: List[str] = []
    capturing = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(text) or f" {text}:" in stripped:
            capturing = True
        elif capturing and line and not line.startswith("        "):
            break
        if capturing:
            out.append(line)
    return "\n".join(out)


def source_of(module: str) -> str:
    return (SRC / "openready" / module).read_text(encoding="utf-8")


def all_source() -> Dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8", errors="replace")
            for p in sorted((SRC / "openready").glob("*.py"))}


@contextlib.contextmanager
def capture_stdout():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        yield buffer


def timed(func: Callable[[], Any]) -> Tuple[Any, float]:
    start = time.time()
    value = func()
    return value, time.time() - start
