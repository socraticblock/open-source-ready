"""Host and fleet capability detection (backlog task OR-002).

Principle: **detect, never assume.** The handoff says the specification must not
guess the owner's OS or fleet architecture, and must report a protection as
``NOT_ENFORCED`` or ``NOT_TESTED`` rather than implying it exists.

One deliberate omission: this module makes **no network call**. Probing reachability
would itself be the egress it is trying to measure, which the handoff forbids
("no silent internet connections"). Egress containment is therefore reported as
``NOT_ENFORCED`` with the reason recorded, not tested.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

CAPABILITY_ENFORCEMENTS = ("SUPPORTED", "NOT_ENFORCED", "NOT_TESTED", "UNKNOWN")


@dataclass
class Capability:
    """One detected capability, with the evidence that produced it."""

    capability_id: str
    value: object
    evidence: str
    enforcement: str = "UNKNOWN"
    note: str = ""

    def as_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {
            "capability_id": self.capability_id,
            "value": self.value,
            "evidence": self.evidence,
            "enforcement": self.enforcement,
        }
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class HostReport:
    capabilities: List[Capability] = field(default_factory=list)

    def get(self, capability_id: str) -> Optional[Capability]:
        for c in self.capabilities:
            if c.capability_id == capability_id:
                return c
        return None

    def as_dict(self) -> Dict[str, object]:
        return {"capabilities": [c.as_dict() for c in self.capabilities]}


def _run(args: List[str], timeout: int = 8) -> Optional[str]:
    """Run a read-only probe. Returns stripped stdout, or None on any failure."""
    try:
        done = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.strip()


def is_wsl() -> bool:
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False


def _credential_indicators() -> Dict[str, bool]:
    """Presence only. Values are never read, logged or returned."""
    home = Path.home()
    return {
        "GH_TOKEN env set": bool(os.environ.get("GH_TOKEN")),
        "GITHUB_TOKEN env set": bool(os.environ.get("GITHUB_TOKEN")),
        "ssh private key present": any(
            (home / ".ssh" / n).is_file()
            for n in ("id_rsa", "id_ed25519", "id_ecdsa")
        ),
        "git credential store present": (home / ".git-credentials").is_file(),
        "gh CLI credential file present": (home / ".config" / "gh" / "hosts.yml").is_file(),
    }


def _sandbox_facilities() -> Dict[str, Optional[str]]:
    found: Dict[str, Optional[str]] = {}
    for tool in ("bwrap", "firejail", "nsjail", "unshare", "docker", "podman"):
        found[tool] = shutil.which(tool)
    return found


def _unprivileged_userns() -> str:
    for probe, pattern in (
        (Path("/proc/sys/user/max_user_namespaces"), None),
        (Path("/proc/sys/kernel/unprivileged_userns_clone"), "1"),
    ):
        try:
            value = probe.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if pattern is None:
            return f"{probe.name}={value}"
        return f"{probe.name}={value}"
    return "no userns sysctl readable"


def detect(root: Optional[Path] = None) -> HostReport:
    """Detect host and fleet facts. Read-only; never touches the network."""
    report = HostReport()
    add = report.capabilities.append

    uname = platform.uname()
    add(Capability(
        "host.os", f"{uname.system} {uname.release} ({uname.machine})",
        "platform.uname()", "SUPPORTED",
    ))
    add(Capability(
        "host.wsl", is_wsl(), "reading /proc/version for 'microsoft'", "SUPPORTED",
        "WSL2: OS sandbox facilities and file permissions differ from a native Linux host.",
    ))
    add(Capability(
        "host.python", f"{platform.python_version()} ({sys.executable})",
        "sys.executable", "SUPPORTED",
    ))

    for tool in ("git", "node", "python3"):
        path = shutil.which(tool)
        version = _run([tool, "--version"]) if path else None
        add(Capability(
            f"tool.{tool}", version or "absent",
            f"shutil.which + `{tool} --version`" if path else "shutil.which",
            "SUPPORTED" if path else "NOT_APPLICABLE",
        ))

    facilities = _sandbox_facilities()
    present = [name for name, path in facilities.items() if path]
    add(Capability(
        "host.isolation-tools", present,
        "shutil.which over bwrap/firejail/nsjail/unshare/docker/podman",
        "SUPPORTED" if present else "NOT_TESTED",
        "A binary being present is not evidence it isolates anything. No isolation "
        "was exercised, so untrusted code must not be run on this host until a "
        "denial is actually demonstrated (acceptance test A23).",
    ))
    add(Capability(
        "host.user-namespaces", _unprivileged_userns(),
        "reading /proc/sys/user/max_user_namespaces", "NOT_TESTED",
        "Reading the sysctl does not prove an unprivileged namespace can be created.",
    ))

    creds = _credential_indicators()
    add(Capability(
        "secrets.credentials-present", creds,
        "existence checks only -- no value was read",
        "SUPPORTED",
        "A builder with these present can reach services. Separating publisher "
        "credentials from builder credentials is not implemented (see "
        "trust.publisher-separation).",
    ))

    add(Capability(
        "trust.publisher-separation", False,
        "no separate publisher principal exists in this implementation",
        "NOT_ENFORCED",
        "ADR-002 requires a publisher distinct from builder and verifier. Until it "
        "exists, publication must stay a manual owner action outside this tool.",
    ))
    add(Capability(
        "egress.containment", "unknown",
        "not probed -- probing reachability would itself be egress",
        "NOT_ENFORCED",
        "The specification's confidentiality claim depends on this. With broad "
        "builder read access plus unrestricted network, private-data containment "
        "cannot be promised; this must be reported, not hidden.",
    ))

    home = Path.home()
    add(Capability(
        "fleet.home", str(home), "$HOME", "SUPPORTED",
    ))
    hermes = home / ".hermes"
    profiles = sorted(p.name for p in (hermes / "profiles").glob("*") if p.is_dir())
    add(Capability(
        "fleet.profiles", profiles or "none detected",
        f"listing {hermes / 'profiles'}", "SUPPORTED" if profiles else "NOT_TESTED",
    ))
    for label, path in (
        ("gateway_state", hermes / "gateway_state.json"),
        ("scripts_dir", hermes / "scripts"),
        ("canonical_skills_dir", hermes / "skills"),
        ("cron_dir", hermes / "cron"),
    ):
        add(Capability(
            f"fleet.{label}", path.exists(), f"existence check on {path}",
            "SUPPORTED",
        ))

    if root is not None:
        add(Capability(
            "project.root", str(root), "the path this command was given",
            "SUPPORTED",
        ))
        add(Capability(
            "project.inside-git-checkout", enclosing_checkout(Path(root)),
            "walking parent directories for .git", "SUPPORTED",
            "A project created inside a published checkout inherits that checkout's "
            "publication surface. See the encloser check in doctor.",
        ))
        add(Capability(
            "project.declared-languages", _declared_languages(Path(root)),
            f"reading languages from {Path(root) / 'openready.project.json'}",
            "SUPPORTED" if _declared_languages(Path(root)) else "NOT_TESTED",
            "The policy is language-neutral: it never inspects language-specific files, so a "
            "new language needs no policy change. What does vary per language is whether this "
            "host can run the project's own tests, reported below.",
        ))
        for language, runners in sorted(_language_runners(Path(root)).items()):
            found = [runner for runner in runners if shutil.which(runner)]
            add(Capability(
                f"language.{language}.runner", found or "none found",
                f"shutil.which over {list(runners)}", "SUPPORTED" if found else "NOT_TESTED",
                None if found else
                f"No runner for {language!r} was found on this host, so the project's own tests "
                f"cannot be run here. The policy still applies unchanged.",
            ))

    # Platform variance is reported per platform, never assumed: the contracts are
    # OS-neutral by construction, which is a different claim from being tested on
    # three operating systems.
    add(Capability(
        "os.cross-platform-tested", [sys.platform],
        "the platforms a runner has actually executed on",
        "NOT_TESTED",
        "Only this platform has a runner. macOS and Windows are untested; per-OS data "
        "roots come from private.data_root, and unsupported protections are reported "
        "per-OS rather than promised (acceptance test A32).",
    ))
    add(Capability(
        "os.data-roots", sorted(_data_root_kinds()),
        "resolving the per-OS application-data directory for linux, darwin and win32",
        "SUPPORTED",
        "Resolving the path is not the same as running on that platform.",
    ))
    return report


def _declared_languages(root: Path) -> List[str]:
    path = Path(root) / "openready.project.json"
    if not path.is_file():
        return []
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    languages = config.get("languages")
    return [str(item) for item in languages] if isinstance(languages, list) else []


#: Runner binaries per language. The policy itself is language-neutral; this table
#: exists only so the tool can say whether *this host* could run a project's tests.
_LANGUAGE_RUNNERS: Dict[str, Tuple[str, ...]] = {
    "python": ("python3",),
    "node": ("node", "npm"),
    "javascript": ("node", "npm"),
    "typescript": ("node", "npm"),
    "rust": ("cargo", "rustc"),
    "go": ("go",),
    "java": ("java", "mvn", "gradle"),
    "ruby": ("ruby",),
    "php": ("php",),
    "dotnet": ("dotnet",),
    "c": ("cc", "make"),
    "cpp": ("c++", "make"),
    "shell": ("sh",),
}


def _language_runners(root: Path) -> Dict[str, Tuple[str, ...]]:
    """Runners to look for, for the languages this project declares.

    An undeclared language is reported as ``generic`` with a NOT_TESTED outcome rather
    than being silently mapped onto Python -- assuming a language is how a
    language-neutral policy stops being one.
    """
    declared = _declared_languages(root)
    if not declared:
        return {}
    table: Dict[str, Tuple[str, ...]] = {}
    for language in declared:
        key = language.strip().lower()
        table[key] = _LANGUAGE_RUNNERS.get(key, ())
    return table


def _data_root_kinds() -> List[str]:
    """Which per-OS data roots this build can resolve. No filesystem is touched."""
    from .private import data_root

    kinds: List[str] = []
    for label, env in (("linux", {"XDG_DATA_HOME": ""}), ("darwin", {"OPENREADY_OS": "darwin"}),
                       ("win32", {"OPENREADY_OS": "win32"})):
        try:
            data_root({**env, "HOME": str(Path.home())})
            kinds.append(label)
        except Exception:  # noqa: BLE001 - a platform this build cannot resolve is a finding
            continue
    return kinds


def environment_label() -> str:
    """A short, non-identifying label for the machine a check ran on.

    Deliberately does NOT include a hostname, username or path: evidence travels
    into review artefacts and must not itself disclose the operator's machine.
    """
    import os

    uname = os.uname()
    return f"{uname.sysname.lower()}-{uname.machine}"


def enclosing_checkout(path: Path) -> Optional[str]:
    """The nearest ancestor that is a git working tree, if any (not counting self)."""
    for parent in Path(path).resolve().parents:
        if (parent / ".git").exists():
            return str(parent)
    return None


def git_remote(url_path: Optional[Path] = None) -> Optional[str]:
    if url_path is None:
        return None
    return _run(["git", "-C", str(url_path), "remote", "get-url", "origin"])


def repo_is_public(remote_url: str) -> Optional[bool]:
    """Best-effort, offline read of a *recorded* visibility. None when unknown.

    This deliberately does not call the network. It recognises GitHub URL shapes
    only, and returning None means "unknown", never "private".
    """
    match = re.match(r"(?:git@github\.com:|https://github\.com/)([^/]+)/([^/.]+?)(?:\.git)?$", remote_url)
    if not match:
        return None
    return None  # visibility is not encoded in a git remote; only the API knows
