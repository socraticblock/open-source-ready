"""Host-provider adapters (OR-026, OR-027).

Two adapters, the same shape:

* :class:`LocalGitProvider` -- fully exercised: it works against a bare repository
  the caller provides. It proves the round trip locally, which is the
  prerequisite for the GitHub adapter being more than a claim.
* :class:`GitHubProvider` -- makes no network call. It reads the local
  ``~/.config/gh/hosts.yml`` to learn the account and token kind, and any
  network-dependent operation is reported as ``NOT_TESTED`` with the reason
  recorded. The local read is the whole point: a tool that asked GitHub would
  itself be the egress it is trying to measure.

Three properties, each a check rather than a promise:

1. **Neither adapter can publish.** ``publish_capable()`` returns ``False`` for
   both, and :attr:`refused_verbs` lists the verbs that an owner, not a tool,
   would run. An adapter that published would be the failure this module exists
   to prevent.
2. **The interfaces are stable, the implementations are pluggable.** A new
   provider (GitLab, Gitea) is a new class with the same four methods, not a
   change to this file's contract.
3. **The network-free GitHub adapter does not pretend to know the visibility.**
   It returns ``None`` rather than guessing -- a guess, by the rule set, is
   "unknown", not "private".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .status import FAIL, INFO, NOT_ENFORCED, NOT_TESTED, PASS, REVIEW, STOP, Result

GH_HOSTS_FILE = Path.home() / ".config" / "gh" / "hosts.yml"

GITHUB_REFUSED = (
    "repo edit --visibility public",
    "repo create",
    "release create",
    "push",
)
LOCAL_REFUSED = ("push",)

LIMITATION = (
    "An adapter that could push would be the failure this module exists to prevent. The "
    "only verbs either adapter can do are read-only; a publication action is an owner act."
)


@dataclass
class Provider:
    kind: str
    target: str
    notes: List[str] = field(default_factory=list)

    def describe(self) -> Dict[str, Any]:
        return {"kind": self.kind, "target": self.target, "notes": list(self.notes)}

    def preflight(self) -> List[Result]:
        return [Result(
            f"provider.{self.kind}.preflight", NOT_TESTED, REVIEW,
            f"no preflight is implemented for {self.kind!r}; the local-git adapter is the "
            f"tested one, and the GitHub adapter is described only",
            __version__, environment_label(), required=True, enforcement=NOT_ENFORCED,
            limitations=[LIMITATION],
        )]

    def publish_capable(self) -> bool:
        return False

    def refused_verbs(self) -> Tuple[str, ...]:
        return ()


class LocalGitProvider(Provider):
    """A provider that works against a bare local repository. Tested in the suite."""

    def __init__(self, target: str) -> None:
        super().__init__(kind="localgit", target=target)
        path = Path(target).expanduser().resolve()
        self.path = path
        self.notes = [f"bare repository at {path}"]

    def preflight(self) -> List[Result]:
        path = self.path
        if not path.is_dir():
            return [Result(
                "provider.localgit.preflight", FAIL, STOP,
                f"{path} is not a directory, so the local adapter cannot reach it",
                __version__, environment_label(), limitations=[LIMITATION],
            )]
        head_dir = path / "HEAD"
        if not head_dir.is_file():
            return [Result(
                "provider.localgit.preflight", FAIL, STOP,
                f"{path} does not look like a git repository (no HEAD file at the root)",
                __version__, environment_label(), limitations=[LIMITATION],
            )]
        try:
            head = head_dir.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [Result(
                "provider.localgit.preflight", FAIL, STOP,
                f"HEAD at {path} is not readable: {exc}",
                __version__, environment_label(), limitations=[LIMITATION],
            )]
        if not re.search(r"^ref:\s*refs/heads/", head, re.M):
            return [Result(
                "provider.localgit.preflight", FAIL, STOP,
                f"{path} is a bare git repository but its HEAD is detached; create a default "
                f"branch (`git symbolic-ref HEAD refs/heads/main`) before using it as a target",
                __version__, environment_label(), limitations=[LIMITATION],
            )]
        return [Result(
            "provider.localgit.preflight", PASS, INFO,
            f"local bare repository at {path} is reachable and on a named branch",
            __version__, environment_label(), evidence_path=str(path),
            limitations=[LIMITATION],
        )]

    def refused_verbs(self) -> Tuple[str, ...]:
        return LOCAL_REFUSED


class GitHubProvider(Provider):
    """The network-free description of the GitHub side. NEVER opens a socket."""

    def __init__(self, target: str) -> None:
        super().__init__(kind="github", target=target)
        self.account, self.token_kind = _read_gh_hosts()
        self.notes = [
            f"target {target!r} (description only -- no network)",
            f"local gh config: account {self.account or 'unknown'}, token kind {self.token_kind or 'unknown'}",
        ]

    def preflight(self) -> List[Result]:
        results: List[Result] = [
            Result(
                "provider.github.no-network", PASS, INFO,
                "this adapter does not contact GitHub: it reads the local "
                "~/.config/gh/hosts.yml and reports what is known from the file alone",
                __version__, environment_label(), evidence_path=str(GH_HOSTS_FILE),
                limitations=[LIMITATION, "An adapter that asked GitHub would itself be the "
                                         "egress this tool promises not to make."],
            ),
        ]
        if not GH_HOSTS_FILE.is_file():
            results.append(Result(
                "provider.github.local-config", NOT_TESTED, REVIEW,
                f"no {GH_HOSTS_FILE} on this host, so the operator's account and token kind "
                f"are unknown. A real preflight would still not contact GitHub; it would "
                f"report this as unknown and stop.",
                __version__, environment_label(), required=False, enforcement=NOT_ENFORCED,
            ))
        else:
            results.append(Result(
                "provider.github.local-config", PASS if self.account else NOT_TESTED, INFO,
                f"account {self.account or 'unknown'}, token kind {self.token_kind or 'unknown'}",
                __version__, environment_label(), evidence_path=str(GH_HOSTS_FILE),
                limitations=[LIMITATION,
                             "A token kind is the prefix only (gho_, ghp_, etc.). The value "
                             "is never read here."],
            ))
        return results

    def refused_verbs(self) -> Tuple[str, ...]:
        return GITHUB_REFUSED


_GH_USER_RE = re.compile(r"^\s+user:\s*(\S+)", re.M)
_GH_TOKEN_RE = re.compile(r"oauth_token:\s*(gh[a-z]+)_")


def _read_gh_hosts() -> Tuple[Optional[str], Optional[str]]:
    if not GH_HOSTS_FILE.is_file():
        return None, None
    try:
        body = GH_HOSTS_FILE.read_text(encoding="utf-8")
    except OSError:
        return None, None
    user = _GH_USER_RE.search(body)
    token = _GH_TOKEN_RE.search(body)
    return (user.group(1) if user else None,
            (token.group(1) + "_") if token else None)


def provider_for(target: str) -> Provider:
    """One entry point: the right adapter for a target description.

    A path is a local bare repository. Anything else is treated as a GitHub
    description and answered from the local ``gh`` configuration. No network
    call is made in either branch.
    """
    if target.startswith(("http://", "https://", "git@", "ssh://")) and "github.com" in target:
        return GitHubProvider(target)
    return LocalGitProvider(target)


def list_adapters() -> List[Dict[str, Any]]:
    return [
        {"kind": "localgit", "description": "tested against a bare local repository"},
        {"kind": "github", "description": "describes the GitHub side from the local "
                                          "~/.config/gh/hosts.yml; makes no network call"},
    ]


def detect(root: Optional[Path] = None) -> List[Result]:
    """One result per adapter: what was tested, what was not, and why."""
    return [
        Result(
            "provider.localgit.tested", PASS, INFO,
            "the local-git adapter is exercised in the test suite against a real bare repository",
            __version__, environment_label(),
            limitations=[LIMITATION],
        ),
        Result(
            "provider.github.network-free", PASS, INFO,
            "the GitHub adapter makes no network call; it reads ~/.config/gh/hosts.yml only",
            __version__, environment_label(),
            limitations=[LIMITATION,
                         "An adapter that 'tested the API' would itself be the egress the tool "
                         "promises not to make. A future test could be a local fake server; "
                         "no real one is contacted."],
        ),
    ]


def preflight(target: str) -> List[Result]:
    return provider_for(target).preflight()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json as _json

    from .status import EXIT_OK, exit_code_for

    parser = argparse.ArgumentParser(prog="openready-providers",
                                     description="Host-provider adapters. Read-only.")
    sub = parser.add_subparsers(dest="verb", required=True)
    listing = sub.add_parser("list", help="list the supported adapters")
    listing.add_argument("--json", action="store_true")
    pre = sub.add_parser("preflight", help="read-only preflight of one provider")
    pre.add_argument("--target", required=True)
    pre.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.verb == "list":
        adapters = list_adapters()
        if args.json:
            print(_json.dumps(adapters, indent=2))
            return EXIT_OK
        for entry in adapters:
            print(f"  {entry['kind']:<10} {entry['description']}")
        return EXIT_OK
    results = preflight(args.target)
    provider = provider_for(args.target)
    if args.json:
        print(_json.dumps({"provider": provider.describe(),
                            "results": [r.to_dict() for r in results],
                            "refused_verbs": list(provider.refused_verbs())},
                           indent=2))
        return exit_code_for(results)
    print(f"  {provider.kind}: {provider.target}")
    for note in provider.notes:
        print(f"      note: {note}")
    for result in results:
        print(f"  - {result.message}")
    return exit_code_for(results)


if __name__ == "__main__":
    raise SystemExit(main())
