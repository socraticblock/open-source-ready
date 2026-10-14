"""Synthetic fixtures and the private runtime data boundary (OR-005).

The boundary rule this module enforces, from the specification:

    Private data must live outside the project. A project must run on a stranger's
    machine, so the project carries a *synthetic* example of anything it needs --
    never the operator's own data.

Three consequences, and this module turns each into a check rather than advice:

1. The private data location must not be inside the project. If it is, then the
   first careless ``git add -A`` publishes it, which is exactly how this fleet's
   own estate ended up publishing 369 files nobody decided to publish.
2. The private data location must not be inside *any* git working tree, for the
   same reason one level out.
3. No project file may contain the private location's path. Referencing it by
   absolute path is how a project becomes unusable anywhere else, and it is also
   how the location leaks into a candidate.

The synthetic corpus is deterministic: same bytes on every machine, no clock, no
hostname. A fixture that varies cannot be a control.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .capabilities import enclosing_checkout, environment_label
from .status import FAIL, INFO, NEEDS_HUMAN, PASS, REVIEW, STOP, Result

PRIVATE_ENV = "OPENREADY_PRIVATE_HOME"
DEFAULT_PRIVATE_DIRNAME = "openready-private"

BOUNDARY_LIMITATION = (
    "A filesystem boundary is a convention, not a control: nothing here prevents "
    "an operator from copying private data into the project by hand."
)


def data_root(env: Optional[Dict[str, str]] = None) -> Path:
    """The operating system's per-user application-data directory.

    ``$HOME/<dir>`` is not a data root on any of the three platforms: Linux
    convention (and the XDG spec) use ``$XDG_DATA_HOME`` or ``~/.local/share``,
    macOS uses ``~/Library/Application Support``, Windows uses ``%LOCALAPPDATA%``.
    Private data parked outside all of them misses every platform's backup and
    permission conventions.
    """
    source = os.environ if env is None else env
    platform = (source.get("OPENREADY_OS") or sys.platform or "").lower()
    if platform.startswith("win") or source.get("LOCALAPPDATA"):
        raw = source.get("LOCALAPPDATA", "").strip()
        return Path(raw).expanduser() if raw else Path.home() / "AppData" / "Local"
    if platform.startswith("darwin"):
        return Path.home() / "Library" / "Application Support"
    raw = source.get("XDG_DATA_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "share"


def private_home(env: Optional[Dict[str, str]] = None) -> Path:
    """Resolve the private data location. Never inside a project by construction."""
    source = os.environ if env is None else env
    raw = source.get(PRIVATE_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (data_root(source) / DEFAULT_PRIVATE_DIRNAME).resolve()


def private_home_source(env: Optional[Dict[str, str]] = None) -> str:
    source = os.environ if env is None else env
    return "environment" if source.get(PRIVATE_ENV, "").strip() else "default"


def boundary_results(project_root: Path, env: Optional[Dict[str, str]] = None) -> List[Result]:
    """The three boundary checks above, plus how the location was decided."""
    project_root = Path(project_root).resolve()
    home = private_home(env)
    source = private_home_source(env)
    results: List[Result] = []

    inside_project = home == project_root or project_root in home.parents
    results.append(Result(
        "private.outside-project", FAIL if inside_project else PASS, STOP if inside_project else INFO,
        (f"private data location {PRIVATE_ENV} is INSIDE the project -- one careless "
         f"`git add -A` publishes it")
        if inside_project else
        f"private data location is outside the project (decided by {source})",
        __version__, environment_label(), limitations=[BOUNDARY_LIMITATION],
    ))

    encloser = None if inside_project else enclosing_checkout(home if home.exists() else home.parent)
    if encloser:
        results.append(Result(
            "private.outside-checkout", NEEDS_HUMAN, REVIEW,
            f"private data location sits inside the git working tree {encloser!r}",
            __version__, environment_label(), required=False,
            limitations=[BOUNDARY_LIMITATION],
        ))

    leaked = _files_referencing(project_root, home)
    results.append(Result(
        "private.no-absolute-reference", FAIL if leaked else PASS, STOP if leaked else INFO,
        (f"{len(leaked)} project file(s) reference the private location by absolute "
         f"path: {', '.join(leaked[:3])}")
        if leaked else
        "no project file references the private location by absolute path",
        __version__, environment_label(),
    ))
    return results


def _files_referencing(project_root: Path, needle: Path, limit: int = 400) -> List[str]:
    """Project files whose bytes contain the private location's path."""
    targets = {str(needle).encode(), str(needle).replace("/", "\\").encode()}
    hits: List[str] = []
    for where, dirs, names in os.walk(project_root, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__", "node_modules"})
        for name in sorted(names):
            if len(hits) >= limit:
                return hits
            path = Path(where) / name
            try:
                if path.lstat().st_size > 2 * 1024 * 1024:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if any(t in data for t in targets):
                hits.append(path.relative_to(project_root).as_posix())
    return hits


# --- synthetic corpus ---------------------------------------------------------

_SYNTHETIC_FILES: Dict[str, str] = {
    "README.md": """# Synthetic example

This corpus is generated, not collected. It exists so the project can be run and
tested on a machine that shares nothing with the machine it was written on.

Every name, note and number below is invented.
""",
    "src/synthetic.py": '''"""A tiny module, so the fixture has something to test."""


def normalize_label(raw: str) -> str:
    """Lowercase, strip, and collapse internal whitespace."""
    return " ".join(raw.split()).lower()


def is_blank(raw: str) -> bool:
    return not raw.strip()
''',
    "tests/test_synthetic.py": '''import unittest

from src.synthetic import is_blank, normalize_label


class TestSynthetic(unittest.TestCase):
    def test_collapses_whitespace(self):
        self.assertEqual(normalize_label("  Two   Words "), "two words")

    def test_blank(self):
        self.assertTrue(is_blank("   "))
        self.assertFalse(is_blank("x"))


if __name__ == "__main__":
    unittest.main()
''',
    "config/scope.example.json": """{
  "include": ["src", "tests"],
  "exclude": ["tests/fixtures"],
  "note": "Placeholder values only. The real file is local and never committed."
}
""",
    "journal/0001-example-entry.md": """# Entry 0001 -- synthetic

Subject: a placeholder change.

Observation. A value was read from a configuration file rather than being passed
as an argument, so two call sites disagreed about the default.

Consequence. The disagreement was invisible until both paths ran in one process.

Note. Written to be readable by someone who was not present.
""",
    "journal/0002-example-entry.md": """# Entry 0002 -- synthetic

Subject: a placeholder decision.

Observation. Two components each kept their own copy of the same list.

Consequence. The copies drifted by one entry within a week.

Decision. One owner for the list; the other reads it.
""",
    "journal/0003-example-entry.md": """# Entry 0003 -- synthetic

Subject: a placeholder limitation.

Observation. The check reports a match when it finds one and cannot report the
absence of a match.

Consequence. A passing check means "nothing matched", not "nothing is there".

Note. Stated in the output rather than in a document, because the distinction is
lost when it lives only in a document.
""",
}


def synthetic_corpus(destination: Path, overwrite: bool = False) -> List[str]:
    """Write the deterministic synthetic fixture. Returns relative paths written."""
    destination = Path(destination)
    written: List[str] = []
    for rel, content in sorted(_SYNTHETIC_FILES.items()):
        target = destination / rel
        if target.exists() and not overwrite:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written.append(rel)
    return written


def synthetic_paths() -> List[str]:
    """The fixture's file list, without writing anything."""
    return sorted(_SYNTHETIC_FILES)
