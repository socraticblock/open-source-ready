"""This repository carries no deny-list shape, and none is excused by an exception.

**Why this test exists.** The tool ships a deny-list and this repository is scanned by
it: the gate that decides whether a tree may be exported runs over these very files. A
fixture, a docstring or a generated record that contains a home path or a credential
shape therefore makes the tool unable to export *itself* -- the gate refuses the file
that reports the gate.

The previous answer was one acknowledgement per affected file, and that is what this
test replaces. `privacy.secret-shape` acknowledged at `tests/test_hardening.py` did not
acknowledge a fixture; it suppressed **every** credential shape in that file until the
entry expired, so a real credential committed there later would have been covered by a
fixture's exception. Two changes removed the need for the exceptions:

* detectable values are assembled from fragments at run time (`tests/fixtures.py`,
  `acceptance/fixtures.py`), so the runtime bytes are identical and the source text
  carries no shape;
* the acceptance record redacts itself (`scan.redact_for_evidence`).

This test is the control that keeps it that way, and it is strictly stricter than the
acknowledgement file was: it catches the shapes themselves rather than excusing the
files they live in.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from openready import scan  # noqa: E402


def files_a_commit_would_include() -> list:
    """Every path a commit could carry: tracked, plus untracked and not ignored.

    `git ls-files` alone is not enough, and that is not theoretical: this test was
    written on 2026-10-14 and the new files it was meant to protect — `tests/fixtures.py`,
    `acceptance/fixtures.py` — were untracked at the time, so it did not scan them. The
    commit-time control caught the ADR that quoted a shape, not this test.
    """
    done = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                          cwd=str(REPO), capture_output=True, text=True, check=False)
    if done.returncode != 0:
        return []
    return [line for line in done.stdout.splitlines() if line.strip()]


class TestRepositoryCarriesNoShapes(unittest.TestCase):
    def test_every_tracked_file_passes_the_tools_own_deny_list(self):
        """The tool must be able to export the repository that contains it."""
        files = files_a_commit_would_include()
        if not files:
            self.skipTest("not a git checkout: there is no set to scan")
        offenders = []
        for rel in files:
            path = REPO / rel
            if not path.is_file():
                continue
            for finding in scan.scan_content(rel, path.read_bytes()):
                offenders.append(f"{rel}: {finding.check_id}: {finding.message}")
        self.assertEqual(
            offenders, [],
            "a tracked file carries a deny-list shape, which makes this repository "
            "unexportable by its own gate:\n  " + "\n  ".join(offenders) +
            "\nAssemble the value at run time (tests/fixtures.py) or redact the record "
            "(scan.redact_for_evidence); do not acknowledge the file -- an "
            "acknowledgement suppresses every shape in it, not just this one.",
        )

    def test_every_acknowledgement_here_binds_to_an_object(self):
        """A path-only entry would cover every shape at that path, now and later.

        That is not a hypothetical: twelve such entries lived here until 2026-10-14,
        each one suppressing a whole file for a year, so a real credential committed
        into `tests/test_hardening.py` would have been hidden behind a fixture's
        exception. The fixtures are assembled at run time now, and what remains is the
        residue in this repository's own object store -- acknowledged per blob.
        """
        allow = REPO / ".openready-allow.json"
        if not allow.is_file():
            # In an exported candidate this file is deliberately absent: the exporter
            # excludes it as machine-private state, and the entries travel inside
            # CANDIDATE.json so a verifier can judge them there.
            self.skipTest("no .openready-allow.json here: this is an exported candidate")
        document = json.loads(allow.read_text(encoding="utf-8"))
        for entry in document.get("entries", []):
            self.assertTrue(
                entry.get("object"),
                f"acknowledgement of {entry.get('check_id')} at {entry.get('path')} "
                f"names no object id, so it covers every shape at that path forever",
            )
            self.assertTrue(entry.get("reason") and entry.get("expires"), entry)
        self.assertTrue(document.get("_note"), "the file must say what it is")


class TestTheRecordCannotPoisonTheExport(unittest.TestCase):
    """The acceptance record is checked before it is written, and not written if it fails.

    The record lives in this repository, so it is scanned by the same deny-list as
    everything else. Writing it anyway -- with a warning, or after the fact -- is how
    the repository became unexportable by its own gate on 2026-10-13: `docs/
    ACCEPTANCE-STATE.json` held 99 absolute home paths, and `openready candidate`
    refused to export the tree that contained it.
    """

    def _record_findings(self, sources):
        sys.path.insert(0, str(REPO))
        from acceptance.runner import _record_findings  # noqa: PLC0415
        return _record_findings(sources)

    def test_a_record_carrying_a_home_path_is_refused(self):
        findings = self._record_findings(
            {"ACCEPTANCE-STATE.md": "sandbox: " + "/home/" + "someone/ws\n"})
        self.assertTrue(findings, "a poisoning record was accepted")
        self.assertIn("docs/ACCEPTANCE-STATE.md", findings[0])

    def test_a_clean_record_is_accepted(self):
        self.assertEqual(self._record_findings({"ACCEPTANCE-STATE.md": "sandbox: ~/ws\n"}), [])


if __name__ == "__main__":
    unittest.main()
