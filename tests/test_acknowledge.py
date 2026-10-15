"""The adoption path: acknowledging residue in the object store, and only narrowly.

The scenario is the one a real user meets and this repository never did. A file carried a
shape in an earlier commit and no longer does: the working tree is clean, the object store
is not, and the export refuses. Cleaning the tree is not enough, and rewriting history is
the owner's decision -- so the honest path is an acknowledgement bound to the exact blob.

What is asserted here is mostly about what the command *refuses* to do, because that is
where the value is. It writes nothing without being asked, it will not supply the
operator's reason, it proposes nothing for a file the operator can simply edit, it never
turns a partial scan into "nothing to acknowledge", and an entry it writes covers the blob
it named and not that path forever.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import acknowledge, candidate, overrides  # noqa: E402
from openready.status import FAIL, INFO, NEEDS_HUMAN, NOT_RUN, PASS, exit_code_for  # noqa: E402

ALLOW = ".openready-allow.json"
REAL_REASON = "Synthetic fixture in this project's own tests, confirmed not a credential."


def _run(base, *args):
    return subprocess.run(
        ["git", *args], cwd=str(base), env=fixtures.git_env(os.environ.copy()),
        capture_output=True, text=True, check=True,
    )


def _write(base, name, text):
    path = pathlib.Path(base) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class AdoptionPathCase(unittest.TestCase):
    """A repository whose working tree is clean and whose object store is not."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        _run(self.base, "init", "-q")
        # Commit one: the shape. Commit two: the same file, cleaned.
        self.history_file = _write(self.base, "docs/notes.md", fixtures.host_path_line())
        _run(self.base, "add", "-A")
        _run(self.base, "commit", "-qm", "first")
        _write(self.base, "docs/notes.md", "Machine-agnostic notes.\n")
        _run(self.base, "add", "-A")
        _run(self.base, "commit", "-qm", "clean")

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_tree_is_clean_and_the_store_is_not(self):
        self.assertEqual(acknowledge.tree_findings(self.base), [])
        residue, why = acknowledge.residue(self.base)
        self.assertEqual(why, "")
        self.assertTrue(residue, "the cleaned blob is still in the object store")

    def test_it_proposes_and_writes_nothing(self):
        results, payload = acknowledge.run(self.base)
        self.assertIn(NEEDS_HUMAN,
                      {r.status for r in results if r.check_id == "acknowledge.object-residue"})
        self.assertFalse((self.base / ALLOW).exists())
        self.assertTrue(payload["proposal"])
        for entry in payload["proposal"]:
            self.assertTrue(entry.get("object"), "an object-store hit is bound to its blob")

    def test_it_will_not_supply_the_operator_s_reason(self):
        for reason in ("", "false positive", "todo"):
            results, _ = acknowledge.run(self.base, reason=reason, write_it=True)
            self.assertEqual(
                {r.status for r in results if r.check_id == "acknowledge.refused"}, {FAIL}, reason)
            self.assertFalse((self.base / ALLOW).exists(), reason)
        self.assertEqual(exit_code_for(acknowledge.run(self.base, reason="", write_it=True)[0]), 1)

    def test_a_written_entry_covers_the_blob_and_not_the_path(self):
        results, _ = acknowledge.run(self.base, reason=REAL_REASON, by="tester",
                                     write_it=True)
        self.assertIn(PASS, {r.status for r in results if r.check_id == "acknowledge.written"})
        self.assertTrue((self.base / ALLOW).is_file())
        self.assertEqual(acknowledge.residue(self.base)[0], [], "the named blob is covered")

        # Different content at the same path, later. A path-wide exception would hide it.
        _write(self.base, "docs/notes.md", fixtures.assignment_n(3) + "\n")
        _run(self.base, "add", "-A")
        _run(self.base, "commit", "-qm", "later")
        later, _ = acknowledge.residue(self.base)
        self.assertTrue(later, "content committed later at that path is still reported")
        self.assertTrue(all(entry.get("object") for entry in
                            acknowledge.proposal(later, REAL_REASON, "tester")))

    def test_a_partial_scan_is_never_nothing_to_acknowledge(self):
        report = {"hits": [], "blobs_scanned": 1, "truncated": True, "scan_failed": False,
                  "hit_count": 0}
        with mock.patch.object(acknowledge, "history_scan", return_value=report):
            results, payload = acknowledge.run(self.base, reason=REAL_REASON, write_it=True)
        self.assertEqual(
            {r.status for r in results if r.check_id == "acknowledge.scan-incomplete"},
            {NOT_RUN})
        self.assertFalse((self.base / ALLOW).exists())
        self.assertEqual(payload["object_residue"], 0)

    def test_a_file_the_operator_can_edit_is_named_not_acknowledged(self):
        _write(self.base, "src/settings.py", fixtures.host_path_line())
        results, payload = acknowledge.run(self.base)
        self.assertIn(NEEDS_HUMAN,
                      {r.status for r in results if r.check_id == "acknowledge.tree-findings"})
        self.assertTrue(all(entry.get("object") for entry in payload["proposal"]),
                        "the working-tree finding is not in the proposal by default")

    def test_include_tree_records_a_wider_entry_and_says_so(self):
        _write(self.base, "src/settings.py", fixtures.host_path_line())
        results, payload = acknowledge.run(self.base, reason=REAL_REASON, by="tester",
                                          write_it=True, include_tree=True)
        path_bound = [entry for entry in payload["proposal"] if not entry.get("object")]
        self.assertEqual(len(path_bound), 1)
        self.assertEqual(path_bound[0]["path"], "src/settings.py")
        wider = [r for r in results if r.check_id == "acknowledge.tree-acknowledged"]
        self.assertTrue(wider and wider[0].limitations)

    def test_a_successful_write_exits_zero_and_stops_claiming_the_residue(self):
        """The residue result described the state before the write, not after it."""
        results, _ = acknowledge.run(self.base, reason=REAL_REASON, by="tester",
                                     write_it=True)
        self.assertNotIn("acknowledge.object-residue", {r.check_id for r in results})
        self.assertEqual(exit_code_for(results), 0)

    def test_writing_keeps_the_entries_already_there(self):
        (self.base / ALLOW).write_text(json.dumps({
            "_note": "kept",
            "entries": [{"check_id": "candidate.host-path", "path": "old/file.txt",
                         "reason": "An earlier acknowledgement that must survive.",
                         "acknowledged_by": "tester", "acknowledged_at": "2026-01-01"}],
        }), encoding="utf-8")
        acknowledge.run(self.base, reason=REAL_REASON, by="tester", write_it=True)
        document = json.loads((self.base / ALLOW).read_text(encoding="utf-8"))
        self.assertEqual(document["_note"], "kept")
        paths = {entry["path"] for entry in document["entries"]}
        self.assertIn("old/file.txt", paths)
        self.assertTrue(any(entry.get("object") for entry in document["entries"]))

    def test_running_twice_does_not_grow_the_file(self):
        acknowledge.run(self.base, reason=REAL_REASON, by="tester", write_it=True)
        first = json.loads((self.base / ALLOW).read_text(encoding="utf-8"))
        results, _ = acknowledge.run(self.base, reason=REAL_REASON, by="tester", write_it=True)
        second = json.loads((self.base / ALLOW).read_text(encoding="utf-8"))
        self.assertEqual(len(first["entries"]), len(second["entries"]))
        self.assertEqual(
            {r.status for r in results if r.check_id == "acknowledge.nothing"}, {PASS})
        # The command returns at "nothing to acknowledge": there is no proposal, so
        # "nothing was written" would be a second way of saying the same thing.
        self.assertNotIn("acknowledge.nothing-written", {r.check_id for r in results})


class TheManifestDescribesThisExport(unittest.TestCase):
    """An artifact must not carry the development history's paperwork.

    Found while publishing this tool: the manifest of a 72-file, single-commit release tree
    listed 43 acknowledgements naming the development repository's own documents, the
    residue reasons and the lane that reviewed them -- in a tree that contains none of them.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        _run(self.base, "init", "-q")
        _write(self.base, "README.md", "A project.\n")
        _write(self.base, "docs/notes.md", fixtures.host_path_line())
        _run(self.base, "add", "-A")
        _run(self.base, "commit", "-qm", "first")
        _write(self.base, "docs/notes.md", "Machine-agnostic notes.\n")
        _run(self.base, "add", "-A")
        _run(self.base, "commit", "-qm", "clean")
        acknowledge.run(self.base, reason=REAL_REASON, by="tester", write_it=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _manifest(self, mode):
        # The history modes are reachable only from an internal caller now; the public
        # workflow exports without history. This helper is such a caller.
        out = self.base.parent / f"candidate-{mode}"
        candidate.export(self.base, out, project_id="p", history_mode=mode,
                         history_modes_allowed=True)
        self.addCleanup(shutil.rmtree, out, True)
        return json.loads((out / "CANDIDATE.json").read_text(encoding="utf-8"))

    def test_nothing_from_history_travels_with_history_none(self):
        manifest = self._manifest("none")
        self.assertEqual(manifest["history_mode"], "none")
        self.assertEqual(manifest["acknowledged_findings"], [])

    def test_the_residue_is_recorded_when_the_mode_is_about_the_residue(self):
        manifest = self._manifest("squash")
        self.assertTrue(manifest["acknowledged_findings"])
        self.assertTrue(all(item.get("object") for item in manifest["acknowledged_findings"]))


class NoResidueCase(unittest.TestCase):
    def test_a_directory_that_is_not_a_repository_has_no_history_to_acknowledge(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            _write(base, "readme.md", "No repository here.\n")
            results, payload = acknowledge.run(base)
            self.assertEqual(payload["object_residue"], 0)
            self.assertEqual(
                {r.status for r in results if r.check_id == "acknowledge.nothing"}, {PASS})
            self.assertFalse((base / ALLOW).exists())


if __name__ == "__main__":
    unittest.main()
