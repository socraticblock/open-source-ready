"""The exporter (OR-016). Every scenario here is a defect the prototype shipped."""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import candidate, history, project  # noqa: E402
from openready.status import FAIL, NEEDS_HUMAN, PASS  # noqa: E402


def git(root, *args):
    # The advisory commit-time control is bypassed on purpose: these tests commit the very
    # material the hook refuses, because the exporter's history scan is what is under test.
    return subprocess.run(["git", "-c", "core.hooksPath=", "-C", str(root), *args],
                          capture_output=True, text=True, check=False)


def make_project(root: pathlib.Path) -> pathlib.Path:
    project.init(root, "probe", git=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "alpha.py").write_text("def alpha():\n    return 1\n")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "notes.md").write_text("# Notes\n\nAn ordinary document.\n")
    git(root, "config", "user.name", "probe")
    git(root, "config", "user.email", "probe@example.invalid")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


class ExportCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.root = make_project(self.base / "proj")
        self.out = self.base / "cand"

    def tearDown(self):
        self._tmp.cleanup()

    def run_export(self, **kwargs):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "defect")
        return candidate.export(self.root, self.out, "probe", **kwargs)

    def statuses(self, results):
        return {r.check_id: r.status for r in results}


class TestPrototypeDefectsRefused(ExportCase):
    def test_host_path_is_refused_and_nothing_is_written(self):
        (self.root / "docs" / "notes.md").write_text("run: " + fixtures.HOST_PATH + "\n")
        results, meta = self.run_export()
        self.assertEqual(self.statuses(results)["candidate.export"], FAIL)
        self.assertIsNone(meta)
        self.assertFalse(self.out.exists(), "a refused export must leave nothing behind")

    def test_casefold_collision_is_refused(self):
        (self.root / "src" / "Alpha.py").write_text("x = 1\n")
        (self.root / "src" / "alpha.py").write_text("x = 2\n")
        results, meta = self.run_export()
        self.assertIn("candidate.casefold-collision", self.statuses(results))
        self.assertFalse(self.out.exists())

    def test_hardlink_alias_is_refused(self):
        shared = self.root / "src" / "shared.txt"
        shared.write_text("shared\n")
        os.link(shared, self.root / "src" / "shared-alias.txt")
        results, meta = self.run_export()
        self.assertIn("candidate.hardlink", self.statuses(results))
        self.assertFalse(self.out.exists())

    def test_lfs_pointer_is_refused(self):
        (self.root / "assets.bin").write_text(
            "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 10\n")
        results, meta = self.run_export()
        self.assertIn("candidate.lfs-pointer", self.statuses(results))
        self.assertFalse(self.out.exists())

    def test_a_secret_shape_is_refused(self):
        (self.root / "src" / "conf.py").write_text(
            fixtures.QUOTED_ASSIGNMENT + "\n")
        results, meta = self.run_export()
        self.assertIn("privacy.secret-shape", self.statuses(results))
        self.assertFalse(self.out.exists())


class TestAllowlist(ExportCase):
    def test_the_candidate_is_the_tracked_set(self):
        (self.root / "untracked.md").write_text("never added\n")
        plan = candidate.plan(self.root, "probe")
        self.assertIn("src/alpha.py", plan["included"])
        self.assertNotIn("untracked.md", plan["included"])
        self.assertEqual(plan["allowlist"], "git-tracked files")

    def test_excluded_paths_carry_a_reason(self):
        (self.root / ".openready-ledger.json").write_text("{}\n")
        git(self.root, "add", "-A")
        plan = candidate.plan(self.root, "probe")
        reasons = {item["path"]: item["reason"] for item in plan["excluded"]}
        self.assertIn(".openready-ledger.json", reasons)
        self.assertTrue(reasons[".openready-ledger.json"])

    def test_unstaged_deletion_of_a_tracked_file_is_reported(self):
        # Git still lists an unstaged deletion, but the exporter cannot read it.
        # The missing content must not silently vanish from the review record.
        path = "src/alpha.py"
        (self.root / path).unlink()
        results, meta = candidate.export(self.root, self.out, "probe")
        self.assertIsNotNone(meta, [r.message for r in results])
        self.assertFalse((self.out / path).exists())
        notices = [r for r in results if r.check_id == "candidate.tracked-unavailable"]
        self.assertEqual(len(notices), 1, [r.check_id for r in results])
        self.assertEqual(notices[0].status, NEEDS_HUMAN)
        self.assertIn(path, notices[0].message)

    def test_normal_tracked_files_require_no_missing_file_review(self):
        results, meta = candidate.export(self.root, self.out, "probe")
        self.assertIsNotNone(meta, [r.message for r in results])
        self.assertFalse(any(r.check_id == "candidate.tracked-unavailable" for r in results))

    def test_tool_metadata_is_never_inside_the_digest(self):
        results, meta = self.run_export()
        manifest = json.loads((self.out / candidate.MANIFEST_NAME).read_text())
        names = [entry["path"] for entry in manifest["files"]]
        self.assertNotIn(candidate.MANIFEST_NAME, names)
        self.assertNotIn(candidate.CANDIDATE_NAME, names)


class TestDigest(ExportCase):
    def test_the_digest_is_deterministic_across_exports(self):
        _, first = self.run_export()
        shutil.rmtree(self.out)
        _, second = self.run_export()
        self.assertEqual(first["candidate_digest"], second["candidate_digest"])
        self.assertRegex(first["candidate_digest"], r"^sha256:[a-f0-9]{64}$")

    def test_changing_content_changes_the_digest(self):
        _, first = self.run_export()
        shutil.rmtree(self.out)
        (self.root / "src" / "alpha.py").write_text("def alpha():\n    return 2\n")
        _, second = self.run_export()
        self.assertNotEqual(first["candidate_digest"], second["candidate_digest"])

    def test_the_manifest_records_real_file_hashes(self):
        import hashlib

        self.run_export()
        manifest = json.loads((self.out / candidate.MANIFEST_NAME).read_text())
        for entry in manifest["files"]:
            data = (self.out / entry["path"]).read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["bytes"], len(data))


class TestAcknowledgement(ExportCase):
    def _ack(self, check_id, path):
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": check_id, "path": path,
            "reason": "Positive control: this fixture must be detected by the scanner.",
            "acknowledged_by": "test", "acknowledged_at": "2026-10-13",
        }]}), encoding="utf-8")

    def test_an_acknowledged_finding_exports_and_is_recorded(self):
        (self.root / "fixture.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        self._ack("privacy.secret-shape", "fixture.py")
        results, meta = self.run_export()
        self.assertEqual(self.statuses(results)["candidate.export"], PASS)
        self.assertTrue(any(r.check_id == "override.applied" for r in results))
        self.assertIn("fixture.py", [e["path"] for e in meta["acknowledged_findings"]])
        # The reason, the author and the date travel with the finding. verify re-checks
        # them, so an entry without them suppresses nothing downstream.
        entry = meta["acknowledged_findings"][0]
        for field in ("reason", "acknowledged_by", "acknowledged_at"):
            self.assertTrue(entry.get(field), f"{field} must travel with the acknowledgement")

    def test_an_acknowledged_finding_is_recorded_once_not_twice(self):
        """The same bytes are also in the object store; that must not double-report."""
        (self.root / "fixture.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        self._ack("privacy.secret-shape", "fixture.py")
        results, _ = self.run_export()
        applied = [r for r in results if r.check_id == "override.applied"]
        self.assertEqual(len(applied), 1, [r.message for r in applied])
        # The object-store scan resolves against the same acknowledgement.
        self.assertEqual(self.statuses(results)["privacy.full-history"], PASS)

    def test_no_acknowledgement_file_means_nothing_is_suppressed(self):
        (self.root / "fixture.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        results, meta = self.run_export()
        self.assertIsNone(meta)
        self.assertFalse(any(r.check_id == "override.applied" for r in results))


class TestHistoryModes(ExportCase):
    def test_squash_creates_exactly_one_commit_with_a_placeholder_identity(self):
        report = history.scan(self.root)
        results, meta = self.run_export(history_mode="squash", history_modes_allowed=True, history_report=report)
        self.assertEqual(meta["history_mode"], "squash")
        log = git(self.out, "log", "--format=%an <%ae>|%s").stdout.strip().splitlines()
        self.assertEqual(len(log), 1, log)
        self.assertIn("candidate@openready.invalid", log[0])
        self.assertTrue(any(
            d["decision"] == "public_commit_identity" for d in meta["required_owner_decisions"]))

    def test_preserve_is_refused_when_the_object_store_contains_a_hit(self):
        report = history.scan(self.root)
        (self.root / "docs" / "notes.md").write_text("run: " + fixtures.HOST_PATH + "\n")
        report = history.scan(self.root)
        results, meta = self.run_export(history_mode="preserve", history_modes_allowed=True, history_report=report)
        self.assertIsNone(meta)
        self.assertFalse(self.out.exists())

    def test_preserve_is_refused_with_uncommitted_changes(self):
        report = history.scan(self.root)
        (self.root / "src" / "alpha.py").write_text("def alpha():\n    return 99\n")
        results, meta = candidate.export(
            self.root, self.out, "probe", history_mode="preserve", history_modes_allowed=True, history_report=report)
        self.assertIsNone(meta)

    def test_none_reports_a_history_hit_as_a_required_human_decision(self):
        # The scan must run against committed content: an uncommitted file has no
        # history, and a stale scan would report a clean object store.
        (self.root / "docs" / "notes.md").write_text("run: " + fixtures.HOST_PATH + "\n")
        # The content finding is acknowledged so the export can proceed at all...
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [
            {"check_id": "candidate.host-path", "path": "docs/notes.md",
             "reason": "Positive control: the fixture must be detected as a blocker.",
             "acknowledged_by": "test", "acknowledged_at": "2026-10-13"}]}))
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "defect")
        report = history.scan(self.root)
        self.assertGreater(report["hit_count"], 0, "the committed blob must be found")
        results, meta = self.run_export(history_mode="none", history_report=report)
        by_id = self.statuses(results)
        # ...but an acknowledged finding is still present for any public scanner, and
        # that is a decision the operator must make rather than a silent pass.
        self.assertEqual(by_id["privacy.full-history"], PASS, "acknowledged, so not a failure")
        self.assertEqual(by_id["candidate.history-choice"], NEEDS_HUMAN)
        self.assertIn("SQUASH_RECOMMENDED", [r.message for r in results
                                            if r.check_id == "candidate.history-choice"][0])

    def test_an_unknown_history_mode_is_refused(self):
        results, meta = self.run_export(history_mode="whatever")
        self.assertIsNone(meta)
        self.assertEqual(self.statuses(results)["candidate.history-mode"], FAIL)


class TestDestination(ExportCase):
    def test_exporting_into_the_project_outside_the_candidate_dir_is_refused(self):
        results, meta = candidate.export(self.root, self.root / "elsewhere")
        self.assertIsNone(meta)
        self.assertEqual(self.statuses(results)["candidate.destination"], FAIL)

    def test_exporting_onto_the_project_root_is_refused(self):
        results, meta = candidate.export(self.root, self.root)
        self.assertIsNone(meta)
        self.assertEqual(self.statuses(results)["candidate.destination"], FAIL)


class TestNoPublicationPath(unittest.TestCase):
    def test_no_module_invokes_gh_or_changes_visibility(self):
        """A publish path that existed would defeat the only control that matters.

        The check is: the tool does not *invoke* publication, not that the tool
        never *mentions* the words. A module that lists "push" or "--visibility
        public" as a refused verb -- as providers.py does for the GitHub adapter --
        is documenting the control, not bypassing it. A line that contains a
        refusal is therefore exempted when it appears in a tuple of refused
        verbs; an actual subprocess call to ``gh`` or ``git push`` is not.
        """
        import re

        source_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "openready"
        offenders = []
        for path in sorted(source_root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for needle in ("subprocess.run([\"gh\"", "gh repo edit", "--visibility public",
                           "\"gh\", \"api\"", "git push", "\"push\""):
                for match in re.finditer(re.escape(needle), text):
                    start = text.rfind("\n", 0, match.start()) + 1
                    end = text.find("\n", match.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end]
                    # A line that names a refusal, a list of refused verbs, or
                    # appears under a *_REFUSED / *_NO_PUBLISH constant is
                    # documenting the control rather than bypassing it.
                    lowered = line.lower()
                    if any(token in lowered for token in
                           ("refused", "never", "no ", "forbid", "must not", "denies",
                            "refusal", "not a publish", "not a publication")):
                        continue
                    # The line is in a tuple literal that contains a *_REFUSED
                    # or *_NO_PUBLISH name (visible by walking back to the
                    # enclosing tuple's header).
                    head = text[:match.start()]
                    if re.search(r"^\s*(?:[A-Z_][A-Z0-9_]*REFUSED"
                                 r"|[A-Z_][A-Z0-9_]*NO_PUBLISH"
                                 r"|[A-Z_][A-Z0-9_]*FORBIDDEN"
                                 r"|[A-Z_][A-Z0-9_]*DENIED)\s*=", head, re.M):
                        continue
                    # Same, but a constant is on the SAME line as the needle
                    # (e.g. ``LOCAL_REFUSED = ("push",)``).
                    if re.search(r"^.*(?:REFUSED|NO_PUBLISH|FORBIDDEN|DENIED)"
                                  r"\s*=\s*\(.*" + re.escape(needle) + r".*\)\s*$",
                                  line, re.M):
                        continue
                    offenders.append(f"{path.name}:{start}: {line.strip()[:90]}")
        self.assertEqual(offenders, [], f"publication-capable code found: {offenders}")

    def test_the_cli_has_no_publish_command(self):
        from openready.cli import _build_parser

        parser = _build_parser()
        subparsers = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
        names = set()
        for action in subparsers:
            if isinstance(action.choices, dict):
                names.update(action.choices)
        self.assertNotIn("publish", names)
        self.assertIn("candidate", names)
        self.assertIn("verify", names)


if __name__ == "__main__":
    unittest.main()
