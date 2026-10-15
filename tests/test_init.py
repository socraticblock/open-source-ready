"""Project initialisation, including acceptance test A01."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready import project  # noqa: E402
from openready.contracts import tool_root, validate_against  # noqa: E402
from openready.status import FAIL, PASS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _statuses(results):
    return {r.check_id: r.status for r in results}


class TestInitHappyPath(unittest.TestCase):
    def test_A01_init_creates_a_valid_private_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            results = project.init(target, "toy-project")
            self.assertTrue(all(r.status != FAIL for r in results), results)
            config = json.loads((target / project.CONFIG_NAME).read_text())
            self.assertEqual(config["visibility"], "PRIVATE")
            self.assertEqual(config["license_intent"], "UNDECIDED")
            self.assertEqual(validate_against(tool_root(), "project", config), [])

    def test_A01_no_public_side_effect_is_claimed_and_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = project.init(pathlib.Path(tmp) / "toy", "toy-project")
            self.assertEqual(
                _statuses(results).get("init.no-public-side-effect"), PASS)

    def test_no_licence_file_is_created(self):
        """ADR-005: the licence decision is staged, not skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            project.init(target, "toy-project")
            self.assertFalse((target / "LICENSE").is_file())

    def test_no_git_repository_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            project.init(target, "toy-project")
            self.assertFalse((target / ".git").exists())

    def test_skeleton_contains_the_expected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            project.init(target, "toy-project")
            for rel in (".gitignore", ".env.example", "AGENTS.md", "README.md",
                        "docs/adr/000-template.md", "examples/synthetic/README.md"):
                with self.subTest(rel=rel):
                    self.assertTrue((target / rel).is_file(), rel)


class TestInitRefusals(unittest.TestCase):
    def test_refuses_a_non_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            target.mkdir()
            (target / "existing.txt").write_text("do not clobber me\n")
            results = project.init(target, "toy-project")
            self.assertEqual(_statuses(results).get("init.target-empty"), FAIL)
            self.assertTrue((target / "existing.txt").is_file())

    def test_refuses_to_create_inside_a_git_working_tree(self):
        """The fleet's own failure mode: a project inside a published checkout."""
        with tempfile.TemporaryDirectory() as tmp:
            outer = pathlib.Path(tmp) / "outer"
            (outer / ".git").mkdir(parents=True)
            results = project.init(outer / "toy", "toy-project")
            self.assertEqual(_statuses(results).get("init.enclosing-checkout"), FAIL)
            self.assertFalse((outer / "toy").exists(), "refusal must not create anything")

    def test_override_allows_it_but_records_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer = pathlib.Path(tmp) / "outer"
            (outer / ".git").mkdir(parents=True)
            results = project.init(outer / "toy", "toy-project", force=True)
            self.assertTrue(all(r.status != FAIL for r in results), results)
            reviewed = [r for r in results if r.check_id == "init.enclosing-checkout"]
            self.assertEqual(reviewed[0].status, "NEEDS_HUMAN")
            self.assertFalse(reviewed[0].required,
                             "an override is recorded for a human but must not block")

    def test_rejects_a_bad_project_id(self):
        for bad in ("Bad_ID", "-leading", "x", "UPPER"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                results = project.init(pathlib.Path(tmp) / "toy", bad)
                self.assertEqual(_statuses(results).get("init.project-id"), FAIL)

    def test_rejects_an_unknown_risk_tier(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = project.init(pathlib.Path(tmp) / "toy", "toy-project", tier="T9")
            self.assertEqual(_statuses(results).get("init.risk-tier"), FAIL)


class TestInitGit(unittest.TestCase):
    def test_git_init_creates_no_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            project.init(target, "toy-project", git=True)
            self.assertTrue((target / ".git").is_dir())
            remote = subprocess.run(
                ["git", "-C", str(target), "remote"], capture_output=True, text=True)
            self.assertEqual(remote.stdout.strip(), "",
                             "a new private project must have no remote")

    def test_config_tier_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "toy"
            project.init(target, "toy-project", tier="T2", languages=["python", "typescript"])
            config = json.loads((target / project.CONFIG_NAME).read_text())
            self.assertEqual(config["risk_tier"], "T2")
            self.assertEqual(sorted(config["languages"]), ["python", "typescript"])


if __name__ == "__main__":
    unittest.main()
