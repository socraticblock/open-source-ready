"""Project creation (``openready new``), the private registry, and status resolution.

Every test here fails against the tree as it was before this change: the creation path
and the registry module did not exist. They are regression tests, not descriptions of
what already happened to work.

The suite's own rule is kept: creation is exercised for real -- real git, real commits,
the project's own tests actually run -- and nothing is asserted from a mock.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import private, project, registry  # noqa: E402
from openready.status import FAIL, NOT_RUN, PASS, STOP  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _statuses(results):
    return {r.check_id: r.status for r in results}


def _cli(*args, env=None):
    """Run the CLI the way an operator does, in a child process."""
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), **fixtures.GIT_IDENTITY)
    if env:
        environment.update(env)
    return subprocess.run([sys.executable, "-m", "openready", *args],
                          capture_output=True, text=True, env=environment, timeout=600)


class CreationCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.vault = self.base / "vault"
        self.vault.mkdir()
        self.root = self.base / "projects" / "widget"
        self._previous = os.environ.get(private.PRIVATE_ENV)
        os.environ[private.PRIVATE_ENV] = str(self.vault)
        # This suite commits, so it supplies its own git identity rather than inheriting
        # whatever the developer's `~/.gitconfig` happens to hold: `verify` runs these
        # tests with only PATH, a throwaway HOME, LANG and TMPDIR, and they used to fail
        # there and pass here for exactly that reason.
        self._identity = {key: os.environ.get(key) for key in fixtures.GIT_IDENTITY}
        os.environ.update(fixtures.GIT_IDENTITY)
        self._pythonpath = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = fixtures.SRC_PATH

    def tearDown(self):
        if self._pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = self._pythonpath
        for key, value in self._identity.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if self._previous is None:
            os.environ.pop(private.PRIVATE_ENV, None)
        else:
            os.environ[private.PRIVATE_ENV] = self._previous
        self._tmp.cleanup()

    def create(self, **kwargs):
        return project.create(self.root, "widget", **kwargs)

    def git(self, *args):
        done = subprocess.run(["git", "-C", str(self.root), *args],
                              capture_output=True, text=True, timeout=120)
        return done.stdout.strip()

    def cli(self, *args, **kwargs):
        kwargs.setdefault("env", {private.PRIVATE_ENV: str(self.vault)})
        return _cli(*args, **kwargs)


class TestCompleteCreation(CreationCase):
    def test_creation_produces_a_project_that_can_run_and_be_recovered(self):
        results = self.create()
        seen = _statuses(results)
        self.assertEqual(seen["create.complete"], PASS)
        self.assertEqual(seen["create.initial-commit"], PASS)
        self.assertTrue((self.root / project.CONFIG_NAME).is_file())
        self.assertEqual(self.git("rev-list", "--all", "--count"), "1")
        self.assertEqual(self.git("remote", "-v"), "")
        self.assertEqual(list(self.root.glob("LICENSE*")), [])

    def test_the_created_project_passes_its_own_test_suite(self):
        self.create()
        self.assertTrue((self.root / "src" / "synthetic.py").is_file())
        self.assertTrue((self.root / "tests" / "test_synthetic.py").is_file())
        done = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                              cwd=str(self.root), capture_output=True, text=True, timeout=600)
        self.assertIn("OK", done.stderr + done.stdout)

    def test_the_commit_captures_the_whole_created_state_not_just_the_scaffold(self):
        self.create()
        tracked = set(self.git("ls-files").splitlines())
        self.assertIn("src/synthetic.py", tracked)
        self.assertIn("tests/test_synthetic.py", tracked)

    def test_the_private_runtime_data_root_is_created_outside_the_project(self):
        self.create()
        data_root = self.vault / "widget"
        self.assertTrue(data_root.is_dir())
        self.assertFalse(str(data_root).startswith(str(self.root) + os.sep))
        self.assertEqual(_statuses(self.create())[  # second run must refuse, not merge
            "init.target-empty"], FAIL)

    def test_creation_refuses_before_writing_when_the_private_root_would_be_inside(self):
        os.environ[private.PRIVATE_ENV] = str(self.root / "private")
        results = self.create()
        self.assertEqual(_statuses(results), {"create.private-root": FAIL})
        self.assertEqual(results[0].severity, STOP)
        self.assertFalse(self.root.exists(), "a STOP must not leave a half-written project")

    def test_creation_refuses_inside_an_enclosing_checkout_and_writes_nothing(self):
        outer = self.base / "outer"
        outer.mkdir()
        subprocess.run(["git", "init", "-q", str(outer)], check=True, timeout=120)
        self.root = outer / "widget"
        results = self.create()
        self.assertEqual(_statuses(results)["init.enclosing-checkout"], FAIL)
        self.assertFalse(self.root.exists())

    def test_completion_states_what_it_did_not_do(self):
        complete = [r for r in self.create() if r.check_id == "create.complete"][0]
        limits = " ".join(complete.limitations).lower()
        self.assertIn("no licence", limits)
        self.assertIn("no backup was taken", limits)
        self.assertIn("doctor", limits)

    def test_a_first_backup_reports_where_the_archive_actually_went(self):
        results = self.create(backup=True)
        handles = [r for r in results if r.check_id == "create.backup-archive"]
        self.assertEqual(len(handles), 1, "the backup location must be a handle, not prose")
        archive = pathlib.Path(handles[0].evidence_path)
        self.assertTrue(archive.is_file())
        self.assertFalse(str(archive).startswith(str(self.root) + os.sep))

    def test_creation_reports_not_run_rather_than_inventing_a_commit_identity(self):
        empty = self.base / "empty-gitconfig"
        empty.write_text("", encoding="utf-8")
        keys = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME", "XDG_CONFIG_HOME",
                "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")
        previous = {key: os.environ.get(key) for key in keys}
        os.environ["GIT_CONFIG_GLOBAL"] = str(empty)
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
        os.environ["HOME"] = str(self.base / "nobody")
        os.environ["XDG_CONFIG_HOME"] = str(self.base / "nobody" / ".config")
        for key in keys:
            if key.startswith("GIT_AUTHOR") or key.startswith("GIT_COMMITTER"):
                os.environ.pop(key, None)
        try:
            results = self.create()
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(_statuses(results)["create.initial-commit"], NOT_RUN)
        self.assertTrue((self.root / project.CONFIG_NAME).is_file())
        self.assertTrue((self.root / ".git").is_dir())
        self.assertFalse(registry.find("widget")["baseline_commit"])

    def test_an_identity_from_the_environment_is_used_and_not_invented(self):
        """git takes an author from `GIT_AUTHOR_EMAIL`; the tool must not call that missing.

        Found by `verify` running this suite in the scrubbed environment: five tests
        failed there and passed on the developer's machine, because they relied on
        `~/.gitconfig`. The fix is in the tests *and* here -- refusing to commit while
        git has an identity is a false `NOT_RUN`.
        """
        empty = self.base / "empty-gitconfig-too"
        empty.write_text("", encoding="utf-8")
        keys = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME", "XDG_CONFIG_HOME",
                *fixtures.GIT_IDENTITY)
        previous = {key: os.environ.get(key) for key in keys}
        os.environ["GIT_CONFIG_GLOBAL"] = str(empty)
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
        os.environ["HOME"] = str(self.base / "nobody-else")
        os.environ["XDG_CONFIG_HOME"] = str(self.base / "nobody-else" / ".config")
        os.environ.update(fixtures.GIT_IDENTITY)
        try:
            results = self.create()
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(_statuses(results)["create.initial-commit"], PASS)
        self.assertTrue(registry.find("widget")["baseline_commit"])


class TestRegistry(CreationCase):
    def test_creation_registers_the_project_with_its_baseline_commit(self):
        self.create()
        found = registry.find("widget")
        self.assertIsNotNone(found)
        self.assertEqual(pathlib.Path(found["path"]), self.root.resolve())
        self.assertEqual(found["risk_tier"], "T1")
        self.assertTrue(found["baseline_commit"])

    def test_registration_is_opt_in_so_scaffolding_has_no_hidden_side_effect(self):
        project.init(self.root, "widget")
        self.assertIsNone(registry.find("widget"))
        project.init(self.base / "second", "second", register=True)
        self.assertIsNotNone(registry.find("second"))

    def test_adopting_an_existing_tree_still_creates_no_repository(self):
        existing = self.base / "existing"
        existing.mkdir()
        (existing / "notes.txt").write_text("operator content\n", encoding="utf-8")
        results = project.init(existing, "existing", adopt=True)
        self.assertFalse((existing / ".git").exists())
        self.assertEqual((existing / "notes.txt").read_text(encoding="utf-8"),
                         "operator content\n")
        self.assertEqual(_statuses(results)["init.created"], PASS)

    def test_registering_an_existing_project_uses_its_own_contract_id(self):
        project.init(self.root, "widget", git=True, register=True)
        self.assertIsNotNone(registry.find("widget"))
        results = project.init(self.root, "renamed", adopt=True, register=True)
        self.assertIsNone(registry.find("renamed"), "a registration must not rename a project")
        self.assertIsNotNone(registry.find("widget"))
        self.assertEqual(_statuses(results)["init.register"], NOT_RUN)

    def test_a_registry_that_cannot_be_read_is_reported_and_never_overwritten(self):
        target = registry.registry_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{ not json at all", encoding="utf-8")
        results = registry.record("something", self.root, "T1", committed=False)
        self.assertEqual(_statuses(results)["registry.unreadable"], FAIL)
        self.assertEqual(target.read_text(encoding="utf-8"), "{ not json at all")

    def test_an_entry_whose_path_is_gone_is_a_stop_not_a_silent_success(self):
        self.create()
        import shutil
        shutil.rmtree(self.root)
        path, results = registry.resolve("widget")
        self.assertIsNone(path)
        self.assertEqual(_statuses(results)["registry.path-missing"], FAIL)

    def test_a_stale_entry_is_reported_rather_than_believed(self):
        self.create()
        config_path = self.root / project.CONFIG_NAME
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["project_id"] = "renamed"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        path, results = registry.resolve("widget")
        self.assertEqual(_statuses(results)["registry.id-mismatch"], FAIL)
        self.assertEqual(path, self.root.resolve())


class TestStatusAndBackupById(CreationCase):
    def test_status_with_no_arguments_reports_the_registry_not_a_project(self):
        self.create()
        done = self.cli("status")
        self.assertEqual(done.returncode, 0)
        self.assertIn("widget", done.stdout)
        self.assertIn("no project contents", done.stdout)
        payload = json.loads(self.cli("status", "--json").stdout)
        self.assertEqual([entry["project_id"] for entry in payload["projects"]], ["widget"])
        self.assertEqual(payload["exit_code"], 0)

    def test_status_on_an_empty_registry_says_so_rather_than_reporting_success(self):
        done = self.cli("status", "--json")
        payload = json.loads(done.stdout)
        self.assertEqual(payload["results"][0]["check_id"], "registry.empty")
        self.assertEqual(payload["results"][0]["status"], NOT_RUN)

    def test_status_resolves_a_project_id_through_the_registry(self):
        self.create()
        done = self.cli("status", "--project", "widget", "--json")
        self.assertEqual(done.returncode, 0)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["project_id"], "widget")
        self.assertEqual(payload["registry"]["exit_code"], 0)

    def test_an_unknown_project_id_is_a_stop(self):
        done = self.cli("status", "--project", "nope", "--json")
        self.assertEqual(done.returncode, 1)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["results"][0]["check_id"], "registry.unknown-project")

    def test_status_by_path_is_unchanged_and_prints_no_registry_block(self):
        self.create()
        done = self.cli("status", "--path", str(self.root), "--json")
        self.assertEqual(done.returncode, 0)
        self.assertNotIn("registry", json.loads(done.stdout))

    def test_backup_accepts_a_project_id_and_keeps_the_archive_outside_the_project(self):
        self.create()
        done = self.cli("backup", "--project", "widget", "--verify", "--json")
        self.assertEqual(done.returncode, 0, done.stdout[-400:] + done.stderr[-400:])
        archive = json.loads(done.stdout)["archive"]
        self.assertIsNotNone(archive)
        self.assertTrue(pathlib.Path(archive).is_file())
        self.assertFalse(str(archive).startswith(str(self.root) + os.sep))

    def test_backup_with_neither_a_path_nor_a_project_is_a_usage_error(self):
        done = _cli("backup", "--json")
        self.assertEqual(done.returncode, 64)


if __name__ == "__main__":
    unittest.main()
