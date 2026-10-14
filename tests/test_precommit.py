"""The commit-time control: ``openready precommit`` and the hook installed by creation.

Two things are being proven here, and the second matters as much as the first:

1. A commit whose STAGED content would put private material into history is refused.
2. The control is honest about being bypassable -- ``git commit --no-verify`` really does
   skip it, and that is asserted rather than left as a claim in a comment. A control that
   quietly overstates itself is worse than no control.
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

ROOT = pathlib.Path(__file__).resolve().parents[1]

from openready import private, project, staged  # noqa: E402
from openready.status import FAIL, NOT_ENFORCED, NOT_RUN, PASS, STOP  # noqa: E402

# A credential shape, not a credential: invented, and self-describing as such.
FAKE_PEM = fixtures.PEM_HEADER + "\nnot-a-real-key-material\n"


def _statuses(results):
    return {r.check_id: r.status for r in results}


class CommitControlCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.vault = self.base / "vault"
        self.vault.mkdir()
        self.root = self.base / "projects" / "widget"
        self._previous = os.environ.get(private.PRIVATE_ENV)
        os.environ[private.PRIVATE_ENV] = str(self.vault)
        # A shim in the test's own temp tree, so these tests do not depend on the tool
        # having been installed on the host that runs them.
        self.bindir = self.base / "bin"
        self.bindir.mkdir()
        shim = self.bindir / "openready"
        shim.write_text(f'#!/bin/sh\nexec env PYTHONPATH="{ROOT / "src"}" python3 -m openready "$@"\n',
                        encoding="utf-8")
        shim.chmod(0o755)
        project.create(self.root, "widget")

    def tearDown(self):
        if self._previous is None:
            os.environ.pop(private.PRIVATE_ENV, None)
        else:
            os.environ[private.PRIVATE_ENV] = self._previous
        self._tmp.cleanup()

    def git(self, *args, **kwargs):
        env = dict(fixtures.git_env(os.environ))
        env["PATH"] = f"{self.bindir}:" + env.get("PATH", "")
        return subprocess.run(["git", "-C", str(self.root), *args],
                              capture_output=True, text=True, env=env,
                              timeout=300, **kwargs)

    def cli(self, *args):
        return subprocess.run([str(self.bindir / "openready"), *args],
                              capture_output=True, text=True, timeout=300,
                              env=fixtures.git_env(os.environ))

    def commits(self):
        return self.git("rev-list", "--all", "--count").stdout.strip()


class TestTheHookIsInstalled(CommitControlCase):
    def test_creation_installs_and_wires_an_executable_advisory_hook(self):
        hook = self.root / project.HOOK_PATH
        self.assertTrue(hook.is_file())
        self.assertTrue(os.access(hook, os.X_OK), "an inert hook looks installed")
        configured = self.git("config", "--local", "core.hooksPath").stdout.strip()
        self.assertEqual(configured, ".githooks")

    def test_the_hook_says_it_is_advisory_and_not_enforcement(self):
        text = (self.root / project.HOOK_PATH).read_text(encoding="utf-8")
        self.assertIn("NOT ENFORCEMENT", text)
        self.assertIn("--no-verify", text)
        self.assertNotIn("/home/", text, "the hook must not embed this machine's path")

    def test_the_creation_result_labels_the_hook_not_enforced(self):
        results = project.create(self.base / "projects" / "second", "second")
        control = [r for r in results if r.check_id == "init.commit-control"][0]
        self.assertEqual(control.status, PASS)
        self.assertEqual(control.enforcement, NOT_ENFORCED)
        self.assertIn("--no-verify", " ".join(control.limitations))

    def test_the_hook_allows_a_commit_when_the_tool_is_not_on_path(self):
        bare = dict(os.environ, PATH="/usr/bin:/bin")
        done = subprocess.run(["sh", str(self.root / project.HOOK_PATH)],
                              cwd=str(self.root), capture_output=True, text=True,
                              env=bare, timeout=120)
        self.assertEqual(done.returncode, 0)
        self.assertIn("ADVISORY CHECK SKIPPED", done.stderr)


class TestPrecommitBlocks(CommitControlCase):
    def test_a_staged_credential_shape_is_refused(self):
        (self.root / "settings.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "settings.py")
        results = staged.run(self.root)
        self.assertEqual(_statuses(results)["precommit.blocked"], FAIL)
        self.assertEqual(results[0].severity, STOP)
        self.assertIn("settings.py", results[0].message)

    def test_a_real_commit_is_actually_refused(self):
        before = self.commits()
        (self.root / "settings.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "settings.py")
        done = self.git("commit", "-m", "add settings")
        self.assertNotEqual(done.returncode, 0, "the hook must fail the commit")
        self.assertEqual(self.commits(), before)

    def test_no_verify_really_does_bypass_it(self):
        """The stated limitation is asserted here, not merely claimed in a comment.

        If this test ever fails, the hook stopped being advisory -- and the honest label
        on it became wrong, which is the more dangerous direction.
        """
        before = int(self.commits())
        (self.root / "settings.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "settings.py")
        done = self.git("commit", "--no-verify", "-m", "bypass the hook deliberately")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(int(self.commits()), before + 1)

    def test_the_staged_blob_is_scanned_not_the_working_tree_file(self):
        """A partial stage means the working tree is clean while history would not be."""
        target = self.root / "settings.py"
        target.write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "settings.py")
        target.write_text('KEY = "removed from the working tree"\n', encoding="utf-8")
        results = staged.run(self.root)
        self.assertEqual(_statuses(results)["precommit.blocked"], FAIL,
                         "the blob that would become history is what matters")

    def test_a_staged_database_is_refused(self):
        (self.root / "records.sqlite3").write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
        self.git("add", "-f", "records.sqlite3")
        results = staged.run(self.root)
        self.assertEqual(_statuses(results)["precommit.blocked"], FAIL)

    def test_nothing_staged_is_a_pass_and_says_what_it_means(self):
        results = staged.run(self.root)
        self.assertEqual(_statuses(results)["precommit.scanned"], PASS)
        self.assertEqual(results[0].enforcement, NOT_ENFORCED)
        self.assertIn("nothing is staged", results[0].message)

    def test_a_clean_staged_change_says_a_pass_means_nothing_matched(self):
        (self.root / "harmless.txt").write_text("nothing sensitive here\n", encoding="utf-8")
        self.git("add", "harmless.txt")
        results = staged.run(self.root)
        self.assertEqual(_statuses(results)["precommit.scanned"], PASS)
        self.assertIn("means nothing matched", " ".join(results[0].limitations))

    def test_a_non_repository_is_not_run_rather_than_clean(self):
        plain = self.base / "plain"
        plain.mkdir()
        results = staged.run(plain)
        self.assertEqual(_statuses(results)["precommit.repository"], NOT_RUN)

    def test_no_release_only_finding_blocks_a_commit(self):
        """Case-fold collisions matter at export; they must not block ordinary work."""
        (self.root / "Notes.md").write_text("one\n", encoding="utf-8")
        (self.root / "notes.md").write_text("two\n", encoding="utf-8")
        self.git("add", "-f", "Notes.md", "notes.md")
        results = staged.run(self.root)
        self.assertNotIn("precommit.blocked", _statuses(results))
        self.assertEqual(_statuses(results)["precommit.advisory-findings"], "NEEDS_HUMAN")


class TestTheExitContract(CommitControlCase):
    """The exit contract is the whole substance of a hook: get it wrong and every commit
    in every project fails, which is how a control gets disabled rather than fixed."""

    def test_a_clean_staged_set_exits_zero_so_the_commit_can_proceed(self):
        done = self.cli("precommit", "--path", str(self.root))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_credential_in_the_staged_set_exits_one(self):
        (self.root / "settings.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "settings.py")
        done = self.cli("precommit", "--path", str(self.root))
        self.assertEqual(done.returncode, 1)

    def test_the_clean_case_is_not_reported_as_an_unenforced_required_check(self):
        """The specific defect: a required NOT_ENFORCED result maps to exit 3."""
        results = staged.run(self.root)
        for result in results:
            if result.status == PASS:
                self.assertFalse(
                    result.required and result.enforcement in (NOT_ENFORCED, "NOT_TESTED"),
                    f"{result.check_id} would force exit 3 and block every commit")


class TestScopeIsWhatTheCommitAdds(CommitControlCase):
    """Material already in history is not what a commit-time control can protect: it is
    already there, and refusing the next commit does not remove it. Scanning the whole
    index instead of the change re-blocks every commit forever, which is how a control
    gets disabled rather than fixed."""

    def test_a_long_committed_fixture_does_not_block_an_unrelated_commit(self):
        (self.root / "legacy.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "legacy.py")
        self.git("commit", "--no-verify", "-m", "a fixture that is already in history")
        (self.root / "typo.py").write_text("# an unrelated, harmless change\n", encoding="utf-8")
        self.git("add", "typo.py")
        done = self.cli("precommit", "--path", str(self.root))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn("precommit.blocked", _statuses(staged.run(self.root)))

    def test_the_same_fixture_blocks_when_it_is_being_added(self):
        """The control still does its job on the case it exists for."""
        (self.root / "legacy.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        self.git("add", "legacy.py")
        done = self.cli("precommit", "--path", str(self.root))
        self.assertEqual(done.returncode, 1)

    def test_the_first_commit_scans_everything_because_it_adds_everything(self):
        import subprocess as sp
        fresh = self.base / "fresh"
        fresh.mkdir()
        sp.run(["git", "init", "-q", "-b", "main", str(fresh)], check=True)
        (fresh / "leak.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        sp.run(["git", "-C", str(fresh), "add", "leak.py"], check=True)
        changed = staged.changed_entries(fresh)
        self.assertTrue(changed is None or "leak.py" in changed,
                        f"the first commit adds everything it stages; got {changed!r}")
        self.assertIn("precommit.blocked", _statuses(staged.run(fresh)))


class TestPrecommitHonoursAcknowledgements(CommitControlCase):
    def test_an_acknowledged_finding_does_not_block_the_commit(self):
        (self.root / "fixtures.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape",
            "path": "fixtures.py",
            "reason": "test fixture: an invented key shape, no real key material",
            "acknowledged_by": "unit test",
            "acknowledged_at": "2026-10-13",
            "expires": "2027-10-13",
        }]}), encoding="utf-8")
        self.git("add", "-f", "fixtures.py")
        results = staged.run(self.root)
        seen = _statuses(results)
        self.assertNotIn("precommit.blocked", seen)
        self.assertEqual(seen["precommit.scanned"], PASS)
        self.assertEqual(seen["override.applied"], "NEEDS_HUMAN")

    def test_an_expired_acknowledgement_does_not_suppress_anything(self):
        (self.root / "fixtures.py").write_text(f'KEY = """{FAKE_PEM}"""\n', encoding="utf-8")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape",
            "path": "fixtures.py",
            "reason": "test fixture: an invented key shape, no real key material",
            "acknowledged_by": "unit test",
            "acknowledged_at": "2020-01-01",
            "expires": "2020-01-02",
        }]}), encoding="utf-8")
        self.git("add", "-f", "fixtures.py")
        results = staged.run(self.root)
        seen = _statuses(results)
        self.assertEqual(seen["precommit.blocked"], FAIL)
        self.assertEqual(seen["override.entry-0.invalid"], "NEEDS_HUMAN")


if __name__ == "__main__":
    unittest.main()
