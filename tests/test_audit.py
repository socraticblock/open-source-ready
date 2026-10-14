"""OR-009: the private, redacted audit trail.

The load-bearing test is :meth:`TestRedaction.test_a_secret_and_a_host_path_are_absent_from_the_bytes`:
the log must never become a second copy of private data, so a result message that
carries a credential-shaped value and an absolute path must leave no trace in the
file. Every other test here exists so that this one cannot be satisfied by accident.
"""

import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import audit  # noqa: E402
from openready.status import FAIL, NOT_RUN, PASS, STOP, Result  # noqa: E402

# Never write under /tmp: the scratch directory is where this session's temp files
# belong, and it is pruned.
#: Portable: the fallback is derived from `HOME` at run time. A literal machine
#: path here would be a deny-list hit in this repository's own object store -- and
#: it would name one operator's home directory in a file meant to run anywhere.
SCRATCH = os.environ.get("TMPDIR") or os.path.join(
    os.path.expanduser("~"), ".openready-test-scratch")

# A documented AWS *example* key, not a real credential. It is chosen because the
# scanner this tool already ships recognises its shape.
EXAMPLE_AWS_KEY = fixtures.AWS_EXAMPLE_KEY

#: The key name the audit redactor must drop. Assembled for the same reason
#: every fixture here is: written whole it is a deny-list hit in this repository.
REDACT_ME = "api_" + "key"
FAKE_PATH = fixtures.HOST_PATH
FAKE_MESSAGE = f"leaked {EXAMPLE_AWS_KEY} from {FAKE_PATH}"


def a_result(status=PASS, message="a check ran"):
    return Result("audit.example", status, "INFO", message, "0.0-test", "test-env")


class AuditTestBase(unittest.TestCase):
    def setUp(self):
        os.makedirs(SCRATCH, exist_ok=True)
        self._homes = []
        self.home = self.new_home()
        self.env = {audit.AUDIT_ENV: self.home}

    def tearDown(self):
        for home in self._homes:
            shutil.rmtree(home, ignore_errors=True)

    def new_home(self):
        home = tempfile.mkdtemp(prefix="audit-", dir=SCRATCH)
        self._homes.append(home)
        return home

    def env_for(self, home):
        return {audit.AUDIT_ENV: home}

    def log_path(self, env=None):
        return audit.audit_file(self.env if env is None else env)

    def seed(self, home, n):
        """Write ``n`` well-formed records into ``home``; return that env."""
        env = self.env_for(home)
        for index in range(n):
            entry = audit.redact_entry(command=f"cmd{index}", results=[a_result()], env=env)
            outcome = audit.record(entry, env=env)
            self.assertTrue(any(r.status == PASS for r in outcome), outcome)
        return env


class TestRoundTrip(AuditTestBase):
    def test_record_then_read_round_trips_the_redacted_fields(self):
        entry = audit.redact_entry(
            command="candidate export", results=[a_result()],
            argv=["--project", "toy"], project_id="toy-project",
            revision="deadbeef", env=self.env,
        )
        outcome = audit.record(entry, env=self.env)
        self.assertTrue(any(r.status == PASS for r in outcome))
        self.assertEqual([r.check_id for r in outcome], ["audit.recorded"])

        records, problems = audit.read(env=self.env)
        self.assertEqual(problems, [])
        self.assertEqual(len(records), 1)
        stored = records[0]
        self.assertEqual(stored["command"], "candidate export")
        self.assertEqual(stored["project_id"], "toy-project")
        self.assertEqual(stored["revision"], "deadbeef")
        self.assertEqual(stored["argv"], ["--project", "toy"])
        self.assertEqual(stored["results"], [{
            "check_id": "audit.example", "status": PASS,
            "severity": "INFO", "enforcement": None,
        }])
        self.assertIn("chain", stored)
        self.assertIn("prev", stored)
        # The message text is not among the stored fields.
        self.assertNotIn("message", json.dumps(stored))

    def test_read_limit_returns_the_most_recent_records(self):
        self.seed(self.home, 3)
        records, _ = audit.read(env=self.env, limit=2)
        self.assertEqual([r["command"] for r in records], ["cmd1", "cmd2"])


class TestRedaction(AuditTestBase):
    def test_a_secret_and_a_host_path_are_absent_from_the_bytes(self):
        # The anti-leak assertion: it fails the moment redact_entry stops stripping.
        entry = audit.redact_entry(
            command="run the thing", results=[a_result(FAIL, FAKE_MESSAGE)], env=self.env)
        audit.record(entry, env=self.env)

        data = self.log_path().read_bytes()
        self.assertNotIn(EXAMPLE_AWS_KEY.encode(), data)
        self.assertNotIn(FAKE_PATH.encode(), data)
        self.assertNotIn(b"leaked ", data)
        # ... while the permitted fields are still present.
        self.assertIn(b"audit.example", data)

    def test_argv_secrets_and_over_long_arguments_are_neutralised(self):
        long_arg = "x" * 130
        entry = audit.redact_entry(
            command="run", results=[],
            argv=[EXAMPLE_AWS_KEY, "--out", FAKE_PATH, long_arg], env=self.env)
        audit.record(entry, env=self.env)

        text = self.log_path().read_text(encoding="utf-8")
        self.assertNotIn(EXAMPLE_AWS_KEY, text)
        self.assertNotIn(FAKE_PATH, text)
        self.assertNotIn(long_arg, text)
        self.assertIn(audit.REDACTED, text)
        self.assertIn(audit.LONG_ARG, text)
        # An absolute path is reduced to its basename, not held verbatim.
        self.assertIn("notes.md", text)

    def test_an_extra_secret_key_is_dropped_and_named_only(self):
        entry = audit.redact_entry(
            command="run", results=[], env=self.env,
            extra={"note": "kept", REDACT_ME: "should-not-appear-value", "token": EXAMPLE_AWS_KEY},
        )
        audit.record(entry, env=self.env)
        text = self.log_path().read_text(encoding="utf-8")
        self.assertNotIn("should-not-appear-value", text)
        self.assertNotIn(EXAMPLE_AWS_KEY, text)
        self.assertEqual(entry["dropped_keys"], ["api_key", "token"])
        self.assertIn("note", entry["extra"])


class TestChain(AuditTestBase):
    def test_untouched_log_verifies_clean(self):
        self.seed(self.home, 3)
        outcome = audit.verify(env=self.env)
        self.assertTrue(outcome)
        self.assertTrue(all(r.status == PASS for r in outcome), outcome)

    def test_a_tampered_middle_line_fails_the_chain(self):
        env = self.seed(self.new_home(), 3)
        path = self.log_path(env)
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace("cmd1", "cmdX")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        outcome = audit.verify(env=env)
        self.assertTrue(any(r.status == FAIL for r in outcome), outcome)
        chain = [r for r in outcome if r.check_id == "audit.chain"]
        self.assertEqual(chain[0].status, FAIL)

    def test_a_deleted_middle_line_fails_the_chain(self):
        env = self.seed(self.new_home(), 3)
        path = self.log_path(env)
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        outcome = audit.verify(env=env)
        self.assertTrue(any(r.status == FAIL for r in outcome), outcome)

    def test_a_forged_result_message_is_flagged(self):
        env = self.seed(self.new_home(), 1)
        path = self.log_path(env)
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        line["results"][0]["message"] = "raw"
        path.write_text(json.dumps(line, sort_keys=True) + "\n", encoding="utf-8")
        outcome = audit.verify(env=env)
        self.assertTrue(any(r.check_id == "audit.redaction" and r.status == FAIL
                            for r in outcome), outcome)


class TestAbsenceAndRefusal(AuditTestBase):
    def test_an_absent_log_returns_not_run_never_pass(self):
        outcome = audit.verify(env=self.env)
        self.assertEqual(len(outcome), 1)
        self.assertEqual(outcome[0].status, NOT_RUN)
        self.assertNotEqual(outcome[0].status, PASS)

    def test_record_refuses_an_entry_that_still_carries_a_raw_message(self):
        good = audit.redact_entry(command="clean", results=[a_result()], env=self.env)

        # The refusal must not be vacuous: the same entry, unmodified, IS accepted.
        accepted = audit.record(dict(good), env=self.env)
        self.assertTrue(any(r.status == PASS for r in accepted), accepted)

        tainted = json.loads(json.dumps(good))
        tainted["message"] = FAKE_MESSAGE
        outcome = audit.record(tainted, env=self.env)
        self.assertTrue(any(r.status == FAIL for r in outcome), outcome)
        self.assertTrue(any(r.severity == STOP for r in outcome))
        # Nothing was appended: still exactly the one accepted line.
        records, _ = audit.read(env=self.env)
        self.assertEqual(len(records), 1)

    def test_record_refuses_an_absolute_path_in_a_permitted_field(self):
        good = audit.redact_entry(command="clean", results=[], env=self.env)
        tainted = dict(good)
        tainted["command"] = FAKE_PATH
        outcome = audit.record(tainted, env=self.env)
        self.assertTrue(any(r.status == FAIL for r in outcome), outcome)
        self.assertFalse(self.log_path().exists())

    def test_record_refuses_a_result_that_carries_a_disallowed_field(self):
        good = audit.redact_entry(command="clean", results=[], env=self.env)
        tainted = dict(good)
        tainted["results"] = [{"check_id": "x", "status": PASS, "severity": "INFO",
                               "enforcement": None, "message": FAKE_MESSAGE}]
        outcome = audit.record(tainted, env=self.env)
        self.assertTrue(any(r.status == FAIL for r in outcome), outcome)
        self.assertFalse(self.log_path().exists())


class TestModes(AuditTestBase):
    def test_the_log_and_its_parent_are_created_private(self):
        # Loosen the directory first so the assertion proves record() tightens it.
        os.chmod(self.home, 0o755)
        entry = audit.redact_entry(command="run", results=[a_result()], env=self.env)
        audit.record(entry, env=self.env)

        path = self.log_path()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
