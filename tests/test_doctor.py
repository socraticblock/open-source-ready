"""doctor must never render "we did not check" as "this is clean"."""

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import doctor, project  # noqa: E402
from openready.contracts import validate_against  # noqa: E402
from openready.status import EXIT_FAIL, EXIT_NOT_RUN, NOT_RUN  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _run_text(root):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = doctor.run(root, json_output=False)
    return code, buf.getvalue()


def _run_json(root):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = doctor.run(root, json_output=True)
    return code, json.loads(buf.getvalue())


class TestHonesty(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name) / "toy"
        project.init(self.root, "toy-project")

    def tearDown(self):
        self._tmp.cleanup()

    def test_private_prose_is_NOT_RUN_and_never_PASS(self):
        _, payload = _run_json(self.root)
        check = [r for r in payload["results"] if r["check_id"] == "privacy.private-prose"]
        self.assertEqual(len(check), 1)
        self.assertEqual(check[0]["status"], NOT_RUN)
        self.assertTrue(check[0]["limitations"])

    def test_exit_code_is_never_zero_while_required_checks_are_unrun(self):
        code, _ = _run_text(self.root)
        self.assertEqual(code, EXIT_NOT_RUN)

    def test_output_never_claims_no_blockers(self):
        _, text = _run_text(self.root)
        lowered = text.lower()
        for forbidden in ("no known blockers", "safe to publish", "no secrets exist",
                          "certified safe", "foolproof"):
            self.assertNotIn(forbidden, lowered)

    def test_output_states_the_publication_status(self):
        _, text = _run_text(self.root)
        self.assertIn("NOT APPROVED", text)

    def test_every_result_satisfies_the_result_contract(self):
        _, payload = _run_json(self.root)
        for record in payload["results"]:
            with self.subTest(check=record["check_id"]):
                self.assertEqual(
                    validate_against(ROOT, "result", record), [],
                    f"{record['check_id']} does not satisfy result.schema.json",
                )

    def test_unenforced_checks_are_labelled(self):
        _, payload = _run_json(self.root)
        by_id = {r["check_id"]: r for r in payload["results"]}
        for check_id in ("trust.publisher-separation", "egress.containment"):
            with self.subTest(check=check_id):
                self.assertEqual(by_id[check_id]["enforcement"], "NOT_ENFORCED")
        # Host isolation is NOT_TESTED, not NOT_ENFORCED: nothing was exercised.
        self.assertEqual(by_id["host.isolation"]["enforcement"], "NOT_TESTED")

    def test_a_placeholder_env_file_is_not_flagged_as_a_secret(self):
        """The spec mandates a committed placeholder config; it must be exportable."""
        _, payload = _run_json(self.root)
        unsafe = [r for r in payload["results"]
                  if r["check_id"] == "candidate.unsafe-name"]
        self.assertEqual(unsafe, [], "`.env.example` must not be treated as a secret path")

    def test_capabilities_are_reported_without_a_network_claim(self):
        _, payload = _run_json(self.root)
        egress = [c for c in payload["capabilities"]
                  if c["capability_id"] == "egress.containment"]
        self.assertEqual(egress[0]["enforcement"], "NOT_ENFORCED")


class TestFindings(unittest.TestCase):
    def test_a_fake_secret_is_a_STOP_and_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "toy"
            project.init(root, "toy-project")
            (root / "src" / "api.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
            code, payload = _run_json(root)
            self.assertEqual(code, EXIT_FAIL)
            secrets = [r for r in payload["results"]
                       if r["check_id"] == "privacy.secret-shape"]
            self.assertEqual(secrets[0]["status"], "FAIL")
            self.assertEqual(secrets[0]["severity"], "STOP")

    def test_a_host_path_is_a_STOP(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "toy"
            project.init(root, "toy-project")
            (root / "docs" / "runbook.md").write_text("store: " + fixtures.HOST_PATH + "\n")
            code, payload = _run_json(root)
            self.assertEqual(code, EXIT_FAIL)
            self.assertIn("candidate.host-path",
                          [r["check_id"] for r in payload["results"]])

    def test_a_project_inside_a_checkout_is_a_STOP(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer = pathlib.Path(tmp) / "outer"
            (outer / ".git").mkdir(parents=True)
            root = outer / "toy"
            project.init(root, "toy-project", force=True)
            code, payload = _run_json(root)
            self.assertEqual(code, EXIT_FAIL)
            check = [r for r in payload["results"]
                     if r["check_id"] == "git.enclosing-checkout"][0]
            self.assertEqual(check["status"], "FAIL")

    def test_missing_config_is_reported_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "notaproject"
            root.mkdir()
            code, payload = _run_json(root)
            self.assertEqual(code, EXIT_FAIL)
            self.assertEqual(
                [r for r in payload["results"] if r["check_id"] == "config.present"][0]["status"],
                "FAIL")

    def test_doctor_refuses_a_missing_directory(self):
        with self.assertRaises(NotADirectoryError):
            doctor.run(pathlib.Path("/nonexistent/path/for/tests"))


if __name__ == "__main__":
    unittest.main()
