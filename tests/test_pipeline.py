"""The rest of the spine: ledger, history, private boundary, verify, backup, advice."""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import (
    advisory,
    backup,
    candidate,
    history,
    ledger,
    private,
    project,
    verify,
)
from openready.contracts import tool_root, validate_against  # noqa: E402
from openready.scan import scan_content  # noqa: E402
from openready.status import (
    EXIT_FAIL,
    FAIL,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    STOP,
    exit_code_for,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


def statuses(results):
    return {r.check_id: r.status for r in results}


def git(root, *args):
    # `core.hooksPath=` deliberately bypasses the commit-time control: this module's tests
    # put a credential into the object store on purpose, to prove the history scanner finds
    # it. The hook is advisory and this is how an operator skips it (see staged.py).
    return subprocess.run(["git", "-c", "core.hooksPath=", "-C", str(root), *args],
                          capture_output=True, text=True)


class TestPrivateBoundary(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_synthetic_fixture_is_clean_and_deterministic(self):
        first = private.synthetic_corpus(self.base / "one")
        second = private.synthetic_corpus(self.base / "two")
        self.assertEqual(first, second)
        for rel in first:
            data = (self.base / "one" / rel).read_bytes()
            self.assertEqual(data, (self.base / "two" / rel).read_bytes(), rel)
            self.assertEqual(scan_content(rel, data), [], f"{rel} must pass the deny-list")

    def test_a_private_location_inside_the_project_is_a_stop(self):
        env = {private.PRIVATE_ENV: str(self.root / "private")}
        results = private.boundary_results(self.root, env)
        self.assertEqual(statuses(results)["private.outside-project"], FAIL)

    def test_a_private_location_outside_the_project_passes(self):
        env = {private.PRIVATE_ENV: str(self.base / "vault")}
        results = private.boundary_results(self.root, env)
        self.assertEqual(statuses(results)["private.outside-project"], PASS)

    def test_a_project_file_naming_the_private_location_is_a_stop(self):
        env = {private.PRIVATE_ENV: str(self.base / "vault")}
        (self.root / "run.sh").write_text(f"tar -C {self.base / 'vault'} -cf x.tar .\n")
        results = private.boundary_results(self.root, env)
        check = [r for r in results if r.check_id == "private.no-absolute-reference"][0]
        self.assertEqual(check.status, FAIL)
        self.assertEqual(check.severity, STOP)

    def test_the_default_location_needs_no_environment_variable(self):
        results = private.boundary_results(self.root, {})
        self.assertEqual(private.private_home_source({}), "default")
        self.assertEqual(statuses(results)["private.outside-project"], PASS)


class TestLedger(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name) / "proj"
        self.root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_zero_dependencies_is_the_only_clean_outcome(self):
        document = ledger.build(self.root, "toy")
        results = ledger.results(document)
        self.assertEqual(statuses(results)["ledger.dependency-licenses"], PASS)

    def test_an_unknown_licence_is_a_human_review_not_a_pass(self):
        (self.root / "package.json").write_text(json.dumps({
            "name": "toy", "dependencies": {"left-pad": "^1.0.0"}}))
        results = ledger.results(ledger.build(self.root, "toy"))
        self.assertEqual(statuses(results)["ledger.dependency-licenses"], NEEDS_HUMAN)

    def test_a_forbidding_licence_is_a_stop(self):
        (self.root / "package.json").write_text(json.dumps({
            "name": "toy", "license": "UNLICENSED", "dependencies": {"x": "^1"}}))
        results = ledger.results(ledger.build(self.root, "toy"))
        self.assertEqual(statuses(results)["ledger.dependency-licenses"], FAIL)

    def test_obligations_never_assert_compatibility(self):
        for licence, expected in (("MIT", "carry_license_text"),
                                  ("Apache-2.0", "carry_license_and_notice"),
                                  ("GPL-3.0", "strong_copyleft_review_required"),
                                  ("UNLICENSED", "distribution_may_be_forbidden"),
                                  (None, "review_required")):
            with self.subTest(licence=licence):
                self.assertEqual(ledger.obligation_for(licence)[0], expected)

    def test_python_dependencies_are_read_from_pyproject(self):
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "toy"\nversion = "0.1"\nlicense = "MIT"\n'
            'dependencies = ["requests>=2.0", "click"]\n')
        document = ledger.build(self.root, "toy")
        names = {d["name"] for d in document["dependencies"]}
        self.assertEqual(names, {"requests", "click", "toy"})

    def test_asset_provenance_survives_a_rebuild(self):
        (self.root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
        first = ledger.build(self.root, "toy")
        self.assertTrue(all(a["provenance"] == "UNKNOWN" for a in first["assets"]))
        for asset in first["assets"]:
            asset["provenance"] = "OWN_WORK"
        ledger.save(self.root, first)
        second = ledger.build(self.root, "toy")
        self.assertEqual(second["assets"][0]["provenance"], "OWN_WORK",
                         "a rebuild must not wipe recorded provenance")

    def test_an_unprovenanced_asset_blocks_with_a_licence_question(self):
        (self.root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        results = ledger.results(ledger.build(self.root, "toy"))
        self.assertEqual(statuses(results)["ledger.assets"], NEEDS_HUMAN)

    def test_machine_generated_assets_carry_the_protectability_note(self):
        (self.root / "art.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        document = ledger.build(self.root, "toy")
        document["assets"][0]["provenance"] = "AI_GENERATED"
        ledger.save(self.root, document)
        rebuilt = ledger.build(self.root, "toy")
        self.assertIn("note", rebuilt["assets"][0])
        self.assertIn("may not attract copyright", rebuilt["assets"][0]["note"])


class TestHistory(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name) / "proj"
        project.init(self.root, "toy", git=True)
        (self.root / "src").mkdir(exist_ok=True)
        (self.root / "src" / "a.py").write_text("x = 1\n")
        git(self.root, "config", "user.name", "t")
        git(self.root, "config", "user.email", "t@example.invalid")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "one")

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_clean_repository_scans_and_reports_clean(self):
        report = history.scan(self.root)
        self.assertTrue(report["is_repository"])
        self.assertEqual(report["hit_count"], 0)
        self.assertFalse(report["truncated"])
        self.assertEqual(history.history_choice(report)["choice"], history.HISTORY_CLEAN_SCAN)

    def test_a_secret_removed_later_is_still_in_the_object_store(self):
        (self.root / "src" / "b.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "leak")
        (self.root / "src" / "b.py").write_text("api_key = None\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "remove")
        report = history.scan(self.root)
        self.assertGreater(report["hit_count"], 0,
                           "removing a value in a later commit must not hide it")
        self.assertEqual(history.history_choice(report)["choice"], history.SQUASH_REQUIRED)

    def test_the_scan_bound_is_reported_rather_than_hidden(self):
        report = history.scan(self.root, limit=1)
        self.assertTrue(report["truncated"])
        self.assertEqual(history.history_choice(report)["choice"], history.HISTORY_UNKNOWN)

    def test_no_repository_is_not_run_not_pass(self):
        plain = pathlib.Path(self._tmp.name) / "plain"
        plain.mkdir()
        results = history.results(None)
        self.assertEqual(results[0].status, NOT_RUN)
        self.assertEqual(results[0].enforcement, NOT_ENFORCED)


class PipelineCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.root = self.base / "proj"
        project.init(self.root, "toy", git=True)
        (self.root / "src").mkdir(exist_ok=True)
        (self.root / "src" / "alpha.py").write_text("def alpha():\n    return 1\n")
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "test_alpha.py").write_text(
            "import unittest\nimport sys, pathlib\n"
            "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n"
            "from src.alpha import alpha\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertEqual(alpha(), 1)\n\n"
            'if __name__ == "__main__":\n    unittest.main()\n')
        git(self.root, "config", "user.name", "t")
        git(self.root, "config", "user.email", "t@example.invalid")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "base")
        self.out = self.base / "cand"
        _, self.meta = candidate.export(self.root, self.out, "toy")

    def tearDown(self):
        self._tmp.cleanup()


class TestVerify(PipelineCase):
    def test_a_frozen_candidate_verifies_and_emits_a_valid_packet(self):
        results, packet = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["verify.digest"], PASS)
        self.assertEqual(statuses(results)["verify.file-integrity"], PASS)
        self.assertEqual(validate_against(tool_root(), "release-packet", packet), [])

    def test_tampering_with_a_file_is_detected(self):
        target = sorted((self.out / "src").glob("*.py"))[0]
        target.write_text(target.read_text() + "\nsneaky = True\n")
        results, packet = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["verify.file-integrity"], FAIL)
        self.assertIsNone(packet, "a packet must not be emitted for a candidate that failed")

    def test_an_added_file_is_detected(self):
        (self.out / "extra.py").write_text("added after export\n")
        results, _ = verify.verify(self.out, run_build=False)
        check = [r for r in results if r.check_id == "verify.manifest-complete"][0]
        self.assertEqual(check.status, FAIL)
        self.assertIn("extra.py", check.message)

    def test_a_removed_file_is_detected(self):
        target = sorted((self.out / "src").glob("*.py"))[0]
        target.unlink()
        results, _ = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["verify.manifest-complete"], FAIL)

    def test_the_packet_carries_every_kind_it_must_address(self):
        _, packet = verify.verify(self.out, run_build=False)
        kinds = {item["kind"] for item in packet["review_items"]}
        for required in verify.ALWAYS_REVIEWED:
            self.assertIn(required, kinds, f"{required} must never be omitted")
        self.assertEqual(packet["status"], "REVIEW_REQUIRED")

    def test_rights_are_never_reported_as_pass(self):
        """Ownership cannot be established by a scan, so PASS would invent a fact."""
        _, packet = verify.verify(self.out, run_build=False)
        rights = [i for i in packet["review_items"] if i["kind"] == "rights"][0]
        self.assertNotEqual(rights["status"], PASS)

    def test_a_missing_manifest_is_refused(self):
        shutil.rmtree(self.out)
        self.out.mkdir()
        results, packet = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["verify.readable"], FAIL)
        self.assertIsNone(packet)

    def test_the_restricted_build_runs_the_candidates_own_tests(self):
        results = verify.restricted_build(self.out)
        check = [r for r in results if r.check_id == "build.restricted-run"][0]
        self.assertEqual(check.status, PASS, check.message)
        self.assertTrue(any("NOT contained" in l for l in check.limitations))

    def test_the_restricted_build_does_not_see_the_operators_credentials(self):
        import os

        results = verify.restricted_build(self.out)
        self.assertTrue(all(r.check_id != "build.restricted-run"
                            or r.status in (PASS, FAIL, NOT_RUN) for r in results))
        # The environment handed to the child is explicitly minimal.
        self.assertTrue(os.environ.get("PATH"))

    def test_a_packet_is_written_when_a_destination_is_given(self):
        target = self.base / "packet.json"
        verify.verify(self.out, target, run_build=False)
        self.assertTrue(target.is_file())
        self.assertEqual(json.loads(target.read_text())["status"], "REVIEW_REQUIRED")


class TestBackup(PipelineCase):
    def test_a_backup_outside_the_project_restores_with_matching_hashes(self):
        vault = self.base / "vault"
        vault.mkdir()
        results, archive = backup.create(self.root, vault / "snap.tar.gz", private_dir=vault)
        self.assertIsNotNone(archive)
        restore_results, report = backup.verify_restore(archive)
        self.assertEqual(statuses(restore_results)["backup.restore-integrity"], PASS)
        self.assertGreater(report["restored"], 0)

    def test_a_backup_inside_the_project_is_refused(self):
        results, archive = backup.create(self.root, self.root / "snap.tar.gz")
        self.assertIsNone(archive)
        self.assertEqual(statuses(results)["backup.outside-project"], FAIL)

    def test_an_existing_backup_is_never_overwritten(self):
        vault = self.base / "vault"
        vault.mkdir()
        target = vault / "snap.tar.gz"
        target.write_text("do not lose me")
        results, archive = backup.create(self.root, target, private_dir=vault)
        self.assertIsNone(archive)
        self.assertEqual(target.read_text(), "do not lose me")

    def test_a_corrupted_archive_fails_the_restore(self):
        vault = self.base / "vault"
        vault.mkdir()
        _, archive = backup.create(self.root, vault / "snap.tar.gz", private_dir=vault)
        archive.write_bytes(b"not a tarball")
        results, _ = backup.verify_restore(archive)
        self.assertEqual(statuses(results)["backup.restore-readable"], FAIL)

    def test_the_migration_drill_proves_rollback_and_the_hazard(self):
        results = backup.migration_drill()
        by_id = statuses(results)
        self.assertEqual(by_id["migration.transactional-rollback"], PASS)
        self.assertEqual(by_id["migration.initial-state-preserved"], PASS)
        self.assertEqual(by_id["migration.reverse-statement"], PASS)
        self.assertEqual(by_id["migration.untransacted-hazard"], PASS)


class TestAdvisory(PipelineCase):
    def test_worth_writes_a_private_memo_outside_the_project(self):
        vault = self.base / "vault"
        vault.mkdir()
        import os

        previous = os.environ.get(private.PRIVATE_ENV)
        os.environ[private.PRIVATE_ENV] = str(vault)
        try:
            results, memo = advisory.worth(self.root, [], ledger.build(self.root, "toy"))
        finally:
            if previous is None:
                os.environ.pop(private.PRIVATE_ENV, None)
            else:
                os.environ[private.PRIVATE_ENV] = previous
        self.assertIn("not a publication decision", memo)
        self.assertIn("not legal advice", memo)
        path = results[0].evidence_path
        self.assertTrue(path and pathlib.Path(path).is_file())
        self.assertTrue(str(path).startswith(str(vault)),
                        "the memo is private and must not land inside the project")

    def test_worth_does_not_decide_the_licence(self):
        _, memo = advisory.worth(self.root, [], None, write=False)
        lowered = memo.lower()
        self.assertNotIn("you should license", lowered)
        self.assertNotIn("choose mit", lowered)

    def test_update_reports_contract_and_policy_state_without_changing_anything(self):
        results = advisory.update_dry_run(self.root)
        by_id = statuses(results)
        self.assertEqual(by_id["update.contracts-load"], PASS)
        self.assertEqual(by_id["update.policy-version"], PASS)
        self.assertEqual(by_id["update.destructive-action"], PASS)

    def test_update_flags_policy_drift(self):
        config_path = self.root / "openready.project.json"
        config = json.loads(config_path.read_text())
        config["checks_profile_version"] = "0.9"
        config_path.write_text(json.dumps(config))
        results = advisory.update_dry_run(self.root)
        self.assertEqual(statuses(results)["update.policy-version"], NEEDS_HUMAN)


class TestVerifyAgreesWithAcknowledgement(unittest.TestCase):
    """The verifier must neither contradict the exporter nor hide a real string."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self.root = self.base / "proj"
        project.init(self.root, "toy", git=True)
        (self.root / "fixture.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape", "path": "fixture.py",
            "reason": "Positive control: this fixture must be detected by the scanner.",
            "acknowledged_by": "test", "acknowledged_at": "2026-10-13"}]}))
        git(self.root, "config", "user.name", "t")
        git(self.root, "config", "user.email", "t@example.invalid")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "base")
        self.out = self.base / "cand"
        _, self.meta = candidate.export(self.root, self.out, "toy")

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_export_succeeds_and_records_the_acknowledgement(self):
        self.assertIsNotNone(self.meta)
        recorded = self.meta["acknowledged_findings"]
        self.assertEqual([(e["check_id"], e["path"]) for e in recorded],
                         [("privacy.secret-shape", "fixture.py")])
        # The reason, the author and the date travel with the finding: verify re-checks
        # them, so an entry without them suppresses nothing.
        for field in ("reason", "acknowledged_by", "acknowledged_at"):
            self.assertTrue(recorded[0].get(field), field)

    def test_verify_refuses_an_acknowledgement_that_would_not_have_been_written(self):
        """A candidate's own metadata must not be able to launder a real finding."""
        meta_path = self.out / "CANDIDATE.json"
        document = json.loads(meta_path.read_text(encoding="utf-8"))
        document["acknowledged_findings"] = [
            {"check_id": "privacy.secret-shape", "path": "fixture.py"}]
        meta_path.write_text(json.dumps(document), encoding="utf-8")
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertEqual(by_id["verify.acknowledgement-invalid"], FAIL)
        self.assertEqual(by_id["privacy.secret-shape"], FAIL,
                         "a finding cannot be suppressed by an invalid entry")

    def test_verify_escalates_instead_of_reporting_a_bare_failure(self):
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertNotIn("privacy.secret-shape", by_id,
                         "a bare FAIL would contradict the exporter")
        self.assertEqual(by_id["privacy.secret-shape.acknowledged"], NEEDS_HUMAN)

    def test_the_technically_clean_rest_still_verifies(self):
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertEqual(by_id["verify.digest"], PASS)
        self.assertEqual(by_id["verify.file-integrity"], PASS)

    def test_an_unacknowledged_string_in_a_frozen_candidate_is_still_a_failure(self):
        """Tampering with the metadata must not launder a finding."""
        meta_path = self.out / candidate.CANDIDATE_NAME
        meta = json.loads(meta_path.read_text())
        meta["acknowledged_findings"] = []
        meta_path.write_text(json.dumps(meta))
        results, _ = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["privacy.secret-shape"], FAIL)


class TestExitCodes(unittest.TestCase):
    def test_an_unrun_required_check_is_never_exit_zero(self):
        from openready.status import Result

        results = [Result("c", PASS, "INFO", "m", "v", "e"),
                   Result("d", NOT_RUN, "REVIEW", "m", "v", "e")]
        self.assertEqual(exit_code_for(results), 3)

    def test_a_failure_outranks_a_human_review(self):
        from openready.status import Result

        results = [Result("c", NEEDS_HUMAN, "REVIEW", "m", "v", "e"),
                   Result("d", FAIL, "STOP", "m", "v", "e")]
        self.assertEqual(exit_code_for(results), EXIT_FAIL)


if __name__ == "__main__":
    unittest.main()
