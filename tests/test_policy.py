"""Scoped owner approvals for external services (OR-011; acceptance tests A10, A12).

Run::

    cd <repo> && PYTHONPATH=src python3 -m unittest tests.test_policy -v

Every test points ``OPENREADY_POLICY_HOME`` at a scratch directory, so nothing
reads or writes the operator's real private data root.
"""

import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
import contextlib
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import policy  # noqa: E402
from openready.status import (  # noqa: E402
    FAIL,
    INFO,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    exit_code_for,
)

#: Use the session scratch directory (never /tmp, never the repo).
SCRATCH = pathlib.Path(os.environ.get(
    "OPENREADY_TEST_SCRATCH",
    os.environ.get("TMPDIR",
                   os.path.join(os.path.expanduser("~"), ".openready-test-scratch"))))
SCRATCH.mkdir(parents=True, exist_ok=True)

#: A documented AWS *example* key, not a real secret. Used to prove a
#: credential-shaped value written into a note is not stored.
FAKE_CREDENTIAL = fixtures.AWS_EXAMPLE_KEY
PRIVATE_PROSE = "my sister's address and a private journal fragment"


def future_date(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()


def past_date(days=1):
    return (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


class PolicyCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.root = pathlib.Path(self._tmp.name)
        self.env = {policy.POLICY_ENV: str(self.root)}
        self.path = policy.policy_file(self.env)

    def tearDown(self):
        self._tmp.cleanup()

    def write_document(self, grants):
        """Write a policy document directly, digesting each record like the writer does."""
        records = {}
        for service_id, record in grants.items():
            record = dict(record)
            record.setdefault("granted_at", datetime.now(timezone.utc).replace(
                microsecond=0).isoformat())
            record["digest"] = policy.record_digest(record)
            records[service_id] = record
        self.path.write_text(json.dumps(
            {"schema_version": policy.SCHEMA_VERSION, "policy": "external-services",
             "grants": records}), encoding="utf-8")


class TestNoPolicy(PolicyCase):
    """Test 1 -- A10/A12's honest state: nothing is authorised, and exit is never 0."""

    def test_no_policy_file_is_not_enforced_and_required(self):
        results = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(len(results), 1)
        result = results[0]
        # NOT_RUN by status (the closed status vocabulary has no NOT_ENFORCED value);
        # NOT_ENFORCED is the enforced label, and required keeps the exit code at 3.
        self.assertEqual(result.status, NOT_RUN)
        self.assertEqual(result.severity, REVIEW)
        self.assertTrue(result.required)
        self.assertEqual(result.enforcement, NOT_ENFORCED)
        # The message must say exactly what the tool can and cannot do.
        self.assertIn("cannot actually block a network call it does not make", result.message)
        self.assertIn("refuse to authorise one", result.message)
        self.assertTrue(result.limitations)

    def test_the_exit_code_is_three_never_zero(self):
        results = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(exit_code_for(results), 3)
        self.assertNotEqual(exit_code_for(results), 0)

    def test_load_reports_absence_as_not_run(self):
        document, problems = policy.load(self.env)
        self.assertEqual(document["grants"], {})
        self.assertEqual(problems[0].status, NOT_RUN)
        self.assertEqual(problems[0].check_id, "policy.absent")
        self.assertFalse(self.path.exists(), "reading must not create the file")


class TestActorGate(PolicyCase):
    """Test 2 -- only the owner writes, and a refused write leaves nothing behind."""

    def test_a_non_owner_grant_is_refused_and_writes_nothing(self):
        for actor in ("builder", "agent", "assistant", "OWNER", ""):
            with self.subTest(actor=actor):
                results = policy.grant("svc", "api.example.invalid", "public-metadata",
                                       future_date(), actor, env=self.env)
                self.assertEqual(results[0].status, FAIL)
                self.assertEqual(results[0].severity, STOP)
                self.assertFalse(self.path.exists(),
                                 "a refused grant must not create the policy file")

    def test_a_non_owner_revoke_is_refused(self):
        policy.grant("svc", "api.example.invalid", "public-metadata", future_date(),
                     "owner", env=self.env)
        before = self.path.read_bytes()
        results = policy.revoke("svc", "builder", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(self.path.read_bytes(), before)


class TestScopedPair(PolicyCase):
    """Test 3 -- the scope is the pair, never the host."""

    def test_an_exact_pair_is_authorised(self):
        results = policy.grant("journal-upload", "api.example.invalid",
                               "public-metadata", future_date(), "owner", env=self.env)
        self.assertEqual(results[0].status, PASS)

        results = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(results[0].status, PASS)
        self.assertEqual(results[0].severity, INFO)
        self.assertIn("journal-upload", results[0].message)
        self.assertIn(future_date(), results[0].message)

    def test_a_different_data_class_on_the_same_host_is_a_stop(self):
        policy.grant("journal-upload", "api.example.invalid", "public-metadata",
                     future_date(), "owner", env=self.env)
        results = policy.check("api.example.invalid", "private-notes", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].severity, STOP)
        self.assertEqual(results[0].check_id, "policy.data-class-mismatch")
        self.assertIn("pair", results[0].message)

    def test_a_different_host_for_the_same_class_is_not_enforced(self):
        policy.grant("journal-upload", "api.example.invalid", "public-metadata",
                     future_date(), "owner", env=self.env)
        results = policy.check("other.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(results[0].status, NOT_RUN)
        self.assertEqual(results[0].enforcement, NOT_ENFORCED)
        self.assertEqual(exit_code_for(results), 3)


class TestExpiry(PolicyCase):
    """Test 4 -- expiry is refused at grant time and lapses at check time."""

    def test_a_past_expiry_is_refused_at_grant_time(self):
        results = policy.grant("svc", "api.example.invalid", "public-metadata",
                               past_date(), "owner", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].severity, STOP)
        self.assertFalse(self.path.exists(), "a refused grant writes nothing")

    def test_an_expiry_more_than_366_days_out_is_refused(self):
        results = policy.grant("svc", "api.example.invalid", "public-metadata",
                               future_date(days=400), "owner", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertFalse(self.path.exists())

    def test_a_record_whose_expiry_has_passed_makes_check_fail(self):
        just_past = (datetime.now(timezone.utc) - timedelta(seconds=5)).replace(
            microsecond=0).isoformat()
        record = {
            "service_id": "svc", "destination": "api.example.invalid",
            "data_class": "public-metadata", "expires": just_past, "actor": "owner",
            "note_digest": None,
        }
        self.assertTrue(policy.is_expired(record), "an instant that has passed is expired")
        self.write_document({"svc": record})

        results = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].severity, STOP)
        self.assertEqual(results[0].check_id, "policy.approval-lapsed")
        self.assertIn("expired", results[0].message)

    def test_is_expired_handles_dates_and_bad_values(self):
        self.assertFalse(policy.is_expired({"expires": future_date(1)}))
        self.assertTrue(policy.is_expired({"expires": past_date(1)}))
        # Unreadable expiry fails closed: it is not a live approval.
        self.assertTrue(policy.is_expired({"expires": "not-a-date"}))


class TestRevocation(PolicyCase):
    """Test 5 -- revoke FAILs the check but the historical grant is still listed."""

    def setUp(self):
        super().setUp()
        policy.grant("svc", "api.example.invalid", "public-metadata", future_date(),
                     "owner", env=self.env)
        self.assertEqual(
            policy.check("api.example.invalid", "public-metadata", env=self.env)[0].status,
            PASS)

    def test_revoking_makes_check_fail(self):
        results = policy.revoke("svc", "owner", env=self.env)
        self.assertEqual(results[0].status, PASS)
        results = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].severity, STOP)
        self.assertIn("revoked", results[0].message)

    def test_the_historical_grant_survives_in_the_listing(self):
        policy.revoke("svc", "owner", env=self.env)
        listing = policy.rows(env=self.env)
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["service_id"], "svc")
        self.assertEqual(listing[0]["state"], "revoked")
        self.assertEqual(listing[0]["destination"], "api.example.invalid")
        self.assertTrue(listing[0]["revoked_at"])

    def test_an_unknown_service_cannot_be_revoked(self):
        results = policy.revoke("ghost", "owner", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].check_id, "policy.unknown-service")


class TestRedaction(PolicyCase):
    """Test 6 -- no note body is ever stored or listed; only its digest."""

    def test_a_credential_shaped_note_is_reduced_to_its_digest(self):
        note = f"deploy key {FAKE_CREDENTIAL} -- {PRIVATE_PROSE}"
        policy.grant("svc", "api.example.invalid", "public-metadata", future_date(),
                     "owner", note=note, env=self.env)

        listed = json.dumps(policy.rows(env=self.env))
        self.assertNotIn(note, listed)
        self.assertNotIn(FAKE_CREDENTIAL, listed)
        self.assertNotIn(PRIVATE_PROSE, listed)

        on_disk = self.path.read_text(encoding="utf-8")
        self.assertNotIn(FAKE_CREDENTIAL, on_disk)
        self.assertNotIn(PRIVATE_PROSE, on_disk)
        self.assertNotIn(note, on_disk)

        stored = json.loads(on_disk)["grants"]["svc"]
        expected = hashlib.sha256(note.encode("utf-8")).hexdigest()
        self.assertEqual(stored["note_digest"], expected,
                         "the file records only a sha256 of the note")

    def test_the_row_says_the_body_is_not_held(self):
        policy.grant("svc", "api.example.invalid", "public-metadata", future_date(),
                     "owner", note=PRIVATE_PROSE, env=self.env)
        row = policy.rows(env=self.env)[0]
        self.assertTrue(row["note_digest"])
        self.assertIn("not stored", row["note"])


class TestCorruptPolicy(PolicyCase):
    """Test 7 -- a corrupt file FAILs and is never silently replaced."""

    def test_a_corrupt_file_fails_and_is_left_untouched(self):
        self.path.write_text("{ this is not valid json", encoding="utf-8")
        before = self.path.read_bytes()

        _, problems = policy.load(self.env)
        self.assertEqual(problems[0].status, FAIL)
        self.assertEqual(problems[0].check_id, "policy.unreadable")

        checked = policy.check("api.example.invalid", "public-metadata", env=self.env)
        self.assertEqual(checked[0].status, FAIL)

        granted = policy.grant("svc", "api.example.invalid", "public-metadata",
                               future_date(), "owner", env=self.env)
        self.assertEqual(granted[0].status, FAIL,
                         "a grant must refuse to overwrite an unreadable policy")

        self.assertEqual(self.path.read_bytes(), before,
                         "the corrupt file must be byte-for-byte unchanged")

    def test_a_malformed_document_fails(self):
        self.path.write_text(json.dumps({"policy": "external-services"}), encoding="utf-8")
        _, problems = policy.load(self.env)
        self.assertEqual(problems[0].check_id, "policy.malformed")


class TestDigestDetection(PolicyCase):
    """A content digest makes a later edit to a grant's scope detectable."""

    def test_editing_a_grant_after_it_is_written_is_detected(self):
        policy.grant("svc", "api.example.invalid", "public-metadata", future_date(),
                     "owner", env=self.env)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        document["grants"]["svc"]["data_class"] = "private-notes"
        self.path.write_text(json.dumps(document), encoding="utf-8")

        results = policy.check("api.example.invalid", "private-notes", env=self.env)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(results[0].check_id, "policy.tampered")


class TestCommandLine(PolicyCase):
    """The CLI refuses a non-owner actor and returns the contract's exit codes."""

    def _with_env(self, func):
        previous = os.environ.get(policy.POLICY_ENV)
        os.environ[policy.POLICY_ENV] = str(self.root)
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                return func()
        finally:
            if previous is None:
                os.environ.pop(policy.POLICY_ENV, None)
            else:
                os.environ[policy.POLICY_ENV] = previous

    def test_list_with_no_policy_exits_three(self):
        self.assertEqual(self._with_env(lambda: policy.main(["list"])), 3)

    def test_a_non_owner_grant_on_the_command_line_exits_one(self):
        def run():
            return policy.main(["grant", "--service-id", "svc", "--destination",
                                "api.example.invalid", "--data-class", "public-metadata",
                                "--expires", future_date(), "--actor", "builder"])
        self.assertEqual(self._with_env(run), 1)
        self.assertFalse(self.path.exists())

    def test_a_missing_actor_is_a_usage_error(self):
        def run():
            return policy.main(["revoke", "--service-id", "svc"])
        self.assertEqual(self._with_env(run), 64)

    def test_a_full_owner_round_trip_through_the_command_line(self):
        def run():
            granted = policy.main(["grant", "--service-id", "svc", "--destination",
                                   "api.example.invalid", "--data-class", "public-metadata",
                                   "--expires", future_date(), "--actor", "owner"])
            checked = policy.main(["check", "--destination", "api.example.invalid",
                                   "--data-class", "public-metadata"])
            revoked = policy.main(["revoke", "--service-id", "svc", "--actor", "owner"])
            after = policy.main(["check", "--destination", "api.example.invalid",
                                 "--data-class", "public-metadata"])
            return granted, checked, revoked, after
        self.assertEqual(self._with_env(run), (0, 0, 0, 1))


if __name__ == "__main__":
    unittest.main()
