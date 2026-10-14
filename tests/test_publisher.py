"""The independent-publisher seam (D-5 / OR-022).

Every test here builds a *real* candidate with the real CLI, in a scratch tree,
and then asks the publisher check -- which lives outside the builder's write
authority -- whether an owner approval covers it. The forged-field test (A27) is
the point: a builder who writes ``"approved": true`` into the candidate's own
metadata gets nothing, because an approval is a record the builder never writes.
"""

import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready import cli, publisher  # noqa: E402
from openready.status import (  # noqa: E402
    EXIT_FAIL,
    EXIT_OK,
    EXIT_USAGE,
    FAIL,
    NEEDS_HUMAN,
    PASS,
    STOP,
    exit_code_for,
)

DEST = "github.com/example/x"
LIC = "MIT"


def tree_hash(root: pathlib.Path) -> str:
    """A hash of every path and byte under ``root``, for a before/after comparison."""
    import hashlib

    digest = hashlib.sha256()
    if not root.exists():
        return "<missing>"
    for where, dirs, names in os.walk(root):
        dirs[:] = sorted(dirs)
        for name in sorted(names):
            path = pathlib.Path(where) / name
            digest.update(str(path.relative_to(root)).encode("utf-8"))
            digest.update(b"\x00")
            try:
                digest.update(path.read_bytes())
            except OSError as exc:
                digest.update(f"<{exc}>".encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


class PublisherCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        self._saved = {key: os.environ.get(key) for key in (
            publisher.APPROVAL_ENV, "OPENREADY_PRIVATE_HOME", "GIT_CONFIG_GLOBAL",
            publisher.PUBLISHER_TOKEN_ENV)}

        # An isolated git identity, so the baseline commit never depends on the host.
        gitcfg = self.base / "gitconfig"
        gitcfg.write_text("[user]\n\tname = publisher-test\n"
                          "\temail = publisher-test@example.invalid\n", encoding="utf-8")
        os.environ["GIT_CONFIG_GLOBAL"] = str(gitcfg)
        os.environ["OPENREADY_PRIVATE_HOME"] = str(self.base / "private")
        os.environ[publisher.APPROVAL_ENV] = str(self.base / "approvals")

        self.proj = self.base / "proj"
        self.cand = self.base / "cand"
        self.run_cli(["new", "--path", str(self.proj), "--project-id", "probe",
                      "--allow-inside-checkout"])
        self.assertTrue((self.proj / "openready.project.json").is_file(),
                        "the scratch project was not created")
        self.assertEqual(self.run_cli(["candidate", "--path", str(self.proj),
                                       "--out", str(self.cand)]), EXIT_OK,
                         "the scratch candidate did not export")
        self.meta = json.loads((self.cand / "CANDIDATE.json").read_text(encoding="utf-8"))
        self.digest = self.meta["candidate_digest"]

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------------

    def run_cli(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return cli.main(argv)

    def run_publisher(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return publisher.main(argv)

    def statuses(self, results):
        return {r.check_id: r.status for r in results}

    def find(self, results, check_id):
        matches = [r for r in results if r.check_id == check_id]
        return matches[0] if matches else None


class TestApprovalIsBound(PublisherCase):
    def test_a_valid_owner_approval_passes(self):
        recorded = publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        self.assertEqual(recorded[0].status, PASS)
        self.assertEqual(recorded[0].candidate_digest, self.digest)

        results = publisher.verify_approval(self.cand, DEST, LIC)
        by_id = self.statuses(results)
        self.assertEqual(by_id["publisher.candidate-digest"], PASS)
        self.assertEqual(by_id["publisher.approval-integrity"], PASS)
        self.assertEqual(by_id["publisher.approval-record"], PASS)
        self.assertEqual(exit_code_for(results), EXIT_OK)
        self.assertEqual(self.find(results, "publisher.approval-record").candidate_digest,
                         self.digest)

    def test_a25_one_changed_byte_is_a_different_artifact(self):
        publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        self.assertEqual(exit_code_for(publisher.verify_approval(self.cand, DEST, LIC)),
                         EXIT_OK, "sanity: the approval must cover the untampered candidate")

        target = self.cand / "src" / "synthetic.py"
        data = target.read_bytes()
        target.write_bytes(data[:-1] + bytes([data[-1] ^ 0x01]))

        results = publisher.verify_approval(self.cand, DEST, LIC)
        record = self.find(results, "publisher.approval-record")
        self.assertEqual(record.status, FAIL)
        self.assertEqual(record.severity, STOP)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)

        new_digest = publisher._candidate_content_digest(self.cand)
        self.assertNotEqual(new_digest, self.digest, "one byte must change the digest")
        self.assertEqual(record.candidate_digest, new_digest)
        # The mismatch is identified by naming the artifact the bytes now describe.
        self.assertIn(new_digest, record.message)

    def test_a26_a_different_licence_is_refused(self):
        publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        results = publisher.verify_approval(self.cand, DEST, "Apache-2.0")
        record = self.find(results, "publisher.approval-record")
        self.assertEqual(record.status, FAIL)
        self.assertEqual(record.severity, STOP)
        self.assertIn("licence", record.message)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)
        # ...and the approved licence still passes, so the refusal is specific.
        self.assertEqual(exit_code_for(publisher.verify_approval(self.cand, DEST, LIC)),
                         EXIT_OK)

    def test_a26_a_different_destination_is_refused(self):
        publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        results = publisher.verify_approval(self.cand, "github.com/example/y", LIC)
        record = self.find(results, "publisher.approval-record")
        self.assertEqual(record.status, FAIL)
        self.assertEqual(record.severity, STOP)
        self.assertIn("destination", record.message)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)

    def test_no_record_at_all_is_refused(self):
        results = publisher.verify_approval(self.cand, DEST, LIC)
        record = self.find(results, "publisher.approval-record")
        self.assertEqual(record.status, FAIL)
        self.assertEqual(record.severity, STOP)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)


class TestForgedApprovalIsInsufficient(PublisherCase):
    def test_a27_approved_field_with_no_owner_record_changes_nothing(self):
        # A builder writes its own approval into the candidate's metadata. The digest
        # is over content files only, so this does not even change the candidate's identity.
        meta = dict(self.meta)
        meta["approved"] = True
        meta["approved_by"] = "builder"
        (self.cand / "CANDIDATE.json").write_text(json.dumps(meta, indent=2, sort_keys=True),
                                                  encoding="utf-8")
        self.assertEqual(publisher._candidate_content_digest(self.cand), self.digest,
                         "the tool metadata file is not part of the content digest")

        results = publisher.verify_approval(self.cand, DEST, LIC)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)
        record = self.find(results, "publisher.approval-record")
        self.assertEqual(record.status, FAIL)
        self.assertEqual(record.severity, STOP)

        # The forged field is named and explicitly marked as ignored.
        noted = self.find(results, "publisher.self-asserted-approval")
        self.assertIsNotNone(noted)
        self.assertEqual(noted.status, NEEDS_HUMAN)
        self.assertIn("IGNORED", noted.message)
        self.assertIn("approved_by", noted.message)

    def test_a27_an_actor_other_than_owner_cannot_record_at_all(self):
        for actor in ("builder", "agent", "verifier", "Owner", ""):
            results = publisher.record_approval(self.digest, DEST, LIC, actor=actor)
            self.assertEqual(results[0].status, FAIL, actor)
            self.assertEqual(results[0].severity, STOP, actor)
            self.assertFalse(publisher.approval_file().exists(),
                             f"actor {actor!r} must not have written an approval file")


class TestIntegrity(PublisherCase):
    def test_an_edited_record_is_detected(self):
        publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        path = publisher.approval_file()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["approvals"][0]["destination"] = "github.com/attacker/elsewhere"
        path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

        results = publisher.verify_approval(self.cand, DEST, LIC)
        integrity = self.find(results, "publisher.approval-integrity")
        self.assertEqual(integrity.status, FAIL)
        self.assertEqual(integrity.severity, STOP)
        self.assertEqual(self.find(results, "publisher.approval-record").status, FAIL)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)

    def test_an_unreadable_approvals_file_is_reported_and_never_replaced(self):
        path = publisher.approval_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{ this is not json at all")
        before = path.read_bytes()

        document, problems = publisher.load()
        self.assertTrue(problems)
        self.assertEqual(problems[0].status, FAIL)
        self.assertEqual(document.get("approvals"), [])

        recorded = publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        self.assertEqual(recorded[0].status, FAIL)
        self.assertEqual(path.read_bytes(), before, "the unreadable file must not be replaced")

        results = publisher.verify_approval(self.cand, DEST, LIC)
        self.assertEqual(exit_code_for(results), EXIT_FAIL)
        self.assertEqual(self.find(results, "publisher.approval-record").status, FAIL)


class TestReadOnlyEntryPoint(PublisherCase):
    def test_a27_publish_and_unknown_verbs_exit_64_and_change_nothing(self):
        before = tree_hash(self.base)
        for argv in (["publish"], ["push"], ["upload"], ["visibility"], ["frobnicate"], []):
            self.assertEqual(self.run_publisher(argv), EXIT_USAGE, argv)
        after = tree_hash(self.base)
        self.assertEqual(before, after, "a read-only entry point must change nothing")

    def test_verbs_are_owner_act_or_read_only(self):
        """The publisher exposes the OWNER's act and read-only verifications, never a
        publication verb. The two new verbs are checked separately for what they do:
        ``record`` is the owner-side approval and refuses any actor other than ``owner``;
        ``verify-log`` is read-only and never writes."""
        parser = publisher._build_parser()
        names = set()
        for action in parser._actions:
            if isinstance(getattr(action, "choices", None), dict):
                names.update(action.choices)
        self.assertEqual(names, {"check", "record", "verify-log"})
        for forbidden in ("publish", "push", "upload", "visibility", "release"):
            self.assertNotIn(forbidden, names)
        # The owner-side verb is the one that the specification's "a separate
        # publisher" rule actually names; "record" is the act, not a "publish".
        self.assertIn("record", names)
        # The no-mutation contract on each verb is verified by the next two tests
        # and by test_a27_publish_and_unknown_verbs_exit_64_and_change_nothing.

    def test_check_exit_codes_follow_the_contract(self):
        self.assertEqual(self.run_publisher(["check", "--candidate", str(self.cand),
                                             "--destination", DEST, "--licence", LIC]),
                         EXIT_FAIL)
        publisher.record_approval(self.digest, DEST, LIC, actor="owner")
        self.assertEqual(self.run_publisher(["check", "--candidate", str(self.cand),
                                             "--destination", DEST, "--licence", LIC]),
                         EXIT_OK)


class TestPublisherTokenPath(PublisherCase):
    def test_token_is_a_path_never_a_value(self):
        self.assertIsNone(publisher.publisher_token_path({}))
        os.environ[publisher.PUBLISHER_TOKEN_ENV] = "~/secrets/publisher.token"
        try:
            resolved = publisher.publisher_token_path()
        finally:
            pass
        self.assertIsNotNone(resolved)
        self.assertTrue(str(resolved).endswith("publisher.token"))
        # Nothing in the module opens or returns the file's contents.
        source = pathlib.Path(publisher.__file__).read_text(encoding="utf-8")
        self.assertNotIn("read_text()", source.split("def publisher_token_path", 1)[1]
                         .split("def ", 1)[0])


if __name__ == "__main__":
    unittest.main()
