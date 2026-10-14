"""Acknowledgements (A05). An override must be named, reasoned and visible."""

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready import overrides  # noqa: E402
from openready.scan import Finding  # noqa: E402

GOOD_REASON = "Positive control: this fixture must be detected by the scanner."


def entry(path, check_id="privacy.secret-shape", **overrides_kwargs):
    base = {
        "check_id": check_id,
        "path": path,
        "reason": GOOD_REASON,
        "acknowledged_by": "owner",
        "acknowledged_at": "2026-10-13",
    }
    base.update(overrides_kwargs)
    return base


class TestOverrides(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.finding = Finding("privacy.secret-shape", "fake key", "tests/fixture.py")

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, entries):
        (self.root / overrides.ALLOW_NAME).write_text(
            json.dumps({"entries": entries}), encoding="utf-8")

    def test_a_valid_acknowledgement_suppresses_and_is_reported(self):
        self._write([entry("tests/fixture.py")])
        remaining, results = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [])
        applied = [r for r in results if r.check_id == "override.applied"]
        self.assertEqual(len(applied), 1)
        self.assertIn("acknowledged_by owner", applied[0].message)
        # Visible, never silent: it appears as a human-review item.
        self.assertEqual(applied[0].status, "NEEDS_HUMAN")
        self.assertFalse(applied[0].required)

    def test_no_allow_file_changes_nothing(self):
        remaining, results = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])
        self.assertEqual(results, [])

    def test_a_blank_or_placeholder_reason_is_rejected_and_suppresses_nothing(self):
        for bad in ("", "n/a", "todo", "false positive", "short"):
            with self.subTest(reason=bad):
                self._write([entry("tests/fixture.py", reason=bad)])
                remaining, results = overrides.apply(self.root, [self.finding])
                self.assertEqual(remaining, [self.finding],
                                 "a bad reason must not suppress the finding")
                self.assertTrue(any("rejected" in r.message for r in results))

    def test_a_missing_acknowledger_is_rejected(self):
        self._write([entry("tests/fixture.py", acknowledged_by="")])
        remaining, _ = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])

    def test_an_expired_acknowledgement_lapses(self):
        self._write([entry("tests/fixture.py", expires="2020-01-01")])
        remaining, results = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])
        self.assertTrue(any("expired" in r.message for r in results))

    def test_a_future_expiry_still_applies(self):
        self._write([entry("tests/fixture.py", expires="2099-01-01")])
        remaining, _ = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [])

    def test_structural_findings_are_not_overridable(self):
        """There is no sense in which a symlink is a false positive."""
        for check_id in ("candidate.symlink", "candidate.hardlink",
                         "candidate.casefold-collision", "release.rights",
                         "egress.containment"):
            with self.subTest(check=check_id):
                finding = Finding(check_id, "m", "src/x")
                self._write([entry("src/x", check_id=check_id)])
                remaining, results = overrides.apply(self.root, [finding])
                self.assertEqual(remaining, [finding])
                self.assertTrue(any("not overridable" in r.message for r in results))

    def test_a_wildcard_path_does_not_match(self):
        self._write([entry("tests/*")])
        remaining, _ = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])

    def test_the_path_must_match_exactly(self):
        self._write([entry("tests/other.py")])
        remaining, _ = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])

    def test_an_acknowledgement_matching_nothing_is_reported(self):
        self._write([entry("tests/gone.py")])
        remaining, results = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])
        self.assertTrue(any(r.check_id == "override.unused" for r in results))

    def test_a_malformed_document_suppresses_nothing(self):
        (self.root / overrides.ALLOW_NAME).write_text("{not json", encoding="utf-8")
        remaining, results = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [self.finding])
        self.assertEqual(results[0].check_id, "override.readable")

    def test_the_acknowledgement_file_is_not_an_authorization(self):
        self._write([entry("tests/fixture.py")])
        _, results = overrides.apply(self.root, [self.finding])
        applied = [r for r in results if r.check_id == "override.applied"][0]
        self.assertTrue(any("not a release approval" in l for l in applied.limitations))

    def test_leading_dot_slash_is_normalised(self):
        self._write([entry("./tests/fixture.py")])
        remaining, _ = overrides.apply(self.root, [self.finding])
        self.assertEqual(remaining, [])


if __name__ == "__main__":
    unittest.main()
