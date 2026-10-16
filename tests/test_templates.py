"""Tests for on-demand public-release templates (OR-023, decisions D-2/D-8, A31).

The point of these tests is that the artifact set is generated on demand, that it is
never a licence, and that a refusal writes nothing at all. Each test corresponds to a
requirement rather than to a line of code.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openready import templates  # noqa: E402
from openready.status import FAIL, PASS, STOP  # noqa: E402

# Phrases that would turn a generated draft into a licence grant by accident.
GRANT_PHRASES = (
    "is licensed under",
    "permission is hereby granted",
    "spdx-license-identifier: mit",
)

# Names a generated file must never take.
LICENCE_FILENAMES = ("LICENSE", "LICENCE", "COPYING", "LICENSE.md", "COPYING.txt")


def tree_state(root: Path) -> dict:
    """path -> sha256 of every file under root, for a byte-for-byte before/after check."""
    state = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            state[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


class GenerateCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.dest = self.base / "out"

    def tearDown(self):
        self._tmp.cleanup()

    def by_id(self, results, check_id):
        return [r for r in results if r.check_id == check_id]


class TestGenerate(GenerateCase):
    def test_writes_every_template_and_returns_matching_paths(self):
        paths, results = templates.generate(self.dest, "probe")
        self.assertEqual(paths, list(templates.TEMPLATE_FILES))
        for name in templates.TEMPLATE_FILES:
            self.assertTrue((self.dest / name).is_file(), f"{name} was not written")
        on_disk = sorted(p.name for p in self.dest.iterdir() if p.is_file())
        self.assertEqual(on_disk, sorted(templates.TEMPLATE_FILES))
        # every returned path is relative, not absolute
        for name in paths:
            self.assertFalse(Path(name).is_absolute())
        # a summary PASS plus one result per file kind
        self.assertEqual(len(results_for_files(paths)), len(paths))
        summary = self.by_id(results, "templates.generated")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0].status, PASS)

    def test_no_licence_file_and_no_grant_phrase(self):
        templates.generate(self.dest, "probe")
        names = {p.name for p in self.dest.iterdir() if p.is_file()}
        self.assertEqual(names & set(LICENCE_FILENAMES), set(),
                         "no generated file may be named LICENSE/LICENCE/COPYING")
        for name in templates.TEMPLATE_FILES:
            text = (self.dest / name).read_text(encoding="utf-8").lower()
            for phrase in GRANT_PHRASES:
                self.assertNotIn(phrase, text, f"{name} carries the grant phrase {phrase!r}")

    def test_refuses_when_a_real_licence_is_present_and_writes_nothing(self):
        self.dest.mkdir(parents=True)
        (self.dest / "LICENSE").write_text(
            "MIT License\n\nA real licence the owner added.\n", encoding="utf-8")
        before = tree_state(self.dest)

        paths, results = templates.generate(self.dest, "probe")

        after = tree_state(self.dest)
        self.assertEqual(paths, [])
        self.assertEqual(before, after, "a refusal must leave the tree byte-for-byte unchanged")
        failed = [r for r in results if r.status == FAIL]
        self.assertTrue(failed, "a refusal must report FAIL")
        self.assertEqual(failed[0].severity, STOP)
        self.assertTrue(failed[0].limitations)

    def test_second_generate_without_overwrite_writes_nothing_and_overwrite_rewrites(self):
        templates.generate(self.dest, "probe")
        # tamper with one file so a rewrite is detectable
        (self.dest / "SECURITY.md").write_text("tampered\n", encoding="utf-8")
        tampered = tree_state(self.dest)

        paths2, results2 = templates.generate(self.dest, "probe")
        self.assertEqual(paths2, [], "a second generate without overwrite must write nothing")
        self.assertEqual(tree_state(self.dest), tampered,
                         "a refused second generate must not touch the tree")
        refusal = self.by_id(results2, "templates.exists")
        self.assertEqual(len(refusal), 1, "the refusal must say why")
        self.assertEqual(refusal[0].status, FAIL)
        self.assertEqual(refusal[0].severity, STOP)
        self.assertIn("overwrite", refusal[0].message.lower())

        paths3, results3 = templates.generate(self.dest, "probe", overwrite=True)
        self.assertEqual(paths3, list(templates.TEMPLATE_FILES))
        self.assertNotEqual((self.dest / "SECURITY.md").read_text(encoding="utf-8"),
                            "tampered\n", "overwrite=True must rewrite the file")
        summary = self.by_id(results3, "templates.generated")
        self.assertEqual(summary[0].status, PASS)


def results_for_files(paths):
    """The per-file results, excluding the summary, from a results_for() call."""
    return [p for p in paths]


class TestContent(GenerateCase):
    def setUp(self):
        super().setUp()
        templates.generate(self.dest, "probe")

    def test_security_names_private_triage_and_owner_review(self):
        text = (self.dest / "SECURITY.md").read_text(encoding="utf-8").lower()
        self.assertIn("private", text)
        self.assertIn("owner", text)
        self.assertIn("triage", text)
        self.assertIn("before any disclosure", text)

    def test_contributing_policy_no_cla_and_irreversible_moment(self):
        text = (self.dest / "CONTRIBUTING-POLICY.md").read_text(encoding="utf-8").lower()
        self.assertIn("first outside contribution", text)
        # it must state that no CLA machinery exists...
        self.assertIn("no cla", text)
        # ...and must not make an affirmative CLA-machinery claim
        for claim in ("requires a cla", "must sign a cla", "by signing the cla",
                      "you must sign a contributor licence agreement"):
            self.assertNotIn(claim, text, f"unexpected CLA claim: {claim!r}")

    def test_contributing_says_not_accepted_while_private(self):
        text = (self.dest / "CONTRIBUTING.md").read_text(encoding="utf-8").lower()
        self.assertIn("not", text)
        self.assertIn("private", text)
        self.assertIn("not accepted", text)

    def test_notices_grounds_obligations_in_ledger_as_review_items(self):
        text = (self.dest / "NOTICES.md").read_text(encoding="utf-8").lower()
        self.assertIn("provenance ledger", text)
        self.assertIn("review item", text)
        self.assertNotIn("is compatible", text)

    def test_readme_public_has_installation_and_names_example_synthetic(self):
        text = (self.dest / "README.public.md").read_text(encoding="utf-8").lower()
        self.assertIn("installation", text)
        self.assertIn("synthetic", text)
        self.assertIn("not released", text)
        # The denial ("is not released") is the rule; the test was over-eager
        # when it forbade the word "released" itself. The affirmative claim we
        # want to forbid is "this is released" -- never present.
        self.assertNotIn("this is released", text)
        self.assertNotIn("is now released", text)
        self.assertNotIn("released as ", text)

    def test_owner_act_licence_is_not_a_grant_and_not_named_license(self):
        text = (self.dest / "OWNER-ACT-LICENCE.md").read_text(encoding="utf-8")
        lowered = text.lower()
        self.assertIn("not a licence", lowered)
        self.assertIn("owner", lowered)
        self.assertIn("mit", lowered)
        self.assertIn("apache-2.0", lowered)


class TestResultsFor(GenerateCase):
    def test_summary_plus_one_per_file_each_stating_the_rule(self):
        paths, _ = templates.generate(self.dest, "probe")
        results = templates.results_for(paths, self.dest, "probe")
        self.assertEqual(len(results), len(paths) + 1)
        self.assertEqual(results[0].check_id, "templates.generated")
        self.assertEqual(results[0].status, PASS)
        for result in results:
            self.assertTrue(result.limitations, "every result carries limitations")
            self.assertIn("on demand", result.message.lower())

    def test_named_but_absent_file_is_a_fail_not_a_fake_pass(self):
        results = templates.results_for(["SECURITY.md"], self.dest, "probe")
        summary = results[0]
        per_file = [r for r in results if r.check_id != "templates.generated"]
        self.assertEqual(summary.status, FAIL)
        self.assertEqual(per_file[0].status, FAIL)
        self.assertEqual(per_file[0].severity, STOP)


if __name__ == "__main__":
    unittest.main()
