"""The one-command honesty view must never omit an unverified control.

Two things are under test:

1. That the view is *real* -- it aggregates live capability detection, not just the
   hand-written table, and it never carries a ``PASS``.
2. That the view is *complete* -- the static source scan finds every place a
   ``NOT_ENFORCED``/``NOT_TESTED`` result is emitted and reports any check id the
   view cannot reach. The anti-omission test writes a brand-new emission into a
   scratch file and requires the scan to call it uncovered, so a stubbed-out
   ``source_scan`` fails the suite instead of passing it.
"""

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready import limits  # noqa: E402
from openready.status import (  # noqa: E402
    ENFORCEMENTS,
    EXIT_OK,
    FAIL,
    INFO,
    PASS,
    exit_code_for,
)

ROW_KEYS = {"requirement_id", "check_id", "status", "enforcement", "reason",
            "verified_by", "source"}


class TestDeclaredTable(unittest.TestCase):
    def test_every_declared_row_is_in_the_view_with_a_reason_and_a_verifier(self):
        declared = limits.declared_rows()
        self.assertTrue(declared, "the declared table must not be empty")
        view = {(row["check_id"], row["source"]): row for row in limits.rows(None)}
        for row in declared:
            with self.subTest(check=row["check_id"]):
                self.assertTrue(row["reason"].strip(),
                                "a declared row must say why it is unverified")
                self.assertTrue(row["verified_by"].strip(),
                                "a declared row must name what would verify it")
                self.assertIn((row["check_id"], "declared"), view)
                self.assertEqual(view[(row["check_id"], "declared")]["reason"],
                                 row["reason"])

    def test_declared_requirement_ids_use_a_known_prefix(self):
        for row in limits.declared_rows():
            with self.subTest(check=row["check_id"]):
                self.assertTrue(
                    row["requirement_id"].startswith(limits.REQUIREMENT_PREFIXES),
                    f"{row['requirement_id']!r} does not start with "
                    f"{limits.REQUIREMENT_PREFIXES}",
                )

    def test_the_required_acceptance_controls_are_all_covered(self):
        """The work order names these; each must have a declared row."""
        covered = {row["requirement_id"] for row in limits.declared_rows()}
        for requirement in ("A10", "A11", "A12", "A23", "A25", "A26", "A27",
                            "A28", "A29", "A31", "A32", "A33", "OR-025"):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, covered)

    def test_rows_carry_exactly_the_specified_keys(self):
        for row in limits.rows(None):
            with self.subTest(check=row["check_id"]):
                self.assertEqual(set(row), ROW_KEYS)
                self.assertIn(row["status"], limits.ROW_STATUSES)
                self.assertIn(row["source"], limits.ROW_SOURCES)
                if row["enforcement"] is not None:
                    self.assertIn(row["enforcement"], ENFORCEMENTS)


class TestRows(unittest.TestCase):
    def test_rows_without_a_project_root_works_and_is_never_pass(self):
        view = limits.rows(None)
        self.assertTrue(view)
        self.assertTrue(all(row["status"] != PASS for row in view))
        self.assertTrue(all(row["reason"].strip() for row in view))
        self.assertTrue(all(row["verified_by"].strip() for row in view))
        self.assertIn("declared", {row["source"] for row in view})

    def test_rows_aggregates_a_capability_row_from_a_real_project(self):
        """Aggregation must be live: prove it with a project built by the CLI."""
        import os

        from openready import cli  # imported here so no test depends on cwd at import

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            private_home = tmp_path / "private-data"
            root = tmp_path / "toy-project"
            os.environ.pop(limits.ENV_LIMITS, None)  # never let a stray override leak in
            os.environ["OPENREADY_PRIVATE_HOME"] = str(private_home)
            try:
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    cli.main(["new", "--path", str(root), "--json"])
            finally:
                os.environ.pop("OPENREADY_PRIVATE_HOME", None)
            self.assertTrue((root / "openready.project.json").is_file(),
                            f"the CLI did not create a project: {buffer.getvalue()[:400]}")
            view = limits.rows(root)

        capability_rows = [row for row in view if row["source"] == "capability"]
        self.assertTrue(capability_rows,
                        "rows(<project>) must aggregate live capability detection")
        for row in capability_rows:
            with self.subTest(check=row["check_id"]):
                self.assertIn(row["status"], limits.ROW_STATUSES)
                self.assertTrue(row["reason"].strip())
                self.assertTrue(row["verified_by"].strip())

    def test_an_unreadable_root_degrades_honestly(self):
        view = limits.rows(pathlib.Path("/nonexistent/openready/for/tests"))
        self.assertTrue(view)
        self.assertTrue(all(row["status"] != PASS for row in view))
        self.assertNotIn("doctor", {row["source"] for row in view})


class TestInjection(unittest.TestCase):
    def test_rows_injected_through_the_environment_are_included(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            extra = pathlib.Path(tmp) / "extra.json"
            extra.write_text(json.dumps({"rows": [{
                "requirement_id": "A99",
                "check_id": "acceptance.injected-probe",
                "status": "NOT_RUN",
                "enforcement": "NOT_ENFORCED",
                "reason": "injected by the test harness",
                "verified_by": "removing this override",
            }]}), encoding="utf-8")
            os.environ[limits.ENV_LIMITS] = str(extra)
            try:
                ids = {row["check_id"] for row in limits.declared_rows()}
                self.assertIn("acceptance.injected-probe", ids)
                view = {row["check_id"]: row for row in limits.rows(None)}
                self.assertIn("acceptance.injected-probe", view)
                self.assertEqual(view["acceptance.injected-probe"]["source"], "declared")
            finally:
                os.environ.pop(limits.ENV_LIMITS, None)
        self.assertNotIn("acceptance.injected-probe",
                         {row["check_id"] for row in limits.declared_rows()})


class TestCollect(unittest.TestCase):
    def test_collect_never_returns_empty_and_never_reports_green(self):
        for label, results in (("no root", limits.collect(None)),
                               ("missing root",
                                limits.collect(pathlib.Path("/nonexistent/openready")))):
            with self.subTest(case=label):
                self.assertTrue(results)
                count = [r for r in results if r.check_id == "limits.unverified-count"]
                self.assertEqual(len(count), 1)
                self.assertNotEqual(count[0].status, PASS)
                self.assertEqual(count[0].severity, INFO)
                self.assertTrue(all(r.check_id.startswith("limits.") for r in results))
                self.assertTrue(all(r.limitations for r in results))
                self.assertNotEqual(exit_code_for(results), EXIT_OK)


class TestSourceCoverage(unittest.TestCase):
    def test_source_scan_finds_no_uncovered_emission_on_this_source_tree(self):
        results = limits.source_scan()
        self.assertTrue(results, "source_scan must always report on itself")
        uncovered = [r for r in results if r.check_id == "limits.source-uncovered"]
        self.assertEqual(
            uncovered, [],
            "an emission is NOT reachable from the limits view: "
            + "; ".join(r.message for r in uncovered),
        )
        summary = [r for r in results if r.check_id == "limits.source-covered"]
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0].status, PASS)
        self.assertTrue(summary[0].limitations)

    def test_source_scan_reports_a_new_uncovered_emission(self):
        """The anti-omission proof: a fresh emission in a scratch dir is uncovered.

        If ``source_scan`` is stubbed out (returns nothing, or nothing uncovered)
        this test fails, because it demands the specific new check id be reported.
        """
        with tempfile.TemporaryDirectory() as tmp:
            scratch = pathlib.Path(tmp)
            (scratch / "fake_new_emission.py").write_text(
                "from openready.status import NOT_ENFORCED, NOT_RUN, REVIEW, Result\n"
                "\n"
                "def emit():\n"
                "    return Result('fake.new.check', NOT_RUN, REVIEW, 'm', 'v', 'e',\n"
                "                  enforcement=NOT_ENFORCED)\n",
                encoding="utf-8",
            )
            (scratch / "fake_unattributed.py").write_text(
                "from openready.status import NOT_TESTED, Result\n"
                "\n"
                "def emit(check_id):\n"
                "    return Result(check_id, 'NOT_RUN', 'REVIEW', 'm', 'v', 'e',\n"
                "                  enforcement=NOT_TESTED)\n",
                encoding="utf-8",
            )
            results = limits.source_scan(scratch)

        uncovered = [r for r in results if r.check_id == "limits.source-uncovered"]
        self.assertEqual(len(uncovered), 1,
                         f"a new emission must be reported uncovered: {results}")
        report = uncovered[0]
        self.assertEqual(report.status, FAIL)
        self.assertIn("fake.new.check", report.message)
        # The unattributable emission is reported too, never silently skipped.
        self.assertIn("fake_unattributed.py", report.message)
        self.assertIn("unattributed", report.message)

        summary = [r for r in results if r.check_id == "limits.source-covered"]
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0].status, FAIL)

    def test_exemptions_each_state_a_reason(self):
        self.assertTrue(limits.EXEMPTIONS)
        for filename, reason in limits.EXEMPTIONS.items():
            with self.subTest(filename=filename):
                self.assertTrue(filename.endswith(".py"))
                self.assertTrue(reason.strip(), "every exemption must state a reason")
                self.assertGreater(len(reason.strip()), 40)


if __name__ == "__main__":
    unittest.main()
