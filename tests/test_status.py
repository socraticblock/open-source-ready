"""Exit-code semantics. The rule under test: 0 never means safe to publish."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready.status import (  # noqa: E402
    EXIT_FAIL,
    EXIT_NEEDS_HUMAN,
    EXIT_NOT_RUN,
    EXIT_OK,
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    STATUSES,
    STOP,
    Result,
    exit_code_for,
    is_release_ready,
    summarize,
)


def mk(status, required=True, enforcement=None, severity=INFO):
    return Result("c", status, severity, "m", "t", "e",
                  required=required, enforcement=enforcement)


class TestExitCodes(unittest.TestCase):
    def test_all_pass_is_zero(self):
        self.assertEqual(exit_code_for([mk(PASS), mk(PASS)]), EXIT_OK)

    def test_failure_outranks_everything(self):
        self.assertEqual(
            exit_code_for([mk(NOT_RUN), mk(NEEDS_HUMAN), mk(FAIL, severity=STOP)]),
            EXIT_FAIL)

    def test_required_human_review_is_two(self):
        self.assertEqual(exit_code_for([mk(NEEDS_HUMAN)]), EXIT_NEEDS_HUMAN)

    def test_required_unrun_is_three(self):
        self.assertEqual(exit_code_for([mk(NOT_RUN)]), EXIT_NOT_RUN)

    def test_required_not_enforced_is_three(self):
        self.assertEqual(
            exit_code_for([mk(PASS, enforcement=NOT_ENFORCED)]), EXIT_NOT_RUN)

    def test_optional_unrun_does_not_force_three(self):
        self.assertEqual(exit_code_for([mk(PASS), mk(NOT_RUN, required=False)]), EXIT_OK)

    def test_optional_human_review_does_not_force_two(self):
        self.assertEqual(
            exit_code_for([mk(NEEDS_HUMAN, required=False)]), EXIT_OK)

    def test_not_enforced_outranks_ok_but_not_failure(self):
        self.assertEqual(
            exit_code_for([mk(PASS, enforcement=NOT_ENFORCED), mk(FAIL)]), EXIT_FAIL)


class TestVocabulary(unittest.TestCase):
    def test_unknown_status_is_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            mk("PROBABLY_FINE")

    def test_unknown_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            Result("c", PASS, "WARN", "m", "t", "e")

    def test_unknown_enforcement_is_rejected(self):
        with self.assertRaises(ValueError):
            mk(PASS, enforcement="SORT_OF")

    def test_there_are_exactly_five_statuses(self):
        self.assertEqual(len(STATUSES), 5)

    def test_release_readiness_is_narrow(self):
        self.assertTrue(is_release_ready([mk(PASS)]))
        # An unrun check blocks readiness even though nothing "failed".
        self.assertFalse(is_release_ready([mk(PASS), mk(NOT_RUN, required=False)]))

    def test_to_dict_excludes_engine_side_bookkeeping(self):
        record = mk(PASS, required=False).to_dict()
        self.assertNotIn("required", record)
        self.assertEqual(record["schema_version"], "1.0")

    def test_summarize_counts_every_status_key(self):
        counts = summarize([mk(PASS), mk(FAIL), mk(PASS)])
        self.assertEqual(sorted(counts), sorted(STATUSES))
        self.assertEqual(counts[PASS], 2)


if __name__ == "__main__":
    unittest.main()
