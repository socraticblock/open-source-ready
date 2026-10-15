"""Contracts: the subset validator must fail loudly, not vacuously."""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openready import contracts  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The vendored contracts belong to the TOOL and travel inside the package, so an
# installed copy resolves them. ROOT stays for the repo-level fixtures.
CONTRACTS_ROOT = contracts.tool_root()


class TestVendoredContracts(unittest.TestCase):
    def test_all_three_contracts_load_and_use_only_implemented_keywords(self):
        for name, path in contracts.contract_paths(CONTRACTS_ROOT).items():
            with self.subTest(contract=name):
                schema = contracts.load_schema(path)
                self.assertEqual(schema["$schema"], contracts.DRAFT_2020_12)
                self.assertEqual(contracts.unsupported_keywords(schema), set())

    def test_example_project_satisfies_the_project_contract(self):
        instance = json.loads(
            (ROOT / "examples" / "synthetic" / "project.example.json").read_text())
        self.assertEqual(contracts.validate_against(CONTRACTS_ROOT, "project", instance), [])


class TestValidatorBehaviour(unittest.TestCase):
    def test_missing_required_property_reported(self):
        errors = contracts.validate_against(CONTRACTS_ROOT, "project", {"schema_version": "1.0"})
        self.assertTrue(any("missing required property" in e for e in errors))

    def test_extra_property_rejected(self):
        instance = json.loads(
            (ROOT / "examples" / "synthetic" / "project.example.json").read_text())
        instance["odometer"] = 12
        errors = contracts.validate_against(CONTRACTS_ROOT, "project", instance)
        self.assertTrue(any("unexpected property" in e for e in errors))

    def test_const_and_enum_enforced(self):
        instance = json.loads(
            (ROOT / "examples" / "synthetic" / "project.example.json").read_text())
        instance["visibility"] = "PUBLIC"
        instance["risk_tier"] = "T9"
        errors = contracts.validate_against(CONTRACTS_ROOT, "project", instance)
        self.assertTrue(any("expected constant" in e for e in errors))
        self.assertTrue(any("is not one of" in e for e in errors))

    def test_pattern_enforced(self):
        instance = json.loads(
            (ROOT / "examples" / "synthetic" / "project.example.json").read_text())
        instance["project_id"] = "Bad_ID"
        errors = contracts.validate_against(CONTRACTS_ROOT, "project", instance)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_boolean_is_not_accepted_as_integer(self):
        schema = {"type": "integer"}
        self.assertTrue(contracts.validate(True, schema))

    def test_date_time_format_enforced(self):
        base = {
            "schema_version": "1.0", "check_id": "x", "status": "PASS",
            "severity": "INFO", "message": "m", "tool_version": "1",
            "timestamp": "yesterday", "environment": "e",
        }
        errors = contracts.validate_against(CONTRACTS_ROOT, "result", base)
        self.assertTrue(any("RFC 3339" in e for e in errors))

    def test_a_result_record_from_the_engine_validates(self):
        """The engine's emitted shape must satisfy its own contract."""
        from openready.status import INFO, PASS, Result
        record = Result("check.one", PASS, INFO, "ok", "0.1.0-p0", "linux-x86_64").to_dict()
        self.assertEqual(contracts.validate_against(CONTRACTS_ROOT, "result", record), [])


class TestSubsetSafety(unittest.TestCase):
    def test_unsupported_keyword_is_detected(self):
        schema = {
            "$schema": contracts.DRAFT_2020_12,
            "type": "object",
            "if": {"required": ["a"]},
            "then": {"required": ["b"]},
        }
        self.assertEqual(contracts.unsupported_keywords(schema), {"if", "then"})

    def test_load_schema_refuses_unsupported_keywords_instead_of_validating_vacuously(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "s.json"
            path.write_text(json.dumps({
                "$schema": contracts.DRAFT_2020_12,
                "type": "object",
                "oneOf": [{"required": ["a"]}],
            }))
            with self.assertRaises(contracts.SchemaError):
                contracts.load_schema(path)

    def test_non_draft_2020_12_schema_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "s.json"
            path.write_text(json.dumps({"$schema": "http://json-schema.org/draft-07/schema#"}))
            with self.assertRaises(contracts.SchemaError):
                contracts.load_schema(path)


if __name__ == "__main__":
    unittest.main()
