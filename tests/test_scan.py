"""Candidate-tree controls. Each test names the inherited defect it prevents."""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import scan  # noqa: E402


class TestPrototypeDefects(unittest.TestCase):
    """The four failures demonstrated against reference/openready.py."""

    def test_host_path_in_content_is_a_finding(self):
        """DEFECT 1: the prototype exported docs/ content verbatim, host paths included."""
        findings = scan.scan_content("docs/runbook.md", ("run --store " + fixtures.HOST_PATH + "\n").encode())
        ids = [f.check_id for f in findings]
        self.assertIn("candidate.host-path", ids)
        self.assertTrue(all(f.status == "FAIL" for f in findings))

    def test_private_prose_is_not_claimable_clean(self):
        """DEFECT 1 corollary: prose is undetectable, so it must never be PASS-shaped."""
        findings = scan.scan_content(
            "docs/notes.md", b"My salary floor is confidential and my employer is X.\n")
        self.assertEqual(findings, [], "the scanner must not pretend to detect prose")

    def test_casefold_collision_detected(self):
        """DEFECT 2: src/CON.py + src/con.py passed with exit 0."""
        findings = scan.scan_paths(["src/Notes.md", "src/notes.md"])
        self.assertIn("candidate.casefold-collision", [f.check_id for f in findings])

    def test_reserved_windows_name_detected(self):
        findings = scan.scan_paths(["src/CON.py"])
        self.assertIn("candidate.reserved-name", [f.check_id for f in findings])

    def test_hardlink_detected(self):
        """DEFECT 3: a hardlink alias was exported as an independent file."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_text("x = 1\n")
            os.link(root / "src" / "a.py", root / "src" / "b.py")
            findings = scan.scan_links(root, "src/b.py")
            self.assertIn("candidate.hardlink", [f.check_id for f in findings])

    def test_lfs_pointer_detected(self):
        """DEFECT 4: a 130-byte LFS pointer was exported as ordinary text."""
        pointer = (b"version https://git-lfs.github.com/spec/v1\n"
                   b"oid sha256:" + b"a" * 64 + b"\nsize 12345\n")
        findings = scan.scan_content("assets/model.glb", pointer)
        self.assertIn("candidate.lfs-pointer", [f.check_id for f in findings])

    def test_symlink_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "outside.txt").write_text("private\n")
            os.symlink(root / "outside.txt", root / "src" / "link.txt")
            findings = scan.scan_links(root, "src/link.txt")
            self.assertIn("candidate.symlink", [f.check_id for f in findings])


class TestSecretShapes(unittest.TestCase):
    def test_credential_assignment_found(self):
        findings = scan.scan_content("src/api.py", fixtures.QUOTED_ASSIGNMENT.encode() + b"\n")
        self.assertIn("privacy.secret-shape", [f.check_id for f in findings])

    def test_every_secret_finding_carries_the_denylist_limitation(self):
        findings = scan.scan_content("src/api.py", b"token = 'ghp_" + b"a" * 36 + b"'\n")
        self.assertTrue(findings)
        for finding in findings:
            self.assertTrue(finding.limitation, "no limitation stated on a finding")

    def test_clean_content_yields_nothing(self):
        self.assertEqual(scan.scan_content("src/main.py", b"def main():\n    return 0\n"), [])


class TestEvidenceRedaction(unittest.TestCase):
    """`scan.redact_for_evidence`: a record must not be able to poison the export.

    Found by running the acceptance harness against this repository: `docs/
    ACCEPTANCE-STATE.md` and `.json` -- the record of the run -- carried the sandbox
    paths of the run and quotes of the credential-shaped fixtures it had just
    measured. The exporter then refused the repository that contained its own
    acceptance record, so every run made the self-export worse.
    """

    def test_a_home_path_becomes_a_tilde(self):
        redacted = scan.redact_for_evidence(("store " + fixtures.HOST_PATH + "\n").encode())
        self.assertIn(b"~/", redacted)
        self.assertEqual([f.check_id for f in scan.scan_content("x", redacted)], [])

    def test_a_credential_shape_is_replaced_by_a_marker(self):
        redacted = scan.redact_for_evidence(fixtures.AWS_EXAMPLE_KEY.encode())
        self.assertIn(scan.EVIDENCE_REDACTION_MARKER, redacted)
        self.assertNotIn(fixtures.AWS_EXAMPLE_KEY.encode(), redacted)
        self.assertEqual([f.check_id for f in scan.scan_content("x", redacted)], [])

    def test_a_value_split_across_a_newline_is_redacted_too(self):
        """The scanner scans a whitespace-stripped copy; redaction must match it."""
        blob = (fixtures.AWS_EXAMPLE_KEY[:12] + "\n" + fixtures.AWS_EXAMPLE_KEY[12:]).encode()
        self.assertEqual([f.check_id for f in scan.scan_content("x", blob)], ["privacy.secret-shape"])
        redacted = scan.redact_for_evidence(blob)
        self.assertEqual([f.check_id for f in scan.scan_content("x", redacted)], [])

    def test_a_header_split_inside_a_word_is_detected_at_all(self):
        """The evasion the whitespace pass could never catch, because it demands `\\s+`.

        Acceptance-row probing found this: compaction removes *all* whitespace, so a
        pattern requiring whitespace between its tokens cannot match the compacted copy
        -- and a header split inside a keyword (`...BEGI<newline>N RSA...`) matched
        neither copy. The pattern is whitespace-optional now.
        """
        blob = fixtures.PEM_HEADER_SPLIT_INSIDE_TOKEN.encode()
        self.assertEqual([f.check_id for f in scan.scan_content("x", blob)], ["privacy.secret-shape"])

    def test_a_value_split_with_indentation_is_detected(self):
        """Newlines *and* the indentation after them: what an evasion actually uses.

        Found on a real project while running this scanner over it. Removing all
        whitespace happened to close this case too, but at the cost below.
        """
        for blob in (fixtures.aws_key_split_with_indentation().encode(),
                     fixtures.pem_header_split_with_indentation().encode()):
            self.assertEqual([f.check_id for f in scan.scan_content("x", blob)],
                             ["privacy.secret-shape"], blob)

    def test_ordinary_code_is_not_read_as_a_credential(self):
        """The false positive the whitespace-stripping pass manufactured.

        On a real project: a binding whose name ends in `Secret` and whose value is a long
        object literal, spread over one line, compacted into what the pattern reads as one
        unbroken assignment. The scanner reported a credential in a line that has none, and
        a false positive costs an acknowledgement -- the currency this tool spends to be
        believed.

        The docstring of this test reproduced the same trap while it was being written: the
        compacted fragment was quoted here, and the joined copy made it match again.
        """
        for blob in (b"const withSecret = { ...draft, markdown: `x` };\n",
                     b"const secret = { a: 1, b: 2, c: 3 };\n",
                     b"access_token = build_token(options)\n"):
            self.assertEqual(scan.scan_content("x", blob), [], blob)

    def test_redaction_removes_an_indentation_split_too(self):
        blob = fixtures.aws_key_split_with_indentation().encode()
        self.assertEqual([f.check_id for f in scan.scan_content("x", blob)],
                         ["privacy.secret-shape"])
        self.assertEqual(scan.scan_content("x", scan.redact_for_evidence(blob)), [])

    def test_redaction_leaves_ordinary_text_alone(self):
        text = b"refused: candidate.export blocked by 12 finding(s)\n"
        self.assertEqual(scan.redact_for_evidence(text), text)


class TestContentObjectId(unittest.TestCase):
    """`scan.content_object_id` must be the id git itself computes.

    If it were not, an acknowledgement bound to a blob would never match the same
    bytes in the working tree, and `verify` would disagree with the exporter about a
    frozen candidate -- the failure this identifier exists to prevent. git is asked
    directly rather than assumed.
    """

    def test_it_matches_git_hash_object(self):
        payload = ("api_" + "key" + " = " + '"' + "a" * 20 + '"' + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            probe = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=str(probe), check=True)
            (probe / "f.txt").write_bytes(payload)
            git_id = subprocess.run(["git", "hash-object", "f.txt"], cwd=str(probe),
                                    capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(scan.content_object_id(payload), git_id[:12])

    def test_different_content_has_a_different_id(self):
        self.assertNotEqual(scan.content_object_id(b"a = 1\n"),
                            scan.content_object_id(b"a = 2\n"))

    def test_a_finding_carries_the_id_of_the_bytes_it_came_from(self):
        payload = b"x = 1\n"
        (finding,) = scan.scan_file("src/x.py", payload + b"run: " + fixtures.HOST_PATH.encode())
        self.assertEqual(finding.object_id, scan.content_object_id(
            payload + b"run: " + fixtures.HOST_PATH.encode()))


class TestPathSafety(unittest.TestCase):
    def test_traversal_and_absolutes_rejected(self):
        for case in ("../secret", "/etc/passwd", "src/../x", "src//x", "src\\x", "", "C:/x"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                scan.safe_relative(case)

    def test_denied_components_rejected(self):
        for case in ("src/.env", ".git/config", "src/id_rsa", "private/notes.md",
                     "secrets/x", "node_modules/x/y.js", "a/b.pem"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                scan.safe_relative(case)

    def test_ordinary_paths_allowed(self):
        self.assertEqual(str(scan.safe_relative("src/main.py")), "src/main.py")


class TestTreeScan(unittest.TestCase):
    def test_generated_directories_are_pruned_not_reported(self):
        """A materialised os.walk silently disables the skip list -- regression guard."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src" / "__pycache__").mkdir(parents=True)
            (root / "src" / "ok.py").write_text("x = 1\n")
            (root / "src" / "__pycache__" / "ok.cpython-314.pyc").write_bytes(b"\0\1\2")
            report = scan.scan_tree(root)
            self.assertNotIn("candidate.unsafe-name", [f.check_id for f in report.findings])
            self.assertNotIn("src/__pycache__/ok.cpython-314.pyc", report.files)
            self.assertIn("src/__pycache__", report.skipped)

    def test_a_mixed_tree_reports_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "ok.py").write_text("x = 1\n")
            (root / "src" / "bad.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
            (root / ".env").write_text("SECRET=1\n")
            report = scan.scan_tree(root)
            ids = {f.check_id for f in report.findings}
            self.assertIn("privacy.secret-shape", ids)
            self.assertIn("candidate.unsafe-name", ids)
            self.assertTrue(report.blocked)

    def test_large_file_is_NOT_RUN_not_PASS(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "big.bin").write_bytes(b"\0" * (scan.MAX_SCAN_BYTES + 1))
            report = scan.scan_tree(root)
            large = [f for f in report.findings if f.check_id == "candidate.unscanned-large-file"]
            self.assertEqual(len(large), 1)
            self.assertEqual(large[0].status, "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
