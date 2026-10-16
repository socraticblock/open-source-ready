"""Regression tests for the defects found by the two fresh-context reviews.

Each test here corresponds to a concrete attack or requirement failure that was
reproduced against commit ef21f19 and then repaired. They exist so the repair cannot
quietly regress, and so the claim "the scanner catches this" is a test rather than a
comment.

Nothing here needs the network, a second machine, or a real secret.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402  (detectable values, assembled at run time)

from openready import advisory, backup, candidate, cli, doctor, history, ledger, overrides  # noqa: E402
from openready import private, project, scan, verify  # noqa: E402
from openready.status import (  # noqa: E402
    EXIT_FAIL,
    FAIL,
    NEEDS_HUMAN,
    NOT_RUN,
    PASS,
)


def statuses(results):
    return {r.check_id: r.status for r in results}


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    # The commit-time control is deliberately bypassed here, and that is the point: these
    # tests exist to prove the *history scanner* finds what is already in the object store,
    # so they have to put a credential there on purpose. `core.hooksPath=` is how an
    # operator bypasses the hook too -- it is advisory, not enforcement (see staged.py).
    return subprocess.run(["git", "-c", "core.hooksPath=", *args], cwd=str(root),
                          capture_output=True)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "project"
        project.init(self.root, "probe", git=True)
        git(self.root, "config", "user.name", "t")
        git(self.root, "config", "user.email", "t@example.invalid")
        self.out = self.base / "cand"

    def tearDown(self):
        self._tmp.cleanup()

    def commit(self, message: str = "x"):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", message)

    def export(self, **kwargs):
        return candidate.export(self.root, self.out, "probe", **kwargs)


# --- content scanning ---------------------------------------------------------

class TestScannerEvasions(Base):
    def test_a_home_path_without_a_trailing_slash_is_still_a_disclosure(self):
        """D01: a home path with no trailing component at end of line is the same
        disclosure as one with a trailing slash: it names the same account."""
        findings = scan.scan_content("src/leak.txt", fixtures.host_path_line().encode())
        self.assertIn("candidate.host-path", [f.check_id for f in findings])

    def test_an_unquoted_credential_assignment_is_detected(self):
        """D02: requiring a quoted value missed an unquoted assignment."""
        findings = scan.scan_content("config/app.yaml", fixtures.UNQUOTED_ASSIGNMENT.encode() + b"\n")
        self.assertIn("privacy.secret-shape", [f.check_id for f in findings])

    def test_a_private_key_header_split_across_a_newline_is_detected(self):
        """D02: a key header split by a newline defeated a line-oriented pattern."""
        findings = scan.scan_content("config/id.txt", fixtures.PEM_HEADER_SPLIT_BETWEEN_TOKENS.encode() + b"\n")
        self.assertIn("privacy.secret-shape", [f.check_id for f in findings])

    def test_a_directory_component_collision_is_detected(self):
        """D08: distinct filenames under `Lib/` and `lib/` collapse on a folding filesystem."""
        findings = scan.scan_paths(["src/Lib/a.txt", "src/lib/b.txt"])
        self.assertIn("candidate.casefold-collision", [f.check_id for f in findings])

    def test_ordinary_paths_are_not_reported_as_collisions(self):
        findings = scan.scan_paths(["src/a.py", "src/b.py", "docs/readme.md"])
        self.assertEqual([f for f in findings if f.check_id == "candidate.casefold-collision"], [])

    def test_a_submodule_is_a_structural_finding(self):
        """D03: `scan_tree` held this check, and only `doctor` ever called it."""
        (self.root / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n')
        findings = scan.scan_structure(self.root)
        self.assertIn("candidate.submodule", [f.check_id for f in findings])

    def test_an_env_file_is_reported_rather_than_silently_dropped(self):
        """F7: `.env` was excluded by name and its contents were never inspected."""
        (self.root / ".env").write_text("REAL_SECRET=1\n")
        findings = scan.scan_structure(self.root)
        self.assertIn("candidate.env-file", [f.check_id for f in findings])


class TestExportPathRunsTheStructuralChecks(Base):
    def test_a_gitmodules_repository_is_refused_by_the_exporter(self):
        (self.root / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n')
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.submodule"], FAIL)
        self.assertFalse(self.out.exists())

    def test_a_host_path_at_end_of_line_blocks_the_export(self):
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line())
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.host-path"], FAIL)


# --- the empty and clobbering exports ----------------------------------------

class TestExportRefusals(Base):
    def test_an_empty_allowlist_is_refused(self):
        """F1: an empty candidate exported and verified clean, digest of empty input."""
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.content"], FAIL)

    def test_a_non_empty_unrelated_destination_is_refused(self):
        """D06: export used to overwrite whatever sat at --out."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        victim = self.base / "victim"
        victim.mkdir()
        (victim / "notes.txt").write_text("IMPORTANT PRE-EXISTING DATA\n")
        results, meta = candidate.export(self.root, victim, "probe")
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.destination"], FAIL)
        self.assertEqual((victim / "notes.txt").read_text(), "IMPORTANT PRE-EXISTING DATA\n")

    def test_re_exporting_preserves_the_existing_candidate(self):
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, first = self.export()
        self.assertIsNotNone(first)
        _, second = self.export()
        self.assertIsNone(second)
        self.assertEqual(json.loads((self.out / "CANDIDATE.json").read_text()), first)


class TestSquashStaging(Base):
    def test_squash_stages_only_planned_paths(self):
        """D07: `git add -A` committed unscanned files sitting in the destination."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, first = self.export()
        self.assertIsNotNone(first)
        # A file that is in the destination but was never scanned: a re-export with
        # squash must not commit it just because it is sitting there.
        (self.out / "secret_leak.txt").write_text(
            fixtures.host_path_line(bare=False))
        results, meta = candidate.export(self.root, self.out, "probe", history_mode="squash", history_modes_allowed=True)
        self.assertIsNone(meta, [r.message for r in results])
        self.assertTrue((self.out / "secret_leak.txt").exists())
        tracked = git(self.out, "ls-files").stdout.decode()
        self.assertNotIn("secret_leak.txt", tracked)

    def test_squash_produces_exactly_one_commit(self):
        """A missing pathspec made `git add` abort, leaving a repository with no commits."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        report = history.scan(self.root)
        _, meta = candidate.export(self.root, self.out, "probe", history_mode="squash", history_modes_allowed=True,
                                   history_report=report)
        self.assertIsNotNone(meta)
        log = git(self.out, "log", "--format=%s").stdout.decode().splitlines()
        self.assertEqual(len(log), 1, log)


# --- history: "we did not check" must never read as clean ---------------------

class TestHistoryHonesty(Base):
    def _commit_a_large_secret_then_delete_it(self):
        (self.root / "big").mkdir()
        # Comfortably over MAX_SCAN_BYTES (4 MiB): the bound, not the content, was the
        # whole gate in the original defect.
        (self.root / "big" / "big.txt").write_text(
            fixtures.AWS_EXAMPLE_KEY + "\n" + "pad" * 3_000_000)
        self.commit("with big")
        git(self.root, "rm", "-q", "-r", "big")
        self.commit("without big")

    def test_an_oversized_object_is_reported_rather_than_skipped_silently(self):
        """D10: a blob over the size bound was counted and never surfaced."""
        self._commit_a_large_secret_then_delete_it()
        report = history.scan(self.root)
        self.assertGreater(report["oversized_skipped"], 0)
        complete, why_not = history.scanned_completely(report)
        self.assertFalse(complete)
        self.assertIn("NOT scanned", why_not)
        by_id = statuses(history.results(report))
        self.assertEqual(by_id["privacy.full-history"], NOT_RUN)
        self.assertNotEqual(by_id["privacy.full-history"], PASS)

    def test_an_oversized_object_refuses_the_export_regardless_of_mode(self):
        """The whole gate was the size bound: the same shape under 4 MiB was refused."""
        self._commit_a_large_secret_then_delete_it()
        results, meta = candidate.export(self.root, self.out, "probe", history_mode="preserve", history_modes_allowed=True)
        self.assertIsNone(meta)
        by_id = statuses(results)
        self.assertEqual(by_id.get("candidate.history-mode", by_id.get("candidate.history-unscanned")),
                         FAIL)
        self.assertFalse(self.out.exists())

    def test_the_default_mode_also_refuses_an_unscanned_object_store(self):
        self._commit_a_large_secret_then_delete_it()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.history-unscanned"], FAIL)

    def test_a_failed_object_store_read_is_not_reported_as_a_clean_scan(self):
        """D09: `rev-list` failing made every scan look like it found nothing."""
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line(bare=False))
        self.commit("with secret")
        git(self.root, "rm", "-q", "src/leak.txt")
        self.commit("without")
        (self.root / ".git" / "refs" / "heads" / "main").write_text("garbage\n")
        report = history.scan(self.root)
        self.assertTrue(report["scan_failed"])
        complete, why_not = history.scanned_completely(report)
        self.assertFalse(complete)
        self.assertEqual(statuses(history.results(report))["privacy.full-history"], NOT_RUN)

    def test_a_broken_object_store_refuses_the_export(self):
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line(bare=False))
        self.commit("with secret")
        git(self.root, "rm", "-q", "src/leak.txt")
        self.commit("without")
        (self.root / ".git" / "refs" / "heads" / "main").write_text("garbage\n")
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.history-unscanned"], FAIL)
        self.assertFalse(self.out.exists())

    def test_verify_scans_the_candidates_own_object_store(self):
        """A `preserve` candidate carries its history; verify used to ignore it."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        report = history.scan(self.root)
        _, meta = candidate.export(self.root, self.out, "probe", history_mode="squash", history_modes_allowed=True,
                                   history_report=report)
        self.assertIsNotNone(meta)
        by_id = statuses(verify.history_results(history.scan(self.out)))
        self.assertIn("privacy.full-history", by_id)

    def test_history_check_is_never_silently_absent_from_verify(self):
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertIn("privacy.full-history", by_id)

    def test_verify_does_not_contradict_the_exporter_about_known_strings(self):
        """Dogfooding found this: a candidate whose strings the exporter had already
        acknowledged failed verification over its own object store, so the two
        commands disagreed about the same frozen artifact."""
        (self.root / "src" / "fixture.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape", "path": "src/fixture.py",
            "reason": "Positive control for the deny-list; the value is synthetic.",
            "acknowledged_by": "owner", "acknowledged_at": "2026-01-01",
            "expires": "2027-01-01"}]}))
        self.commit()
        _, meta = self.export(history_mode="squash", history_modes_allowed=True)
        self.assertIsNotNone(meta)
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertEqual(by_id["candidate.history-excluded"], FAIL,
                         "history-bearing research artifacts are refused before further reads")


# --- identity and acknowledgements -------------------------------------------

class TestIdentity(Base):
    def _exported(self):
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        return meta

    def test_disagreeing_candidate_digests_fail_verification(self):
        """D05: `candidate_digest` was written and never read."""
        self._exported()
        meta_path = self.out / "CANDIDATE.json"
        document = json.loads(meta_path.read_text())
        document["candidate_digest"] = "sha256:" + "0" * 64
        meta_path.write_text(json.dumps(document))
        results, packet = verify.verify(self.out, run_build=False)
        self.assertEqual(statuses(results)["verify.digest"], FAIL)
        self.assertIsNone(packet, "no packet may be emitted for an inconsistent candidate")

    def test_an_acknowledgement_entry_must_carry_its_evidence(self):
        """D14: reason, author and date must travel with the entry to the artifact."""
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line())
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "candidate.host-path", "path": "src/leak.txt",
            "reason": "Documentation example; no real username is disclosed here.",
            "acknowledged_by": "owner", "acknowledged_at": "2026-01-01",
            "expires": "2027-01-01"}]}))
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        entry = meta["acknowledged_findings"][0]
        for field in ("reason", "acknowledged_by", "acknowledged_at", "expires"):
            self.assertTrue(entry.get(field), field)

    def test_an_expired_acknowledgement_suppresses_nothing(self):
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line())
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "candidate.host-path", "path": "src/leak.txt",
            "reason": "A lapsed acknowledgement must stop working.",
            "acknowledged_by": "owner", "acknowledged_at": "2020-01-01",
            "expires": "2020-06-01"}]}))
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.host-path"], FAIL)

    def test_an_acknowledgement_may_not_name_a_traversing_path(self):
        """D16: `lstrip("./")` turned `../src/leak.txt` into a valid-looking key."""
        with self.assertRaises(ValueError):
            overrides.normalise_path("../src/leak.txt")

    def test_a_traversing_acknowledgement_path_suppresses_nothing(self):
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line())
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "candidate.host-path", "path": "../src/leak.txt",
            "reason": "Naming a traversal path must not suppress a real finding.",
            "acknowledged_by": "owner", "acknowledged_at": "2026-01-01"}]}))
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.host-path"], FAIL)


class TestUnreadableFile(Base):
    def test_an_unreadable_candidate_file_is_a_finding_not_a_traceback(self):
        """D12: `read_bytes` raised out of `verify` and the bytes were never checked."""
        if os.geteuid() == 0:
            self.skipTest("root ignores mode bits")
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        target = self.out / "src" / "a.py"
        target.chmod(0o000)
        try:
            results, _ = verify.verify(self.out, run_build=False)
        finally:
            target.chmod(0o644)
        self.assertEqual(statuses(results)["verify.file-unreadable"], FAIL)


# --- ledger: unparsed is not absent ------------------------------------------

class TestLedgerHonesty(Base):
    def test_an_unparsed_manifest_is_reported_instead_of_passing(self):
        """D11: a Cargo.toml full of GPL crates produced "no dependencies declared"."""
        (self.root / "Cargo.toml").write_text('[package]\nname = "x"\n')
        (self.root / "Gemfile").write_text('source "https://rubygems.org"\n')
        document = ledger.build(self.root, "probe")
        self.assertIn("Cargo.toml", document["unparsed_manifests"])
        by_id = statuses(ledger.results(document))
        self.assertEqual(by_id["ledger.dependency-licenses"], NOT_RUN)
        self.assertNotEqual(by_id["ledger.dependency-licenses"], PASS)

    def test_an_uninventoried_binary_is_reported_instead_of_passing(self):
        (self.root / "vendor").mkdir()
        (self.root / "vendor" / "libfoo.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        document = ledger.build(self.root, "probe")
        self.assertIn("vendor/libfoo.so", document["unparsed_binaries"])
        self.assertEqual(statuses(ledger.results(document))["ledger.assets"], NOT_RUN)

    def test_a_genuinely_empty_project_still_passes_the_dependency_check(self):
        document = ledger.build(self.root, "probe")
        self.assertEqual(statuses(ledger.results(document))["ledger.dependency-licenses"], PASS)


# --- backup: both directions -------------------------------------------------

class TestBackupArchiveIntegrity(Base):
    def _make(self):
        (self.root / "src" / "a.py").write_text("a = 1\n")
        archive = self.base / "backup.tar.gz"
        results, path = backup.create(self.root, archive)
        return path

    def test_an_honest_archive_restores_cleanly(self):
        archive = self._make()
        results, report = backup.verify_restore(archive)
        by_id = statuses(results)
        self.assertEqual(by_id["backup.restore-integrity"], PASS)
        self.assertNotIn("backup.restore-unexpected", by_id)
        self.assertEqual(report["unexpected"], [])

    def test_a_file_injected_into_the_archive_is_detected(self):
        """D15: restore verification only checked that recorded files were present."""
        archive = self._make()
        members = []
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                data = tar.extractfile(member).read() if member.isfile() else None
                members.append((member, data))
        doctored = self.base / "doctored.tar.gz"
        with tarfile.open(doctored, "w:gz") as tar:
            for member, data in members:
                info = tarfile.TarInfo(member.name)
                info.size = len(data or b"")
                tar.addfile(info, io.BytesIO(data or b""))
            payload = b"#!/bin/sh\necho injected\n"
            info = tarfile.TarInfo("injected/evil.sh")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        shutil.copy(str(archive) + backup.MANIFEST_SUFFIX,
                    str(doctored) + backup.MANIFEST_SUFFIX)
        results, report = backup.verify_restore(doctored)
        by_id = statuses(results)
        self.assertEqual(by_id["backup.restore-unexpected"], FAIL)
        self.assertEqual(by_id["backup.archive-integrity"], FAIL)
        self.assertIn("injected/evil.sh", report["unexpected"])


# --- CLI contract ------------------------------------------------------------

class TestCliContract(Base):
    def test_a_usage_error_is_not_the_human_review_code(self):
        """F2: argparse exited 2, which the contract reserves for a blocking review."""
        self.assertEqual(cli.main(["init"]), 64)
        self.assertEqual(cli.main(["no-such-command"]), 64)

    def test_init_matches_the_documented_invocation(self):
        """F8: the contract's signature is `init --path PATH --language NAME`."""
        target = self.base / "from-name"
        self.assertEqual(cli.main(["init", "--path", str(target), "--language", "python"]), 0)
        document = json.loads((target / "openready.project.json").read_text())
        self.assertEqual(document["project_id"], "from-name")


class TestPrivateDataRoot(Base):
    def test_the_private_root_follows_the_platform_convention(self):
        """F9: `$HOME/openready-private` is not a data root on any platform."""
        linux = private.data_root({})
        self.assertEqual(linux.name, "share")
        self.assertEqual(private.data_root({}), Path.home() / ".local" / "share")
        self.assertEqual(private.data_root({"XDG_DATA_HOME": "/custom/share"}),
                         Path("/custom/share"))
        mac = private.data_root({"OPENREADY_OS": "darwin"})
        self.assertEqual(mac, Path.home() / "Library" / "Application Support")
        windows = private.data_root({"OPENREADY_OS": "win32", "LOCALAPPDATA": "/appdata"})
        self.assertEqual(windows, Path("/appdata"))

    def test_an_explicit_override_still_wins(self):
        self.assertEqual(private.private_home({private.PRIVATE_ENV: "/explicit/place"}),
                         Path("/explicit/place"))


class TestAdvisoryChecksCanFail(Base):
    def test_the_validator_probe_actually_probes(self):
        """F10: this was an unconditional PASS that could not fail."""
        results = advisory.update_dry_run(self.root)
        by_id = statuses(results)
        self.assertIn("update.validator-refuses-unknown-keywords", by_id)
        self.assertNotEqual(by_id["update.validator-refuses-unknown-keywords"], NOT_RUN)


class TestRoundTwoRepairs(Base):
    """Repairs from the second review round, each a reproduced failure before it."""

    # --- the denied-suffix escape (a database shipped with exit 0) -------------

    def test_a_rotated_copy_of_a_denied_artefact_is_excluded(self):
        """D17: only the final extension was compared, so `records.db.bak-161134` --
        a real database with every row intact -- was exported and verified clean."""
        (self.root / "data").mkdir()
        (self.root / "data" / "records.db.bak-161134").write_bytes(
            scan.DATABASE_SIGNATURES[0][1] + b"\x00" * 64)
        with self.assertRaises(ValueError):
            scan.safe_relative("data/records.db.bak-161134")
        plan = candidate.plan(self.root)
        self.assertNotIn("data/records.db.bak-161134", plan["included"])

    def test_a_timestamped_copy_of_a_denied_artefact_is_excluded(self):
        with self.assertRaises(ValueError):
            scan.safe_relative("data/records.db.20261013")

    def test_an_ordinary_extension_is_not_denied(self):
        """The rule must not swallow `db.py`, which is a source file."""
        for safe in ("db.py", "src/records.py", "docs/readme.md", ".gitignore",
                     ".env.example", "vendor/libfoo.so"):
            with self.subTest(path=safe):
                scan.safe_relative(safe)

    def test_a_database_is_refused_by_content_whatever_it_is_called(self):
        """A rename defeats any extension rule, so the magic number is checked too."""
        payload = scan.DATABASE_SIGNATURES[0][1] + b"\x00" * 64
        findings = scan.scan_content("notes.txt", payload)
        self.assertIn("candidate.database-file", [f.check_id for f in findings])
        (self.root / "src" / "notes.txt").write_bytes(payload)
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.database-file"], FAIL)

    def test_a_sqlite_sidecar_is_refused_by_name(self):
        """`records.db-wal` was allowed: one dotted token, `db-wal`, names no denied
        extension, and a write-ahead log's header is not the database magic."""
        for denied in ("data/records.db-wal", "data/records.db-shm",
                       "data/records.db-journal", "data/records.db.bak-1-wal"):
            with self.subTest(path=denied):
                with self.assertRaises(ValueError):
                    scan.safe_relative(denied)
        for allowed in ("src/db.py", "src/db-utils.py", "plugins/wal-utils.py",
                        "docs/db-notes.md", "src/walrus.py"):
            with self.subTest(path=allowed):
                scan.safe_relative(allowed)

    def test_a_renamed_write_ahead_log_is_refused_by_content(self):
        header = (b"\x37\x7f\x06\x82"
                  + (3007000).to_bytes(4, "big")
                  + (4096).to_bytes(4, "big")
                  + b"\x00" * 20)
        self.assertIsNotNone(scan._sqlite_sidecar_signature(header + b"row payload"))
        hits = [f.check_id for f in scan.scan_content("dump.dat", header + b"row payload")]
        self.assertIn("candidate.database-file", hits)
        # A four-byte magic alone is too weak to report, so the version and page size
        # have to agree too.
        for wrong in (b"\x37\x7f\x06\x82" + b"\x00" * 28,
                      b"\x37\x7f\x06\x82" + (12345).to_bytes(4, "big")
                      + (4096).to_bytes(4, "big") + b"\x00" * 20,
                      b"\x37\x7f\x06\x82" + (3007000).to_bytes(4, "big")
                      + (4000).to_bytes(4, "big") + b"\x00" * 20):
            with self.subTest(wrong=wrong[:12]):
                self.assertIsNone(scan._sqlite_sidecar_signature(wrong))

    def test_a_sidecar_holding_a_row_does_not_ship(self):
        """The reproduced leak: a write-ahead log carrying a committed row was exported
        at exit 0 with the row inside it."""
        payload = (b"\x37\x7f\x06\x82" + (3007000).to_bytes(4, "big")
                   + (4096).to_bytes(4, "big") + b"\x00" * 20
                   + b"|Jane Q. Applicant|123-45-6789|")
        (self.root / "data").mkdir()
        (self.root / "data" / "records.db-wal").write_bytes(payload)
        (self.root / "src" / "a.py").write_text("a = 1\n")
        git(self.root, "add", "-f", "data/records.db-wal")
        self.commit()
        results, meta = self.export()
        # The refusal this used to assert was about a file the plan drops: a history-free
        # candidate contains none of it. The property that has to hold is that the row does
        # not ship (checked against the candidate's own bytes below) and that the finding
        # stays visible instead of being cleared by an acknowledgement nobody read.
        self.assertIsNotNone(meta, "the export should proceed: the sidecar is not in the plan")
        self.assertFalse((self.out / "data" / "records.db-wal").exists())
        self.assertTrue([r for r in results
                         if r.check_id == "privacy.full-history" and r.status == FAIL],
                        "the object-store finding was not reported")
        leaked = [p for p in self.out.rglob("*")
                  if p.is_file() and b"123-45-6789" in p.read_bytes()]
        self.assertEqual(leaked, [], f"the row shipped inside {leaked}")

    # --- the credential-assignment false positives ----------------------------

    def test_a_key_at_end_of_line_is_not_a_credential(self):
        """D18: `\\s*` reached the newline, so a dictionary dispatch
        (a secret-named key followed by a call on the next line) was read as a
        credential."""
        source = (b'd = {\n'
                  b'    "client_secret":\n'
                  b'        store_client_secret(args.client_secret),\n'
                  b'}\n')
        findings = scan.scan_content("tools/setup.py", source)
        self.assertNotIn("privacy.secret-shape", [f.check_id for f in findings])

    def test_an_assignment_whose_value_is_a_call_is_not_a_credential(self):
        """D18: `secret = artifactFor(...)` is an expression, not a credential."""
        findings = scan.scan_content(
            "tests/gate.test.ts", b"const secret = artifactFor(join(root, 'x'));\n")
        self.assertNotIn("privacy.secret-shape", [f.check_id for f in findings])

    def test_the_assignment_evasions_are_still_detected(self):
        """The tightening must not cost the detections D02 was about."""
        for blob in (fixtures.UNQUOTED_ASSIGNMENT.encode() + b"\n",
                     fixtures.QUOTED_ASSIGNMENT.encode() + b"\n",
                     fixtures.CLIENT_SECRET_ASSIGNMENT.encode() + b"\n",
                     fixtures.PEM_HEADER_SPLIT_BETWEEN_TOKENS.encode() + b"\n"):
            with self.subTest(blob=blob):
                findings = scan.scan_content("config/app.yaml", blob)
                self.assertIn("privacy.secret-shape", [f.check_id for f in findings])

    # --- history: "is a repository" must not be asserted for a non-repository --

    def test_a_directory_that_is_not_a_repository_is_not_reported_as_one(self):
        """D19: `scan` returned is_repository True for any directory, which made the
        honest "carries no object store" branch in verify unreachable."""
        plain = self.base / "plain"
        plain.mkdir()
        (plain / "a.txt").write_text("hello\n")
        report = history.scan(plain)
        self.assertFalse(report["is_repository"])
        self.assertFalse(report["scan_failed"])

    def test_verify_says_a_candidate_carries_no_object_store(self):
        """D19: it used to say the object store "could not be read", which is a
        different and alarming claim about a candidate that has none by design."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, meta = self.export()          # history_mode="none": no .git travels
        self.assertIsNotNone(meta)
        results, _ = verify.verify(self.out, run_build=False)
        by_id = {r.check_id: r for r in results}
        self.assertEqual(by_id["privacy.full-history"].status, NOT_RUN)
        self.assertIn("carries no git object store",
                      by_id["privacy.full-history"].message)

    def test_doctor_runs_the_history_scan_it_used_to_deny_having(self):
        """D20: doctor asserted "no git history scan is implemented" while the exporter
        enforced one, so one object store was unscannable here and 20 findings there."""
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line(bare=False))
        self.commit("with secret")
        git(self.root, "rm", "-q", "src/leak.txt")
        self.commit("without")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            doctor.run(self.root, json_output=True)
        payload = json.loads(buffer.getvalue())
        by_id = {r["check_id"]: r for r in payload["results"]}
        self.assertIn("privacy.full-history", by_id)
        self.assertEqual(by_id["privacy.full-history"]["status"], FAIL)
        self.assertNotIn("no git history scan is implemented",
                         by_id["privacy.full-history"]["message"])

    def test_doctor_reports_a_history_hit_that_the_exporter_would_refuse(self):
        (self.root / "src" / "leak.txt").write_text(fixtures.host_path_line(bare=False))
        self.commit("with secret")
        git(self.root, "rm", "-q", "src/leak.txt")
        self.commit("without")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = doctor.run(self.root, json_output=True)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(code, EXIT_FAIL)
        # The gate must agree with the advice it prints.
        choice = [r for r in payload["results"]
                  if r["check_id"] == "candidate.history-choice"][0]
        self.assertIn("HISTORY_ROTATION_REQUIRED", choice["message"])
        self.assertIn("--history squash", choice["message"])

    # --- one acknowledgement, one report --------------------------------------

    def test_an_acknowledgement_is_not_reported_as_gone_and_applied_at_once(self):
        """D21: two acknowledgement passes made one entry "matched nothing -- the
        finding is gone" and "acknowledged (1 occurrence)" in the same run."""
        (self.root / "src" / "gone.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape", "path": "src/gone.py",
            "reason": "Synthetic value committed and deleted to exercise the blob scan.",
            "acknowledged_by": "test", "acknowledged_at": "2026-01-01",
            "expires": "2027-01-01"}]}))
        self.commit("with value")
        git(self.root, "rm", "-q", "src/gone.py")
        self.commit("without")
        results, meta = self.export()
        self.assertIsNotNone(meta, [r.message for r in results])
        self.assertEqual([r for r in results if r.check_id == "override.unused"], [],
                         "an entry that matched a blob was also reported as matching nothing")
        applied = [r for r in results if r.check_id == "override.applied"]
        self.assertEqual(len(applied), 1, [r.message for r in applied])

    # --- the digest anchor ----------------------------------------------------

    def _clean_export(self):
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        return meta

    def test_verification_without_an_anchor_says_what_it_did_not_prove(self):
        """D22: every check compared the candidate with itself, so a forgery that
        regenerated both records verified clean. The gap is now stated."""
        self._clean_export()
        results, _ = verify.verify(self.out, run_build=False)
        by_id = statuses(results)
        self.assertEqual(by_id["verify.digest-anchor"], NOT_RUN)

    def test_a_candidate_that_is_not_the_expected_artifact_fails(self):
        self._clean_export()
        results, packet = verify.verify(
            self.out, run_build=False, expected_digest="sha256:" + "0" * 64)
        self.assertEqual(statuses(results)["verify.digest-anchor"], FAIL)
        self.assertIsNone(packet, "no packet may describe an artifact that was not reviewed")

    def test_the_anchor_passes_when_it_matches(self):
        meta = self._clean_export()
        results, packet = verify.verify(
            self.out, run_build=False, expected_digest=meta["candidate_digest"])
        self.assertEqual(statuses(results)["verify.digest-anchor"], PASS)
        self.assertIsNotNone(packet)

    def test_the_anchor_accepts_a_bare_hex_digest(self):
        meta = self._clean_export()
        bare = meta["candidate_digest"].split(":", 1)[1]
        results, _ = verify.verify(self.out, run_build=False, expected_digest=bare)
        self.assertEqual(statuses(results)["verify.digest-anchor"], PASS)

    def test_a_regenerated_forgery_is_not_caught_without_an_anchor(self):
        """The honest statement of the residual limit: consistent forgery passes the
        integrity checks, and only the anchor closes it."""
        meta = self._clean_export()
        (self.out / "src" / "a.py").write_text("import os\nos.system('curl evil.invalid')\n")
        for name in (candidate.MANIFEST_NAME, candidate.CANDIDATE_NAME):
            document = json.loads((self.out / name).read_text())
            if name == candidate.MANIFEST_NAME:
                for entry in document["files"]:
                    data = (self.out / entry["path"]).read_bytes()
                    entry["sha256"] = hashlib.sha256(data).hexdigest()
                    entry["bytes"] = len(data)
                h = hashlib.sha256()
                for entry in sorted(document["files"], key=lambda e: e["path"]):
                    h.update(entry["path"].encode()); h.update(b"\x00")
                    h.update(entry["sha256"].encode()); h.update(b"\n")
                document["digest"] = "sha256:" + h.hexdigest()
                document["total_bytes"] = sum(e["bytes"] for e in document["files"])
            else:
                manifest = json.loads((self.out / candidate.MANIFEST_NAME).read_text())
                document["candidate_digest"] = manifest["digest"]
            (self.out / name).write_text(json.dumps(document, sort_keys=True))
        by_id = statuses(verify.verify(self.out, run_build=False)[0])
        self.assertEqual(by_id["verify.file-integrity"], PASS)
        self.assertEqual(by_id["verify.digest"], PASS)
        # ...and the anchor is the only thing that refuses it.
        results, _ = verify.verify(self.out, run_build=False,
                                   expected_digest=meta["candidate_digest"])
        self.assertEqual(statuses(results)["verify.digest-anchor"], FAIL)

    # --- a missing dependency is not a defect in the candidate -----------------

    def test_a_missing_dependency_is_NOT_RUN_not_a_candidate_failure(self):
        """D23: the restricted build installs nothing, so a module this machine lacks
        was reported as an actionable failure of the candidate (exit 1)."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "test_needs_a_module.py").write_text(
            "import openready_absent_module_for_tests\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        results = verify.restricted_build(self.out)
        check = [r for r in results if r.check_id == "build.restricted-run"][0]
        self.assertEqual(check.status, NOT_RUN, check.message)
        self.assertIn("openready_absent_module_for_tests", check.message)
        self.assertIn("not the candidate", check.message)

    def test_a_genuine_test_failure_is_still_a_FAIL(self):
        """The missing-dependency path must not swallow a real failure."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "test_broken.py").write_text(
            "import unittest\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_it(self):\n"
            "        self.assertEqual(1, 2)\n")
        self.commit()
        _, meta = self.export()
        self.assertIsNotNone(meta)
        results = verify.restricted_build(self.out)
        check = [r for r in results if r.check_id == "build.restricted-run"][0]
        self.assertEqual(check.status, FAIL, check.message)

    def test_a_failing_build_is_reported_with_a_reason(self):
        """The diagnosis arrived on stderr and the message only showed stdout."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "test_broken.py").write_text(
            "import unittest\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_it(self):\n"
            "        self.assertEqual(1, 2)\n")
        self.commit()
        _, meta = self.export()
        results = verify.restricted_build(self.out)
        check = [r for r in results if r.check_id == "build.restricted-run"][0]
        self.assertGreater(len(check.message.split("exited", 1)[-1].strip()), 10,
                           "the failure needs a reason, not an empty tail")

    # --- adopting an existing project ----------------------------------------

    def test_adopt_scaffolds_without_overwriting_anything(self):
        """D24: init refused every non-empty directory and offered no way to attach an
        existing project, so its config had to be hand-written."""
        existing = self.base / "existing"
        (existing / "src").mkdir(parents=True)
        (existing / "README.md").write_text("# my own readme, do not touch\n")
        (existing / "src" / "app.py").write_text("print('mine')\n")
        results = project.init(existing, "existing", adopt=True)
        by_id = statuses(results)
        self.assertNotIn("init.target-empty", by_id)
        self.assertEqual((existing / "README.md").read_text(), "# my own readme, do not touch\n")
        self.assertEqual((existing / "src" / "app.py").read_text(), "print('mine')\n")
        self.assertTrue((existing / project.CONFIG_NAME).is_file())
        self.assertEqual(by_id["init.kept"], NEEDS_HUMAN)
        document = json.loads((existing / project.CONFIG_NAME).read_text())
        self.assertEqual(document["project_id"], "existing")

    def test_init_without_adopt_still_refuses_a_populated_directory(self):
        existing = self.base / "populated"
        existing.mkdir()
        (existing / "keep.txt").write_text("x\n")
        results = project.init(existing, "populated")
        self.assertEqual(statuses(results)["init.target-empty"], FAIL)
        self.assertFalse((existing / project.CONFIG_NAME).exists())

    def test_adopting_a_project_that_already_has_a_config_is_refused(self):
        existing = self.base / "already"
        project.init(existing, "already")
        results = project.init(existing, "renamed", adopt=True)
        self.assertEqual(statuses(results)["init.already-project"], FAIL)

    # --- ledger and enforcement labels ----------------------------------------

    def test_the_ledger_does_not_call_a_project_its_own_dependency(self):
        """D25: a project whose own package.json says UNLICENSED failed a check whose
        message blamed "1 dependency(ies)" -- itself."""
        (self.root / "package.json").write_text(json.dumps({
            "name": "engineering-journal", "version": "0.1.0", "private": True,
            "license": "UNLICENSED"}))
        by_id = statuses(ledger.results(ledger.build(self.root, "probe")))
        self.assertEqual(by_id["ledger.dependency-licenses"], FAIL)
        message = [r for r in ledger.results(ledger.build(self.root, "probe"))
                   if r.check_id == "ledger.dependency-licenses"][0].message
        self.assertIn("this project's own manifest", message)
        self.assertNotIn("1 dependency(ies)", message)

    def test_the_two_surfaces_agree_about_host_isolation(self):
        by_id = {r.check_id: r for r in verify.limitation_results()}
        self.assertEqual(by_id["host.isolation"].enforcement, "NOT_TESTED")

    def test_a_file_a_path_rule_drops_is_named_in_the_result(self):
        """The exclusion is safe but was silent: the run said "wrote 10 file(s)" and
        never mentioned the file it left out."""
        (self.root / "private").mkdir()
        # `private/` is denied as a path component and is also in the scaffold's
        # `.gitignore`, so it has to be force-added -- which is exactly what the
        # `.gitignore` says is possible ("a guard can be bypassed with git add -f").
        (self.root / "private" / "notes.txt").write_text("plain note, no secret shape\n")
        (self.root / "src" / "a.py").write_text("a = 1\n")
        git(self.root, "add", "-f", "private/notes.txt")
        self.commit()
        self.assertIn("private/notes.txt", git(self.root, "ls-files").stdout.decode())
        results, meta = self.export()
        self.assertIsNotNone(meta, [r.message for r in results])
        named = [r for r in results if r.check_id == "candidate.path-rules-excluded"]
        self.assertEqual(len(named), 1, [r.check_id for r in results])
        self.assertIn("private/notes.txt", named[0].message)
        self.assertFalse((self.out / "private" / "notes.txt").exists(),
                         "a path-rule-refused file must not be written into the candidate")

    def test_a_tracked_database_does_not_ship_and_the_finding_stays_visible(self):
        """A database that reaches git must not enter a candidate, whatever it is called.

        This used to assert a refusal. The refusal was about bytes that do not travel: the
        tree rules drop the file from the plan, so a history-free candidate contains none of
        it. What has to hold instead is the pair: the file is absent from the candidate, and
        the object-store finding is reported rather than dropped. Requiring the refusal made
        a safe export depend on a finding about bytes that stay behind, which teaches an
        operator to clear findings instead of reading them."""
        for name in ("data/records.db.bak-161134", "data/records.db"):
            with self.subTest(name=name):
                for stale in (self.out,):
                    if stale.exists():
                        shutil.rmtree(stale)
                (self.root / "data").mkdir(exist_ok=True)
                path = self.root / "data" / name.rsplit("/", 1)[1]
                path.write_bytes(scan.DATABASE_SIGNATURES[0][1] + b"\x00" * 64)
                (self.root / "src" / "a.py").write_text("a = 1\n")
                # `.db` is ignored by the scaffold's .gitignore, so force it in: git's
                # hygiene file is not a confidentiality control.
                git(self.root, "add", "-f", name)
                self.commit()
                results, meta = self.export()
                self.assertIsNotNone(meta, f"{name}: the export carries no history")
                self.assertFalse((self.out / name).exists(), f"{name} was exported")
                self.assertFalse(
                    sorted(p.relative_to(self.out).as_posix()
                           for p in self.out.rglob("records.db*")),
                    "a database reached the candidate")
                self.assertTrue(
                    [r for r in results
                     if r.check_id == "privacy.full-history" and r.status == FAIL],
                    f"{name}: the object-store finding was not reported")
                shutil.rmtree(self.root / "data")
                git(self.root, "rm", "-q", "--cached", name)
                self.commit("drop")

    def test_an_untracked_file_is_named_rather_than_silently_absent(self):
        """The allowlist is tracked files, so a file the operator just wrote appears in
        neither the included nor the excluded list -- it is simply missing."""
        (self.root / "src" / "a.py").write_text("a = 1\n")
        self.commit()
        (self.root / "src" / "just-written.py").write_text("b = 2\n")
        results, meta = self.export()
        self.assertIsNotNone(meta)
        named = [r for r in results if r.check_id == "candidate.untracked-absent"]
        self.assertEqual(len(named), 1, [r.check_id for r in results])
        self.assertIn("src/just-written.py", named[0].message)
        self.assertFalse((self.out / "src" / "just-written.py").exists())

    def test_acknowledgement_diagnostics_survive_a_refusal(self):
        """The refusal returned before the override results were added, so a mistyped
        or malformed acknowledgement told the operator nothing -- which is the state
        that keeps the export failing."""
        (self.root / "src" / "app.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        for label, entry in (
            ("a path that does not exist",
             {"check_id": "privacy.secret-shape", "path": "src/app.js",
              "reason": "mistyped: the file is app.py", "acknowledged_by": "op",
              "acknowledged_at": "2026-01-01", "expires": "2027-01-01"}),
            ("an expired entry",
             {"check_id": "privacy.secret-shape", "path": "src/app.py",
              "reason": "expired on purpose", "acknowledged_by": "op",
              "acknowledged_at": "2024-01-01", "expires": "2024-02-01"}),
        ):
            with self.subTest(case=label):
                if self.out.exists():
                    shutil.rmtree(self.out)
                (self.root / ".openready-allow.json").write_text(
                    json.dumps({"entries": [entry]}))
                self.commit()
                results, meta = self.export()
                self.assertIsNone(meta)
                ids = [r.check_id for r in results]
                self.assertIn("privacy.secret-shape", ids)
                self.assertTrue(
                    any(i.startswith(("override.unused", "override.entry-")) for i in ids),
                    f"the acknowledgement was silently ignored: {ids}")

    def test_a_refusal_names_every_distinct_file_it_blocks_on(self):
        """A message that says "act on this" while naming four copies of one path is
        unactionable: the operator cannot enumerate what to acknowledge."""
        for name in ("a", "b", "c"):
            (self.root / "src" / f"leak-{name}.py").write_text(
                fixtures.QUOTED_ASSIGNMENT + "\n")
        self.commit()
        results, meta = self.export()
        self.assertIsNone(meta)
        message = [r for r in results if r.check_id == "privacy.secret-shape"][0].message
        self.assertIn("3 occurrence(s) in 3 file(s)", message)
        for name in ("a", "b", "c"):
            self.assertIn(f"src/leak-{name}.py", message)

    def test_a_history_refusal_enumerates_distinct_pairs_not_raw_hits(self):
        """Twenty hits on five pairs rendered as four identical lines."""
        for n in range(3):
            # Different content each time: identical content is one blob, and the
            # object store holds blobs, so the count has to come from real difference.
            (self.root / "src" / "same.py").write_text(
                fixtures.assignment_n(n) + "\n")
            self.commit(f"v{n}")
        git(self.root, "rm", "-q", "src/same.py")
        self.commit("gone")
        # This refusal is reachable only from an internal caller now: the public workflow
        # exports without history, so an unresolved blob cannot block it. The rendering it
        # guards -- distinct pairs, not four identical raw lines -- is still live code.
        results, meta = self.export(history_modes_allowed=True)
        self.assertIsNone(meta)
        message = [r for r in results
                   if r.check_id == "candidate.history-unacknowledged"][0].message
        self.assertIn("src/same.py (privacy.secret-shape) x3", message)
        self.assertIn("distinct path(s)/check(s)", message)

    def test_doctor_does_not_call_a_blob_acknowledgement_gone(self):
        """doctor's acknowledgement pass saw only tree findings, so an entry that
        matched a blob was reported as "matched nothing -- the finding is gone" while
        the exporter still required it. Acting on that advice recreates the refusal."""
        (self.root / "src" / "gone.py").write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        (self.root / ".openready-allow.json").write_text(json.dumps({"entries": [{
            "check_id": "privacy.secret-shape", "path": "src/gone.py",
            "reason": "Synthetic fixture committed then deleted to exercise the blob run.",
            "acknowledged_by": "test", "acknowledged_at": "2026-01-01",
            "expires": "2027-01-01"}]}))
        self.commit("with value")
        git(self.root, "rm", "-q", "src/gone.py")
        self.commit("without")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            doctor.run(self.root, json_output=True)
        payload = json.loads(buffer.getvalue())
        ids = [r["check_id"] for r in payload["results"]]
        self.assertNotIn("override.unused", ids,
                         "doctor advised removing an entry the export gate requires")
        self.assertIn("override.applied", ids)

    def test_stray_files_in_an_existing_candidate_are_reported_at_export_time(self):
        """D26: a destination that merely held the two tool filenames was treated as
        ours, and a stray file in it was only ever mentioned by `verify`."""
        self._clean_export()
        (self.out / "somebody-elses.txt").write_text("not mine\n")
        results, meta = self.export()
        self.assertIsNone(meta)
        self.assertEqual(statuses(results)["candidate.destination"], FAIL)
        self.assertEqual((self.out / "somebody-elses.txt").read_text(), "not mine\n")


class TestAcknowledgementsBindToAnObject(Base):
    """An exception should name the bytes it covers, not every shape at a path.

    The twelve entries this repository used to carry each acknowledged a *whole file*:
    `privacy.secret-shape` at `tests/test_hardening.py` suppressed every credential
    shape in that file until it expired, so a real credential committed there later
    would have been covered by a fixture's exception. An entry may now name the object
    id it looked at, which covers those bytes and nothing else.
    """

    def _leak(self, name: str = "fixture.py") -> str:
        """Commit a credential-shaped file and return the object id it landed as."""
        (self.root / "src" / name).write_text(fixtures.QUOTED_ASSIGNMENT + "\n")
        self.commit("leak")
        report = history.scan(self.root)
        return str(report["hits"][0]["object"])

    def _allow(self, entries) -> None:
        (self.root / ".openready-allow.json").write_text(
            json.dumps({"entries": entries}, indent=2) + "\n")

    def _entry(self, object_id: str = "", path: str = "src/fixture.py") -> dict:
        entry = {"check_id": "privacy.secret-shape", "path": path,
                 "reason": "Synthetic fixture committed to exercise the binding rule.",
                 "acknowledged_by": "test", "acknowledged_at": "2026-01-01"}
        if object_id:
            entry["object"] = object_id
        return entry

    def test_a_path_only_entry_still_covers_the_path_and_says_how_wide_it_is(self):
        """The older form keeps working -- and its width is stated, not implied."""
        self._leak()
        self._allow([self._entry()])
        results, meta = self.export()
        self.assertIsNotNone(meta, "a path-only acknowledgement must still suppress")
        applied = [r for r in results if r.check_id == "override.applied"]
        self.assertTrue(applied)
        self.assertTrue(any("no object id" in item or "every shape found at that path" in item
                            for item in applied[0].limitations),
                        applied[0].limitations)

    def test_a_bound_entry_covers_the_object_it_names(self):
        object_id = self._leak()
        self._allow([self._entry(object_id)])
        results, meta = self.export()
        self.assertIsNotNone(meta)
        self.assertIn(object_id, [r.message for r in results
                                  if r.check_id == "override.applied"][0])

    def test_a_bound_entry_does_not_cover_a_different_object_at_the_same_path(self):
        """The point of the binding: different bytes, different decision."""
        self._leak()
        self._allow([self._entry("0" * 12)])
        results, meta = self.export()
        self.assertIsNone(meta, "an entry naming some other blob must suppress nothing")
        by_id = statuses(results)
        self.assertEqual(by_id["privacy.secret-shape"], FAIL)
        self.assertEqual(by_id["candidate.export"], FAIL)

    def test_the_packet_records_the_object_the_entry_named(self):
        object_id = self._leak()
        self._allow([self._entry(object_id)])
        _, meta = self.export()
        recorded = meta["acknowledged_findings"]
        self.assertEqual([entry.get("object") for entry in recorded], [object_id])


if __name__ == "__main__":
    unittest.main()
