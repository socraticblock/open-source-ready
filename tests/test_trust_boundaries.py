"""Adversarial regressions for artifact and recovery boundaries."""

import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from openready import backup, candidate, verify
from openready.history import content_digest
from openready.status import FAIL


class TrustBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "README.md").write_bytes(b"original\n")
        self.out = self.base / "candidate"

    def test_export_uses_the_bytes_that_were_scanned(self):
        original_scan = candidate.scan_file

        def mutate_after_scan(rel, data):
            findings = original_scan(rel, data)
            (self.root / rel).write_bytes(b"unchecked replacement\n")
            return findings

        with patch.object(candidate, "scan_file", side_effect=mutate_after_scan):
            results, meta = candidate.export(self.root, self.out)
        self.assertIsNotNone(meta, results)
        self.assertEqual((self.out / "README.md").read_bytes(), b"original\n")

    def test_backup_large_file_never_reports_partial_success(self):
        with (self.root / "large.bin").open("wb") as handle:
            handle.truncate(64 * 1024 * 1024 + 1)
        results, archive = backup.create(self.root, self.base / "backup.tar.gz")
        self.assertIsNone(archive)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_backup_read_failure_never_reports_success(self):
        (self.root / "other.txt").write_bytes(b"readable")
        original = Path.read_bytes
        original_open = os.open

        def deny_open(path, *args, **kwargs):
            if path == "README.md":
                raise PermissionError("injected")
            return original_open(path, *args, **kwargs)

        def unreadable(path):
            if path == self.root / "README.md":
                raise PermissionError("injected")
            return original(path)

        with patch.object(Path, "read_bytes", unreadable), patch.object(os, "open", deny_open):
            results, archive = backup.create(self.root, self.base / "backup.tar.gz")
        self.assertIsNone(archive)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_manifest_paths_are_rejected_before_any_content_read(self):
        external = self.base / "outside.txt"
        external.write_bytes(b"outside")
        for rel in (
            "../outside.txt",
            str(external),
            "a/../../outside.txt",
            "a//b",
            "a/./b",
            "C:/file",
            "a\\b",
        ):
            with self.subTest(rel=rel):
                manifest = {
                    "files": [
                        {"path": rel, "sha256": hashlib.sha256(b"outside").hexdigest(), "bytes": 7}
                    ],
                    "digest": content_digest([(rel, b"outside")]),
                }
                with patch.object(
                    Path,
                    "read_bytes",
                    side_effect=AssertionError("content read before path validation"),
                ):
                    results, paths = verify.digest_check(self.root, manifest)
                self.assertTrue(any(r.status == FAIL for r in results))
                self.assertEqual(paths, [])

    def test_manifest_duplicate_is_refused(self):
        data = b"original\n"
        entry = {
            "path": "README.md",
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        results, paths = verify.digest_check(
            self.root, {"files": [entry, entry], "digest": content_digest([("README.md", data)])}
        )
        self.assertTrue(any(r.status == FAIL for r in results))
        self.assertEqual(paths, [])

    def test_symlink_manifest_file_is_not_read(self):
        external = self.base / "outside.txt"
        external.write_bytes(b"outside")
        (self.root / "linked.txt").symlink_to(external)
        entry = {"path": "linked.txt", "sha256": hashlib.sha256(b"outside").hexdigest(), "bytes": 7}
        results, paths = verify.digest_check(
            self.root, {"files": [entry], "digest": content_digest([("linked.txt", b"outside")])}
        )
        self.assertTrue(any(r.status == FAIL for r in results))
        self.assertEqual(paths, [])

    def test_archive_fifo_is_refused(self):
        archive = self.base / "fifo.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("pipe")
            info.type = tarfile.FIFOTYPE
            tar.addfile(info)
        _, unsafe = backup._safe_members(archive)
        self.assertIsNotNone(unsafe)

    def test_archive_duplicate_is_refused(self):
        archive = self.base / "duplicate.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for _ in range(2):
                info = tarfile.TarInfo("file.txt")
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        _, unsafe = backup._safe_members(archive)
        self.assertIsNotNone(unsafe)

    def test_invalid_manifest_never_executes_candidate(self):
        candidate.export(self.root, self.out)
        manifest = json.loads((self.out / "MANIFEST.json").read_text())
        manifest["files"][0]["path"] = "../outside.txt"
        (self.out / "MANIFEST.json").write_text(json.dumps(manifest))
        with patch.object(verify, "restricted_build") as build:
            results, packet = verify.verify(self.out, run_build=True)
        build.assert_not_called()
        self.assertIsNone(packet)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_source_parent_symlink_is_refused(self):
        outside = self.base / "external"
        outside.mkdir()
        (outside / "file.txt").write_bytes(b"private")
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        results, meta = candidate.export(self.root, self.out, source_files=["linked/file.txt"])
        self.assertIsNone(meta)
        self.assertFalse(self.out.exists())

    def test_source_traversal_is_refused_before_hazard_scan(self):
        with patch.object(candidate, "_scan_hazards", side_effect=AssertionError("unsafe read")):
            results, meta = candidate.export(self.root, self.out, source_files=["../outside.txt"])
        self.assertIsNone(meta)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_destination_symlink_is_never_followed(self):
        outside = self.base / "external"
        outside.mkdir()
        self.out.symlink_to(outside, target_is_directory=True)
        results, meta = candidate.export(self.root, self.out)
        self.assertIsNone(meta)
        self.assertEqual(list(outside.iterdir()), [])

    def test_assembly_failure_leaves_no_partial_candidate(self):
        original = candidate._assemble_snapshot

        def fail_after_write(out, snapshot):
            original(out, snapshot)
            raise OSError("disk failure")

        with patch.object(candidate, "_assemble_snapshot", side_effect=fail_after_write):
            results, meta = candidate.export(self.root, self.out)
        self.assertIsNone(meta)
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.base.glob(".openready-stage-*")), [])

    def test_destination_changed_during_scan_preserves_other_data(self):
        original = candidate.scan_file

        def swap_destination(rel, data):
            self.out.mkdir(exist_ok=True)
            (self.out / "owner.txt").write_bytes(b"keep")
            return original(rel, data)

        with patch.object(candidate, "scan_file", side_effect=swap_destination):
            results, meta = candidate.export(self.root, self.out)
        self.assertIsNone(meta)
        self.assertEqual((self.out / "owner.txt").read_bytes(), b"keep")
        self.assertFalse((self.out / "MANIFEST.json").exists())

    def test_executable_mode_is_preserved(self):
        (self.root / "README.md").chmod(0o755)
        results, meta = candidate.export(self.root, self.out)
        self.assertIsNotNone(meta, results)
        self.assertEqual((self.out / "README.md").stat().st_mode & 0o777, 0o755)

    def test_verification_does_not_execute_by_default(self):
        candidate.export(self.root, self.out)
        with patch.object(verify, "restricted_build") as build:
            verify.verify(self.out)
        build.assert_not_called()

    def test_candidate_metadata_symlink_is_refused(self):
        candidate.export(self.root, self.out)
        metadata = self.out / "MANIFEST.json"
        external = self.base / "metadata.json"
        metadata.rename(external)
        metadata.symlink_to(external)
        results, packet = verify.verify(self.out)
        self.assertIsNone(packet)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_malformed_manifest_corpus_fails_without_content_reads(self):
        from openready import boundaries

        entries = [
            None,
            [],
            "text",
            1,
            {"files": None},
            {"files": [None]},
            {"files": [{"path": "safe", "bytes": True, "sha256": "0" * 64}]},
            {"files": [{"path": "safe", "bytes": -1, "sha256": "0" * 64}]},
        ]
        for document in entries:
            with (
                self.subTest(document=document),
                patch.object(boundaries, "read_file", side_effect=AssertionError("read")),
            ):
                results, paths = verify.digest_check(self.root, document)
            self.assertTrue(any(r.status == FAIL for r in results))
            self.assertEqual(paths, [])

    def test_generated_traversal_corpus_is_refused(self):
        from openready import boundaries
        import random

        randomizer = random.Random(1701)
        for _ in range(200):
            parts = ["dir" + str(randomizer.randrange(100)) for _ in range(randomizer.randrange(5))]
            parts.insert(randomizer.randrange(len(parts) + 1), "..")
            with self.assertRaises(boundaries.BoundaryError):
                boundaries.relative_parts("/".join(parts))

    def test_duplicate_json_keys_are_refused(self):
        from openready import boundaries

        with self.assertRaises(boundaries.BoundaryError):
            boundaries.decode_object(b'{"files": [], "files": []}')

    def test_archive_member_size_limit_is_enforced(self):
        from openready import boundaries

        archive = self.base / "large.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("file.txt")
            info.size = 10
            tar.addfile(info, io.BytesIO(b"x" * 10))
        with patch.object(boundaries, "MAX_FILE_BYTES", 5):
            _, unsafe = backup._safe_members(archive)
        self.assertIsNotNone(unsafe)

    def test_archive_decompression_limit_includes_headers(self):
        from openready import boundaries
        import gzip

        raw = gzip.compress(b"\0" * 10000)
        with (
            patch.object(boundaries, "MAX_TOTAL_BYTES", 100),
            patch.object(boundaries, "MAX_METADATA_BYTES", 100),
        ):
            with self.assertRaises(boundaries.BoundaryError):
                backup._tar_bytes(raw)

    def test_restore_uses_validated_bytes_after_archive_replacement(self):
        _, archive = backup.create(self.root, self.base / "backup.tar.gz")
        original = backup._validated_backup

        def swap_after_validation(*args, **kwargs):
            validated = original(*args, **kwargs)
            archive.write_bytes(b"injected replacement")
            return validated

        with patch.object(backup, "_validated_backup", side_effect=swap_after_validation):
            results, restored = backup.restore(archive, self.base / "restored")
        self.assertIsNotNone(restored, results)
        self.assertEqual((restored / "README.md").read_bytes(), b"original\n")

    def test_backup_manifest_traversal_is_refused(self):
        _, archive = backup.create(self.root, self.base / "backup.tar.gz")
        sidecar = archive.with_name(archive.name + backup.MANIFEST_SUFFIX)
        manifest = json.loads(sidecar.read_text())
        manifest["files"][0]["path"] = "../outside.txt"
        sidecar.write_text(json.dumps(manifest))
        results, restored = backup.restore(archive, self.base / "restored")
        self.assertIsNone(restored)
        self.assertFalse((self.base / "restored").exists())
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_backup_directory_enumeration_error_is_not_ignored(self):
        def failing_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError("enumeration denied"))
            return iter(())

        with patch.object(os, "walk", side_effect=failing_walk):
            results, archive = backup.create(self.root, self.base / "backup.tar.gz")
        self.assertIsNone(archive)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_backup_namespace_collision_is_refused(self):
        (self.root / "private").mkdir()
        (self.root / "private" / "record.txt").write_bytes(b"project")
        private = self.base / "vault"
        private.mkdir()
        (private / "record.txt").write_bytes(b"private")
        results, archive = backup.create(self.root, self.base / "backup.tar.gz", private)
        self.assertIsNone(archive)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_file_changed_during_capture_is_refused(self):
        from openready import boundaries

        original_read = os.read
        changed = False

        def mutate(fd, size):
            nonlocal changed
            data = original_read(fd, size)
            if data and not changed:
                changed = True
                (self.root / "README.md").write_bytes(b"changed during read")
            return data

        with patch.object(os, "read", side_effect=mutate):
            with self.assertRaises(boundaries.BoundaryError):
                boundaries.capture(self.root, ["README.md"])

    def test_verifier_enumeration_failure_is_refused(self):
        candidate.export(self.root, self.out)

        def unreadable(*args, **kwargs):
            kwargs["onerror"](PermissionError("directory denied"))
            return iter(())

        with patch.object(os, "walk", side_effect=unreadable):
            results, packet = verify.verify(self.out)
        self.assertIsNone(packet)
        self.assertTrue(any(r.status == FAIL for r in results))

    def test_publisher_refuses_symlink_content(self):
        from openready import publisher

        candidate.export(self.root, self.out)
        target = self.out / "README.md"
        target.unlink()
        target.symlink_to(self.root / "README.md")
        results = publisher.verify_approval(self.out, "example.invalid/repo", "MIT")
        self.assertTrue(
            any(r.check_id == "publisher.candidate-digest" and r.status == FAIL for r in results)
        )

    def test_loopback_probe_refuses_redirect_without_following_it(self):
        from openready import promote
        import urllib.error
        import urllib.request

        request = urllib.request.Request("http://127.0.0.1:1/")
        with self.assertRaises(urllib.error.HTTPError):
            promote._NoRedirect().redirect_request(
                request, None, 302, "Found", {}, "https://example.invalid/"
            )

    def test_restore_does_not_overwrite_existing_data(self):
        _, archive = backup.create(self.root, self.base / "backup.tar.gz")
        destination = self.base / "restored"
        destination.mkdir()
        (destination / "owner.txt").write_bytes(b"keep")
        results, restored = backup.restore(archive, destination)
        self.assertIsNone(restored)
        self.assertEqual((destination / "owner.txt").read_bytes(), b"keep")
        self.assertFalse((destination / "README.md").exists())

    def test_git_enumeration_failure_never_falls_back_to_untracked_files(self):
        import subprocess

        responses = [
            subprocess.CompletedProcess([], 0, stdout=b"true\n"),
            subprocess.CompletedProcess([], 1, stdout=b""),
        ]
        with patch.object(candidate.subprocess, "run", side_effect=responses):
            results, meta = candidate.export(self.root, self.out)
        self.assertIsNone(meta)
        self.assertFalse(self.out.exists())
        self.assertTrue(any(r.status == FAIL for r in results))
