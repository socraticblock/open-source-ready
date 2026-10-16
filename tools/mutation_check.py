"""Remove six boundary controls in disposable copies and demand failing tests.

This is a small, reviewable mutation gate, not a comprehensive mutation score.
The baseline must pass first. A stale mutation target or surviving mutation fails.
"""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
MUTATIONS = (
    (
        "candidate.py",
        "    results.extend(decision_results)",
        "    snapshot = boundaries.capture(root, paths)\n    results.extend(decision_results)",
        "test_export_uses_the_bytes_that_were_scanned",
    ),
    (
        "boundaries.py",
        "if path.casefold() in folded:",
        "if False:",
        "test_manifest_duplicate_is_refused",
    ),
    (
        "boundaries.py",
        "os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK",
        "os.O_RDONLY | os.O_NONBLOCK",
        "test_symlink_manifest_file_is_not_read",
    ),
    (
        "backup.py",
        "if not (member.isfile() or member.isdir()) or member.sparse is not None:",
        "if member.sparse is not None:",
        "test_archive_fifo_is_refused",
    ),
    (
        "backup.py",
        "if total > limit:",
        "if False:",
        "test_archive_decompression_limit_includes_headers",
    ),
    (
        "verify.py",
        "run_build: bool = False,",
        "run_build: bool = True,",
        "test_verification_does_not_execute_by_default",
    ),
)


def run_test(root: Path, test: str = "") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    target = "tests.test_trust_boundaries" + (".TrustBoundaries." + test if test else "")
    return subprocess.run(
        [sys.executable, "-m", "unittest", target, "-q"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def main() -> int:
    baseline = run_test(REPO)
    if baseline.returncode:
        print(baseline.stdout + baseline.stderr)
        return 1
    for module, before, after, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="openready-mutation-") as tmp:
            root = Path(tmp)
            shutil.copytree(
                REPO / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__")
            )
            (root / "tests").mkdir()
            (root / "tests" / "__init__.py").touch()
            shutil.copyfile(
                REPO / "tests" / "test_trust_boundaries.py",
                root / "tests" / "test_trust_boundaries.py",
            )
            target = root / "src" / "openready" / module
            source = target.read_text()
            if before not in source:
                print(f"FAIL: stale mutation target in {module}: {test}")
                return 1
            target.write_text(source.replace(before, after, 1))
            result = run_test(root, test)
            if result.returncode == 0 or "FAIL:" not in result.stderr:
                print(f"FAIL: mutation survived or crashed instead of asserting: {test}")
                print(result.stdout + result.stderr)
                return 1
            print(f"killed: {test}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
