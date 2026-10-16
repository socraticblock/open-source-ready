"""One local/CI engineering gate. Failures stop the gate; limits stay explicit."""

from pathlib import Path
import os
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
CORE = ["src/openready/" + name + ".py" for name in ("boundaries", "backup", "candidate", "verify")]
FORMATTED = CORE + [
    "tests/test_trust_boundaries.py",
    "tools/check.py",
    "tools/mutation_check.py",
    "tools/distribution_check.py",
]


def run(*args: str) -> None:
    print("+ " + " ".join(args), flush=True)
    subprocess.run(
        [sys.executable, *args],
        cwd=REPO,
        env=dict(os.environ, PYTHONPATH=str(REPO / "src")),
        check=True,
    )


def main() -> None:
    run("-m", "ruff", "check", "src", "tests", "acceptance", "tools")
    run("-m", "ruff", "format", "--diff", "src/openready/candidate.py")
    run("-m", "ruff", "format", "--check", *FORMATTED)
    run("-m", "mypy")
    run("-m", "bandit", "-r", "src/openready", "-ll", "-q")
    run("-m", "coverage", "run", "-m", "unittest", "discover", "-s", "tests", "-q")
    run("-m", "coverage", "report", "--include=" + ",".join(CORE), "--fail-under=85")
    # Per-module floors stop a highly covered module hiding an untested boundary.
    for module in CORE:
        floor = "85" if module.endswith(("boundaries.py", "backup.py", "verify.py")) else "80"
        run("-m", "coverage", "report", "--include=" + module, "--fail-under=" + floor)
    run("tools/mutation_check.py")
    run("-m", "acceptance.runner", "--no-report")
    run("tools/release_tree_check.py")


if __name__ == "__main__":
    main()
