"""Build wheel and sdist; smoke-test both distributions outside the source tree."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import venv

REPO = Path(__file__).resolve().parents[1]
SMOKE = """
from pathlib import Path
from openready import candidate, verify, backup
root = Path('project')
root.mkdir()
(root / 'README.md').write_text('Distribution smoke test\\n')
results, meta = candidate.export(root, Path('candidate'))
assert meta is not None, results
results, packet = verify.verify(Path('candidate'), expected_digest=meta['candidate_digest'])
assert packet is not None, results
assert not any(result.status == 'FAIL' for result in results), results
results, archive = backup.create(root, Path('backup.tar.gz'))
assert archive is not None, results
results, restored = backup.restore(archive, Path('restored'))
assert restored is not None, results
assert (restored / 'README.md').read_bytes() == (root / 'README.md').read_bytes()
"""


def run(args: list[str], cwd: Path, env: dict[str, str]) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> None:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory(prefix="openready-dist-") as tmp:
        work = Path(tmp)
        dist = work / "dist"
        run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)], REPO, env)
        wheel = next(dist.glob("*.whl"))
        sdist = next(dist.glob("*.tar.gz"))
        rebuilt = work / "rebuilt"
        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-index",
                "--wheel-dir",
                str(rebuilt),
                str(sdist),
            ],
            work,
            env,
        )
        for name, artifact in (("wheel", wheel), ("sdist", next(rebuilt.glob("*.whl")))):
            home = work / name
            venv.EnvBuilder(with_pip=True).create(home)
            python = str(home / "bin" / "python")
            run(
                [python, "-m", "pip", "install", "--no-deps", "--no-index", str(artifact)],
                work,
                env,
            )
            case = work / (name + "-smoke")
            case.mkdir()
            run([python, "-I", "-m", "openready", "--version"], case, env)
            run([python, "-I", "-c", SMOKE], case, env)
            print(name + " installed-artifact smoke passed", flush=True)


if __name__ == "__main__":
    main()
